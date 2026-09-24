"""The cross-repo interop check.

`vectors/wallet_spend_vectors.json` is produced by lnurl-wallet's OWN code (its
script templates, taproot tweak, control-block builder, cp1/ck1/cw1 encoders
and ck1 signer, with script-path signing by @scure/btc-signer's own
transaction code). Here those wire strings are decoded by this package's
independent Python codec and judged by Bitcoin Core.

Nothing is shared between the two sides but the wire format - so a pass means
the format and the canonical spend transaction are genuinely implementable
from the spec, not an accident of one codebase. Regenerate with the command
in the wallet's src/addons/taproot/spendInterop.test.ts.
"""

import json
from pathlib import Path

import pytest

import taproot_ref as t
from lnurlcashkernel import (
    SpendRejected,
    TimeClaimRejected,
    decode_cp1,
    decode_spend,
    verify_k1,
    verify_witness,
)

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "wallet_spend_vectors.json").read_text()
)["vectors"]
IDS = [v["name"] for v in VECTORS]
SCRIPT_VECTORS = [v for v in VECTORS if "leaf_script" in v]
SCRIPT_IDS = [v["name"] for v in SCRIPT_VECTORS]
BY_NAME = {v["name"]: v for v in VECTORS}


def test_vectors_cover_both_spend_paths():
    assert IDS[0] == "key"
    assert {"pk", "cltv", "csv", "hashlock", "multisig2"} <= set(IDS)


@pytest.mark.parametrize("v", VECTORS, ids=IDS)
def test_wire_strings_decode_to_what_the_wallet_meant(v):
    q = bytes.fromhex(v["output_key"])
    assert decode_cp1(v["cp1"]) == q
    spend = decode_spend(v["spend"])
    assert spend is not None and spend.output_key == q
    if "leaf_script" in v:
        assert spend.locktime == v["locktime"]
        assert spend.sequence == v["sequence"]
        assert spend.script == bytes.fromhex(v["leaf_script"])
        assert spend.control_block == bytes.fromhex(v["control_block"])
        assert [w.hex() for w in spend.witness] == v["witness"]
    else:
        assert spend.key_path


@pytest.mark.parametrize("v", VECTORS, ids=IDS)
def test_bitcoin_core_accepts_the_wallets_spend(v):
    verify_k1(cp1=v["cp1"], k1=v["spend"], domain=v["domain"], now=v["now"], locked_at=v["locked_at"])


@pytest.mark.parametrize("v", VECTORS, ids=IDS)
def test_a_spend_is_bound_to_its_mint(v):
    spend = decode_spend(v["spend"])
    signs_something = spend.key_path or any(len(w) in (64, 65) for w in spend.witness)
    if not signs_something:
        pytest.skip("no signature in this spend, so nothing binds it to a domain")
    with pytest.raises(SpendRejected):
        verify_k1(cp1=v["cp1"], k1=v["spend"], domain="other.example", now=v["now"],
                  locked_at=v["locked_at"])


@pytest.mark.parametrize("v", SCRIPT_VECTORS, ids=SCRIPT_IDS)
def test_the_wallets_output_key_is_a_real_taproot_commitment(v):
    # independently re-derive Q from the wallet's internal key + leaf using the
    # Python reference, and confirm the wallet's control block reveals the same
    control = bytes.fromhex(v["control_block"])
    if len(control) != 33:
        pytest.skip("multi-leaf tree: covered by Core accepting the spend")
    q, parity = t.tweak_output_key(control[1:33], t.tapleaf_hash(bytes.fromhex(v["leaf_script"])))
    assert q.hex() == v["output_key"]
    assert control[0] & 1 == parity


@pytest.mark.parametrize("v", SCRIPT_VECTORS, ids=SCRIPT_IDS)
def test_tampering_with_the_wallets_spend_is_rejected(v):
    spend = decode_spend(v["spend"])
    base = dict(output_key=spend.output_key, domain=v["domain"], stack=spend.stack,
                locktime=spend.locktime, sequence=spend.sequence)
    assert verify_witness(**base)
    sig_index = next((i for i, w in enumerate(spend.witness) if len(w) in (64, 65)), None)
    if sig_index is None:
        pytest.skip("no signature to tamper with")
    stack = list(spend.stack)
    stack[sig_index] = bytes([stack[sig_index][0] ^ 1]) + stack[sig_index][1:]
    assert not verify_witness(**{**base, "stack": stack})
    assert not verify_witness(**{**base, "locktime": spend.locktime ^ 1})


def test_the_mint_clock_gates_the_wallets_timelocks():
    cltv, csv = BY_NAME["cltv"], BY_NAME["csv"]
    with pytest.raises(TimeClaimRejected):
        verify_k1(cp1=cltv["cp1"], k1=cltv["spend"], domain=cltv["domain"],
                  now=cltv["locktime"] - 1, locked_at=cltv["locked_at"])
    with pytest.raises(TimeClaimRejected):
        verify_k1(cp1=csv["cp1"], k1=csv["spend"], domain=csv["domain"],
                  now=csv["locked_at"] + 2047, locked_at=csv["locked_at"])
