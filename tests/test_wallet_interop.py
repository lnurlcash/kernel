"""The cross-repo interop check.

`vectors/wallet_ct1_vectors.json` is produced by lnurl-wallet's OWN code (its
script templates, taproot tweak, control-block builder and ct1/cw1 encoders,
with Schnorr signing by @scure/btc-signer). Here those wire strings are decoded
by this package's independent Python codec and judged by Bitcoin Core.

Nothing is shared between the two sides but the wire format - so a pass means
the format is genuinely implementable from the spec, not an accident of one
codebase. Regenerate with the command in the wallet's ct1Interop.test.ts.
"""

import json
from pathlib import Path

import pytest

import taproot_ref as t
from lnurlcashkernel import (
    SpendRejected,
    TimeClaimRejected,
    decode_ct1,
    decode_cw1,
    verify_cw1,
    verify_script_path,
)

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "wallet_ct1_vectors.json").read_text()
)["vectors"]
IDS = [v["name"] for v in VECTORS]


def test_vectors_cover_every_supported_shape():
    assert IDS == ["pk", "cltv", "csv", "hashlock", "multisig2"]


@pytest.mark.parametrize("v", VECTORS, ids=IDS)
def test_wire_strings_decode_to_what_the_wallet_meant(v):
    # a cross-language check of the wire format itself
    assert decode_ct1(v["ct1"]) == bytes.fromhex(v["output_key"])
    spend = decode_cw1(v["cw1"])
    assert spend is not None
    assert spend.locktime == v["locktime"]
    assert spend.sequence == v["sequence"]
    assert spend.script == bytes.fromhex(v["leaf_script"])
    assert spend.control_block == bytes.fromhex(v["control_block"])
    assert [w.hex() for w in spend.witness] == v["witness"]


@pytest.mark.parametrize("v", VECTORS, ids=IDS)
def test_bitcoin_core_accepts_the_wallets_spend(v):
    tpl = verify_cw1(
        ct1=v["ct1"], cw1=v["cw1"], amount_msat=v["amount_msat"],
        now=v["now"], locked_at=v["locked_at"],
    )
    assert tpl.kind == v["expect_kind"]


@pytest.mark.parametrize("v", VECTORS, ids=IDS)
def test_the_wallets_output_key_is_a_real_taproot_commitment(v):
    # independently re-derive Q from the wallet's internal key + leaf using the
    # Python reference, and confirm the wallet's control block reveals the same
    control = bytes.fromhex(v["control_block"])
    internal = control[1:33]
    q, parity = t.tweak_output_key(internal, t.tapleaf_hash(bytes.fromhex(v["leaf_script"])))
    assert q.hex() == v["output_key"]
    assert control[0] & 1 == parity


@pytest.mark.parametrize("v", VECTORS, ids=IDS)
def test_tampering_with_the_wallets_spend_is_rejected(v):
    control = bytes.fromhex(v["control_block"])
    base = dict(
        output_key=bytes.fromhex(v["output_key"]), amount_msat=v["amount_msat"],
        leaf_script=bytes.fromhex(v["leaf_script"]), control_block=control,
        witness=[bytes.fromhex(w) for w in v["witness"]],
        locktime=v["locktime"], sequence=v["sequence"],
    )
    assert verify_script_path(**base)
    # a different amount, a flipped witness byte, and a different claimed
    # locktime must each break the signature
    assert not verify_script_path(**{**base, "amount_msat": v["amount_msat"] + 1})
    bad = list(base["witness"])
    bad[0] = bytes([bad[0][0] ^ 1]) + bad[0][1:]
    assert not verify_script_path(**{**base, "witness": bad})
    assert not verify_script_path(**{**base, "locktime": v["locktime"] ^ 1})


def test_the_mint_clock_gates_the_walletss_timelocks():
    by_name = {v["name"]: v for v in VECTORS}
    cltv, csv = by_name["cltv"], by_name["csv"]
    with pytest.raises(TimeClaimRejected):
        verify_cw1(ct1=cltv["ct1"], cw1=cltv["cw1"], amount_msat=cltv["amount_msat"],
                   now=cltv["locktime"] - 1, locked_at=cltv["locked_at"])
    with pytest.raises(TimeClaimRejected):
        verify_cw1(ct1=csv["ct1"], cw1=csv["cw1"], amount_msat=csv["amount_msat"],
                   now=csv["locked_at"] + 2047, locked_at=csv["locked_at"])


def test_a_malformed_cw1_is_a_rejection_not_a_crash():
    v = VECTORS[0]
    for junk in ("", "cw1", "not bech32m", v["ct1"], v["cw1"][:-3], v["cw1"].upper()[:-1] + "x"):
        with pytest.raises(SpendRejected):
            verify_cw1(ct1=v["ct1"], cw1=junk, amount_msat=v["amount_msat"],
                       now=v["now"], locked_at=v["locked_at"])
