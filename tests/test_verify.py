import hashlib

import pytest

import spends as s
import taproot_ref as t
from lnurlcashkernel import (
    ScriptInvalid,
    TimeClaimRejected,
    UnsupportedScript,
    build_spend_tx,
    p2tr_script,
    verify_script_path,
    verify_spend,
)

LOCK = 1_800_000_000
NOW = LOCK + 10


def spend_kwargs(sp: s.Spend, *, now=NOW, locked_at=s.LOCKED_AT) -> dict:
    return {**sp.kwargs(), "now": now, "locked_at": locked_at}


def test_canonical_transaction_is_byte_identical_to_what_a_signer_signs():
    # the shipped library and the test signer are independent implementations of
    # the same normative transaction shape; if they ever diverge, no wallet
    # signature could verify. Compare full serialisations.
    sp = s.sign_spend(s.cltv_leaf(LOCK), signers=[s.OWNER_SK], locktime=LOCK)
    expected = t.serialize_tx(
        version=2, prevouts=[(b"\x00" * 32, 0)], sequences=[sp.sequence],
        outputs=[(0, b"")], locktime=LOCK,
        witnesses=[[*sp.witness, sp.leaf, sp.control]],
    )
    assert build_spend_tx(
        leaf_script=sp.leaf, control_block=sp.control, witness=sp.witness,
        locktime=LOCK, sequence=sp.sequence,
    ) == expected
    assert p2tr_script(sp.q) == t.p2tr_script(sp.q)


# ---- every supported leaf shape, redeemed for real ----
def test_pk_leaf():
    sp = s.sign_spend(s.pk_leaf(), signers=[s.OWNER_SK])
    assert verify_spend(**spend_kwargs(sp)).kind == "pk"


def test_cltv_leaf():
    sp = s.sign_spend(s.cltv_leaf(LOCK), signers=[s.OWNER_SK], locktime=LOCK)
    assert verify_spend(**spend_kwargs(sp)).kind == "cltv"


def test_csv_leaf():
    seq = (1 << 22) | 4  # 4 * 512 = 2048 seconds
    sp = s.sign_spend(s.csv_leaf(seq), signers=[s.OWNER_SK], sequence=seq)
    tpl = verify_spend(**spend_kwargs(sp, now=s.LOCKED_AT + 2048))
    assert tpl.kind == "csv" and tpl.csv_seconds == 2048


def test_hashlock_leaf():
    preimage = b"correct horse battery staple"
    sp = s.sign_spend(
        s.hashlock_leaf(hashlib.sha256(preimage).digest()),
        signers=[s.OWNER_SK], extra_witness=[preimage],
    )
    assert verify_spend(**spend_kwargs(sp)).kind == "hashlock"


def test_hashlock_wrong_preimage_is_rejected():
    sp = s.sign_spend(
        s.hashlock_leaf(hashlib.sha256(b"right").digest()),
        signers=[s.OWNER_SK], extra_witness=[b"wrong"],
    )
    with pytest.raises(ScriptInvalid):
        verify_spend(**spend_kwargs(sp))


def test_multisig2_leaf_needs_both_signatures():
    both = s.sign_spend(s.multisig2_leaf(), signers=[s.OWNER_SK, s.OTHER_SK])
    assert verify_spend(**spend_kwargs(both)).kind == "multisig2"
    # a lone signature (the other slot empty) must fail
    one = s.sign_spend(s.multisig2_leaf(), signers=[s.OWNER_SK], extra_witness=[])
    one.witness = [b"", *one.witness]
    with pytest.raises(ScriptInvalid):
        verify_spend(**spend_kwargs(one))


# ---- the split between script-level and clock-level enforcement ----
def test_script_level_timelock_is_enforced_by_core_with_no_clock():
    sp = s.sign_spend(s.cltv_leaf(LOCK), signers=[s.OWNER_SK], locktime=LOCK - 1)
    # pure verification never looks at any time: Core alone says no
    assert not verify_script_path(**sp.kwargs())


def test_a_locktime_still_in_the_future_is_refused_by_the_mint_clock():
    sp = s.sign_spend(s.cltv_leaf(LOCK), signers=[s.OWNER_SK], locktime=LOCK)
    # the script is perfectly satisfied...
    assert verify_script_path(**sp.kwargs())
    # ...but the mint's clock says it is too early to honour that claim
    with pytest.raises(TimeClaimRejected):
        verify_spend(**spend_kwargs(sp, now=LOCK - 1))


def test_a_relative_lock_that_has_not_elapsed_is_refused_by_the_mint_clock():
    seq = (1 << 22) | 4
    sp = s.sign_spend(s.csv_leaf(seq), signers=[s.OWNER_SK], sequence=seq)
    assert verify_script_path(**sp.kwargs())
    with pytest.raises(TimeClaimRejected):
        verify_spend(**spend_kwargs(sp, now=s.LOCKED_AT + 2047))
    verify_spend(**spend_kwargs(sp, now=s.LOCKED_AT + 2048))  # exactly at the boundary


def test_the_redeemer_cannot_change_the_claim_after_signing():
    # the signature commits to locktime, so a mint can't be handed a different
    # (e.g. earlier) value than the one that was signed
    sp = s.sign_spend(
        s.cltv_leaf(LOCK), signers=[s.OWNER_SK], locktime=LOCK, sign_locktime=LOCK + 99,
    )
    with pytest.raises(ScriptInvalid):
        verify_spend(**spend_kwargs(sp))


# ---- scope and forgery ----
def test_unrecognised_leaf_is_refused_before_the_kernel_is_consulted():
    weird = b"\x51"  # OP_TRUE - valid Bitcoin, not a shape a mint redeems
    sp = s.sign_spend(weird, signers=[])
    with pytest.raises(UnsupportedScript):
        verify_spend(**spend_kwargs(sp))


def test_a_leaf_not_committed_under_q_is_rejected():
    honest = s.sign_spend(s.cltv_leaf(LOCK), signers=[s.OWNER_SK], locktime=LOCK)
    forged = s.sign_spend(s.cltv_leaf(1_700_000_001), signers=[s.OWNER_SK],
                          locktime=1_700_000_001)
    forged.q = honest.q  # present the attacker's leaf against the victim's Q
    with pytest.raises(ScriptInvalid):
        verify_spend(**spend_kwargs(forged))


def test_untrusted_garbage_is_a_rejection_never_an_exception():
    sp = s.sign_spend(s.pk_leaf(), signers=[s.OWNER_SK])
    for bad in (
        {**sp.kwargs(), "control_block": b"\x00"},
        {**sp.kwargs(), "control_block": b""},
        {**sp.kwargs(), "leaf_script": b""},
        {**sp.kwargs(), "witness": [b"\x00" * 1000]},
        {**sp.kwargs(), "locktime": -1},
        {**sp.kwargs(), "locktime": 1 << 40},
        {**sp.kwargs(), "sequence": 1 << 40},
    ):
        assert verify_script_path(**bad) is False


def test_trusted_inputs_are_validated_loudly():
    sp = s.sign_spend(s.pk_leaf(), signers=[s.OWNER_SK])
    with pytest.raises(ValueError):
        verify_script_path(**{**sp.kwargs(), "output_key": b"\x00" * 31})
    with pytest.raises(ValueError):
        verify_script_path(**{**sp.kwargs(), "amount_msat": -1})


def test_the_amount_is_bound_to_the_signature():
    sp = s.sign_spend(s.pk_leaf(), signers=[s.OWNER_SK])
    assert verify_script_path(**sp.kwargs())
    assert not verify_script_path(**{**sp.kwargs(), "amount_msat": s.AMOUNT + 1})
