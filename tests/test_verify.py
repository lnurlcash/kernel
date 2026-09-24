import hashlib

import pytest

import spends as s
import taproot_ref as t
from lnurlcashkernel import (
    Spend,
    ScriptInvalid,
    TimeClaimRejected,
    UnsupportedScript,
    build_spend_tx,
    encode_cp1,
    encode_spend,
    p2tr_script,
    spend_prevout,
    verify_k1,
    verify_spend,
    verify_witness,
)

LOCK = 1_800_000_000
NOW = LOCK + 10


def spend_kwargs(sp: s.Spend, *, now=NOW, locked_at=s.LOCKED_AT, domain=s.DOMAIN) -> dict:
    return dict(output_key=sp.q, domain=domain, spend=sp.to_spend(), now=now, locked_at=locked_at)


def test_canonical_transaction_is_byte_identical_to_what_a_signer_signs():
    # the shipped library and the test signer are independent implementations of
    # the same normative transaction shape; if they ever diverge, no wallet
    # signature could verify. Compare full serialisations.
    sp = s.sign_spend(s.cltv_leaf(LOCK), signers=[s.OWNER_SK], locktime=LOCK)
    expected = t.serialize_tx(
        version=2, prevouts=[(s.prevout(), 0)], sequences=[sp.sequence],
        outputs=[(0, b"")], locktime=LOCK, witnesses=[sp.stack],
    )
    assert build_spend_tx(
        domain=s.DOMAIN, stack=sp.stack, locktime=LOCK, sequence=sp.sequence,
    ) == expected
    assert p2tr_script(sp.q) == t.p2tr_script(sp.q)


def test_the_prevout_is_the_tagged_hash_of_the_lowercase_domain():
    assert spend_prevout("mint.example") == s.prevout("mint.example")
    assert spend_prevout("Mint.Example") == spend_prevout("mint.example")
    with pytest.raises(ValueError):
        spend_prevout("")


# ---- the key path and the canonical bearer note ----
def test_key_path():
    sp = s.key_spend()
    verify_spend(**spend_kwargs(sp))


def test_key_path_by_the_wrong_key_is_rejected():
    sp = s.key_spend(s.OTHER_SK)
    sp.q = s.OWNER_PK  # claims the owner's note with someone else's signature
    with pytest.raises(ScriptInvalid):
        verify_spend(**spend_kwargs(sp))


def test_key_path_must_not_carry_a_time_claim():
    sp = s.key_spend()
    tampered = Spend(1, sp.sequence, None, None, tuple(sp.witness), key=sp.q)
    with pytest.raises(ScriptInvalid):
        verify_spend(output_key=sp.q, domain=s.DOMAIN, spend=tampered, now=NOW, locked_at=0)


def test_preimage_note():
    sp = s.preimage_spend(b"\x42" * 32)
    verify_spend(**spend_kwargs(sp))


def test_preimage_note_wrong_preimage_is_rejected():
    sp = s.preimage_spend(b"\x42" * 32)
    sp.witness = [b"\x43" * 32]
    with pytest.raises(ScriptInvalid):
        verify_spend(**spend_kwargs(sp))


def test_preimage_note_from_its_wire_form():
    sp = s.preimage_spend(b"\x42" * 32)
    verify_k1(cp1=encode_cp1(sp.q), k1=encode_spend(sp.to_spend()), domain=s.DOMAIN,
               now=NOW, locked_at=0)


def test_preimage_note_from_the_hex_short_form():
    preimage = b"\x42" * 32
    sp = s.preimage_spend(preimage)
    verify_k1(cp1=encode_cp1(sp.q), k1=preimage.hex(), domain=s.DOMAIN,
               now=NOW, locked_at=0)


def test_a_preimage_note_is_not_bound_to_a_domain():
    # no signature, nothing to bind: a bare preimage is a bearer secret anywhere
    sp = s.preimage_spend(b"\x42" * 32)
    verify_spend(**spend_kwargs(sp, domain="other.example"))


# ---- other scripts, redeemed for real ----
def test_pk_leaf():
    sp = s.sign_spend(s.pk_leaf(), signers=[s.OWNER_SK])
    verify_spend(**spend_kwargs(sp))


def test_cltv_leaf():
    sp = s.sign_spend(s.cltv_leaf(LOCK), signers=[s.OWNER_SK], locktime=LOCK)
    verify_spend(**spend_kwargs(sp))


def test_csv_leaf():
    seq = (1 << 22) | 4  # 4 * 512 = 2048 seconds
    sp = s.sign_spend(s.csv_leaf(seq), signers=[s.OWNER_SK], sequence=seq)
    verify_spend(**spend_kwargs(sp, now=s.LOCKED_AT + 2048))


def test_hashlock_leaf():
    preimage = b"correct horse battery staple"
    sp = s.sign_spend(
        s.hashlock_leaf(hashlib.sha256(preimage).digest()),
        signers=[s.OWNER_SK], extra_witness=[preimage],
    )
    verify_spend(**spend_kwargs(sp))


def test_hashlock_wrong_preimage_is_rejected():
    sp = s.sign_spend(
        s.hashlock_leaf(hashlib.sha256(b"right").digest()),
        signers=[s.OWNER_SK], extra_witness=[b"wrong"],
    )
    with pytest.raises(ScriptInvalid):
        verify_spend(**spend_kwargs(sp))


def test_multisig2_leaf_needs_both_signatures():
    both = s.sign_spend(s.multisig2_leaf(), signers=[s.OWNER_SK, s.OTHER_SK])
    verify_spend(**spend_kwargs(both))
    # a lone signature (the other slot empty) must fail
    one = s.sign_spend(s.multisig2_leaf(), signers=[s.OWNER_SK], extra_witness=[])
    one.witness = [b"", *one.witness]
    with pytest.raises(ScriptInvalid):
        verify_spend(**spend_kwargs(one))


# ---- the split between script-level and clock-level enforcement ----
def test_script_level_timelock_is_enforced_by_core_with_no_clock():
    sp = s.sign_spend(s.cltv_leaf(LOCK), signers=[s.OWNER_SK], locktime=LOCK - 1)
    # pure verification never looks at any time: Core alone says no
    assert not verify_witness(**sp.kwargs())


def test_a_locktime_still_in_the_future_is_refused_by_the_mint_clock():
    sp = s.sign_spend(s.cltv_leaf(LOCK), signers=[s.OWNER_SK], locktime=LOCK)
    # the script is perfectly satisfied...
    assert verify_witness(**sp.kwargs())
    # ...but the mint's clock says it is too early to honour that claim
    with pytest.raises(TimeClaimRejected):
        verify_spend(**spend_kwargs(sp, now=LOCK - 1))


def test_a_relative_lock_that_has_not_elapsed_is_refused_by_the_mint_clock():
    seq = (1 << 22) | 4
    sp = s.sign_spend(s.csv_leaf(seq), signers=[s.OWNER_SK], sequence=seq)
    assert verify_witness(**sp.kwargs())
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


# ---- any script, but no upgrade hooks ----
def test_any_leaf_script_is_judged_by_core_alone():
    # 2-of-2 via CHECKSIGVERIFY: in no list of shapes, and needs none
    leaf = (s.push_key(s.OWNER_PK) + b"\xad" + s.push_key(s.OTHER_PK) + s.OP["CHECKSIG"])
    sp = s.sign_spend(leaf, signers=[s.OWNER_SK, s.OTHER_SK])
    verify_spend(**spend_kwargs(sp))
    # OP_TRUE: valid Bitcoin, and whoever holds its ck1 may spend it - the
    # holder's own choice, exactly as on-chain
    verify_spend(**spend_kwargs(s.sign_spend(b"\x51", signers=[])))


def test_an_op_success_leaf_is_refused_before_the_kernel_is_consulted():
    # consensus would accept this unconditionally; it must stay unspendable so
    # the opcode can be given a meaning later
    sp = s.sign_spend(b"\x50", signers=[])  # OP_SUCCESS80
    assert verify_witness(**sp.kwargs())  # Core alone would say yes
    with pytest.raises(UnsupportedScript):
        verify_spend(**spend_kwargs(sp))


def test_op_success_inside_pushed_data_is_just_data():
    leaf = b"\x01\x50\x75\x51"  # push 0x50, DROP, TRUE
    verify_spend(**spend_kwargs(s.sign_spend(leaf, signers=[])))


def test_an_unknown_leaf_version_is_refused():
    leaf = b"\x51"
    q, control = t.single_leaf_tree(s.INTERNAL, leaf, version=0xC2)
    sp = s.Spend(q, leaf, control, [], 0, 0xFFFFFFFF)
    assert verify_witness(**sp.kwargs())  # consensus: unknown version succeeds
    with pytest.raises(UnsupportedScript):
        verify_spend(**spend_kwargs(sp))


def test_a_leaf_not_committed_under_q_is_rejected():
    honest = s.sign_spend(s.cltv_leaf(LOCK), signers=[s.OWNER_SK], locktime=LOCK)
    forged = s.sign_spend(s.cltv_leaf(1_700_000_001), signers=[s.OWNER_SK],
                          locktime=1_700_000_001)
    # present the attacker's leaf against the victim's Q: caught before Core...
    with pytest.raises(ScriptInvalid):
        verify_spend(**{**spend_kwargs(forged), "output_key": honest.q})
    # ...and by Core itself, had it got that far
    assert not verify_witness(**{**forged.kwargs(), "output_key": honest.q})


def test_untrusted_garbage_is_a_rejection_never_an_exception():
    sp = s.sign_spend(s.pk_leaf(), signers=[s.OWNER_SK])
    for bad in (
        {**sp.kwargs(), "stack": [*sp.witness, sp.leaf, b"\x00"]},
        {**sp.kwargs(), "stack": [*sp.witness, sp.leaf, b""]},
        {**sp.kwargs(), "stack": [*sp.witness, b"", sp.control]},
        {**sp.kwargs(), "stack": [b"\x00" * 1000]},
        {**sp.kwargs(), "stack": []},
        {**sp.kwargs(), "locktime": -1},
        {**sp.kwargs(), "locktime": 1 << 40},
        {**sp.kwargs(), "sequence": 1 << 40},
    ):
        assert verify_witness(**bad) is False


def test_trusted_inputs_are_validated_loudly():
    sp = s.sign_spend(s.pk_leaf(), signers=[s.OWNER_SK])
    with pytest.raises(ValueError):
        verify_witness(**{**sp.kwargs(), "output_key": b"\x00" * 31})
    with pytest.raises(ValueError):
        verify_witness(**{**sp.kwargs(), "domain": ""})


# ---- what a signature does and does not commit to ----
@pytest.mark.parametrize("make", [
    lambda: s.key_spend(),
    lambda: s.sign_spend(s.pk_leaf(), signers=[s.OWNER_SK]),
], ids=["key", "pk-leaf"])
def test_a_signature_is_bound_to_its_mint(make):
    sp = make()
    assert verify_witness(**sp.kwargs())
    assert not verify_witness(**sp.kwargs(domain="other.example"))


def test_the_amount_is_not_signed():
    # the spent output is always worth 0: one key has exactly one signature for
    # its note, whatever the mint has recorded that note to be worth
    sp = s.key_spend()
    assert sp.witness == s.key_spend().witness
    assert verify_witness(**sp.kwargs())


def test_a_signed_spend_round_trips_through_its_wire_form():
    for sp in (s.key_spend(), s.sign_spend(s.cltv_leaf(LOCK), signers=[s.OWNER_SK], locktime=LOCK)):
        verify_k1(cp1=encode_cp1(sp.q), k1=encode_spend(sp.to_spend()), domain=s.DOMAIN,
                   now=NOW, locked_at=s.LOCKED_AT)
