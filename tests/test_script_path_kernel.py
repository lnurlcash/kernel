"""A REAL script-path spend, built from scratch and judged by Bitcoin Core.

This is the end-to-end proof the cp1 design rests on: a CLTV timelock leaf,
committed under a taproot output key Q, redeemed by revealing the leaf + control
block + a genuine Schnorr signature over the tapscript sighash - and accepted or
rejected by libbitcoinkernel, exactly as a mint would use it.
"""

import struct

import pytest

import taproot_ref as t
from lnurlcashkernel import _native

# fixed, arbitrary test keys (never real funds)
# an internal key must be a real curve point, so derive it from a secret
INTERNAL = t.xonly_pubkey(bytes.fromhex("11" * 32))
OWNER_SK = bytes.fromhex("22" * 32)
OWNER_PK = t.xonly_pubkey(OWNER_SK)

AMOUNT = 20_000_000
DUMMY_TXID = b"\x00" * 32
OP_CLTV, OP_DROP, OP_CHECKSIG = b"\xb1", b"\x75", b"\xac"


def push_num(n: int) -> bytes:
    # minimal ScriptNum data push, 1-5 bytes little-endian (n > 16 here)
    assert n > 16
    raw = n.to_bytes((n.bit_length() + 7) // 8, "little")
    if raw[-1] & 0x80:
        raw += b"\x00"
    return bytes([len(raw)]) + raw


def cltv_leaf(locktime: int) -> bytes:
    return push_num(locktime) + OP_CLTV + OP_DROP + b"\x20" + OWNER_PK + OP_CHECKSIG


def build_spend(*, leaf: bytes, control: bytes, q: bytes, locktime: int,
                sequence: int = 0xFFFFFFFE, sign_locktime: int | None = None,
                sk: bytes = OWNER_SK):
    """Returns (serialized tx, spent_outputs). `sign_locktime` lets a test sign
    over a DIFFERENT locktime than the one the tx carries."""
    prevouts = [(DUMMY_TXID, 0)]
    outputs = [(0, b"")]
    spk = t.p2tr_script(q)
    sig = t.schnorr_sign(
        t.tapscript_sighash(
            version=2,
            locktime=locktime if sign_locktime is None else sign_locktime,
            prevouts=prevouts,
            amounts=[AMOUNT],
            spent_scripts=[spk],
            sequences=[sequence],
            outputs=outputs,
            input_index=0,
            leaf_hash=t.tapleaf_hash(leaf),
        ),
        sk,
    )
    tx = t.serialize_tx(
        version=2,
        prevouts=prevouts,
        sequences=[sequence],
        outputs=outputs,
        locktime=locktime,
        witnesses=[[sig, leaf, control]],
    )
    return tx, [(spk, AMOUNT)]


def verify(tx, spent):
    return _native.verify_input(
        script_pubkey=spent[0][0], amount=AMOUNT, tx=tx,
        spent_outputs=spent, input_index=0,
    )


LOCK = 1_800_000_000  # a Unix-time locktime (>= 500,000,000)


def test_a_genuine_cltv_script_path_spend_is_accepted():
    leaf = cltv_leaf(LOCK)
    q, control = t.single_leaf_tree(INTERNAL, leaf)
    tx, spent = build_spend(leaf=leaf, control=control, q=q, locktime=LOCK)
    assert verify(tx, spent)


def test_the_timelock_is_enforced_by_the_script_itself():
    # the tx claims a locktime EARLIER than the leaf's threshold: Core's
    # OP_CHECKLOCKTIMEVERIFY must reject it, no clock consulted anywhere
    leaf = cltv_leaf(LOCK)
    q, control = t.single_leaf_tree(INTERNAL, leaf)
    tx, spent = build_spend(leaf=leaf, control=control, q=q, locktime=LOCK - 1)
    assert not verify(tx, spent)


def test_a_final_sequence_disables_locktime_and_is_rejected():
    # nSequence 0xffffffff makes nLockTime inert; CLTV must refuse it
    leaf = cltv_leaf(LOCK)
    q, control = t.single_leaf_tree(INTERNAL, leaf)
    tx, spent = build_spend(
        leaf=leaf, control=control, q=q, locktime=LOCK, sequence=0xFFFFFFFF
    )
    assert not verify(tx, spent)


def test_the_signature_commits_to_the_locktime():
    # THE design constraint: the redeemer signs a specific locktime, so the
    # mint cannot pick "now" after the fact. Signing one value while the tx
    # carries another must fail.
    leaf = cltv_leaf(LOCK)
    q, control = t.single_leaf_tree(INTERNAL, leaf)
    tx, spent = build_spend(
        leaf=leaf, control=control, q=q, locktime=LOCK + 500, sign_locktime=LOCK
    )
    assert not verify(tx, spent)


def test_the_wrong_signer_is_rejected():
    leaf = cltv_leaf(LOCK)
    q, control = t.single_leaf_tree(INTERNAL, leaf)
    tx, spent = build_spend(
        leaf=leaf, control=control, q=q, locktime=LOCK, sk=bytes.fromhex("33" * 32)
    )
    assert not verify(tx, spent)


def test_a_leaf_that_is_not_committed_under_q_is_rejected():
    # the forgery case: an attacker's own (valid-looking) leaf and control block
    # presented against the victim's Q
    leaf = cltv_leaf(LOCK)
    q, _ = t.single_leaf_tree(INTERNAL, leaf)
    forged_leaf = cltv_leaf(1_700_000_000)  # an earlier, more convenient lock
    _, forged_control = t.single_leaf_tree(INTERNAL, forged_leaf)
    tx, spent = build_spend(
        leaf=forged_leaf, control=forged_control, q=q, locktime=1_700_000_000
    )
    assert not verify(tx, spent)


def test_multi_leaf_tree_each_leaf_redeems_independently():
    a, b = cltv_leaf(LOCK), b"\x20" + OWNER_PK + OP_CHECKSIG
    q, control_a, control_b = t.two_leaf_tree(INTERNAL, a, b)
    tx_a, spent = build_spend(leaf=a, control=control_a, q=q, locktime=LOCK)
    tx_b, _ = build_spend(leaf=b, control=control_b, q=q, locktime=0)
    assert verify(tx_a, spent)
    assert verify(tx_b, spent)
    # ...and a leaf cannot be redeemed with the OTHER leaf's control block
    tx_x, _ = build_spend(leaf=a, control=control_b, q=q, locktime=LOCK)
    assert not verify(tx_x, spent)
