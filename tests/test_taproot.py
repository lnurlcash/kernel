"""The shipped public-key arithmetic (lnurlcashkernel.taproot) against the
independent test reference, and against BIP-341's own definition of H."""

import hashlib

import spends as s
import taproot_ref as t
from lnurlcashkernel import NUMS_H, output_key, preimage_leaf, preimage_note


def test_nums_h_is_bip341s_point():
    g_uncompressed = b"\x04" + t.G[0].to_bytes(32, "big") + t.G[1].to_bytes(32, "big")
    assert NUMS_H == hashlib.sha256(g_uncompressed).digest()
    t.lift_x(int.from_bytes(NUMS_H, "big"))  # and it is on the curve


def test_output_key_matches_the_reference_for_one_and_two_leaf_trees():
    leaf = s.pk_leaf()
    q, control = t.single_leaf_tree(s.INTERNAL, leaf)
    assert output_key(leaf, control) == q
    a, b = s.cltv_leaf(1_800_000_000), s.pk_leaf(s.OTHER_PK)
    q2, ca, cb = t.two_leaf_tree(s.INTERNAL, a, b)
    assert output_key(a, ca) == q2 == output_key(b, cb)


def test_output_key_rejects_a_wrong_parity_bit_and_malformed_blocks():
    leaf = s.pk_leaf()
    _, control = t.single_leaf_tree(s.INTERNAL, leaf)
    assert output_key(leaf, bytes([control[0] ^ 1]) + control[1:]) is None
    assert output_key(leaf, control[:32]) is None
    assert output_key(leaf, control + b"\x00") is None
    assert output_key(leaf, control[:1] + b"\xff" * 32) is None  # not a curve point


def test_preimage_note_matches_the_reference():
    image = hashlib.sha256(b"secret").digest()
    q, control = preimage_note(image)
    assert (q, control) == t.single_leaf_tree(NUMS_H, preimage_leaf(image))
    assert preimage_leaf(image) == s.preimage_leaf(image)
