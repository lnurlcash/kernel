"""The shipped sighash helpers against the independent test reference, the
LUD-25 spec's own test vector 3, and Core itself (via verify)."""

import spends as s
import taproot_ref as t
from lnurlcashkernel import key_path_sighash, script_path_sighash, verify_witness


def test_key_path_matches_the_reference_signer():
    assert key_path_sighash(s.OWNER_PK, s.DOMAIN) == s.sighash(
        s.OWNER_PK, locktime=0, sequence=0xFFFFFFFF, leaf=None
    )


def test_script_path_matches_the_reference_signer():
    leaf = s.cltv_leaf(1_800_000_000)
    q, _ = t.single_leaf_tree(s.INTERNAL, leaf)
    assert script_path_sighash(q, s.DOMAIN, leaf, locktime=1_800_000_000) == s.sighash(
        q, locktime=1_800_000_000, sequence=0xFFFFFFFE, leaf=leaf
    )


def test_lud25_test_vector_3():
    q = bytes.fromhex("aad3a0e36c083eb0d2d92ec0860977dc46d10c952f31830e6443b1faa1997634")
    assert key_path_sighash(q, "mint.example").hex() == (
        "b8933a42090297a1f80d7f1fc0023ec1aa2ab36a7df332520f0dacf07f617943"
    )


def test_a_signature_over_it_verifies_in_core():
    sk = s.OWNER_SK
    sig = t.schnorr_sign(key_path_sighash(s.OWNER_PK, s.DOMAIN), sk)
    assert verify_witness(output_key=s.OWNER_PK, domain=s.DOMAIN, stack=[sig], locktime=0, sequence=0xFFFFFFFF)
