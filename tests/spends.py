"""Builders for genuine, correctly-signed spends (test-only).

Every helper signs the BIP341/342 sighash of the CANONICAL synthetic transaction
described in lnurlcashkernel.verify - which is exactly what a wallet must do to
redeem a note, so these double as an executable statement of that contract.
The canonical prevout is recomputed here from scratch (not imported), so the
signer stays an independent implementation of it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import taproot_ref as t
from lnurlcashkernel import Spend as KernelSpend

INTERNAL = t.xonly_pubkey(bytes.fromhex("11" * 32))
OWNER_SK = bytes.fromhex("22" * 32)
OWNER_PK = t.xonly_pubkey(OWNER_SK)
OTHER_SK = bytes.fromhex("33" * 32)
OTHER_PK = t.xonly_pubkey(OTHER_SK)

DOMAIN = "mint.example"
AMOUNT = 20_000_000  # what the mint records; never signed (the spent output is worth 0)
LOCKED_AT = 1_700_000_000
NUMS_H = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
OP = dict(CLTV=b"\xb1", CSV=b"\xb2", DROP=b"\x75", CHECKSIG=b"\xac",
          CHECKSIGADD=b"\xba", SHA256=b"\xa8", EQUALVERIFY=b"\x88",
          NUMEQUAL=b"\x9c", TWO=b"\x52", EQUAL=b"\x87")


def prevout(domain: str = DOMAIN) -> bytes:
    return t.tagged_hash("LNURLcash/mint", domain.encode())


def sighash(q: bytes, *, locktime: int, sequence: int, leaf: bytes | None,
            domain: str = DOMAIN) -> bytes:
    """The canonical transaction's sighash for spending Q (leaf=None: key path)."""
    return t.tapscript_sighash(
        version=2, locktime=locktime,
        prevouts=[(prevout(domain), 0)], amounts=[0], spent_scripts=[t.p2tr_script(q)],
        sequences=[sequence], outputs=[(0, b"")], input_index=0,
        leaf_hash=None if leaf is None else t.tapleaf_hash(leaf),
    )


def push_num(n: int) -> bytes:
    """Minimal data push of a positive ScriptNum > 16."""
    assert n > 16
    raw = n.to_bytes((n.bit_length() + 7) // 8, "little")
    if raw[-1] & 0x80:
        raw += b"\x00"
    return bytes([len(raw)]) + raw


def push_key(pk: bytes) -> bytes:
    return b"\x20" + pk


def pk_leaf(pk: bytes = OWNER_PK) -> bytes:
    return push_key(pk) + OP["CHECKSIG"]


def cltv_leaf(locktime: int, pk: bytes = OWNER_PK) -> bytes:
    return push_num(locktime) + OP["CLTV"] + OP["DROP"] + push_key(pk) + OP["CHECKSIG"]


def csv_leaf(sequence: int, pk: bytes = OWNER_PK) -> bytes:
    return push_num(sequence) + OP["CSV"] + OP["DROP"] + push_key(pk) + OP["CHECKSIG"]


def hashlock_leaf(image: bytes, pk: bytes = OWNER_PK) -> bytes:
    return (OP["SHA256"] + push_key(image) + OP["EQUALVERIFY"]
            + push_key(pk) + OP["CHECKSIG"])


def preimage_leaf(image: bytes) -> bytes:
    return OP["SHA256"] + push_key(image) + OP["EQUAL"]


def multisig2_leaf(a: bytes = OWNER_PK, b: bytes = OTHER_PK) -> bytes:
    return (push_key(a) + OP["CHECKSIG"] + push_key(b) + OP["CHECKSIGADD"]
            + OP["TWO"] + OP["NUMEQUAL"])


@dataclass
class Spend:
    q: bytes
    leaf: bytes | None  # None: key path
    control: bytes | None
    witness: list[bytes]
    locktime: int
    sequence: int

    @property
    def stack(self) -> list[bytes]:
        if self.leaf is None:
            return list(self.witness)
        return [*self.witness, self.leaf, self.control]

    def kwargs(self, domain: str = DOMAIN) -> dict:
        """Arguments for lnurlcashkernel.verify_witness."""
        return dict(output_key=self.q, domain=domain, stack=self.stack,
                    locktime=self.locktime, sequence=self.sequence)

    def to_spend(self) -> KernelSpend:
        return KernelSpend(self.locktime, self.sequence, self.leaf, self.control,
                   tuple(self.witness), key=self.q if self.leaf is None else None)


def sign_spend(
    leaf: bytes, *, signers: list[bytes], locktime: int = 0,
    sequence: int = 0xFFFFFFFE, extra_witness: list[bytes] | None = None,
    tree_with: bytes | None = None, sign_locktime: int | None = None,
    internal: bytes = INTERNAL, domain: str = DOMAIN,
) -> Spend:
    """A correctly-signed spend of `leaf` (optionally sharing a tree with
    another leaf). `signers` are secret keys, in the order their signatures must
    appear on the witness stack (BIP342 pops the LAST key's sig first, so the
    stack is built reversed)."""
    if tree_with is None:
        q, control = t.single_leaf_tree(internal, leaf)
    else:
        q, control, _ = t.two_leaf_tree(internal, leaf, tree_with)
    digest = sighash(q, locktime=locktime if sign_locktime is None else sign_locktime,
                     sequence=sequence, leaf=leaf, domain=domain)
    sigs = [t.schnorr_sign(digest, sk) for sk in signers]
    # bottom-to-top: signatures first, then any leaf-specific items (e.g. a
    # hashlock preimage) on TOP, since the script consumes those first
    return Spend(q, leaf, control, [*reversed(sigs), *(extra_witness or [])],
                 locktime, sequence)


def key_spend(sk: bytes = OWNER_SK, *, domain: str = DOMAIN) -> Spend:
    """A key-path spend of Q = x(sk·G): always locktime 0, final sequence."""
    q = t.xonly_pubkey(sk)
    sig = t.schnorr_sign(sighash(q, locktime=0, sequence=0xFFFFFFFF, leaf=None,
                                 domain=domain), sk)
    return Spend(q, None, None, [sig], 0, 0xFFFFFFFF)


def preimage_spend(preimage: bytes) -> Spend:
    """The canonical bearer note: NUMS internal key, one preimage leaf."""
    leaf = preimage_leaf(hashlib.sha256(preimage).digest())
    q, control = t.single_leaf_tree(NUMS_H, leaf)
    return Spend(q, leaf, control, [preimage], 0, 0xFFFFFFFF)
