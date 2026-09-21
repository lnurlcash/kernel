"""Builders for genuine, correctly-signed script-path spends (test-only).

Every helper signs the BIP341/342 sighash of the CANONICAL synthetic transaction
described in lnurlcashkernel.verify - which is exactly what a wallet must do to
redeem a ct1, so these double as an executable statement of that contract.
"""

from __future__ import annotations

from dataclasses import dataclass

import taproot_ref as t

INTERNAL = t.xonly_pubkey(bytes.fromhex("11" * 32))
OWNER_SK = bytes.fromhex("22" * 32)
OWNER_PK = t.xonly_pubkey(OWNER_SK)
OTHER_SK = bytes.fromhex("33" * 32)
OTHER_PK = t.xonly_pubkey(OTHER_SK)

AMOUNT = 20_000_000
LOCKED_AT = 1_700_000_000
OP = dict(CLTV=b"\xb1", CSV=b"\xb2", DROP=b"\x75", CHECKSIG=b"\xac",
          CHECKSIGADD=b"\xba", SHA256=b"\xa8", EQUALVERIFY=b"\x88",
          NUMEQUAL=b"\x9c", TWO=b"\x52")


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


def multisig2_leaf(a: bytes = OWNER_PK, b: bytes = OTHER_PK) -> bytes:
    return (push_key(a) + OP["CHECKSIG"] + push_key(b) + OP["CHECKSIGADD"]
            + OP["TWO"] + OP["NUMEQUAL"])


@dataclass
class Spend:
    q: bytes
    leaf: bytes
    control: bytes
    witness: list[bytes]
    locktime: int
    sequence: int

    def kwargs(self) -> dict:
        """Arguments for lnurlcashkernel.verify_script_path."""
        return dict(output_key=self.q, amount_msat=AMOUNT, leaf_script=self.leaf,
                    control_block=self.control, witness=self.witness,
                    locktime=self.locktime, sequence=self.sequence)


def sign_spend(
    leaf: bytes, *, signers: list[bytes], locktime: int = 0,
    sequence: int = 0xFFFFFFFE, extra_witness: list[bytes] | None = None,
    tree_with: bytes | None = None, sign_locktime: int | None = None,
) -> Spend:
    """A correctly-signed spend of `leaf` (optionally sharing a tree with
    another leaf). `signers` are secret keys, in the order their signatures must
    appear on the witness stack (BIP342 pops the LAST key's sig first, so the
    stack is built reversed)."""
    if tree_with is None:
        q, control = t.single_leaf_tree(INTERNAL, leaf)
    else:
        q, control, _ = t.two_leaf_tree(INTERNAL, leaf, tree_with)
    spk = t.p2tr_script(q)
    sighash = t.tapscript_sighash(
        version=2,
        locktime=locktime if sign_locktime is None else sign_locktime,
        prevouts=[(b"\x00" * 32, 0)], amounts=[AMOUNT], spent_scripts=[spk],
        sequences=[sequence], outputs=[(0, b"")], input_index=0,
        leaf_hash=t.tapleaf_hash(leaf),
    )
    sigs = [t.schnorr_sign(sighash, sk) for sk in signers]
    # bottom-to-top: signatures first, then any leaf-specific items (e.g. a
    # hashlock preimage) on TOP, since the script consumes those first
    return Spend(q, leaf, control, [*reversed(sigs), *(extra_witness or [])],
                 locktime, sequence)
