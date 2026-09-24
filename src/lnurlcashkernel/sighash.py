"""The BIP-341/342 signature hash a LUD-25 spend signs - for wallets and tests.

This package never signs anything, and never needs these to verify (Core
computes the sighash itself). They exist so a signer in Python gets the one
hash that will verify, for the canonical spend transaction (see verify.py),
without re-deriving BIP-341's SigMsg by hand. SIGHASH_DEFAULT only.
"""

from __future__ import annotations

import hashlib
import struct

from .taproot import tagged_hash, tapleaf_hash
from .verify import SPENT_AMOUNT, TX_VERSION, p2tr_script, spend_prevout


def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sig_msg(
    *, output_key: bytes, domain: str, locktime: int, sequence: int, leaf_script: bytes | None
) -> bytes:
    """BIP-341's SigMsg for input 0 of the canonical spend transaction,
    SIGHASH_DEFAULT, plus BIP-342's extension when `leaf_script` is given."""
    spk = p2tr_script(output_key)
    msg = b"\x00"  # hash_type: SIGHASH_DEFAULT
    msg += struct.pack("<i", TX_VERSION) + struct.pack("<I", locktime)
    msg += _sha(spend_prevout(domain) + struct.pack("<I", 0))  # sha_prevouts
    msg += _sha(struct.pack("<q", SPENT_AMOUNT))  # sha_amounts
    msg += _sha(bytes([len(spk)]) + spk)  # sha_scriptpubkeys
    msg += _sha(struct.pack("<I", sequence))  # sha_sequences
    msg += _sha(struct.pack("<q", 0) + b"\x00")  # sha_outputs: one empty output
    msg += bytes([0 if leaf_script is None else 2])  # spend_type, no annex
    msg += struct.pack("<I", 0)  # input_index
    if leaf_script is not None:
        msg += tapleaf_hash(leaf_script) + b"\x00" + b"\xff\xff\xff\xff"
    return msg


def key_path_sighash(output_key: bytes, domain: str) -> bytes:
    """What a `ck1` signature signs: key path, locktime 0, final sequence."""
    msg = sig_msg(output_key=output_key, domain=domain, locktime=0, sequence=0xFFFFFFFF, leaf_script=None)
    return tagged_hash("TapSighash", b"\x00" + msg)


def script_path_sighash(
    output_key: bytes, domain: str, leaf_script: bytes, *, locktime: int = 0, sequence: int = 0xFFFFFFFE
) -> bytes:
    """What a signature inside a `cw1`'s leaf signs, for the claimed time."""
    msg = sig_msg(
        output_key=output_key, domain=domain, locktime=locktime, sequence=sequence, leaf_script=leaf_script
    )
    return tagged_hash("TapSighash", b"\x00" + msg)
