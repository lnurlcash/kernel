"""Verify a taproot script-path spend of a ct1 note.

Two entry points, deliberately separate:

 * `verify_script_path` - PURE. Asks Bitcoin Core whether a revealed leaf,
   control block and witness satisfy the output key Q under the redeemer's
   claimed locktime/sequence. Never consults a clock; results depend only on
   its arguments.
 * `verify_spend` - the mint-facing composition: recognise the leaf shape, check
   the redeemer's time claim against the mint's own clock (`policy`), then call
   `verify_script_path`. Denies by raising `SpendRejected`.

The canonical spend transaction
-------------------------------
Core verifies an input of a transaction, so this package assembles a fixed,
minimal synthetic one. A signer must sign the BIP341 sighash of exactly this
transaction, so its shape is normative and MUST NOT change without a version
bump - every field below is committed to by the signature:

    nVersion    2   (OP_CHECKSEQUENCEVERIFY requires >= 2)
    vin[0]      prevout (32 zero bytes, index 0), empty scriptSig,
                nSequence = the redeemer's claimed sequence
    vout[0]     value 0, empty scriptPubKey
    nLockTime   = the redeemer's claimed locktime
    spent       (OP_1 <Q>, amount_msat) - a P2TR output, amount committed as-is

`amount_msat` is passed to Core as the "satoshi" amount purely as an opaque
committed value; signer and mint just have to agree on it.
"""

from __future__ import annotations

import struct

from . import _native
from .encoding import decode_ct1, decode_cw1
from .errors import ScriptInvalid, SpendRejected, UnsupportedScript
from .policy import check_time_claim
from .templates import Template, recognize_template

TX_VERSION = 2
_PREVOUT_TXID = b"\x00" * 32
_U32_MAX = 0xFFFFFFFF
_I64_MAX = (1 << 63) - 1


def _compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def p2tr_script(output_key: bytes) -> bytes:
    """scriptPubKey for a taproot output: OP_1 <32-byte key>."""
    return b"\x51\x20" + output_key


def build_spend_tx(
    *, leaf_script: bytes, control_block: bytes, witness: list[bytes],
    locktime: int, sequence: int,
) -> bytes:
    """The canonical synthetic spend transaction (see module docstring), with
    the segwit witness stack `[*witness, leaf_script, control_block]`."""
    stack = [*witness, leaf_script, control_block]
    out = struct.pack("<i", TX_VERSION) + b"\x00\x01"  # segwit marker + flag
    out += b"\x01" + _PREVOUT_TXID + struct.pack("<I", 0)
    out += b"\x00" + struct.pack("<I", sequence)  # empty scriptSig
    out += b"\x01" + struct.pack("<q", 0) + b"\x00"  # one empty output
    out += _compact_size(len(stack))
    for item in stack:
        out += _compact_size(len(item)) + item
    return out + struct.pack("<I", locktime)


def verify_script_path(
    *,
    output_key: bytes,
    amount_msat: int,
    leaf_script: bytes,
    control_block: bytes,
    witness: list[bytes],
    locktime: int,
    sequence: int,
) -> bool:
    """Does this script-path spend satisfy `output_key` under Core's rules?

    `output_key` and `amount_msat` come from the mint's own records, so a bad
    one is a programming error (ValueError). Everything else is supplied by the
    redeemer and is untrusted: anything malformed is simply not a valid spend
    (False), never an exception an attacker can use to crash a request.
    """
    if len(output_key) != 32:
        raise ValueError("output_key must be a 32-byte x-only key")
    if not 0 <= amount_msat <= _I64_MAX:
        raise ValueError("amount_msat out of range")

    if not (0 <= locktime <= _U32_MAX and 0 <= sequence <= _U32_MAX):
        return False
    if not leaf_script or not control_block:
        return False

    spk = p2tr_script(output_key)
    tx = build_spend_tx(
        leaf_script=leaf_script, control_block=control_block, witness=witness,
        locktime=locktime, sequence=sequence,
    )
    return _native.verify_input(
        script_pubkey=spk,
        amount=amount_msat,
        tx=tx,
        spent_outputs=[(spk, amount_msat)],
        input_index=0,
    )


def verify_spend(
    *,
    output_key: bytes,
    amount_msat: int,
    leaf_script: bytes,
    control_block: bytes,
    witness: list[bytes],
    locktime: int,
    sequence: int,
    now: int,
    locked_at: int,
) -> Template:
    """Mint-facing: accept the spend (returning the recognised Template) or
    raise `SpendRejected`. `now`/`locked_at` are the mint's own clock, in Unix
    seconds - this library never reads one itself."""
    template = recognize_template(leaf_script)
    if template is None:
        raise UnsupportedScript("leaf script is not a supported shape")

    check_time_claim(
        locktime=locktime, sequence=sequence, now=now, locked_at=locked_at
    )

    if not verify_script_path(
        output_key=output_key, amount_msat=amount_msat,
        leaf_script=leaf_script, control_block=control_block, witness=witness,
        locktime=locktime, sequence=sequence,
    ):
        raise ScriptInvalid("bitcoin core rejected the script-path spend")
    return template


def verify_cw1(
    *, ct1: str, cw1: str, amount_msat: int, now: int, locked_at: int
) -> Template:
    """`verify_spend` for the wire values themselves: the note's `ct1` (from the
    mint's records) and the `cw1` a redeemer presents. Raises `SpendRejected`
    if the cw1 is malformed - it is attacker-supplied - and ValueError if the
    ct1 is, since that comes from the mint's own storage."""
    output_key = decode_ct1(ct1)
    if output_key is None:
        raise ValueError("not a valid ct1")
    spend = decode_cw1(cw1)
    if spend is None:
        raise SpendRejected("malformed cw1")
    return verify_spend(
        output_key=output_key,
        amount_msat=amount_msat,
        leaf_script=spend.script,
        control_block=spend.control_block,
        witness=list(spend.witness),
        locktime=spend.locktime,
        sequence=spend.sequence,
        now=now,
        locked_at=locked_at,
    )
