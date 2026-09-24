"""Verify a spend of a LUD-25 note.

Every note is a taproot output key Q. It is opened either by its key path (a
signature by Q itself) or by one of its script-path leaves; both are judged by
Bitcoin Core against the same canonical transaction.

Two entry points, deliberately separate:

 * `verify_witness` - PURE. Asks Bitcoin Core whether a witness stack spends
   the output key Q under the redeemer's claimed locktime/sequence. Never
   consults a clock; results depend only on its arguments.
 * `verify_spend` - the mint-facing composition: close tapscript's upgrade
   hooks (`script`), check the redeemer's time claim against the mint's own
   clock (`policy`), then call `verify_witness`. Denies by raising
   `SpendRejected`.

Any leaf script is accepted: what it may do is decided by Bitcoin Core's
consensus rules alone, not by a list of shapes.

The canonical spend transaction (version 2)
-------------------------------------------
Core verifies an input of a transaction, so this package assembles a fixed,
minimal synthetic one. A signer must sign the BIP341 sighash of exactly this
transaction, so its shape is normative and MUST NOT change without a version
bump - every field below is committed to by the signature:

    nVersion    2   (OP_CHECKSEQUENCEVERIFY requires >= 2)
    vin[0]      prevout (tagged_hash("LNURLcash/mint", domain), 0),
                empty scriptSig, nSequence = the redeemer's claimed sequence
    vout[0]     value 0, empty scriptPubKey
    nLockTime   = the redeemer's claimed locktime
    spent       (OP_1 <Q>, 0) - a P2TR output worth 0

`domain` is the mint's own lowercase host name, so a signature a mint has seen
can never be replayed at a different mint. The spent amount is always 0: the
mint enforces a note's value from its own records, and keeping it out of the
signature lets a key sign for its note before (or regardless of) knowing the
exact post-fee value - one key, one signature, reproducible from seed.
A key-path spend always signs locktime 0 and the final sequence 0xffffffff.
"""

from __future__ import annotations

import struct

from . import _native
from .encoding import CANONICAL_LOCKTIME, CANONICAL_SEQUENCE, Spend, decode_cp1, decode_spend
from .errors import ScriptInvalid, SpendRejected
from .policy import check_time_claim
from .taproot import tagged_hash
from .script import check_leaf

CANONICAL_TX_VERSION = 2  # of the shape above, not nVersion
TX_VERSION = 2
SPENT_AMOUNT = 0
_U32_MAX = 0xFFFFFFFF


def _compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def p2tr_script(output_key: bytes) -> bytes:
    """scriptPubKey for a taproot output: OP_1 <32-byte key>."""
    return b"\x51\x20" + output_key


def spend_prevout(domain: str) -> bytes:
    """The canonical transaction's prevout txid for the mint at `domain`."""
    if not domain:
        raise ValueError("domain is required")
    return tagged_hash("LNURLcash/mint", domain.lower().encode())


def build_spend_tx(*, domain: str, stack: list[bytes], locktime: int, sequence: int) -> bytes:
    """The canonical synthetic spend transaction (see module docstring), with
    the segwit witness `stack` (`[sig]` for a key path, `[*witness, script,
    control_block]` for a script path)."""
    out = struct.pack("<i", TX_VERSION) + b"\x00\x01"  # segwit marker + flag
    out += b"\x01" + spend_prevout(domain) + struct.pack("<I", 0)
    out += b"\x00" + struct.pack("<I", sequence)  # empty scriptSig
    out += b"\x01" + struct.pack("<q", 0) + b"\x00"  # one empty output
    out += _compact_size(len(stack))
    for item in stack:
        out += _compact_size(len(item)) + item
    return out + struct.pack("<I", locktime)


def verify_witness(
    *,
    output_key: bytes,
    domain: str,
    stack: list[bytes],
    locktime: int,
    sequence: int,
) -> bool:
    """Does this witness stack spend `output_key` under Core's rules?

    `output_key` and `domain` come from the mint itself, so a bad one is a
    programming error (ValueError). Everything else is supplied by the
    redeemer and is untrusted: anything malformed is simply not a valid spend
    (False), never an exception an attacker can use to crash a request.
    """
    if len(output_key) != 32:
        raise ValueError("output_key must be a 32-byte x-only key")
    if not (0 <= locktime <= _U32_MAX and 0 <= sequence <= _U32_MAX):
        return False
    if not stack:
        return False

    spk = p2tr_script(output_key)
    tx = build_spend_tx(domain=domain, stack=stack, locktime=locktime, sequence=sequence)
    return _native.verify_input(
        script_pubkey=spk,
        amount=SPENT_AMOUNT,
        tx=tx,
        spent_outputs=[(spk, SPENT_AMOUNT)],
        input_index=0,
    )


def verify_spend(
    *,
    output_key: bytes,
    domain: str,
    spend: Spend,
    now: int,
    locked_at: int,
) -> None:
    """Mint-facing: accept `spend` of the note `output_key`, or raise
    `SpendRejected`. `now`/`locked_at` are the mint's own clock, in Unix
    seconds - this library never reads one itself."""
    if spend.output_key != output_key:
        raise ScriptInvalid("spend does not open this note")

    if spend.key_path:
        if (spend.locktime, spend.sequence) != (CANONICAL_LOCKTIME, CANONICAL_SEQUENCE):
            raise ScriptInvalid("a key-path spend carries no time claim")
    else:
        check_leaf(spend.script, spend.control_block)
        check_time_claim(
            locktime=spend.locktime, sequence=spend.sequence, now=now, locked_at=locked_at
        )

    if not verify_witness(
        output_key=output_key, domain=domain, stack=spend.stack,
        locktime=spend.locktime, sequence=spend.sequence,
    ):
        raise ScriptInvalid("bitcoin core rejected the spend")


def verify_k1(
    *, cp1: str, k1: str, domain: str, now: int, locked_at: int
) -> None:
    """`verify_spend` for the wire values themselves: the note's `cp1` (from the
    mint's records) and the `k1` a redeemer presents - a `ck1`, a `cw1`, or a
    bearer note's 64-hex preimage. Raises `SpendRejected` if that is malformed - it is attacker-supplied - and ValueError if the
    cp1 is, since that comes from the mint's own storage."""
    output_key = decode_cp1(cp1)
    if output_key is None:
        raise ValueError("not a valid cp1")
    spend = decode_spend(k1)
    if spend is None:
        raise SpendRejected("malformed k1")
    verify_spend(
        output_key=output_key, domain=domain, spend=spend, now=now, locked_at=locked_at,
    )
