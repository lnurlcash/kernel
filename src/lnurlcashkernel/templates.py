"""Recognise the leaf shapes a mint is willing to redeem.

This is a *scope filter*, not an interpreter: it never executes a script. It
decodes the leaf into pushes/opcodes, matches that list against a small set of
exact skeletons, and pulls out the embedded parameters. Anything else - however
valid to Bitcoin - is refused before the native library is ever called. That is
deliberate: a custodial mint should redeem only shapes it has reasoned about.

The skeletons mirror the wallet's own script templates
(lnurl-wallet: src/addons/taproot/taproot.ts SCRIPT_TEMPLATES), byte for byte.

Timelocks are only accepted in the forms that mean something with no chain:
 * CLTV must be a Unix time (>= 500,000,000). A block-height lock has no
   off-chain meaning, so it is refused rather than guessed at.
 * CSV must carry BIP68's time-type flag (units of 512 seconds). A block-count
   lock is refused for the same reason.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

OP_0 = 0x00
OP_1 = 0x51
OP_2 = 0x52
OP_16 = 0x60
OP_CHECKSIG = 0xAC
OP_CHECKSIGADD = 0xBA
OP_NUMEQUAL = 0x9C
OP_EQUALVERIFY = 0x88
OP_SHA256 = 0xA8
OP_DROP = 0x75
OP_CLTV = 0xB1
OP_CSV = 0xB2

LOCKTIME_THRESHOLD = 500_000_000  # below this an nLockTime is a block height
CSV_TYPE_FLAG = 1 << 22  # BIP68: relative lock is time-based (512 s units)
CSV_VALUE_MASK = 0xFFFF
CSV_GRANULARITY_SECONDS = 512

Kind = Literal["pk", "csv", "cltv", "hashlock", "multisig2"]


@dataclass(frozen=True)
class Template:
    kind: Kind
    pubkeys: tuple[bytes, ...]  # x-only, in script order
    locktime: int | None = None  # cltv: Unix time
    sequence: int | None = None  # csv: the BIP68-encoded operand
    hash: bytes | None = None  # hashlock: sha256 image

    @property
    def csv_seconds(self) -> int | None:
        """The relative lock a CSV leaf demands, in seconds."""
        if self.sequence is None:
            return None
        return (self.sequence & CSV_VALUE_MASK) * CSV_GRANULARITY_SECONDS


# An element of a decoded script: an opcode int, or pushed data bytes.
Elem = int | bytes


def _decode(script: bytes) -> list[Elem] | None:
    """Decode into opcodes and data pushes; None if malformed. Only the push
    forms a well-formed script of these shapes can contain are accepted
    (direct pushes 1-75), so anything exotic is refused up front."""
    out: list[Elem] = []
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if 1 <= op <= 75:
            if i + op > len(script):
                return None
            out.append(bytes(script[i : i + op]))
            i += op
        elif op in (0x4C, 0x4D, 0x4E):  # PUSHDATA1/2/4 - never needed here
            return None
        else:
            out.append(op)
    return out


def _scriptnum(elem: Elem) -> int | None:
    """A minimally-encoded non-negative ScriptNum, or None."""
    if isinstance(elem, int):
        if elem == OP_0:
            return 0
        if OP_1 <= elem <= OP_16:
            return elem - OP_1 + 1
        return None
    if not 1 <= len(elem) <= 5:
        return None
    # minimal encoding: no redundant trailing zero byte
    if elem[-1] & 0x7F == 0 and (len(elem) == 1 or not elem[-2] & 0x80):
        return None
    if elem[-1] & 0x80:  # negative - a timelock is never negative
        return None
    return int.from_bytes(elem, "little")


def _key(elem: Elem) -> bytes | None:
    return elem if isinstance(elem, bytes) and len(elem) == 32 else None


def recognize_template(script: bytes) -> Template | None:
    """Return the matching Template, or None if this leaf is not one a mint
    should redeem (unknown shape, malformed, or an unsupported timelock)."""
    s = _decode(script)
    if s is None:
        return None

    # <pubkey> CHECKSIG
    if len(s) == 2 and s[1] == OP_CHECKSIG and (k := _key(s[0])):
        return Template("pk", (k,))

    # <n> CSV DROP <pubkey> CHECKSIG   |   <n> CLTV DROP <pubkey> CHECKSIG
    if len(s) == 5 and s[2] == OP_DROP and s[4] == OP_CHECKSIG:
        k = _key(s[3])
        n = _scriptnum(s[0])
        if k is not None and n is not None:
            if s[1] == OP_CLTV:
                if n < LOCKTIME_THRESHOLD:
                    return None  # block-height lock: no meaning without a chain
                return Template("cltv", (k,), locktime=n)
            if s[1] == OP_CSV:
                if not n & CSV_TYPE_FLAG or n & ~(CSV_TYPE_FLAG | CSV_VALUE_MASK):
                    return None  # block-count (or malformed) relative lock
                return Template("csv", (k,), sequence=n)

    # SHA256 <hash> EQUALVERIFY <pubkey> CHECKSIG
    if (
        len(s) == 5
        and s[0] == OP_SHA256
        and s[2] == OP_EQUALVERIFY
        and s[4] == OP_CHECKSIG
        and isinstance(s[1], bytes)
        and len(s[1]) == 32
        and (k := _key(s[3]))
    ):
        return Template("hashlock", (k,), hash=s[1])

    # <A> CHECKSIG <B> CHECKSIGADD 2 NUMEQUAL
    if (
        len(s) == 6
        and s[1] == OP_CHECKSIG
        and s[3] == OP_CHECKSIGADD
        and s[4] == OP_2
        and s[5] == OP_NUMEQUAL
        and (a := _key(s[0]))
        and (b := _key(s[2]))
    ):
        return Template("multisig2", (a, b))

    return None
