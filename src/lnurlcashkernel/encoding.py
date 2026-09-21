"""Decode the LUD-25 wire values a mint receives: `ct1` (a note's output key) and
`cw1` (a script-path spend).

Zero dependencies, so the package's dependency surface stays empty: this is a
compact BIP-350 (bech32m) implementation. Decoding is strict - mixed case, bad
checksums, wrong HRPs, wrong lengths and truncated parts are all rejected (None),
because these strings are attacker-supplied.

Wire layout of a cw1 payload (all integers big-endian):

    u32 locktime || u32 sequence
    || u16 len(script) || script || u16 len(control_block) || control_block
    || (u16 len(witness_i) || witness_i)*

The locktime/sequence are the redeemer's SIGNED claim - a tapscript signature
commits to both, so they must travel with the proof (see verify.py).
"""

from __future__ import annotations

from dataclasses import dataclass

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2BC830A3
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values: list[int]) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= _GEN[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convert_bits(data: list[int], frm: int, to: int) -> bytes | None:
    """5-bit groups -> bytes, strictly (BIP-173: padding <= 4 bits, all zero)."""
    acc = bits = 0
    out = bytearray()
    for v in data:
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & ((1 << to) - 1))
    if bits >= frm or (acc << (to - bits)) & ((1 << to) - 1):
        return None
    return bytes(out)


def bech32m_decode(value: str) -> tuple[str, bytes] | None:
    """Return (hrp, payload bytes), or None if `value` is not valid bech32m."""
    if value != value.lower() and value != value.upper():
        return None  # mixed case
    value = value.lower()
    pos = value.rfind("1")
    if pos < 1 or pos + 7 > len(value):
        return None
    hrp, data_part = value[:pos], value[pos + 1 :]
    if any(ord(c) < 33 or ord(c) > 126 for c in hrp):
        return None
    if any(c not in _CHARSET for c in data_part):
        return None
    data = [_CHARSET.index(c) for c in data_part]
    if _polymod(_hrp_expand(hrp) + data) != _BECH32M_CONST:
        return None
    payload = _convert_bits(data[:-6], 5, 8)
    return None if payload is None else (hrp, payload)


def decode_ct1(value: str) -> bytes | None:
    """A `ct1` note output key: the 32-byte x-only taproot output key Q."""
    decoded = bech32m_decode(value.strip())
    if decoded is None or decoded[0] != "ct" or len(decoded[1]) != 32:
        return None
    return decoded[1]


@dataclass(frozen=True)
class Cw1:
    locktime: int
    sequence: int
    script: bytes
    control_block: bytes
    witness: tuple[bytes, ...]


def decode_cw1(value: str) -> Cw1 | None:
    """A `cw1` script-path spend, or None if malformed in any way."""
    decoded = bech32m_decode(value.strip())
    if decoded is None or decoded[0] != "cw":
        return None
    data = decoded[1]
    if len(data) < 8:
        return None
    locktime = int.from_bytes(data[0:4], "big")
    sequence = int.from_bytes(data[4:8], "big")
    parts: list[bytes] = []
    i = 8
    while i < len(data):
        if i + 2 > len(data):
            return None  # a truncated length prefix
        n = int.from_bytes(data[i : i + 2], "big")
        i += 2
        if i + n > len(data):
            return None  # claims more bytes than remain
        parts.append(data[i : i + n])
        i += n
    if len(parts) < 2:  # script and control block are mandatory
        return None
    return Cw1(locktime, sequence, parts[0], parts[1], tuple(parts[2:]))
