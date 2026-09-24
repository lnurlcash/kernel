"""The LUD-25 wire values: `cp1` (a note's output key), `ck1` (a key-path
spend of it) and `cw1` (a script-path spend of it), plus the 64-hex short forms
of a bearer note.

Zero dependencies, so the package's dependency surface stays empty: this is a
compact BIP-350 (bech32m) implementation. Decoding is strict - mixed case, bad
checksums, wrong HRPs, wrong lengths and truncated parts are all rejected (None),
because these strings are attacker-supplied.

Payloads (integers big-endian):

    cp1   Q (32)
    ck1   Q (32) || sig (64)
    cw1   u32 locktime || u32 sequence
          || u16 len(script) || script || u16 len(control_block) || control_block
          || (u16 len(witness_i) || witness_i)*     bottom of stack first

A key-path spend carries Q explicitly (a Schnorr signature does not reveal its
key) and no time claim: it is always signed over the canonical locktime 0 and
final sequence. A script-path spend carries no Q (the control block commits to
it), but does carry the redeemer's SIGNED locktime/sequence - a tapscript
signature commits to both, so they must travel with the proof (see verify.py).

Short forms: a bearer note (taproot.preimage_note - NUMS internal key, one
`OP_SHA256 <h> OP_EQUAL` leaf) is fully determined by its hash `h`, and its
spend by the preimage. So wherever a `k1` is expected, 64 hex characters are
the preimage (`decode_spend`); wherever a `cp1` is expected, 64 hex characters
are `h` (`decode_note`). The mint builds the script from them.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .taproot import is_xonly_point, output_key, preimage_leaf, preimage_note

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


def _convert_bits_out(data: bytes) -> list[int]:
    """bytes -> 5-bit groups, zero-padded."""
    acc = bits = 0
    out = []
    for b in data:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    return out


def bech32m_encode(hrp: str, payload: bytes) -> str:
    data = _convert_bits_out(payload)
    polymod = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ _BECH32M_CONST
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


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


CANONICAL_LOCKTIME = 0
CANONICAL_SEQUENCE = 0xFFFFFFFF  # final: no time claim


def decode_cp1(value: str) -> bytes | None:
    """A `cp1` note output key: the 32-byte x-only taproot output key Q. None
    unless Q is the x coordinate of a curve point - no spend could open it."""
    decoded = bech32m_decode(value.strip())
    if decoded is None or decoded[0] != "cp" or len(decoded[1]) != 32:
        return None
    if not is_xonly_point(decoded[1]):
        return None
    return decoded[1]


def encode_cp1(q: bytes) -> str:
    if len(q) != 32:
        raise ValueError("Q must be a 32-byte x-only key")
    return bech32m_encode("cp", q)


@dataclass(frozen=True)
class Spend:
    """A spend of a note. Key path (`ck1`): `script`/`control_block` are None
    and `witness` is `(sig,)`. Script path (`cw1`): both are set."""

    locktime: int
    sequence: int
    script: bytes | None
    control_block: bytes | None
    witness: tuple[bytes, ...]
    key: bytes | None = None  # key path only: the Q it signs for

    @property
    def key_path(self) -> bool:
        return self.script is None

    @property
    def stack(self) -> list[bytes]:
        """The full segwit witness stack Core verifies."""
        if self.key_path:
            return list(self.witness)
        return [*self.witness, self.script, self.control_block]

    @property
    def output_key(self) -> bytes | None:
        """The Q this spend opens - for a script path recomputed from the
        control block, None if that is malformed. What a mint looks up."""
        if self.key_path:
            return self.key
        return output_key(self.script, self.control_block)


def decode_ck1(value: str) -> Spend | None:
    """A `ck1` key-path spend, or None if malformed in any way."""
    decoded = bech32m_decode(value.strip())
    if decoded is None or decoded[0] != "ck" or len(decoded[1]) != 32 + 64:
        return None
    data = decoded[1]
    return Spend(CANONICAL_LOCKTIME, CANONICAL_SEQUENCE, None, None, (data[32:],), key=data[:32])


def decode_cw1(value: str) -> Spend | None:
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
    return Spend(locktime, sequence, parts[0], parts[1], tuple(parts[2:]))


def encode_ck1(spend: Spend) -> str:
    if not spend.key_path:
        raise ValueError("a ck1 is a key-path spend")
    if spend.key is None or len(spend.key) != 32 or len(spend.witness) != 1 or len(spend.witness[0]) != 64:
        raise ValueError("a key-path spend is exactly Q and one 64-byte signature")
    return bech32m_encode("ck", spend.key + spend.witness[0])


def encode_cw1(spend: Spend) -> str:
    if spend.key_path:
        raise ValueError("a cw1 is a script-path spend")
    out = spend.locktime.to_bytes(4, "big") + spend.sequence.to_bytes(4, "big")
    for item in (spend.script, spend.control_block, *spend.witness):
        out += len(item).to_bytes(2, "big") + item
    return bech32m_encode("cw", out)


def encode_spend(spend: Spend) -> str:
    """`ck1` for a key-path spend, `cw1` for a script-path one."""
    return encode_ck1(spend) if spend.key_path else encode_cw1(spend)


def _hex32(value: str) -> bytes | None:
    if len(value) != 64 or any(c not in "0123456789abcdefABCDEF" for c in value):
        return None
    return bytes.fromhex(value)


def preimage_spend(preimage: bytes) -> Spend:
    """The script-path spend of the bearer note locked to sha256(preimage)."""
    image = hashlib.sha256(preimage).digest()
    _, control = preimage_note(image)
    return Spend(CANONICAL_LOCKTIME, CANONICAL_SEQUENCE, preimage_leaf(image),
               control, (preimage,))


def decode_spend(value: str) -> Spend | None:
    """Whatever a redeemer put in `k1`: a `ck1`, a `cw1`, or the 64-hex
    preimage of a bearer note (short form). None if it is none of them."""
    value = value.strip()
    preimage = _hex32(value)
    if preimage is not None:
        return preimage_spend(preimage)
    return decode_ck1(value) or decode_cw1(value)


def decode_note(value: str) -> bytes | None:
    """Whatever was put where a `cp1` goes (a mint comment, p1/p2, ?p=): a
    `cp1`, or the 64-hex `h` of a bearer note (short form). Returns Q."""
    value = value.strip()
    image = _hex32(value)
    if image is not None:
        return preimage_note(image)[0]
    return decode_cp1(value)
