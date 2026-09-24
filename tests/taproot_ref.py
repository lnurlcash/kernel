"""Reference BIP340/341/342 helpers, TEST-ONLY.

Written so tests can build genuine, correctly-signed taproot spends (a real
script-path spend needs a real Schnorr signature over the tapscript sighash).
Correctness is not taken on faith: `test_taproot_ref.py` checks this against
Bitcoin Core's own BIP341 vectors, and every spend built here is ultimately
judged by libbitcoinkernel itself, the real oracle.

Never imported by the shipped package.
"""

from __future__ import annotations

import hashlib
import struct

# ---- secp256k1, straight from the BIP340 reference implementation ----
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
Point = tuple[int, int] | None


def _add(a: Point, b: Point) -> Point:
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and a[1] != b[1]:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def _mul(pt: Point, k: int) -> Point:
    acc: Point = None
    for i in range(256):
        if (k >> i) & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
    return acc


def tagged_hash(tag: str, msg: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _has_even_y(pt: tuple[int, int]) -> bool:
    return pt[1] % 2 == 0


def lift_x(x: int) -> tuple[int, int]:
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    assert pow(y, 2, P) == y_sq, "x is not on the curve"
    return x, y if y % 2 == 0 else P - y


def xonly_pubkey(seckey: bytes) -> bytes:
    d = int.from_bytes(seckey, "big")
    pt = _mul(G, d)
    assert pt is not None
    return pt[0].to_bytes(32, "big")


def schnorr_sign(msg: bytes, seckey: bytes, aux: bytes = b"\x00" * 32) -> bytes:
    d0 = int.from_bytes(seckey, "big")
    pt = _mul(G, d0)
    assert pt is not None
    d = d0 if _has_even_y(pt) else N - d0
    t = (d ^ int.from_bytes(tagged_hash("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(
        tagged_hash("BIP0340/nonce", t + pt[0].to_bytes(32, "big") + msg), "big"
    ) % N
    r_pt = _mul(G, k0)
    assert r_pt is not None
    k = k0 if _has_even_y(r_pt) else N - k0
    e = int.from_bytes(
        tagged_hash(
            "BIP0340/challenge",
            r_pt[0].to_bytes(32, "big") + pt[0].to_bytes(32, "big") + msg,
        ),
        "big",
    ) % N
    return r_pt[0].to_bytes(32, "big") + ((k + e * d) % N).to_bytes(32, "big")


# ---- BIP341 taproot ----
def compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def tapleaf_hash(script: bytes, version: int = 0xC0) -> bytes:
    return tagged_hash("TapLeaf", bytes([version]) + compact_size(len(script)) + script)


def tapbranch_hash(a: bytes, b: bytes) -> bytes:
    lo, hi = sorted((a, b))
    return tagged_hash("TapBranch", lo + hi)


def tweak_output_key(internal_x: bytes, merkle_root: bytes) -> tuple[bytes, int]:
    """Returns (Q x-only, parity bit) for Q = P + t*G."""
    t = int.from_bytes(tagged_hash("TapTweak", internal_x + merkle_root), "big")
    assert t < N
    q = _add(lift_x(int.from_bytes(internal_x, "big")), _mul(G, t))
    assert q is not None
    return q[0].to_bytes(32, "big"), q[1] & 1


def single_leaf_tree(
    internal_x: bytes, script: bytes, version: int = 0xC0
) -> tuple[bytes, bytes]:
    """A one-leaf taproot tree. Returns (Q, control_block)."""
    root = tapleaf_hash(script, version)
    q, parity = tweak_output_key(internal_x, root)
    return q, bytes([version | parity]) + internal_x


def two_leaf_tree(
    internal_x: bytes, script_a: bytes, script_b: bytes
) -> tuple[bytes, bytes, bytes]:
    """Returns (Q, control_block_for_a, control_block_for_b)."""
    ha, hb = tapleaf_hash(script_a), tapleaf_hash(script_b)
    q, parity = tweak_output_key(internal_x, tapbranch_hash(ha, hb))
    head = bytes([0xC0 | parity]) + internal_x
    return q, head + hb, head + ha


def p2tr_script(output_key: bytes) -> bytes:
    return b"\x51\x20" + output_key


# ---- transaction serialisation + BIP341/342 sighash ----
def serialize_tx(
    *,
    version: int,
    prevouts: list[tuple[bytes, int]],
    sequences: list[int],
    outputs: list[tuple[int, bytes]],
    locktime: int,
    witnesses: list[list[bytes]] | None = None,
) -> bytes:
    out = struct.pack("<i", version)
    if witnesses is not None:
        out += b"\x00\x01"
    out += compact_size(len(prevouts))
    for (txid, vout), seq in zip(prevouts, sequences):
        out += txid + struct.pack("<I", vout) + b"\x00" + struct.pack("<I", seq)
    out += compact_size(len(outputs))
    for value, script in outputs:
        out += struct.pack("<q", value) + compact_size(len(script)) + script
    if witnesses is not None:
        for stack in witnesses:
            out += compact_size(len(stack))
            for item in stack:
                out += compact_size(len(item)) + item
    return out + struct.pack("<I", locktime)


def _sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def tapscript_sighash(
    *,
    version: int,
    locktime: int,
    prevouts: list[tuple[bytes, int]],
    amounts: list[int],
    spent_scripts: list[bytes],
    sequences: list[int],
    outputs: list[tuple[int, bytes]],
    input_index: int,
    leaf_hash: bytes | None,
    hash_type: int = 0x00,
) -> bytes:
    """BIP341 SigMsg + BIP342 extension, for SIGHASH_DEFAULT/ALL (the only modes
    this package's tests use). leaf_hash=None => key-path (ext_flag 0)."""
    assert hash_type in (0x00, 0x01)
    ext_flag = 0 if leaf_hash is None else 1
    # SigMsg begins with the epoch byte (0) - it is part of the message itself,
    # NOT an extra prefix outside it (Core's own vectors' `sigMsg` includes it)
    msg = bytes([0, hash_type]) + struct.pack("<i", version) + struct.pack("<I", locktime)
    msg += _sha(b"".join(t + struct.pack("<I", n) for t, n in prevouts))
    msg += _sha(b"".join(struct.pack("<q", a) for a in amounts))
    msg += _sha(b"".join(compact_size(len(s)) + s for s in spent_scripts))
    msg += _sha(b"".join(struct.pack("<I", s) for s in sequences))
    msg += _sha(
        b"".join(struct.pack("<q", v) + compact_size(len(s)) + s for v, s in outputs)
    )
    msg += bytes([ext_flag << 1])  # no annex
    msg += struct.pack("<I", input_index)
    if leaf_hash is not None:
        msg += leaf_hash + b"\x00" + b"\xff\xff\xff\xff"  # key_version, codesep
    return tagged_hash("TapSighash", msg)
