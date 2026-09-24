"""The bech32m codec, pinned two independent ways.

An earlier draft of this codec silently dropped one character of the 32-character
alphabet, which broke every decode. Hand-typed spec vectors did not catch it
quickly (they were easy to mis-transcribe), so this is checked against machine
output from a vetted implementation instead:

 * a differential fixture: random payloads and HRPs encoded by @scure/base
   (the library lnurl-wallet itself uses) and required to decode here, and
 * BIP-350 vectors that are simple enough to be unambiguous.
"""

import json
from pathlib import Path

import pytest

from lnurlcashkernel import bech32m_decode, decode_cp1, decode_ck1
from lnurlcashkernel.encoding import _CHARSET
from lnurlcashkernel.taproot import is_xonly_point

DIFFERENTIAL = json.loads(
    (Path(__file__).parent / "vectors" / "bech32m_differential.json").read_text()
)["cases"]


def test_the_alphabet_is_exactly_32_unique_characters():
    # the specific bug this file exists because of
    assert len(_CHARSET) == 32 and len(set(_CHARSET)) == 32
    assert _CHARSET == "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def test_differential_fixture_is_substantial():
    assert len(DIFFERENTIAL) >= 190


@pytest.mark.parametrize("case", DIFFERENTIAL, ids=lambda c: f"{c['hrp']}-{len(c['payload'])//2}B")
def test_decodes_everything_the_vetted_library_encodes(case):
    assert bech32m_decode(case["string"]) == (case["hrp"], bytes.fromhex(case["payload"]))


def test_every_single_character_corruption_is_rejected():
    # bech32m detects any 1-5 character error; verify exhaustively on a real string
    s = DIFFERENTIAL[len(DIFFERENTIAL) // 2]["string"]
    pos = s.rfind("1")
    for i in range(pos + 1, len(s)):
        for c in _CHARSET:
            if c != s[i]:
                assert bech32m_decode(s[:i] + c + s[i + 1 :]) is None


# BIP-350's short, unambiguous vectors
@pytest.mark.parametrize("value", ["A1LQFN3A", "a1lqfn3a", "?1v759aa"])
def test_bip350_valid_vectors(value):
    assert bech32m_decode(value) is not None


@pytest.mark.parametrize(
    "value",
    [
        "qyrz8wqd2c9m",  # no separator
        "1qyrz8wqd2c9m",  # empty HRP
        "y1b0jsk6g",  # invalid data character
        "in1muywd",  # checksum too short
        "M1VUXWEZ",  # checksum computed over the uppercase form of the HRP
        "16plkw9",  # empty HRP
        "1p2gdwpf",  # empty HRP
    ],
)
def test_bip350_invalid_vectors(value):
    assert bech32m_decode(value) is None


def test_mixed_case_is_rejected():
    assert bech32m_decode("A1lqfn3a") is None


def test_a_classic_bech32_checksum_is_not_bech32m():
    # BIP-173 vector: valid bech32, invalid as bech32m - must never cross-decode
    assert bech32m_decode("A12UEL5L") is None


def test_typed_decoders_reject_the_wrong_hrp_and_length():
    ck = next(c["string"] for c in DIFFERENTIAL if c["hrp"] == "ck" and len(c["payload"]) == 64)
    assert bech32m_decode(ck) is not None
    assert decode_cp1(ck) is None  # right shape, wrong type
    cp = next(c for c in DIFFERENTIAL if c["hrp"] == "cp" and len(c["payload"]) == 64
              and is_xonly_point(bytes.fromhex(c["payload"])))
    assert decode_cp1(cp["string"]) == bytes.fromhex(cp["payload"])
    assert decode_ck1(cp["string"]) is None
    short = next(c["string"] for c in DIFFERENTIAL if c["hrp"] == "cp" and len(c["payload"]) == 62)
    assert decode_cp1(short) is None  # 31 bytes


# ---- ck1 (key path) and cw1 (script path) ----
import hashlib  # noqa: E402

import pytest  # noqa: E402

import spends as s  # noqa: E402
from lnurlcashkernel import (  # noqa: E402
    Spend,
    bech32m_encode,
    decode_cw1,
    decode_note,
    decode_spend,
    encode_ck1,
    encode_cp1,
    encode_cw1,
    encode_spend,
    preimage_note,
    preimage_spend,
)


def test_bech32m_encode_matches_the_vetted_library():
    for case in DIFFERENTIAL[:50]:
        assert bech32m_encode(case["hrp"], bytes.fromhex(case["payload"])) == case["string"]


def test_cp1_rejects_a_q_that_is_not_a_curve_point():
    assert decode_cp1(bech32m_encode("cp", b"\x00" * 32)) is None  # x = 0: no y
    assert decode_cp1(bech32m_encode("cp", b"\xff" * 32)) is None  # x >= p


def test_cp1_round_trips():
    q = s.OWNER_PK
    assert decode_cp1(encode_cp1(q)) == q
    assert len(encode_cp1(q)) == 61  # still fits LUD-12's 64-char comment


def test_ck1_round_trips_and_is_compact():
    sp = s.key_spend()
    wire = encode_ck1(sp.to_spend())
    assert len(wire) == 163
    spend = decode_ck1(wire)
    assert spend.key_path and spend.output_key == sp.q
    assert spend.stack == sp.witness
    assert (spend.locktime, spend.sequence) == (0, 0xFFFFFFFF)


def test_ck1_is_exactly_q_and_one_signature():
    good = b"\x01" * 32 + b"\x02" * 64
    assert decode_ck1(bech32m_encode("ck", good)) is not None
    assert decode_ck1(bech32m_encode("ck", good + b"\x01")) is None  # sighash byte: not allowed
    assert decode_ck1(bech32m_encode("ck", good[:-1])) is None
    assert decode_ck1(bech32m_encode("ck", b"")) is None


def test_cw1_round_trips():
    sp = s.sign_spend(s.cltv_leaf(1_800_000_000), signers=[s.OWNER_SK], locktime=1_800_000_000)
    spend = decode_cw1(encode_cw1(sp.to_spend()))
    assert not spend.key_path
    assert spend.output_key == sp.q
    assert spend.stack == sp.stack
    assert spend.locktime == 1_800_000_000


def test_cw1_rejects_truncation_and_missing_parts():
    sp = s.sign_spend(s.pk_leaf(), signers=[s.OWNER_SK])
    _, payload = bech32m_decode(encode_cw1(sp.to_spend()))
    assert decode_cw1(bech32m_encode("cw", payload[:-1])) is None  # item shorter than its prefix
    assert decode_cw1(bech32m_encode("cw", payload + b"\x00")) is None  # a dangling prefix byte
    assert decode_cw1(bech32m_encode("cw", payload[:7])) is None  # no time claim
    only_script = payload[:8] + len(sp.leaf).to_bytes(2, "big") + sp.leaf
    assert decode_cw1(bech32m_encode("cw", only_script)) is None  # no control block


def test_the_hrp_says_which_path():
    key, script = s.key_spend().to_spend(), s.sign_spend(s.pk_leaf(), signers=[s.OWNER_SK]).to_spend()
    assert decode_cw1(encode_ck1(key)) is None
    assert decode_ck1(encode_cw1(script)) is None
    assert encode_spend(key).startswith("ck1") and encode_spend(script).startswith("cw1")
    with pytest.raises(ValueError):
        encode_ck1(script)
    with pytest.raises(ValueError):
        encode_cw1(key)


def test_bearer_note_cw1_round_trips():
    ref = s.preimage_spend(b"\x42" * 32)
    wire = encode_cw1(ref.to_spend())
    assert len(wire) == 192
    spend = decode_cw1(wire)
    assert spend.stack == ref.stack
    assert spend.output_key == ref.q == preimage_note(hashlib.sha256(b"\x42" * 32).digest())[0]


def test_a_bare_hex_preimage_is_neither_a_ck1_nor_a_cw1():
    assert decode_ck1((b"\x42" * 32).hex()) is None
    assert decode_cw1((b"\x42" * 32).hex()) is None


# ---- decode_spend: anything that goes in k1 ----
def test_decode_spend_takes_ck1_cw1_and_hex():
    assert decode_spend(encode_ck1(s.key_spend().to_spend())).key_path
    sp = s.sign_spend(s.pk_leaf(), signers=[s.OWNER_SK])
    assert decode_spend(encode_cw1(sp.to_spend())).output_key == sp.q
    assert decode_spend(encode_cp1(s.OWNER_PK)) is None  # a note, not a spend


def test_hex_k1_is_the_bearer_note_spend_the_mint_builds():
    preimage = b"\x42" * 32
    ref = s.preimage_spend(preimage)
    for form in (preimage.hex(), preimage.hex().upper(), " " + preimage.hex()):
        spend = decode_spend(form)
        assert spend.stack == ref.stack and spend.output_key == ref.q
    assert preimage_spend(preimage).stack == ref.stack


def test_hex_note_is_the_bearer_notes_q():
    preimage = b"\x42" * 32
    image = hashlib.sha256(preimage).digest()
    assert decode_note(image.hex()) == s.preimage_spend(preimage).q
    assert decode_note(encode_cp1(s.OWNER_PK)) == s.OWNER_PK


def test_short_forms_are_exactly_32_bytes_of_hex():
    for bad in ("ab" * 31, "ab" * 33, "g" * 64, ""):
        assert decode_spend(bad) is None
        assert decode_note(bad) is None


def test_encode_ck1_refuses_a_malformed_key_path():
    with pytest.raises(ValueError):
        encode_ck1(Spend(0, 0xFFFFFFFF, None, None, (b"\x00" * 65,), key=b"\x00" * 32))
