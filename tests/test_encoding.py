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

from lnurlcashkernel import bech32m_decode, decode_ct1, decode_cw1
from lnurlcashkernel.encoding import _CHARSET

DIFFERENTIAL = json.loads(
    (Path(__file__).parent / "vectors" / "bech32m_differential.json").read_text()
)["cases"]


def test_the_alphabet_is_exactly_32_unique_characters():
    # the specific bug this file exists because of
    assert len(_CHARSET) == 32 and len(set(_CHARSET)) == 32
    assert _CHARSET == "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def test_differential_fixture_is_substantial():
    assert len(DIFFERENTIAL) >= 200


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
    cp1 = next(c["string"] for c in DIFFERENTIAL if c["hrp"] == "cp" and len(c["payload"]) == 64)
    assert bech32m_decode(cp1) is not None
    assert decode_ct1(cp1) is None  # right shape, wrong type
    assert decode_cw1(cp1) is None
    ct = next(c for c in DIFFERENTIAL if c["hrp"] == "ct" and len(c["payload"]) == 64)
    assert decode_ct1(ct["string"]) == bytes.fromhex(ct["payload"])
    short = next(c["string"] for c in DIFFERENTIAL if c["hrp"] == "ct" and len(c["payload"]) == 62)
    assert decode_ct1(short) is None  # 31 bytes
