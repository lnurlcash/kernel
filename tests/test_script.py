import pytest

from lnurlcashkernel import OP_SUCCESS, UnsupportedScript, check_leaf

CONTROL = bytes([0xC0]) + b"\x00" * 32


def test_the_op_success_set_is_bip342s():
    assert len(OP_SUCCESS) == 87
    for op in (0x50, 0x62, 0x7E, 0x81, 0x83, 0x86, 0x89, 0x8A, 0x8D, 0x8E, 0x95, 0x99, 0xBB, 0xFE):
        assert op in OP_SUCCESS
    for op in (0x51, 0x87, 0xA8, 0xAC, 0xAD, 0xB1, 0xB2, 0xBA, 0xFF):
        assert op not in OP_SUCCESS


def test_ordinary_leaves_pass():
    check_leaf(b"\x20" + b"\x01" * 32 + b"\xac", CONTROL)
    check_leaf(b"", CONTROL)


@pytest.mark.parametrize("script", [
    b"\x50",
    b"\x51\x7e",  # OP_CAT
    b"\x20" + b"\x01" * 32 + b"\xbb",
])
def test_op_success_anywhere_is_refused(script):
    with pytest.raises(UnsupportedScript):
        check_leaf(script, CONTROL)


@pytest.mark.parametrize("script", [
    b"\x01\x50",
    b"\x4c\x01\x50",
    b"\x4d\x01\x00\x50",
    b"\x4e\x01\x00\x00\x00\x50",
])
def test_pushed_bytes_are_never_opcodes(script):
    check_leaf(script, CONTROL)


def test_a_truncated_push_stops_the_scan():
    check_leaf(b"\x4d\x01", CONTROL)  # Core fails it; nothing here to refuse


@pytest.mark.parametrize("version", [0xC2, 0x50, 0x00])
def test_unknown_leaf_versions_are_refused(version):
    with pytest.raises(UnsupportedScript):
        check_leaf(b"\x51", bytes([version]) + b"\x00" * 32)
    with pytest.raises(UnsupportedScript):
        check_leaf(b"\x51", b"")


def test_the_parity_bit_is_not_part_of_the_version():
    check_leaf(b"\x51", bytes([0xC1]) + b"\x00" * 32)
