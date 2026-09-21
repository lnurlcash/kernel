import spends as s
from lnurlcashkernel import recognize_template
from lnurlcashkernel.templates import CSV_TYPE_FLAG

LOCK = 1_800_000_000


def test_each_supported_shape_round_trips_its_parameters():
    tpl = recognize_template(s.pk_leaf())
    assert (tpl.kind, tpl.pubkeys) == ("pk", (s.OWNER_PK,))

    tpl = recognize_template(s.cltv_leaf(LOCK))
    assert (tpl.kind, tpl.locktime, tpl.pubkeys) == ("cltv", LOCK, (s.OWNER_PK,))

    seq = CSV_TYPE_FLAG | 7
    tpl = recognize_template(s.csv_leaf(seq))
    assert (tpl.kind, tpl.sequence, tpl.csv_seconds) == ("csv", seq, 7 * 512)

    image = b"\xab" * 32
    tpl = recognize_template(s.hashlock_leaf(image))
    assert (tpl.kind, tpl.hash) == ("hashlock", image)

    tpl = recognize_template(s.multisig2_leaf())
    assert (tpl.kind, tpl.pubkeys) == ("multisig2", (s.OWNER_PK, s.OTHER_PK))


def test_block_height_timelocks_are_refused_not_guessed_at():
    # with no chain there is no block height, so these have no honest meaning
    assert recognize_template(s.cltv_leaf(800_000)) is None
    assert recognize_template(s.cltv_leaf(499_999_999)) is None
    assert recognize_template(s.cltv_leaf(500_000_000)) is not None  # boundary
    # a block-count CSV (BIP68 type flag clear)
    assert recognize_template(s.csv_leaf(144)) is None


def test_csv_with_stray_bits_is_refused():
    assert recognize_template(s.csv_leaf(CSV_TYPE_FLAG | 1 | (1 << 30))) is None


def test_anything_else_is_refused_however_valid_bitcoin_finds_it():
    for script in (
        b"",
        b"\x51",  # OP_TRUE
        b"\x51\x51\x93",  # 1 1 ADD
        s.pk_leaf() + b"\x75",  # trailing junk
        b"\x20" + s.OWNER_PK,  # a bare push, no opcode
        b"\x21" + b"\x02" + s.OWNER_PK + b"\xac",  # a 33-byte (non-x-only) key
        b"\x4c\x20" + s.OWNER_PK + b"\xac",  # PUSHDATA1 form
        b"\x20" + s.OWNER_PK[:31],  # truncated push
    ):
        assert recognize_template(script) is None, script.hex()


def test_a_non_minimal_number_push_is_refused():
    # LOCK with a redundant trailing 0x00: same value, non-minimal encoding
    raw = LOCK.to_bytes(4, "little") + b"\x00"
    script = bytes([len(raw)]) + raw + b"\xb1\x75" + s.push_key(s.OWNER_PK) + b"\xac"
    assert recognize_template(script) is None


def test_a_negative_timelock_is_refused():
    raw = (0x80000001).to_bytes(4, "little")  # high bit set => negative ScriptNum
    script = bytes([len(raw)]) + raw + b"\xb1\x75" + s.push_key(s.OWNER_PK) + b"\xac"
    assert recognize_template(script) is None
