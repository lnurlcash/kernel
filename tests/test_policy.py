import pytest

from lnurlcashkernel import TimeClaimRejected, check_time_claim
from lnurlcashkernel.policy import CSV_TYPE_FLAG

NOW = 1_800_000_000
LOCKED = 1_700_000_000
FINAL = 0xFFFFFFFF
NON_FINAL = 0xFFFFFFFE  # what a plain CLTV spend sets (locktime live, no relative lock)


def ok(**kw):
    check_time_claim(**{"locktime": 0, "sequence": FINAL, "now": NOW,
                        "locked_at": LOCKED, **kw})


def bad(**kw):
    with pytest.raises(TimeClaimRejected):
        ok(**kw)


def test_no_claim_at_all_is_fine():
    ok()


def test_locktime_boundary():
    ok(locktime=NOW, sequence=NON_FINAL)  # exactly now: final
    bad(locktime=NOW + 1, sequence=NON_FINAL)  # one second early


def test_height_locktimes_are_refused():
    bad(locktime=800_000, sequence=NON_FINAL)
    bad(locktime=499_999_999, sequence=NON_FINAL)


def test_relative_lock_boundary_uses_512_second_units():
    seq = CSV_TYPE_FLAG | 4  # 2048 seconds
    ok(sequence=seq, locked_at=NOW - 2048)  # exactly matured
    bad(sequence=seq, locked_at=NOW - 2047)  # one second short


def test_block_count_relative_locks_are_refused():
    bad(sequence=144)  # type flag clear => blocks


def test_a_disabled_sequence_claims_no_relative_lock():
    ok(sequence=1 << 31)
    ok(sequence=(1 << 31) | 1234)


def test_a_lock_dated_after_now_never_matures():
    bad(sequence=CSV_TYPE_FLAG | 1, locked_at=NOW + 1000)
