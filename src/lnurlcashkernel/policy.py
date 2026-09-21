"""The mint's clock: the ONE place time enters this library, and always as an
explicit argument.

Bitcoin splits timelock enforcement in two, and so does this package:

 1. the *script* compares its embedded number to the spending transaction's own
    nLockTime / nSequence  (done by Core, in `verify_script_path`), and
 2. separate consensus code (`CheckFinalTx` / `SequenceLocks`) checks that those
    transaction fields are themselves acceptable *right now* against the chain.

With no chain, step 2 falls to the mint - and it can only be the mint's own
assertion. That is a custodial policy decision, not a consensus guarantee:
nothing here stops a mint lying about its clock. This module makes that decision
visible and testable rather than leaving it buried in serialisation.

Nothing in this package reads the system clock. `now` and `locked_at` are
always passed in by the caller, so results are reproducible and the pure
verification path can be proven independent of time.
"""

from __future__ import annotations

from .errors import TimeClaimRejected
from .templates import (
    CSV_GRANULARITY_SECONDS,
    CSV_TYPE_FLAG,
    CSV_VALUE_MASK,
    LOCKTIME_THRESHOLD,
)

SEQUENCE_FINAL = 0xFFFFFFFF
SEQUENCE_DISABLE_FLAG = 1 << 31


def check_time_claim(
    *, locktime: int, sequence: int, now: int, locked_at: int
) -> None:
    """Raise TimeClaimRejected unless the redeemer's claimed locktime/sequence
    is acceptable at `now` (Unix seconds) for a note locked at `locked_at`.

    This mirrors what a real node does with a transaction's own fields: an
    nLockTime in the future is not yet final; a relative lock that hasn't
    elapsed hasn't matured. The redeemer signs these exact values (BIP341's
    sighash commits to both), so they cannot be altered after the fact.
    """
    if locktime:
        if locktime < LOCKTIME_THRESHOLD:
            raise TimeClaimRejected(
                "block-height locktimes have no meaning without a chain"
            )
        if locktime > now:
            raise TimeClaimRejected(
                f"locktime {locktime} is in the future (now {now})"
            )

    if sequence & SEQUENCE_DISABLE_FLAG:
        return  # no relative lock claimed (includes the fully-final 0xffffffff)

    if not sequence & CSV_TYPE_FLAG:
        raise TimeClaimRejected(
            "block-count relative locks have no meaning without a chain"
        )
    elapsed = now - locked_at
    required = (sequence & CSV_VALUE_MASK) * CSV_GRANULARITY_SECONDS
    if elapsed < required:
        raise TimeClaimRejected(
            f"relative lock of {required}s not yet satisfied "
            f"({max(elapsed, 0)}s elapsed)"
        )
