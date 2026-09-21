"""Exceptions.

Anything an attacker can influence (a malformed proof, an unsupported script,
an unsatisfied timelock) is a `SpendRejected` - callers are expected to catch
it and deny the spend. Everything else (a missing native library, an
impossible flag combination) is a plain bug or a broken install and is raised
as `KernelError`, never swallowed into a "deny", so it cannot masquerade as a
legitimate rejection.
"""


class KernelError(RuntimeError):
    """The native library is missing/unusable, or was called incorrectly."""


class SpendRejected(Exception):
    """This spend must be denied. `reason` is safe to log."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class UnsupportedScript(SpendRejected):
    """Not one of the recognised leaf shapes (or a timelock of a kind that has
    no meaning off-chain, e.g. a block-height lock)."""


class ScriptInvalid(SpendRejected):
    """Bitcoin Core's own script verification rejected the spend."""


class TimeClaimRejected(SpendRejected):
    """The redeemer's claimed locktime/sequence is not yet satisfied by the
    mint's clock."""
