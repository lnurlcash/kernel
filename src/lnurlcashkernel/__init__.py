"""lnurlcashkernel - verify LUD-25 `ct1` script-path spends with Bitcoin Core's
own script interpreter (libbitcoinkernel), unmodified.

This library verifies SCRIPTS. It never verifies time: the caller's clock enters
only as explicit arguments to `check_time_claim` / `verify_spend`, and a timelock
"verified" here means the mint asserts its own clock - a custodial policy
decision, not a consensus guarantee. See README.md.
"""

from ._upstream import UPSTREAM_COMMIT, UPSTREAM_TAG
from .encoding import Cw1, bech32m_decode, decode_ct1, decode_cw1
from .errors import (
    KernelError,
    ScriptInvalid,
    SpendRejected,
    TimeClaimRejected,
    UnsupportedScript,
)
from .policy import check_time_claim
from .templates import Template, recognize_template
from .verify import (
    build_spend_tx,
    p2tr_script,
    verify_cw1,
    verify_script_path,
    verify_spend,
)

__all__ = [
    "Cw1",
    "KernelError",
    "ScriptInvalid",
    "SpendRejected",
    "Template",
    "TimeClaimRejected",
    "UnsupportedScript",
    "build_spend_tx",
    "bech32m_decode",
    "check_time_claim",
    "decode_ct1",
    "decode_cw1",
    "p2tr_script",
    "recognize_template",
    "upstream_version",
    "verify_cw1",
    "verify_script_path",
    "verify_spend",
]


def upstream_version() -> str:
    """The Bitcoin Core release the verification code comes from, e.g.
    'v31.1 (9be056a)'. Log it: it is what tells an operator which script
    verification they are actually running."""
    return f"{UPSTREAM_TAG} ({UPSTREAM_COMMIT[:7]})"
