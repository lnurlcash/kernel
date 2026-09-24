"""lnurlcashkernel - verify spends of LUD-25 notes (taproot output keys, `cp1`)
with Bitcoin Core's own script interpreter (libbitcoinkernel), unmodified.

This library verifies SCRIPTS. It never verifies time: the caller's clock enters
only as explicit arguments to `check_time_claim` / `verify_spend`, and a timelock
"verified" here means the mint asserts its own clock - a custodial policy
decision, not a consensus guarantee. See README.md.
"""

from ._upstream import UPSTREAM_COMMIT, UPSTREAM_TAG
from .encoding import (
    Spend,
    bech32m_decode,
    bech32m_encode,
    decode_cp1,
    decode_ck1,
    decode_cw1,
    decode_note,
    decode_spend,
    encode_cp1,
    encode_ck1,
    encode_cw1,
    encode_spend,
    preimage_spend,
)
from .errors import (
    KernelError,
    ScriptInvalid,
    SpendRejected,
    TimeClaimRejected,
    UnsupportedScript,
)
from .policy import check_time_claim
from .sighash import key_path_sighash, script_path_sighash
from .taproot import NUMS_H, output_key, preimage_leaf, preimage_note
from .script import OP_SUCCESS, check_leaf
from .verify import (
    build_spend_tx,
    p2tr_script,
    spend_prevout,
    verify_k1,
    verify_spend,
    verify_witness,
)

__all__ = [
    "OP_SUCCESS",
    "NUMS_H",
    "Spend",
    "KernelError",
    "ScriptInvalid",
    "SpendRejected",
    "TimeClaimRejected",
    "UnsupportedScript",
    "build_spend_tx",
    "bech32m_decode",
    "bech32m_encode",
    "check_leaf",
    "check_time_claim",
    "decode_cp1",
    "decode_ck1",
    "decode_cw1",
    "decode_note",
    "decode_spend",
    "encode_cp1",
    "encode_ck1",
    "encode_cw1",
    "encode_spend",
    "output_key",
    "key_path_sighash",
    "p2tr_script",
    "script_path_sighash",
    "preimage_leaf",
    "preimage_note",
    "preimage_spend",
    "spend_prevout",
    "upstream_version",
    "verify_k1",
    "verify_spend",
    "verify_witness",
]


def upstream_version() -> str:
    """The Bitcoin Core release the verification code comes from, e.g.
    'v31.1 (9be056a)'. Log it: it is what tells an operator which script
    verification they are actually running."""
    return f"{UPSTREAM_TAG} ({UPSTREAM_COMMIT[:7]})"
