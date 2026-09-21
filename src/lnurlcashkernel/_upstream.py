"""The Bitcoin Core release this library's verification code comes from.

Must match the `vendor/bitcoin` submodule pin - tests/test_upstream.py fails
if they drift. An operator can read this at runtime via
`lnurlcashkernel.upstream_version()`.
"""

UPSTREAM_TAG = "v31.1"
UPSTREAM_COMMIT = "9be056a8a72b624dae9623b2f7bded92c2a21c91"
