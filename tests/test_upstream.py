import subprocess
from pathlib import Path

import pytest

from lnurlcashkernel import UPSTREAM_COMMIT, UPSTREAM_TAG, upstream_version

ROOT = Path(__file__).resolve().parent.parent


def test_pinned_upstream_matches_the_vendored_submodule():
    # the runtime `upstream_version()` is what an operator trusts to know which
    # Core code they run - so it must be impossible for it to drift from the pin
    if not (ROOT / "vendor" / "bitcoin" / ".git").exists():
        pytest.skip("submodule not present")
    head = subprocess.check_output(
        ["git", "-C", str(ROOT / "vendor" / "bitcoin"), "rev-parse", "HEAD"], text=True
    ).strip()
    assert head == UPSTREAM_COMMIT
    tag_commit = subprocess.check_output(
        ["git", "-C", str(ROOT / "vendor" / "bitcoin"), "rev-parse", f"{UPSTREAM_TAG}^{{commit}}"],
        text=True,
    ).strip()
    assert tag_commit == UPSTREAM_COMMIT


def test_upstream_version_is_human_readable():
    assert upstream_version() == f"{UPSTREAM_TAG} ({UPSTREAM_COMMIT[:7]})"
