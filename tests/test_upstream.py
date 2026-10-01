import re
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


def test_the_rust_crate_reports_the_same_pin():
    rust = (ROOT / "rust" / "lib.rs").read_text()
    assert re.search(r'UPSTREAM_TAG: &str = "(.*?)"', rust).group(1) == UPSTREAM_TAG
    assert re.search(r'UPSTREAM_COMMIT: &str = "(.*?)"', rust).group(1) == UPSTREAM_COMMIT
