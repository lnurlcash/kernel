#!/usr/bin/env python3
"""Move the vendored Bitcoin Core pin to a new release tag.

Updates the submodule, src/lnurlcashkernel/_upstream.py and rust/lib.rs, because
tests/test_upstream.py fails if they ever disagree - `upstream_version()` is what
an operator trusts to know which script verification they are running.

    python scripts/bump_upstream.py v31.2
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORE = ROOT / "vendor" / "bitcoin"
UPSTREAM = ROOT / "src" / "lnurlcashkernel" / "_upstream.py"
RUST_LIB = ROOT / "rust" / "lib.rs"


def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(CORE), *args], text=True).strip()


def main(tag: str) -> None:
    if not re.fullmatch(r"v\d+\.\d+(\.\d+)?", tag):
        sys.exit(f"refusing {tag!r}: expected a stable release tag like v31.2")
    git("fetch", "--depth", "1", "origin", "tag", tag)
    git("checkout", "-q", tag)
    commit = git("rev-parse", f"{tag}^{{commit}}")

    # the Python package and the Rust crate both report the pin
    for path in (UPSTREAM, RUST_LIB):
        text = path.read_text()
        text = re.sub(r'UPSTREAM_TAG(: &str)? = ".*?"', lambda m: f'UPSTREAM_TAG{m.group(1) or ""} = "{tag}"', text)
        text = re.sub(
            r'UPSTREAM_COMMIT(: &str)? = ".*?"',
            lambda m: f'UPSTREAM_COMMIT{m.group(1) or ""} = "{commit}"',
            text,
        )
        path.write_text(text)
    print(f"pinned Bitcoin Core {tag} ({commit})")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
