import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DEV_LIB = ROOT / "build" / "kernel" / "lib" / "libbitcoinkernel.so"
CORE_DATA = ROOT / "vendor" / "bitcoin" / "src" / "test" / "data"

# tests run against the dev build unless a wheel's bundled library exists or
# the caller points somewhere else explicitly
if "LNURLCASHKERNEL_LIB" not in os.environ and DEV_LIB.exists():
    os.environ["LNURLCASHKERNEL_LIB"] = str(DEV_LIB)


@pytest.fixture(scope="session")
def core_data() -> Path:
    if not CORE_DATA.exists():
        pytest.fail("vendor/bitcoin submodule is not checked out")
    return CORE_DATA
