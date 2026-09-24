"""The executable form of "this library verifies scripts, never time".

`verify_witness` is documented as pure; prove it by making the system clock
unusable and confirming nothing changes - and that nothing in the package even
tries to read it.
"""

import time

import spends as s
from lnurlcashkernel import check_time_claim, verify_spend, verify_witness

LOCK = 1_800_000_000


def test_verification_never_reads_the_system_clock(monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("the system clock was read")

    for name in ("time", "time_ns", "monotonic", "perf_counter", "gmtime", "localtime"):
        monkeypatch.setattr(time, name, forbidden)

    sp = s.sign_spend(s.cltv_leaf(LOCK), signers=[s.OWNER_SK], locktime=LOCK)
    assert verify_witness(**sp.kwargs()) is True
    verify_spend(output_key=sp.q, domain=s.DOMAIN, spend=sp.to_spend(), now=LOCK + 1,
                 locked_at=s.LOCKED_AT)
    check_time_claim(locktime=LOCK, sequence=0xFFFFFFFE, now=LOCK, locked_at=0)


def test_the_result_depends_only_on_the_arguments():
    sp = s.sign_spend(s.cltv_leaf(LOCK), signers=[s.OWNER_SK], locktime=LOCK)
    results = {verify_witness(**sp.kwargs()) for _ in range(20)}
    assert results == {True}


def test_no_module_imports_a_clock_source():
    import pathlib
    import re

    src = pathlib.Path(__file__).resolve().parent.parent / "src" / "lnurlcashkernel"
    pattern = re.compile(r"\b(import time|from time|datetime|time\.time|utcnow)\b")
    offenders = [
        p.name for p in src.glob("*.py") if pattern.search(
            # ignore prose: only executable lines
            "\n".join(l for l in p.read_text().splitlines()
                      if not l.lstrip().startswith(("#", '"', "'")))
        )
    ]
    assert offenders == [], f"clock access found in: {offenders}"
