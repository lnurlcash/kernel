# lnurlcashkernel

Verify [LUD-25](https://github.com/lnurl/luds) **`ct1`** (taproot script-path)
spends with **Bitcoin Core's own script interpreter, unmodified**
(`libbitcoinkernel`), from Python.

```python
import lnurlcashkernel as k

tpl = k.verify_spend(
    output_key=q,            # 32-byte x-only Q - the ct1 payload, from the mint's records
    amount_msat=20_000_000,
    leaf_script=leaf,        # revealed by the redeemer (a cw1)
    control_block=control,
    witness=[sig],
    locktime=1_800_000_000,  # the redeemer's SIGNED claim
    sequence=0xFFFFFFFE,
    now=now,                 # THE MINT'S clock, Unix seconds - passed in, never read
    locked_at=locked_at,     # when the mint locked this note
)                            # returns the recognised Template, or raises SpendRejected
```

## What this verifies - and what it does not

**It verifies scripts.** Whether a revealed leaf and control block really commit
to `Q`, and whether the leaf's conditions (a signature, a hash preimage, a
multisig, a timelock comparison) are satisfied, is decided by Bitcoin Core's own
code, compiled from an unmodified pinned tree. This package adds no
verification logic of its own.

**It does not verify time, and cannot.** There is no chain here. Bitcoin splits
timelock enforcement in two: the *script* compares its number to the spending
transaction's `nLockTime`/`nSequence`, and separate consensus code checks that
those fields are acceptable against the chain tip. With no chain, the second half
falls to the mint's own clock (`policy.check_time_claim`).

> **A timelock "verified" by this library means the mint asserts its own clock.**
> It is a custodial policy decision, not a consensus guarantee: nothing stops a
> mint from lying about the time, and nobody can independently re-check it. That
> is no new trust beyond what a custodial mint already asks for - but it must not
> be described as trustless, in UI copy or anywhere else.

The library never reads the system clock; `now` and `locked_at` are always
arguments, and `tests/test_purity.py` enforces this.

### The redeemer signs the time claim

A tapscript `CHECKSIG` signature commits to the transaction's `nLockTime` **and**
`nSequence` (even under `ANYONECANPAY`). So the redeemer chooses those values,
signs them, and presents them; the mint cannot pick "now" after the fact. The
script check (Core) and the clock check (mint) are then independent, exactly as on
a real node.

### The canonical spend transaction

Core verifies an input of a transaction, so a fixed minimal one is assembled. A
signer must sign the BIP341 sighash of **exactly** this shape (see
`verify.py`; it is normative and versioned):

| field | value |
|---|---|
| `nVersion` | `2` (CSV requires ≥ 2) |
| `vin[0]` | prevout `(32 zero bytes, 0)`, empty scriptSig, `nSequence` = claimed |
| `vout[0]` | value `0`, empty scriptPubKey |
| `nLockTime` | claimed |
| spent output | `(OP_1 <Q>, amount_msat)` |

## Supported leaves

A **scope filter**, not an interpreter - the leaf is decoded, never executed, and
must match one of these exactly (mirroring lnurl-wallet's script templates);
anything else is refused before Core is called:

`pk` · `csv` · `cltv` · `hashlock` · `multisig2`

Timelocks are accepted only in forms that mean something with no chain: **CLTV
must be a Unix time** (≥ 500,000,000) and **CSV must carry BIP68's time flag**
(512-second units). Block-height and block-count locks are refused, not guessed at.

## Upstream

`vendor/bitcoin` is a git submodule pinned to one release tag and **never
edited**. `upstream_version()` reports which (`v31.1 (9be056a)`) - log it; it is
what tells an operator which script verification they actually run. See
[UPSTREAM.md](UPSTREAM.md) and [SECURITY.md](SECURITY.md).

Core builds this as `libbitcoinkernel`, which **Core itself labels
"experimental."** Its predecessor `libbitcoinconsensus` was removed in Core 28.

## Development

```sh
git clone --recurse-submodules --depth 1 <this repo>
python -m venv .venv && . .venv/bin/activate
pip install cmake ninja scikit-build-core pytest
pip install .            # builds Core's kernel library (~3 min cold) into the wheel
pytest
```

Core's CMake requires Boost **headers** (≥ 1.74) unconditionally. The distro's may
be too old (manylinux_2_28 ships 1.66), so fetch a known version:

```sh
scripts/fetch_boost_headers.sh            # -> build/deps/boost-shim
pip install . -Ccmake.define.Boost_DIR=$PWD/build/deps/boost-shim
```

Tests include Core's **own** BIP341 vectors driven through the binding, and real
script-path spends built from scratch and judged by Core.

## Releases

Publishing follows [lnbits/electrum-client](https://github.com/lnbits/electrum-client)'s
flow: pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`, which uploads to
PyPI with `uv publish` over **OIDC trusted publishing** (no API token is stored
anywhere) and then creates a GitHub release.

```sh
git tag v0.1.0 && git push origin v0.1.0
```

It differs from electrum-client in one way: that package is pure Python, this one
ships Bitcoin Core's native library. So wheels are built per platform with
`cibuildwheel` in manylinux containers (a wheel built on a developer machine is
tagged `linux_x86_64`, which PyPI rejects - the one built during development
needed `manylinux_2_39`, far too new for real servers), plus an sdist that bundles
Core's sources. Only the final `publish` job holds `id-token: write`.

### One-time PyPI setup

Trusted publishing must be registered on PyPI before the first tag - it cannot be
done from this repo. On pypi.org, add a *pending publisher* for `lnurlcash-kernel`
with the GitHub owner/repo, workflow **`release.yml`**, and **no environment**
(the workflow does not use one, exactly like electrum-client's).

> The GitHub Actions workflows in `.github/` are written but **have not been run**
> - they need a real runner. Treat the first tag as the test. What *was* verified
> locally: the version-from-tag behaviour, the dev-build guard, the Boost fetch
> script, and a full wheel + sdist build.

## Versioning

The version comes from the git tag (`vX.Y.Z` -> `X.Y.Z`) via `setuptools-scm`, as
electrum-client does with `hatch-vcs`. PyPI rejects PEP 440 local versions, so
none is ever emitted (`local_scheme = "no-local-version"`); an untagged build gets
a `.devN` version, and the `publish` job **refuses to upload** any `0.0.0`/`.dev`
artifact, so a build that could not see its tag can never reach PyPI.

The bundled Bitcoin Core release is deliberately **not** in the version string
(`0.1.0+core31.1` would be a local version, which PyPI rejects). It is exposed by
`upstream_version()`, stated in each GitHub release's notes, and enforced against
the submodule pin by a test.
