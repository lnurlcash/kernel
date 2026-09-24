# lnurlcashkernel

Verify spends of [LUD-25](https://github.com/lnurl/luds) notes with **Bitcoin
Core's own script interpreter, unmodified** (`libbitcoinkernel`), from Python.

Every LUD-25 note is a taproot output key `Q` (`cp1<Q>`). A redeemer opens it
with a `ck1` (a key-path signature by `Q`) or a `cw1` (a script-path spend of
one of its leaves). The plain bearer note is a single `OP_SHA256 <h> OP_EQUAL` leaf under
BIP-341's NUMS key, spent by revealing the preimage.

```python
import lnurlcashkernel as k

spend = k.decode_spend(k1)   # a ck1, a cw1, or a bearer note's 64-hex preimage; None if none
q = spend.output_key         # the note to look up in the mint's records
tpl = k.verify_spend(
    output_key=q,            # 32-byte x-only Q, as recorded by the mint
    domain="mint.example",   # this mint's own host: signatures are bound to it
    spend=spend,
    now=now,                 # THE MINT'S clock, Unix seconds - passed in, never read
    locked_at=locked_at,     # when the mint locked this note
)                            # returns None, or raises SpendRejected
```

## What this verifies - and what it does not

**It verifies scripts.** Whether a key-path signature is valid for `Q`, whether
a revealed leaf and control block really commit to `Q`, and whether the leaf's
conditions (a signature, a hash preimage, a multisig, a timelock comparison)
are satisfied, is decided by Bitcoin Core's own code, compiled from an
unmodified pinned tree. This package adds no verification logic of its own; the
only arithmetic it does itself is recomputing `Q` from a control block
(`taproot.py`, public data only) so a mint knows which note to look up.

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

### The canonical spend transaction (version 2)

Core verifies an input of a transaction, so a fixed minimal one is assembled. A
signer must sign the BIP341 sighash of **exactly** this shape (see
`verify.py`; it is normative and versioned):

| field | value |
|---|---|
| `nVersion` | `2` (CSV requires ≥ 2) |
| `vin[0]` | prevout `(tagged_hash("LNURLcash/mint", domain), 0)`, empty scriptSig, `nSequence` = claimed |
| `vout[0]` | value `0`, empty scriptPubKey |
| `nLockTime` | claimed |
| spent output | `(OP_1 <Q>, 0)` |

`domain` is the mint's lowercase host, so a signature seen by one mint cannot be
replayed at another. The spent amount is always `0`: the mint enforces a note's
value from its own records, and leaving it unsigned means one key has exactly
one signature for its note, reproducible from seed. A key-path spend always
signs locktime `0` and the final sequence `0xffffffff`.

Version 1 (zero prevout, `amount_msat` committed) is gone; signatures made for
it do not verify.

This package never signs. For a signer in Python, `key_path_sighash(Q, domain)`
and `script_path_sighash(Q, domain, leaf, locktime=, sequence=)` return the one
hash that will verify (`SIGHASH_DEFAULT`), checked against LUD-25's own test
vector 3.

### Wire format

| value | payload |
|---|---|
| `cp1` | `Q` (32 bytes) - 61 characters, fits a LUD-12 comment |
| `ck1` | key-path spend: `Q ‖ sig(64)` - 163 characters |
| `cw1` | script-path spend: `u32 locktime ‖ u32 sequence ‖ (u16 len ‖ item)*` over script, control block, witness (bottom first) |
| 64 hex in `k1` | a bearer note's preimage - `decode_spend` builds the `OP_SHA256 <h> OP_EQUAL` spend under NUMS |
| 64 hex for a `cp1` | a bearer note's `h` - `decode_note` returns its `Q` |

## Supported spends

Any key-path signature by `Q`, and **any** leaf script: what a leaf may do is
decided by Bitcoin Core's consensus rules alone, not by a list of shapes. The
plain bearer note, `OP_SHA256 <h> OP_EQUAL` under BIP-341's NUMS key, is just
one such leaf.

The one exception is tapscript's upgrade hooks, which consensus accepts
unconditionally and on-chain nodes only refuse by policy - a policy
`libbitcoinkernel` does not expose. `script.check_leaf` refuses them itself,
before Core is called:

* a leaf version other than `0xc0`
* any `OP_SUCCESSx` opcode in the leaf (pushed data is not scanned)

Otherwise such a leaf would be spendable by anyone who sees it, and no new
opcode could ever be given a meaning. BIP-342's third hook, a signature check
against a key that is neither empty nor 32 bytes, can't be spotted statically
(the key may come from the witness) and is left to consensus: wallets must
never write such keys.

Time claims are accepted only in forms that mean something with no chain: a
non-zero **`nLockTime` must be a Unix time** (≥ 500,000,000) and an enabled
**relative `nSequence` must carry BIP68's time flag** (512-second units).
Block-height and block-count claims are refused, not guessed at.

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
