# Upstream: Bitcoin Core

| | |
|---|---|
| Pinned tag | `v31.1` |
| Commit | `9be056a8a72b624dae9623b2f7bded92c2a21c91` |
| Library | `libbitcoinkernel` (`-DBUILD_KERNEL_LIB=ON`) |

## Why `libbitcoinkernel` and not `libbitcoinconsensus`

`libbitcoinconsensus` was deprecated in Core 27 and **removed in 28** (#29648).
Its replacement, `libbitcoinkernel`, exposes `btck_script_pubkey_verify` with
`btck_ScriptVerificationFlags_TAPROOT` and a spent-outputs API - everything
needed for taproot script-path verification. (Verified against v31.1's header;
the package's tests drive Core's own BIP341 vectors through it.)

## The rule: never edit `vendor/bitcoin`

Core ships real fixes to script verification. The smaller the diff from upstream,
the more mechanical absorbing them stays. If a patch ever becomes unavoidable it
goes in `patches/` (applied at build time) with a documented reason and an
upstream PR link - never as commits into the vendored tree. `patches/` is empty
and should stay that way.

## Bumping

```sh
python scripts/bump_upstream.py v31.2   # submodule + _upstream.py together
pytest                                   # test_upstream.py fails if they drift
```

`.github/workflows/upstream-watch.yml` opens this PR automatically when Core tags
a release. **Read Core's release notes for script/consensus changes before
merging**; a security-relevant release should be expedited, not batched.

## Build requirements

- C++20 compiler, CMake ≥ 3.22, Ninja
- **Boost headers ≥ 1.74.** Core's CMake requires them unconditionally even for a
  kernel-only build (its own `AddBoostIfNeeded.cmake` carries a TODO admitting
  the check isn't scoped per target). Header-only: nothing is linked.
- Runtime: only libstdc++ / libm / libgcc / libc. No Boost, libevent or OpenSSL.
