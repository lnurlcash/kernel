# lnurlcash-kernel (Rust)

Verify [LUD-25](https://github.com/lnurl/luds) note spends with **Bitcoin Core's own script interpreter, unmodified**. `libbitcoinkernel` is built from this repository's pinned `vendor/bitcoin` tree (see [UPSTREAM.md](../UPSTREAM.md)) and linked in statically, so a binary using this crate carries its verifier inside it.

This is the Rust face of the [`lnurlcash-kernel`](https://pypi.org/project/lnurlcash-kernel/) Python package, built from the same tree. It answers exactly one question: does this witness stack spend the note `Q` at this domain? Decoding `ck1`/`cw1`, the leaf rules and time claims belong to [`lnurlcash-core`](https://github.com/lnurlcash/lnurlcash-core), and this crate never reads a clock.

```rust
use lnurlcash_kernel::{verify_key_path, verify_script_path};

// a ck1: a BIP-340 signature by Q itself
let opens = verify_key_path(&q, "mint.example", &signature)?;

// a cw1: witness items (bottom of the stack first), the leaf and its control block
let opens = verify_script_path(&q, "mint.example", &leaf, &control_block, &[&preimage], locktime, sequence)?;
```

`Ok(false)` means Core rejected the spend. `Err` means the library could not be asked (a malformed object, or an empty domain) and must never be read as a verdict.

## Building

The first build compiles Core's kernel (a few minutes). It needs:

- a C++20 compiler, CMake ≥ 3.22 (Ninja is used if present)
- Boost ≥ 1.74 **headers** (Core's CMake requires them; nothing is linked). A system Boost is used if found. Otherwise set `LNURLCASHKERNEL_BOOST_DIR` to a `boost-shim` made by `scripts/fetch_boost_headers.sh`, or let the build run that script itself (needs `curl` and network access)

To skip the build, set `LNURLCASHKERNEL_LIB_DIR` to a directory holding a static `libbitcoinkernel.a` built from the same pin.

As a git dependency, cargo checks out the `vendor/bitcoin` submodule itself:

```toml
lnurlcash-kernel = { git = "https://github.com/lnurlcash/kernel", tag = "v0.2.0" }
```
