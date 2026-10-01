//! Builds Bitcoin Core's libbitcoinkernel from the pinned, UNMODIFIED tree at
//! vendor/bitcoin, as a static library, and links it in.
//!
//! The same Core build options as the Python package's CMakeLists.txt, except
//! BUILD_SHARED_LIBS=OFF: a Rust binary carries its verifier inside it, with
//! nothing to ship or find at runtime. Core's static target already folds in
//! its internal dependencies (crypto, leveldb, crc32c, secp256k1), so one
//! archive and the C++ runtime is all that is linked.
//!
//! Environment:
//!   LNURLCASHKERNEL_LIB_DIR  a directory holding a prebuilt static
//!                            libbitcoinkernel.a from this same pin: skips the
//!                            CMake build entirely
//!   LNURLCASHKERNEL_BOOST_DIR  a directory with BoostConfig.cmake (see
//!                            scripts/fetch_boost_headers.sh). Unset, the
//!                            system's Boost is tried, then that script is run
//!                            into OUT_DIR (needs curl and network access)

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    println!("cargo:rerun-if-changed=rust/build.rs");
    println!("cargo:rerun-if-env-changed=LNURLCASHKERNEL_LIB_DIR");
    println!("cargo:rerun-if-env-changed=LNURLCASHKERNEL_BOOST_DIR");

    // docs.rs has no network and no time for a Core build
    if env::var_os("DOCS_RS").is_some() {
        return;
    }

    let lib_dir = match env::var_os("LNURLCASHKERNEL_LIB_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => build_kernel(),
    };
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=bitcoinkernel");

    let target = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match target.as_str() {
        "macos" | "ios" | "freebsd" | "openbsd" => println!("cargo:rustc-link-lib=c++"),
        "windows" => println!("cargo:rustc-link-lib=bcrypt"),
        _ => println!("cargo:rustc-link-lib=stdc++"),
    }
}

fn build_kernel() -> PathBuf {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let source = root.join("vendor/bitcoin");
    if !source.join("CMakeLists.txt").exists() {
        panic!("vendor/bitcoin is empty - run: git submodule update --init --depth 1");
    }
    println!(
        "cargo:rerun-if-changed={}",
        source.join("src/kernel/bitcoinkernel.h").display()
    );

    let mut config = cmake::Config::new(&source);
    // always an optimized Core, whatever the cargo profile
    config
        .profile("Release")
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("BUILD_KERNEL_LIB", "ON")
        .define("BUILD_KERNEL_TEST", "OFF")
        .define("BUILD_BITCOIN_BIN", "OFF")
        .define("BUILD_DAEMON", "OFF")
        .define("BUILD_CLI", "OFF")
        .define("BUILD_TESTS", "OFF")
        .define("BUILD_TX", "OFF")
        .define("BUILD_UTIL", "OFF")
        .define("BUILD_UTIL_CHAINSTATE", "OFF")
        .define("BUILD_GUI", "OFF")
        .define("BUILD_BENCH", "OFF")
        .define("BUILD_FUZZ_BINARY", "OFF")
        .define("ENABLE_WALLET", "OFF")
        .define("ENABLE_IPC", "OFF")
        .define("WITH_ZMQ", "OFF")
        .define("INSTALL_MAN", "OFF")
        .build_target("bitcoinkernel");
    if let Some(boost) = boost_dir(&root) {
        config.define("Boost_DIR", boost);
    }
    if Command::new("ninja").arg("--version").output().is_ok() {
        config.generator("Ninja");
    }
    config.build().join("build").join("lib")
}

/// Where Core's CMake finds Boost's headers.
fn boost_dir(root: &Path) -> Option<PathBuf> {
    if let Some(dir) = env::var_os("LNURLCASHKERNEL_BOOST_DIR") {
        return Some(PathBuf::from(dir));
    }
    if Path::new("/usr/include/boost/version.hpp").exists()
        || Path::new("/usr/local/include/boost/version.hpp").exists()
        || Path::new("/opt/homebrew/include/boost/version.hpp").exists()
    {
        return None;
    }
    // no system Boost: the same pinned headers the Python wheels build with
    let deps = PathBuf::from(env::var("OUT_DIR").unwrap()).join("deps");
    let status = Command::new("bash")
        .arg(root.join("scripts/fetch_boost_headers.sh"))
        .arg(&deps)
        .status()
        .expect("running scripts/fetch_boost_headers.sh");
    if !status.success() {
        panic!(
            "could not fetch Boost headers; install Boost >= 1.74 headers or set \
             LNURLCASHKERNEL_BOOST_DIR (see scripts/fetch_boost_headers.sh)"
        );
    }
    Some(deps.join("boost-shim"))
}
