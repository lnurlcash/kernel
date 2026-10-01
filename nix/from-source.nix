{ lib
, buildPythonPackage
, scikit-build-core
, setuptools-scm
, cmake
, ninja
, boost
, version
, bitcoin # the vendor/bitcoin submodule tree, passed in as a flake input
}:

# Builds the package - and with it Bitcoin Core's libbitcoinkernel, from the
# pinned, unmodified tree - entirely from source. No prebuilt artifacts: this
# is the variant for consumers who do not want to trust the PyPI wheels (and
# the only option on platforms they do not cover).
#
# What would otherwise be fetched at build time is supplied by nix instead:
# the vendored Core tree (a git submodule upstream) comes in as the `bitcoin`
# flake input, and Core's CMake gets its Boost >= 1.74 headers from nixpkgs
# (upstream's cibuildwheel runs scripts/fetch_boost_headers.sh because
# manylinux_2_28 ships 1.66; see CMakeLists.txt and UPSTREAM.md).
buildPythonPackage {
  pname = "lnurlcash-kernel";
  inherit version;
  pyproject = true;

  src = ../.;

  # the flake source carries vendor/bitcoin as an empty gitlink; put the
  # pinned tree in its place (writable - Core's ExternalProject stamps into
  # its own build dir, but CMake may glob the source)
  postPatch = ''
    rm -rf vendor/bitcoin
    mkdir -p vendor
    cp -r ${bitcoin} vendor/bitcoin
    chmod -R u+w vendor/bitcoin
  '';

  # the flake source has no .git for setuptools-scm to derive a version from
  env.SETUPTOOLS_SCM_PRETEND_VERSION = version;
  # Boost_DIR: directory containing BoostConfig.cmake (see CMakeLists.txt)
  env.CMAKE_ARGS = "-DBoost_DIR=${lib.getDev boost}/lib/cmake/Boost-${boost.version}";

  nativeBuildInputs = [
    cmake
    ninja
  ];

  # cmake on PATH is for scikit-build-core (it drives Core's build during
  # pypaBuildPhase); do not let its setup hook claim configurePhase and
  # configure this repo's top-level CMakeLists into ./build
  dontUseCmakeConfigure = true;

  build-system = [
    scikit-build-core
    setuptools-scm
  ];

  pythonImportsCheck = [ "lnurlcashkernel" ];

  meta = {
    description = "Verify LUD-25 note (taproot key- and script-path) spends with Bitcoin Core's own script interpreter";
    homepage = "https://github.com/lnurlcash/kernel";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
}
