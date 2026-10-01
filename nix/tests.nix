{ runCommand
, python3
, pkg # the lnurlcash-kernel package under test
, bitcoin # the vendor/bitcoin submodule tree (test vectors)
, src # the repo root (tests/ and the conftest expectations)
}:

# Runs the repo's pytest suite against the INSTALLED package, mirroring
# cibuildwheel's test-command (`-o pythonpath=tests` keeps src/ off sys.path
# so imports resolve to the installed package, whose bundled
# libbitcoinkernel.so is what conftest then loads). test_native_vectors /
# test_upstream read Core's own test data from vendor/bitcoin - the empty
# gitlink in the flake source is replaced by the pinned input.
runCommand "lnurlcash-kernel-${pkg.version}-tests"
{
  nativeBuildInputs = [
    (python3.withPackages (ps: [
      pkg
      ps.pytest
    ]))
  ];
}
''
  cp -r ${src} repo
  chmod -R u+w repo
  rm -rf repo/vendor/bitcoin
  mkdir -p repo/vendor
  ln -s ${bitcoin} repo/vendor/bitcoin
  cd repo
  pytest tests -q -o pythonpath=tests
  touch $out
''
