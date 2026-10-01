{ lib
, stdenv
, buildPythonPackage
, fetchurl
, autoPatchelfHook
, version
}:

# Repackages the prebuilt manylinux wheel from PyPI. The release workflow
# (.github/workflows/release.yml) builds it in manylinux_2_28 containers from
# this exact tree, so the hash below is byte-identical to what `pip install
# lnurlcash-kernel` fetches - same trust anchor as the uv.lock entry, not a
# second one. Pure ctypes: one bundled libbitcoinkernel.so loaded at import
# time, no CPython C-API surface. autoPatchelfHook rewires the .so's dynamic
# loader from the manylinux image's glibc to nixpkgs' (it links only
# libstdc++/libm/libgcc_s/libpthread/libc - no libpython).
#
# For a build that compiles Core's kernel from source instead, see
# from-source.nix.
let
  wheels = {
    x86_64-linux = {
      url = "https://files.pythonhosted.org/packages/6d/36/c26b04d3dad49c71ac0be5064bdd0e454d370e7800edb20b6438d9eba9d7/lnurlcash_kernel-0.2.2-py3-none-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl";
      # same sha256 as PyPI records (hex, not SRI, to stay diffable against it)
      sha256 = "46fb5b9821489333b1246d49c2ebdeeb321a24d48175fd8f99ad6f768a6e4178";
    };
    aarch64-linux = {
      url = "https://files.pythonhosted.org/packages/7f/51/a90aa2810d352866fc5629bf2916dad4e7ced9fb33754d6b8615c8657618/lnurlcash_kernel-0.2.2-py3-none-manylinux_2_27_aarch64.manylinux_2_28_aarch64.whl";
      sha256 = "0c04ebf8d619b306efa38be1236d3f77fe6d9e8b15c74fe631378cc3493f80a4";
    };
  };

  wheel =
    wheels.${stdenv.hostPlatform.system}
      or (throw "lnurlcash-kernel: no prebuilt wheel for ${stdenv.hostPlatform.system} - use the from-source package instead");
in
buildPythonPackage {
  pname = "lnurlcash-kernel";
  inherit version;
  format = "wheel";

  src = fetchurl { inherit (wheel) url sha256; };

  nativeBuildInputs = [ autoPatchelfHook ];
  buildInputs = [ stdenv.cc.cc.lib ];

  pythonImportsCheck = [ "lnurlcashkernel" ];

  meta = {
    description = "Verify LUD-25 note (taproot key- and script-path) spends with Bitcoin Core's own script interpreter";
    homepage = "https://github.com/lnurlcash/kernel";
    license = lib.licenses.mit;
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}
