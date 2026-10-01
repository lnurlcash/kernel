{
  description = "lnurlcash-kernel: verify LUD-25 note spends with Bitcoin Core's own script interpreter - Nix packaging";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

    # The vendor/bitcoin submodule, pinned to the same rev. Used by the
    # from-source package and by the test checks (Core's test vectors);
    # keep in sync when bumping the submodule (see UPSTREAM.md).
    bitcoin = {
      url = "github:bitcoin/bitcoin/9be056a8a72b624dae9623b2f7bded92c2a21c91";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      bitcoin,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;

      # keep in sync with the git tag: PyPI releases derive the version from
      # the tag via setuptools-scm, but flake builds have no .git
      version = "0.2.2";
    in
    {
      # The idiomatic way to consume the package from a NixOS configuration:
      #   nixpkgs.overlays = [ inputs.lnurlcash-kernel.overlays.default ];
      #   environment.systemPackages = [
      #     (python3.withPackages (ps: [ ps.lnurlcash-kernel ]))
      #   ];
      # pythonPackagesExtensions puts it on every python3* interpreter, not
      # just the default one.
      overlays.default = final: prev: {
        pythonPackagesExtensions = prev.pythonPackagesExtensions ++ [
          (python-final: python-prev: {
            lnurlcash-kernel = python-final.callPackage ./nix/wheel.nix { inherit version; };
          })
        ];
      };

      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ self.overlays.default ];
          };
        in
        rec {
          # default: the prebuilt PyPI wheel, repackaged (fast, byte-identical
          # to what pip installs)
          lnurlcash-kernel = pkgs.python3Packages.lnurlcash-kernel;
          # compiles Core's kernel from the pinned source tree instead -
          # no prebuilt artifacts (slow first build, then cached)
          lnurlcash-kernel-from-source = pkgs.python3Packages.callPackage ./nix/from-source.nix {
            inherit version bitcoin;
          };
          default = lnurlcash-kernel;
        }
      );

      # the repo's pytest suite, run against each installed package
      checks = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          mkTests =
            pkg:
            pkgs.callPackage ./nix/tests.nix {
              inherit pkg bitcoin;
              src = self;
            };
        in
        {
          wheel = mkTests self.packages.${system}.lnurlcash-kernel;
          from-source = mkTests self.packages.${system}.lnurlcash-kernel-from-source;
        }
      );
    };
}
