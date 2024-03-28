{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      # TODO(XXX): in theory this flake could support aarch64-linux,
      #   x86_64-darwin and aarch64-darwin, but it is untested.
      systems = [ "x86_64-linux" ];
      perSystem = { config, self', pkgs, lib, system, ... }:
        let
          devDeps = with pkgs; [
            clang-tools
            cmake
            lld
            llvm
            pkg-config
            rust-cbindgen
            valgrind
          ];
          buildDeps = [ pkgs.cargo-c ];

          cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
          msrv = cargoToml.package.rust-version;

          nightlyRust = (pkgs.rust-bin.selectLatestNightlyWith
            (toolchain: toolchain.default));
          stableRust = pkgs.rust-bin.stable.latest.default;
          msrvRust = pkgs.rust-bin.stable.${msrv}.default;
          rustTarget = pkgs.stdenv.hostPlatform.rust.rustcTarget;

          mkDevShell = rustc:
            pkgs.mkShell {
              shellHook = ''
                export RUST_SRC_PATH=${pkgs.rustPlatform.rustLibSrc}
                echo 1>&2 "🦀🇨 "
              '';
              nativeBuildInputs = devDeps ++ buildDeps ++ [ rustc ];
            };

          librustls-capi = (pkgs.makeRustPlatform {
            cargo = stableRust;
            rustc = stableRust;
          }).buildRustPackage {
            inherit (cargoToml.package) name version;
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            doCheck = true;
            nativeBuildInputs = buildDeps;

            buildPhase = ''
              runHook preBuild
              cargo cbuild -j $NIX_BUILD_CORES --release --frozen --prefix=${
                placeholder "out"
              } --target ${rustTarget}
            '';

            installPhase = ''
              runHook preInstall
              cargo cinstall -j $NIX_BUILD_CORES --release --frozen --prefix=${
                placeholder "out"
              } --target ${rustTarget}
            '';

            checkPhase = ''
              runHook preCheck
               cargo ctest -j $NIX_BUILD_CORES --release --frozen --prefix=${
                 placeholder "out"
               } --target ${rustTarget}
            '';
          };

          librustls-legacy = (pkgs.makeRustPlatform {
            cargo = stableRust;
            rustc = stableRust;
          }).buildRustPackage {
            inherit (cargoToml.package) name version;
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            doCheck = true;
            nativeBuildInputs = buildDeps;

            installPhase = ''
              runHook preInstall
              make install DESTDIR=${placeholder "out"}
              runHook postInstall
            '';
          };
        in {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ (import inputs.rust-overlay) ];
          };

          packages.librustls = librustls-capi;
          packages.librustls-legacy = librustls-legacy;
          packages.default = self'.packages.librustls;

          devShells.nightly = (mkDevShell nightlyRust);
          devShells.stable = (mkDevShell stableRust);
          devShells.msrv = (mkDevShell msrvRust);
          devShells.default = self'.devShells.nightly;
        };
    };
}
