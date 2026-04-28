{
  description = "Kona development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Use the specific Rust version from rust-toolchain.toml
        rustToolchain = pkgs.rust-bin.stable."1.88.0".default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
        };

        # Native build inputs for compilation
        nativeBuildInputs = with pkgs; [
          rustToolchain
          pkg-config
          cmake
          git
          cargo-nextest
          clang
          llvm
        ];

        # Runtime dependencies
        buildInputs = with pkgs; [
          openssl
          zlib
          just
          libiconv
        ] ++ lib.optionals stdenv.isDarwin [
          apple-sdk
        ];

      in
      {
        devShells.default = pkgs.mkShell {
          inherit nativeBuildInputs buildInputs;

          # Environment variables
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
          RUST_BACKTRACE = "1";

          # Clang/LLVM configuration for bindgen
          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
         # BINDGEN_EXTRA_CLANG_ARGS = "-I${pkgs.glibc.dev}/include";

          # OpenSSL configuration for cross-platform compatibility
          OPENSSL_NO_VENDOR = "1";
          PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";

          # Force rustc to link binaries (including cargo build scripts) with
          # nix's wrapped cc/gcc. Without this, rustc falls back to the host
          # toolchain on systems where /usr/bin/cc is present, producing
          # binaries whose interpreter is /lib64/ld-linux-x86-64.so.2 and
          # whose libc is the host's. That breaks bindgen later because it
          # dlopens nix-built libclang.so, which needs nix's glibc 2.40 — but
          # the host's loader/libc (Ubuntu 22.04 = glibc 2.35) is what gets
          # used, hitting `GLIBC_2.38 not found`. Pointing the linker at
          # nix's cc means build-script-build is linked against nix's glibc,
          # so libclang's RUNPATH resolves consistently at dlopen time.
          CC = "${pkgs.stdenv.cc}/bin/cc";
          CXX = "${pkgs.stdenv.cc}/bin/c++";
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = "${pkgs.stdenv.cc}/bin/cc";

          shellHook = ''
            echo "🦀 Kona development environment loaded!"
            echo "Rust version: $(rustc --version)"
            echo "Cargo version: $(cargo --version)"
            echo ""
            echo "just tests         - Run all tests"
            echo ""
          '';
        };

        # Provide the Rust toolchain as a package
        packages.rust = rustToolchain;
      });
}
