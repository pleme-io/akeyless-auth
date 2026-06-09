{
  description = "akeyless-auth — biometric-gated Akeyless authentication (Touch ID for every secret access)";

  inputs = {
    nixpkgs.follows = "substrate/nixpkgs";
    crate2nix.url = "github:nix-community/crate2nix";
    flake-utils.url = "github:numtide/flake-utils";
    substrate = {
      url = "github:pleme-io/substrate";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crate2nix,
      flake-utils,
      substrate,
    }:
    (import "${substrate}/lib/rust-tool-release-flake.nix" {
      inherit nixpkgs crate2nix flake-utils;
    }) {
      toolName = "akeyless-auth";
      systems = [ "aarch64-darwin" "x86_64-darwin" ];
      src = self;
      repo = "pleme-io/akeyless-auth";
    }
    // {
      homeManagerModules.default = import ./module;
    };
}
