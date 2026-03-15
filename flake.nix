{
  description = "akeyless-auth — biometric-gated Akeyless authentication (Touch ID for every secret access)";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      substrate,
      ...
    }:
    let
      system = "aarch64-darwin";
      pkgs = import nixpkgs { inherit system; };
      package = pkgs.rustPlatform.buildRustPackage {
        pname = "akeyless-auth";
        version = "0.1.0";
        src = ./.;
        useFetchCargoVendor = true;
        cargoHash = "";
        buildInputs = [ pkgs.darwin.apple_sdk.frameworks.Security ];
        meta = {
          description = "Biometric-gated Akeyless authentication";
          homepage = "https://github.com/pleme-io/akeyless-auth";
          license = pkgs.lib.licenses.mit;
          platforms = [ "aarch64-darwin" "x86_64-darwin" ];
        };
      };
    in
    {
      packages.${system}.default = package;

      overlays.default = final: prev: {
        akeyless-auth = self.packages.${final.system}.default;
      };

      homeManagerModules.default = import ./module;

      devShells.${system}.default = pkgs.mkShellNoCC {
        buildInputs = [
          pkgs.rustc
          pkgs.cargo
          pkgs.darwin.apple_sdk.frameworks.Security
        ];
      };

      formatter.${system} = pkgs.nixfmt-tree;
    };
}
