{
  description = "akeyless-auth — biometric-gated Akeyless authentication (Touch ID for every secret access)";

  inputs.substrate.url = "github:pleme-io/substrate";

  outputs =
    { substrate, ... }:
    substrate.rust.tool {
      src = ./.;
    }
    // {
      # Custom, feature-rich home-manager module (keyLabel / keyProtection /
      # launchd agent / shikumi config) — preserved verbatim; substrate's
      # auto-generated trio stub is intentionally overridden here.
      homeManagerModules.default = import ./module;
    };
}
