# akeyless-auth — home-manager module
#
# Manages the biometric authentication daemon for Akeyless.
# Generates JWTs signed by a Keychain/Secure Enclave key,
# requiring Touch ID for every signing operation.
{ config, lib, pkgs, ... }:
let
  cfg = config.akeyless-auth;

  configJson = pkgs.writeText "akeyless-auth-config.json" (builtins.toJSON {
    key_label = cfg.keyLabel;
    key_protection = cfg.keyProtection;
    socket_path = cfg.socketPath;
    issuer = cfg.issuer;
    expiry_secs = cfg.expirySecs;
    subject = cfg.subject;
    audience = cfg.audience;
    autostart = cfg.autostart;
  });
in {
  options.akeyless-auth = {
    enable = lib.mkEnableOption "akeyless-auth biometric authentication daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.akeyless-auth;
      description = "The akeyless-auth package.";
    };

    keyLabel = lib.mkOption {
      type = lib.types.str;
      default = "com.pleme.akeyless-auth";
      description = "Key label in the macOS Keychain.";
    };

    keyProtection = lib.mkOption {
      type = lib.types.enum [ "biometric" "secure_enclave" ];
      default = "biometric";
      description = ''
        Key protection mode.
        "biometric" — software Keychain with Touch ID (no Apple Developer Program needed).
        "secure_enclave" — hardware Secure Enclave (requires Developer ID code signing).
      '';
    };

    socketPath = lib.mkOption {
      type = lib.types.str;
      default = "${config.xdg.configHome}/akeyless-auth/sock";
      description = "Unix socket path for the daemon.";
    };

    issuer = lib.mkOption {
      type = lib.types.str;
      default = "akeyless-auth";
      description = "JWT issuer claim.";
    };

    subject = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "Default JWT subject claim. Empty = current username.";
    };

    audience = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "Default JWT audience claim (Akeyless access ID or endpoint).";
    };

    expirySecs = lib.mkOption {
      type = lib.types.int;
      default = 60;
      description = "Default JWT expiry in seconds.";
    };

    autostart = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Auto-start the daemon via launchd on login.";
    };
  };

  config = lib.mkIf cfg.enable {
    xdg.enable = true;

    # Deploy config file.
    xdg.configFile."akeyless-auth/config.json".source = configJson;

    # launchd agent for auto-start.
    launchd.agents.akeyless-auth = lib.mkIf cfg.autostart {
      enable = true;
      config = {
        Label = "io.pleme.akeyless-auth";
        ProgramArguments = [
          "${cfg.package}/bin/akeyless-auth"
          "daemon"
        ];
        RunAtLoad = true;
        KeepAlive = true;
        StandardOutPath = "${config.home.homeDirectory}/Library/Logs/AkeylessAuth/stdout.log";
        StandardErrorPath = "${config.home.homeDirectory}/Library/Logs/AkeylessAuth/stderr.log";
        EnvironmentVariables = {
          AKEYLESS_AUTH_CONFIG = "${config.xdg.configHome}/akeyless-auth/config.json";
        };
      };
    };
  };
}
