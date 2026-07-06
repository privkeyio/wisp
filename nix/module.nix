# NixOS module for the wisp nostr relay. `settings` is a freeform attrset serialized to wisp's
# config.toml, so it maps every current (and future) config option without this module enumerating
# them: sections [server], [relay], [limits], [storage], [timeouts], [rate_limits], [auth] (NIP-42:
# required / to_write / relay_url), [security]. `port` and `dataDir` are convenience options that
# populate [server].port and [storage].path.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.wisp;
  tomlFormat = pkgs.formats.toml { };
  # Convenience options feed the freeform settings; explicit user settings win. wisp opens LMDB with
  # MDB_NOSUBDIR, so storage.path is the DB *file* (and it creates `<path>-lock` beside it) -- point it
  # at a file INSIDE dataDir, so both land in the writable StateDirectory, not its read-only parent.
  finalSettings = lib.recursiveUpdate {
    server.port = cfg.port;
    storage.path = "${cfg.dataDir}/wisp.mdb";
  } cfg.settings;
  configFile = tomlFormat.generate "wisp.toml" finalSettings;
in
{
  options.services.wisp = {
    enable = lib.mkEnableOption "the wisp nostr relay";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.wisp;
      defaultText = lib.literalExpression "pkgs.wisp";
      description = ''
        The wisp package to run. The flake's `nixosModules.wisp` sets this to its own build
        automatically; if you import this module directly, apply the flake's overlay (which adds
        `pkgs.wisp`) or set this explicitly.
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 7777;
      description = "TCP port the relay listens on (maps to `[server].port`).";
    };

    dataDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/wisp";
      description = ''
        Directory for the LMDB store; the database file is `''${dataDir}/wisp.mdb` (`[storage].path`).
        Managed as a systemd `StateDirectory`, so the default lives under /var/lib/wisp owned by the
        service's dynamic user; if you point it elsewhere you must create and own that path yourself.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open `port` in the firewall.";
    };

    settings = lib.mkOption {
      type = tomlFormat.type;
      default = { };
      example = lib.literalExpression ''
        {
          server.host = "0.0.0.0";
          relay = { name = "my relay"; contact = "me@example.com"; };
          auth = { required = true; to_write = true; relay_url = "wss://relay.example.com"; };
          rate_limits = { events_per_minute = 120; queries_per_minute = 300; };
        }
      '';
      description = ''
        wisp configuration as a Nix attrset, serialized to config.toml. See wisp's config sections
        ([server], [relay], [limits], [storage], [timeouts], [rate_limits], [auth], [security]).
        `port` and `dataDir` populate `server.port` and `storage.path` unless overridden here.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.wisp = {
      description = "wisp nostr relay";
      documentation = [ "https://github.com/privkeyio/wisp" ];
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} relay ${configFile}";
        Restart = "on-failure";
        RestartSec = 5;

        # A dedicated, unprivileged, ephemeral user; LMDB store persists under StateDirectory.
        DynamicUser = true;
        StateDirectory = "wisp";
        WorkingDirectory = cfg.dataDir;

        # Sandboxing: a network relay needs no more than its data dir and inet sockets.
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
          "~@resources"
        ];
        CapabilityBoundingSet = "";
        UMask = "0077";
      };
    };

    networking.firewall.allowedTCPPorts = lib.optional cfg.openFirewall cfg.port;
  };
}
