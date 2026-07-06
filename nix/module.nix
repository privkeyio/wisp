# NixOS module for the wisp nostr relay. `settings` is a freeform attrset serialized to wisp's
# config.toml, so it maps every current (and future) config option without this module enumerating
# them: sections [server], [relay], [limits], [storage], [timeouts], [rate_limits], [auth] (NIP-42:
# required / to_write / relay_url), [security], [spider], [negentropy], [management]. `host`, `port`,
# and `dataDir` are convenience options that populate [server].host, [server].port, and [storage].path.
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
    server.host = cfg.host;
    server.port = cfg.port;
    storage.path = "${cfg.dataDir}/wisp.mdb";
  } cfg.settings;
  configFile = tomlFormat.generate "wisp.toml" finalSettings;

  # The spider (disabled by default) makes outbound relay connections; when it is on the sandbox must
  # allow the address families glibc's resolver needs -- AF_NETLINK for interface enumeration, AF_UNIX
  # for the nss-resolve/nscd socket -- otherwise DNS lookups fail.
  spiderEnabled = cfg.settings.spider.enabled or false;
  # A wildcard or loopback bind succeeds regardless of link state; a specific address (or the spider's
  # outbound sync) needs actual connectivity, so wait for network-online.target in those cases.
  needsNetworkOnline =
    spiderEnabled
    || !(lib.elem finalSettings.server.host [
      "127.0.0.1"
      "::1"
      "localhost"
      "0.0.0.0"
      "::"
    ]);
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

    host = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = ''
        Address the relay binds (maps to `[server].host`). Defaults to loopback; set to `"0.0.0.0"`
        (and enable `openFirewall`) to accept external connections. wisp requires an IP literal here.
      '';
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
      description = ''
        Open the relay's port in the firewall. On its own this is not enough to be reachable: the
        relay binds loopback by default, so also set `host = "0.0.0.0"` (or a specific address).
      '';
    };

    settings = lib.mkOption {
      type = tomlFormat.type;
      default = { };
      example = lib.literalExpression ''
        {
          relay = { name = "my relay"; contact = "me@example.com"; };
          auth = { required = true; to_write = true; relay_url = "wss://relay.example.com"; };
          rate_limits = { events_per_minute = 120; queries_per_minute = 300; };
          # List-valued options are comma-separated strings, not Nix lists.
          spider = { enabled = true; relays = "wss://relay.damus.io,wss://nos.lol"; };
        }
      '';
      description = ''
        wisp configuration as a Nix attrset, serialized to config.toml. See wisp's config sections
        ([server], [relay], [limits], [storage], [timeouts], [rate_limits], [auth], [security],
        [spider], [negentropy], [management]). `host`, `port`, and `dataDir` populate `server.host`,
        `server.port`, and `storage.path` unless overridden here.

        List-like options (`spider.relays`, `security.ip_whitelist`, `management.admin_pubkeys`, ...)
        are comma-separated strings, not TOML arrays: use `"wss://a,wss://b"`, not `[ "wss://a" ]`.

        Do not put secrets here: the rendered config.toml is stored world-readable in the Nix store.
        Route any secret through systemd `LoadCredential=`/`EnvironmentFile=` instead.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.wisp = {
      description = "wisp nostr relay";
      documentation = [ "https://github.com/privkeyio/wisp" ];
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ] ++ lib.optional needsNetworkOnline "network-online.target";
      wants = lib.optional needsNetworkOnline "network-online.target";
      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} relay ${configFile}";
        Restart = "on-failure";
        RestartSec = 5;

        # wisp defaults to max_connections = 1000 and never raises its own rlimit; the stock 1024 soft
        # NOFILE would EMFILE near capacity (client sockets + listener + LMDB + spider fds).
        LimitNOFILE = 65536;

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
        ]
        ++ lib.optionals spiderEnabled [
          "AF_UNIX"
          "AF_NETLINK"
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

    networking.firewall.allowedTCPPorts = lib.optional cfg.openFirewall finalSettings.server.port;
  };
}
