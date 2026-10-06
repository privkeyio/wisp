# NixOS module for the wisp nostr relay. `settings` is a freeform attrset serialized to wisp's
# config.toml, so it maps every current (and future) config option without this module enumerating
# them: sections [server], [relay], [limits], [storage], [timeouts], [rate_limits], [auth] (NIP-42:
# required / to_write / relay_url), [security], [spider], [negentropy], [management], [watchdog].
# `host`, `port`,
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

  # wisp reads one config file and its line parser lets a later key override an earlier one, so the
  # secret file is appended after the generated one. The `[]` line resets the section, so keys at the
  # top of the secret file are read as top-level keys (as they would be standalone), not as keys of
  # the generated file's last section.
  mergeConfig = pkgs.writeShellScript "wisp-merge-config" ''
    { ${pkgs.coreutils}/bin/cat "$CREDENTIALS_DIRECTORY/wisp.toml"
      printf '\n[]\n'
      ${pkgs.coreutils}/bin/cat "$CREDENTIALS_DIRECTORY/secrets.toml"
    } > "$RUNTIME_DIRECTORY/wisp.toml"
  '';
  runtimeConfig = if cfg.settingsFile == null then "%d/wisp.toml" else "%t/wisp/wisp.toml";

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
        [spider], [negentropy], [management], [watchdog]). `host`, `port`, and `dataDir` populate `server.host`,
        `server.port`, and `storage.path` unless overridden here.

        List-like options (`spider.relays`, `security.ip_whitelist`, `management.admin_pubkeys`, ...)
        are comma-separated strings, not TOML arrays: use `"wss://a,wss://b"`, not `[ "wss://a" ]`.

        Do not put secrets here: the rendered config.toml is stored world-readable in the Nix store.
        Put them in `settingsFile` instead.
      '';
    };

    settingsFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/run/secrets/wisp.toml";
      description = ''
        Absolute path to an extra wisp config file, in the same format as config.toml, for values that
        must stay out of the Nix store. It is read at service start through systemd `LoadCredential=`,
        so it can be owned by root with mode 0600, and it is appended after `settings`, so any key it
        sets overrides the same key from `settings`. It must be an absolute path given as a string; a
        Nix path literal is rejected because it would be copied into the store.

        The module reads only `settings` (not this file) to decide the firewall port, the sandbox's
        address families and the network-online ordering, so keep `server.host`, `server.port` and
        `spider.enabled` in `settings`.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.settingsFile == null || lib.hasPrefix "/" cfg.settingsFile;
        message = "services.wisp.settingsFile must be an absolute path.";
      }
    ];

    systemd.services.wisp = {
      description = "wisp nostr relay";
      documentation = [ "https://github.com/privkeyio/wisp" ];
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ] ++ lib.optional needsNetworkOnline "network-online.target";
      wants = lib.optional needsNetworkOnline "network-online.target";
      serviceConfig = {
        # Credentials keep the config off the command line and let a root-only settingsFile be read
        # by the service's dynamic user.
        LoadCredential = [
          "wisp.toml:${configFile}"
        ]
        ++ lib.optional (cfg.settingsFile != null) "secrets.toml:${cfg.settingsFile}";
        ExecStartPre = lib.optional (cfg.settingsFile != null) mergeConfig;
        ExecStart = "${lib.getExe cfg.package} relay ${runtimeConfig}";
        Restart = "on-failure";
        RestartSec = 5;

        # wisp defaults to max_connections = 1000 and never raises its own rlimit; the stock 1024 soft
        # NOFILE would EMFILE near capacity (client sockets + listener + LMDB + spider fds).
        LimitNOFILE = 65536;

        # A dedicated, unprivileged, ephemeral user; LMDB store persists under StateDirectory.
        DynamicUser = true;
        StateDirectory = "wisp";
        RuntimeDirectory = "wisp";
        RuntimeDirectoryMode = "0700";
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
