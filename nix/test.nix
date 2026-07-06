# Boots the services.wisp module and connects a real WebSocket client: a NIP-01 REQ must draw a
# response (EOSE/EVENT/NOTICE), proving the relay is live and speaking the protocol under the module's
# sandbox. Consumed by the flake as `checks.<system>.wisp-module`.
self:
{ pkgs, ... }:
let
  pyClient = pkgs.python3.withPackages (ps: [ ps.websockets ]);
  probe = pkgs.writeText "wisp-probe.py" ''
    import asyncio, json, websockets

    async def main():
        async with websockets.connect("ws://127.0.0.1:7777") as ws:
            await ws.send(json.dumps(["REQ", "t", {"limit": 0}]))
            msg = await asyncio.wait_for(ws.recv(), timeout=10)
            verb = json.loads(msg)[0]
            assert verb in ("EVENT", "EOSE", "NOTICE", "CLOSED"), msg
        print("nip-01 ok:", verb)

    asyncio.run(main())
  '';
in
{
  name = "wisp-module";

  nodes.relay =
    { ... }:
    {
      imports = [ self.nixosModules.wisp ];
      services.wisp = {
        enable = true;
        openFirewall = true;
        settings.relay.name = "test relay";
      };
    };

  testScript = ''
    relay.wait_for_unit("wisp.service")
    relay.wait_for_open_port(7777)

    # A client REQ over WebSocket must draw a NIP-01 response back.
    relay.succeed("${pyClient}/bin/python3 ${probe}")

    # NIP-11: the relay document must echo the name set via `settings`, proving the module's generated
    # config.toml round-tripped through wisp's hand-rolled parser (not merely that the service booted).
    relay.succeed(
        "${pkgs.curl}/bin/curl -sf -H 'Accept: application/nostr+json' http://127.0.0.1:7777/ "
        + "| grep -q '\"name\":\"test relay\"'"
    )

    # The data dir is the managed StateDirectory, and the sandbox is in effect.
    relay.succeed("test -d /var/lib/wisp")
    relay.succeed("systemctl show wisp.service | grep -qx 'ProtectSystem=strict'")
    relay.succeed("systemctl show wisp.service | grep -qx 'DynamicUser=yes'")
  '';
}
