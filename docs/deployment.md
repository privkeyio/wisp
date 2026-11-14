# Deployment

To make your relay publicly accessible with TLS, run Wisp behind [Caddy](https://caddyserver.com),
which provisions and renews certificates automatically.

```sh
# Run wisp
docker run -d --restart always -p 127.0.0.1:7777:7777 -v wisp-data:/data \
  ghcr.io/privkeyio/wisp --spider-admin npub1yourkey...

# Install Caddy for automatic TLS
sudo apt install -y caddy
```

Create `/etc/caddy/Caddyfile`:

```
relay.yourdomain.com {
    respond /metrics 404
    reverse_proxy localhost:7777
}
```

Reload Caddy:

```sh
sudo systemctl restart caddy
```

Your relay is now live at `wss://relay.yourdomain.com`.

> **Behind a proxy:** set `trust_proxy = true` and `trusted_proxies = "127.0.0.1"` (the
> proxy's address) in the `[security]` section of `wisp.toml` so per-IP connection limits and
> IP allow/deny lists see the real client IP from Caddy's `X-Forwarded-For` header instead of
> `127.0.0.1`. `trust_proxy` with an empty `trusted_proxies` honors the header from every peer,
> so a client that reaches the relay port directly can spoof any IP.
>
> Without `trust_proxy`, every client shares the proxy's IP, so all per-IP controls become
> relay-wide: not only `max_connections_per_ip`, but also the `events_per_minute` and
> `queries_per_minute` rate limits and the IP allow/deny lists. One busy client then gets
> everyone `rate-limited`. wisp warns when it ignores an `X-Forwarded-For` or `X-Real-IP`
> header, and the wording depends on the socket peer:
>
> - From a peer that could be a proxy (loopback, RFC 1918, CGNAT `100.64.0.0/10`,
>   link-local, IPv6 ULA `fc00::/7`) while `trust_proxy` is off, the warning names the peer
>   and suggests `trust_proxy = true` together with `trusted_proxies` set to it.
> - From such a peer while `trust_proxy` is on but the peer is missing from a non-empty
>   `trusted_proxies` (for example a container gateway such as `10.0.3.1`), the warning says
>   the peer is not in `trusted_proxies`; add it if it is your proxy.
> - From a public peer while `trust_proxy` is off, the warning only notes that a client sent
>   the header. If you don't run a reverse proxy this is client-supplied and can be ignored.
>   A public peer missing from `trusted_proxies` is not logged.
>
> Each kind of peer (could-be-proxy, public) is logged at most once an hour, so a direct
> client cannot crowd out the proxy warning. `wisp_forwarded_header_ignored_total` on
> `/metrics` counts every ignored forwarded header.

## Limiting connections per source

`max_connections_per_ip` is applied during the WebSocket upgrade, because that is the first
point at which wisp knows the client IP. A connection that completes the TCP handshake and
then sends nothing never reaches it. Those connections are bounded — they are closed after
`10s` if no request arrives — but until then they occupy a worker slot, so a single source can
hold `max_conn` slots per worker by reconnecting.

Capping concurrent connections per source address closes that, and it belongs at the edge,
where connections arrive. **Apply it wherever the public port is, not on the relay port.**
Behind a reverse proxy every connection reaches wisp from `127.0.0.1`, so a per-IP rule on the
relay port would either do nothing or throttle the proxy itself.

**Exposed directly** — limit on the relay port:

```sh
# nftables
nft add rule inet filter input tcp dport 7777 ct count over 10 reject

# iptables
iptables -A INPUT -p tcp --dport 7777 \
  -m connlimit --connlimit-above 10 --connlimit-mask 32 -j REJECT
```

**Behind a proxy** — limit on the public port instead:

```sh
iptables -A INPUT -p tcp --dport 443 \
  -m connlimit --connlimit-above 10 --connlimit-mask 32 -j REJECT
```

Caddy has no built-in per-connection limiter, so with the Caddyfile above the firewall rule is
the control. If you front wisp with nginx instead, it can do this itself:

```nginx
limit_conn_zone $binary_remote_addr zone=perip:10m;

server {
    listen 443 ssl;
    location = /metrics { return 404; }
    location / {
        limit_conn perip 10;
        proxy_pass http://127.0.0.1:7777;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Set the limit above `max_connections_per_ip` (default 10) so the edge only rejects what wisp
would have refused anyway. `--connlimit-mask 32` counts per address; lower it to limit per
subnet. Note that any of these only constrain a single source: they do not help against a
flood distributed across many addresses, which is what `max_conn` and the request timeout
bound.
