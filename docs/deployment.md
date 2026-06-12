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
    reverse_proxy localhost:7777
}
```

Reload Caddy:

```sh
sudo systemctl restart caddy
```

Your relay is now live at `wss://relay.yourdomain.com`.
