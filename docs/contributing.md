# Contributing

Contributions are welcome. Wisp's guiding principles are **fast**, **lightweight**, and
**simple** — feature requests and changes should align with those goals.

See [`CONTRIBUTING.md`](https://github.com/privkeyio/wisp/blob/main/CONTRIBUTING.md) for the
full guidelines, including the issue policy, branch naming, commit conventions, the NIP
implementation policy, and development setup.

## Development setup

```sh
# Install dependencies (Ubuntu/Debian)
sudo apt install -y liblmdb-dev libsecp256k1-dev libssl-dev

# Clone and build
git clone https://github.com/privkeyio/wisp && cd wisp
zig build

# Run tests
zig build test

# Build optimized release
zig build -Doptimize=ReleaseFast

# Format code
zig fmt src/*.zig
```
