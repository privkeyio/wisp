FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl xz-utils ca-certificates \
    liblmdb-dev libsecp256k1-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Verified against the sha256s in ziglang.org/download/index.json before it is
# extracted, as CI does.
RUN arch="$(uname -m)" && \
    case "$arch" in \
      x86_64) sum=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026 ;; \
      aarch64) sum=9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8 ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac && \
    curl -fsSL -o /tmp/zig.tar.xz "https://ziglang.org/download/0.17.0/zig-$arch-linux-0.17.0.tar.xz" && \
    echo "$sum  /tmp/zig.tar.xz" | sha256sum -c - && \
    tar -xJf /tmp/zig.tar.xz -C /opt && rm /tmp/zig.tar.xz && \
    ln -s "/opt/zig-$arch-linux-0.17.0/zig" /usr/local/bin/zig

WORKDIR /src
COPY . .
# The image runs on other machines than the one that built it, so target the
# baseline CPU rather than the builder's own.
RUN zig build -Doptimize=ReleaseSafe -Dcpu=baseline

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    liblmdb0 libsecp256k1-1 libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false wisp \
    && mkdir -p /data && chown wisp:wisp /data

COPY --from=build /src/zig-out/bin/wisp /usr/local/bin/wisp

USER wisp
WORKDIR /data
EXPOSE 7777

ENV WISP_HOST=0.0.0.0
ENTRYPOINT ["wisp"]
