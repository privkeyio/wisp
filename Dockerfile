FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl xz-utils ca-certificates \
    liblmdb-dev libsecp256k1-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://ziglang.org/download/0.15.2/zig-$(uname -m)-linux-0.15.2.tar.xz | \
    tar -xJ -C /opt && ln -s /opt/zig-$(uname -m)-linux-0.15.2/zig /usr/local/bin/zig

WORKDIR /src
COPY . .
RUN zig build -Doptimize=ReleaseSafe

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
