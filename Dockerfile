# syntax=docker/dockerfile:1
FROM rust:1-slim-trixie AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY upstream ./upstream
RUN cargo build --locked --release

FROM debian:trixie-slim AS assets
ARG TARGETARCH
ARG XRAY_VERSION=v26.11.9
ARG GEOCHECK_VERSION=0.3.0
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip && rm -rf /var/lib/apt/lists/*
COPY scripts/verify_xray.py /tmp/verify_xray.py
RUN apt-get update && apt-get install -y --no-install-recommends python3-minimal && rm -rf /var/lib/apt/lists/*
RUN case "$TARGETARCH" in amd64) archive=Xray-linux-64.zip ;; arm64) archive=Xray-linux-arm64-v8a.zip ;; *) exit 1 ;; esac \
    && base="https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION" \
    && curl -fLsS --retry 3 "$base/$archive" -o /tmp/xray.zip \
    && curl -fLsS --retry 3 "$base/$archive.dgst" -o /tmp/xray.zip.dgst \
    && python3 /tmp/verify_xray.py /tmp/xray.zip /tmp/xray.zip.dgst \
    && mkdir -p /tmp/xray && unzip -q /tmp/xray.zip -d /tmp/xray \
    && base="https://github.com/remnawave/geocheck/releases/download/v$GEOCHECK_VERSION" \
    && archive="geocheck_linux_$TARGETARCH.tar.gz" \
    && cd /tmp && curl -fLsS --retry 3 "$base/$archive" -o "$archive" \
    && curl -fLsS --retry 3 "$base/checksums.txt" -o checksums.txt \
    && python3 -c 'import hashlib,pathlib,sys; p=pathlib.Path(sys.argv[1]); expected=[line.split()[0] for line in pathlib.Path("checksums.txt").read_text().splitlines() if line.split()[-1].lstrip("*")==p.name]; assert len(expected)==1 and hashlib.sha256(p.read_bytes()).hexdigest()==expected[0], "geocheck checksum mismatch"' "$archive" \
    && tar -xzf "$archive" geocheck

FROM debian:trixie-slim
LABEL org.opencontainers.image.source="https://github.com/akimovvpn/remnanode_rust" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.description="Rust management service compatible with Remnawave Node 3.4.5"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 nftables && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/remnanode /var/log/xray /usr/local/share/xray
COPY --from=build /build/target/release/remnanode-rust /usr/local/bin/remnanode-rust
COPY --from=assets /tmp/xray/xray /usr/local/bin/xray
COPY --from=assets /tmp/xray/geoip.dat /tmp/xray/geosite.dat /usr/local/share/xray/
COPY --from=assets /tmp/geocheck /usr/local/bin/geocheck
ENV XRAY_LOCATION_ASSET=/usr/local/share/xray
ENV STATE_DIR=/var/lib/remnanode
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/remnanode-rust"]
