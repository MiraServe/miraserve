# syntax=docker/dockerfile:1.7
# Multi-stage rootless distroless OCI image for MiraServe
# Runs as UID/GID 65532:65532 with no shell, no package manager, and no root privileges.

FROM rust:1.95-slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy manifests first to leverage layer caching for dependency compilation.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY vendor ./vendor
COPY examples ./examples
COPY packaging/container/miraserve.kdl ./packaging/container/miraserve.kdl
COPY LICENSE-APACHE LICENSE-MIT ./

RUN cargo build --release --locked --bin miraserve \
    && target/release/miraserve check --strict --dev-tls packaging/container/miraserve.kdl \
    && mkdir -p /rootfs/etc/miraserve /rootfs/var/lib/miraserve/acme /rootfs/var/lib/miraserve/releases /rootfs/var/www/html \
    && chmod 0700 /rootfs/var/lib/miraserve/acme \
    && cp packaging/container/miraserve.kdl /rootfs/etc/miraserve/miraserve.kdl \
    && printf '<!doctype html><html><head><meta charset="utf-8"><title>MiraServe</title></head><body><h1>MiraServe</h1><p>Memory-safe, post-quantum HTTPS &amp; AI-native web server.</p></body></html>\n' > /rootfs/var/www/html/index.html

# Distroless nonroot runtime (includes glibc, libgcc_s, tzdata, CA certs, UID 65532:65532, zero shell).
FROM gcr.io/distroless/cc-debian12:nonroot

LABEL org.opencontainers.image.title="MiraServe" \
      org.opencontainers.image.description="Web server and edge gateway in memory-safe Rust with post-quantum HTTPS" \
      org.opencontainers.image.url="https://github.com/miraserve/miraserve" \
      org.opencontainers.image.source="https://github.com/miraserve/miraserve" \
      org.opencontainers.image.licenses="Apache-2.0 OR MIT"

COPY --from=builder /src/target/release/miraserve /usr/local/bin/miraserve
COPY --from=builder /src/LICENSE-APACHE /usr/share/doc/miraserve/LICENSE-APACHE
COPY --from=builder /src/LICENSE-MIT /usr/share/doc/miraserve/LICENSE-MIT
COPY --from=builder /src/vendor/h2/LICENSE /usr/share/doc/miraserve/LICENSE-h2-MIT
COPY --from=builder --chown=65532:65532 /rootfs/etc/miraserve /etc/miraserve
COPY --from=builder --chown=65532:65532 /rootfs/var /var

USER 65532:65532
WORKDIR /var/lib/miraserve

# Dual-stack IPv4+IPv6 HTTPS (TCP H1/H2 + UDP H3/QUIC) and HTTP->HTTPS redirect
EXPOSE 8443/tcp
EXPOSE 8443/udp
EXPOSE 8080/tcp

ENTRYPOINT ["/usr/local/bin/miraserve"]
# Default CMD uses `--dev-tls` so out-of-the-box container starts generate a fresh ephemeral
# per-container ECDSA P-256 certificate (never baking a shared private key into the image).
# For production, mount your KDL config + certs/ACME and override CMD without `--dev-tls`.
CMD ["run", "/etc/miraserve/miraserve.kdl", "--acme-dir", "/var/lib/miraserve/acme", "--dev-tls"]
