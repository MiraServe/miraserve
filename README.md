# MiraServe

**A web server and edge gateway written in memory-safe Rust, with post-quantum HTTPS and protections for the AI-era web.**

MiraServe bridges today's web (**Nginx, Apache, OpenLiteSpeed, WordPress/PHP**) safely into tomorrow's web (**AI-authored, self-updating atomic websites, RFC 9421 Web Bot Auth, and MCP security gateways**).

---

## Core Design Pillars

1. **Memory-Safe, Zero-Panic Core**
   - Written in Rust: every MiraServe crate that ships in the binary (15 of 16 workspace members) enforces `#![forbid(unsafe_code)]` and `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`. The 16th workspace member (`miraserve-alloc-tests`, tests-only) contains one audited `unsafe impl GlobalAlloc` for allocation measurement, and third-party dependencies — including the vendored `h2` crate and the `aws-lc-rs` cryptography library — contain `unsafe` Rust or C/assembly code.
   - Composes established Rust libraries (`rustls`, `aws-lc-rs`, `hyper`, `quinn`, `h3`, `cap-std`, `wasmtime`).
2. **Latest HTTPS, Dual-Stack IPv4+IPv6 & Cryptographic Isolation**
   - **TLS 1.3 only by default** with **Post-Quantum Hybrid Key Exchange (`X25519MLKEM768` / RFC 10024)** prioritized out of the box.
   - **Dual-stack IPv4 + IPv6 by default** on bare `":port"` listeners (`IPV6_V6ONLY = true` on TCP & QUIC UDP with automatic IPv4-only fallback when kernel IPv6 is disabled).
   - Automatic ACME v2 + short-lived certificates + RFC 9773 ARI; Encrypted Client Hello (ECH / RFC 9849) ready.
   - **Split-privilege `miraserve-keyd` mode:** Private TLS keys live outside worker address space.
3. **Defense-in-Depth Isolation**
   - Kernel-enforced static file confinement via `cap-std` (`openat2` / `RESOLVE_BENEATH`).
   - Linux **Landlock LSM** (applied across all Tokio worker threads) + **seccomp-bpf** worker sandboxing, with cross-platform support on macOS and Windows.
   - Sandboxed **WebAssembly (`wasi:http`)** plugins replacing unsafe native C `.so` modules.
4. **Transition Bridge for Existing Sites**
   - Pure-Rust async **FastCGI** client for isolated PHP-FPM / WordPress hosting (zero PHP/C code in MiraServe's process) + `wordpress-hardened` security preset.
   - Automated fail-closed **`miraserve import`** migrator for Nginx, Caddy, Apache, and OpenLiteSpeed configs.
5. **AI-Native & Future-Web Ready**
   - **Atomic Self-Updating AI Website Publisher (`miraserve-publish`):** Ed25519 signed immutable snapshots, pre-flight secret/CSP checks, zero-downtime swap, instant rollback, and site-scoped authenticated MCP publishing endpoint.
   - **RFC 9421 / Web Bot Auth** cryptographic agent verification with atomic key-registry reload.
   - **MCP Security Gateway** with OAuth RFC 9728 metadata, strict JWT verification, JSON-RPC tool-level RBAC, and redacted audit logs.
   - Zero-buffer SSE streaming for LLM endpoints + `llms.txt` / Markdown content negotiation.

---

## Project status

Version 0.1.7. Binaries for Linux, macOS and Windows, a Debian package and a container image are listed at
<https://miraserve.org/download/>; what changed in each version is at <https://miraserve.org/releases/>.
Configuration and command-line interfaces may still change before 1.0.

MiraServe has not been audited by an outside security firm. Each release is reviewed by independent AI code
reviewers and run on a hosting-panel server before it is tagged; `docs/SECURITY_AUDIT_PREP.md` records the
internal review rounds and maps the attack surface for anyone who wants to audit it. Comments in the source
that say "Codex Round N" or similar refer to those review rounds.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Documentation

- [Architecture & Specification](docs/SPEC.md)
- [Threat Model & Trust Boundaries](docs/THREAT_MODEL.md)
- [Production Deployment Guide](docs/DEPLOYMENT.md) (`systemd`, `.deb`/`.rpm`, distroless OCI, Homebrew/`launchd`, Windows Service)
- [Migration Guide](docs/MIGRATION.md) (Nginx, Caddy, Apache, OpenLiteSpeed → KDL)
- [Measuring MiraServe yourself](docs/BENCHMARKS.md)
- [Security Review Record & Audit Map](docs/SECURITY_AUDIT_PREP.md)
- [Example Configuration](examples/miraserve.kdl)
- [Setup guide for AI assistants](skills/miraserve-setup/SKILL.md) (also at <https://miraserve.org/ai-setup.txt>; see [AGENTS.md](AGENTS.md))

## Quickstart

```bash
# 1. Validate configurations (human-readable or JSON + strict security audit)
cargo run --bin miraserve -- check examples/miraserve.kdl
cargo run --bin miraserve -- check --strict --dev-tls --fs examples/dev-local.kdl

# 2. Boot a live local HTTPS server (TLS 1.3 + X25519MLKEM768 PQC, HTTP/3 + HTTP/2 + HTTP/1.1)
cargo run --bin miraserve -- run examples/dev-local.kdl --dev-tls

# 3. Generate hardened OS service definitions (systemd, systemd-keyd, launchd, Windows Service)
cargo run --bin miraserve -- service generate --target systemd
cargo run --bin miraserve -- service generate --target systemd-keyd

# 4. Run the isolated split-privilege TLS signing daemon (private keys stay out of worker memory)
cargo run --bin miraserve -- keyd --socket /tmp/miraserve-keyd.sock --dev-tls --hosts localhost

# 5. Generate RFC 9849 Encrypted Client Hello (ECH) HPKE config + RFC 9460 DNS HTTPS record
cargo run --bin miraserve -- cert ech-generate --public-name edge.example.com

# 6. Atomic signed AI website publishing (Ed25519 keygen, pre-flight secret/CSP checks, deploy & rollback)
cargo run --bin miraserve -- publish keygen --secret deploy.key --public deploy.pub
cargo run --bin miraserve -- publish deploy ./public --storage ./releases --key deploy.key --pubkey deploy.pub --no-inline-scripts
cargo run --bin miraserve -- publish list --storage ./releases
cargo run --bin miraserve -- publish rollback --storage ./releases

# 7. Import legacy Nginx / Caddy / Apache / OpenLiteSpeed configs into validated KDL
cargo run --bin miraserve -- import /etc/nginx/sites-enabled/default --from auto --output miraserve.kdl

# 8. Run workspace lints, tests, docs, and supply-chain security audit
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo deny check
```

## Status

- **Milestone 0 (Foundation — Complete):** Workspace + strict `#![forbid(unsafe_code)]` / zero-panic lints, `deny.toml`, `THREAT_MODEL.md`, `miraserve-config` KDL schema/validator + `ArcSwap` store, `miraserve check`, cross-platform CI.
- **Milestone 1 (Secure Core MVP — Complete):** `miraserve-tls` (TLS 1.3 + `X25519MLKEM768` PQC, per-site `compat-tls-1-2` & per-site client CA mTLS, dev TLS, X.509 inspect, ACME v2/TLS-ALPN-01/HTTP-01/ARI), `miraserve-static` (`cap-std` confined static server, ETag/304, Range, precompressed & pure-Rust `br`/`gzip`, `try-files`), `miraserve-proxy` (weighted LB, active health checks, zero-buffer SSE, WebSocket upgrades, upstream mTLS), `miraserve-http` (HTTP/1.1, HTTP/2, HTTP/3 over QUIC, router, security headers, HTTP→HTTPS 308), `miraserve-core` (dual-stack IPv4+IPv6 TCP/QUIC listeners, lazy per-SNI TLS acceptor, atomic hot reload, graceful drain), and `miraserve run` / `cert` / `reload` CLI.
- **Milestone 2 (Hardening & Transition Bridge — Complete):** `miraserve-security` (RFC 9110/9112 anti-smuggling normalizer, H2/H3 flood & Slowloris body guards, sharded bounded-memory GCRA rate limiter, `wordpress-hardened`/`static-strict`/`api-gateway` presets), `miraserve-fastcgi` (pure-Rust async FastCGI v1.0 client with HTTPoxy protection + live WordPress test harness), `miraserve-sandbox` (cross-platform worker confinement policy + multi-thread Linux Landlock LSM & seccomp-bpf), and `miraserve-migrate` (fail-closed `miraserve import` for Nginx, Caddy, Apache, and OpenLiteSpeed).
- **Milestone 3 (AI-Native Edge & Publish — Complete):** `miraserve-publish` (Ed25519 signed atomic site bundles with manifest re-verification across key rotation, pre-flight secret/XSS/CSP/quota checks, immutable versioned release store with lock-free `ArcSwap` swap & instant rollback, site-scoped authenticated MCP publisher at `/_miraserve/publish`, and `miraserve publish` CLI) and `miraserve-ai` (RFC 9421 / Web Bot Auth Ed25519 agent verification with atomic key reload, unverified AI UA throttle/challenge/block, MCP Security Gateway with OAuth RFC 9728 metadata, strict JWT verification, JSON nesting/size bounds, tool-level RBAC + `tools/list` filtering, secret-redacted audit logs, and `llms.txt` / `Accept: text/markdown` negotiation).
- **Milestone 4 (WASM, Split-Key & ECH — Complete):** `miraserve-wasm` (`wasmtime 48` + `wasi:http/proxy` & core module sandbox with deterministic CPU fuel limits, linear memory caps, timeouts, and zero ambient FS/env/network capabilities), `miraserve-keyd` (split-privilege TLS signing daemon over `0600` + `SO_PEERCRED` Unix socket or HMAC-SHA256 loopback TCP with RFC 8446 anti-oracle guard), RFC 9849 ECH (`DHKEM(X25519, HKDF-SHA256)` key rotation + RFC 9460 DNS `HTTPS` record helper + `miraserve cert ech-generate`), and `miraserve-telemetry` (lock-free Prometheus exposition server, OTLP/HTTP v1 JSON exporter, and secret-redacting access/audit logs).
- **Milestone 5 (Packaging, Release Supply Chain & Audit Readiness — Complete):** `miraserve service generate` (`systemd`, `systemd-keyd`, `launchd`, Windows Scheduled Task), `.deb`/`.rpm` (`nFPM`) + `sysusers.d`/`tmpfiles.d`, rootless distroless OCI `Containerfile`, Homebrew formula, WinGet manifest, SHA-pinned cross-platform `.github/workflows/release.yml` (CycloneDX SBOM, Sigstore Cosign keyless signing, SLSA Build Level 2 provenance), reproducible smoke-baseline harness (`scripts/bench.sh` + `docs/BENCHMARKS.md`), production deployment/migration guides, 8 `cargo-fuzz` targets, and internal pre-release security reviews (`docs/SECURITY_AUDIT_PREP.md`); the release pipeline is defined in the repository and has not produced a release yet (0.1.x downloads are built by hand from the tag and are unsigned).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your
option. Third-party components and their licenses are listed in [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md);
the vendored `h2` crate keeps its own license in `vendor/h2/LICENSE`.
