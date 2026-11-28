# MiraServe Security Review Record & Audit Map

This document provides an external auditor's map of MiraServe's attack surface, trust boundaries, deterministic fuzzing harness, and the three internal pre-release review rounds whose findings were fixed before packaging. MiraServe has not been audited by an outside security firm; the review rounds below were carried out by AI code reviewers working independently of the code's author.

---

## 1. Architectural Security Guarantees

| Property | Enforcement Mechanism |
| :--- | :--- |
| **Memory Safety** | `#![forbid(unsafe_code)]` enforced on all 15 shipped MiraServe crates (of 16 workspace members; the tests-only `miraserve-alloc-tests` crate holds one audited `unsafe impl GlobalAlloc`); third-party dependencies — including the vendored `h2` crate and the `aws-lc-rs` cryptography library — contain `unsafe` Rust or C/assembly; zero OpenSSL C linkage (`deny.toml` bans `openssl` / `openssl-sys`). |
| **Zero-Panic Runtime** | Workspace denies `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`, `clippy::indexing_slicing`, `clippy::todo`, `clippy::unimplemented`, `clippy::exit`. |
| **Modern Cryptography** | `rustls` + `aws-lc-rs`: TLS 1.3 only by default, `X25519MLKEM768` (RFC 10024) PQC hybrid KEX prioritized, optional split-privilege `miraserve-keyd` over a Unix socket with kernel `SO_PEERCRED` (`0600` same-UID default; `0660` with exact-UID `--allow-peer-user` in the packaged unit, where systemd tmpfiles provisions `/run/miraserve-keyd` with mode `2750` in `packaging/systemd/miraserve.tmpfiles` while direct `miraserve keyd` creates a missing parent `0750` subject to umask in `crates/miraserve-tls/src/keyd.rs`) or HMAC-SHA256 `LoopbackTcp`, RFC 8446 anti-oracle guard, `zeroize` on secret drop. In `split-daemon` mode, the worker's inbound TLS resolver obtains public chains from `miraserve-keyd` and delegates inbound handshake signatures to it without loading configured signing keys (`server.tls.key`, `site[N].tls.key`), and the worker's credential inventory skips configured signing keys and matching inventory entries (by name or, on Unix, by metadata `(device, inode)`); outbound mTLS client keys are loaded by the worker. Configuration load rejects `owner-dir` per-tenant TLS pairs (`E109`) and emits `E109` as an early diagnostic for obvious lexical key overlaps (read/socket/acme-webroot trees and `server.tls.cert`, `site[N].tls.cert`, `server.tls.client-ca`, `site[N].tls.client-ca`, `upstream-tls.ca-cert`, `upstream-tls.client-cert`, `upstream-tls.client-key`, and `basic-auth` users file). Ensuring that the worker account cannot read a signing key at all depends on the key-storage layout in `docs/DEPLOYMENT.md` §2.3; MiraServe does not verify it. |
| **Filesystem Confinement** | `cap-std::fs::Dir` (`openat2` + `RESOLVE_BENEATH` on Linux) for static file serving + Linux Landlock LSM (applied across main thread and all Tokio worker threads via `on_thread_start`, failing closed on late thread errors) + seccomp-bpf dangerous-syscall denylist filtering. |
| **Plugin Isolation** | WebAssembly (`wasmtime 48` + `wasi:http/proxy`) with deterministic CPU fuel budgets, linear memory caps, wall-clock timeouts, and zero ambient FS/env/network capabilities. |
| **Supply Chain** | Locked `Cargo.lock` builds (`--locked`), pinned Rust toolchain in release CI, uncached release builds with cross-job SHA-256 verification, `cargo-deny` license/advisory/ban gates, release-blocking vendored-`h2` provenance/graph/advisory gates (`scripts/verify-vendor-h2.sh`, `scripts/verify-h2-graph.sh`, `scripts/audit-vendor-h2.sh`, dependency owner: maintainer; see `vendor/README.md`), 40-char SHA-pinned GitHub Actions, CycloneDX SBOM, Sigstore Cosign keyless signatures, and SLSA Build Level 2 provenance. |

---

## 2. Crate-by-Crate Audit Map

| Crate | Trust Boundary | Primary Security Responsibilities |
| :--- | :--- | :--- |
| `miraserve-config` | Operator input / reload | KDL parser, strict security validator, `ArcSwap` atomic config store, fails closed on unimplemented/insecure claim policies. |
| `miraserve-tls` | TB-1, TB-2 | TLS 1.3 + PQC config, per-site SNI & per-site client CA verification (TCP + QUIC), ACME v2 (`instant-acme`) with reload preservation, ECH (RFC 9849), `miraserve-keyd` IPC server/client. |
| `miraserve-security` | TB-1 | RFC 9110/9112 anti-smuggling normalizer, canonical path normalization, H2/H3 flood & Slowloris guards, sharded bounded-memory GCRA rate limiter, `wordpress-hardened`/`static-strict`/`api-gateway` presets. |
| `miraserve-http` | TB-1, TB-4, TB-6 | HTTP/1.1, HTTP/2, HTTP/3 (QUIC) servers, unified router, script-extension source-disclosure guard, atomic bot-key registry reload, HTTP→HTTPS 308 redirector. |
| `miraserve-static` | TB-4 | `cap-std` confined static server, symlink/traversal rejection, `try-files` path/query separation & script-extension guard, ETag/Range/br/gzip. |
| `miraserve-fastcgi` | TB-6 | Pure-Rust async FastCGI v1.0 client, HTTPoxy `HTTP_PROXY` stripping, response header validation, out-of-process PHP-FPM boundary. |
| `miraserve-proxy` | TB-6 | Reverse proxy pool, upstream mTLS, hop-by-hop header stripping, WebSocket upgrade handling, zero-buffer SSE streaming. |
| `miraserve-publish` | TB-5 | Ed25519 signed atomic site bundles, signed manifest re-verification on activate/restore/rollback, pre-flight secret/XSS/CSP/quota checks, serialized write locking vs side-effect-free read-only listing, MCP publisher auth (Ed25519 / JWT / site-scoped mTLS). |
| `miraserve-ai` | TB-1, TB-6 | RFC 9421 / Web Bot Auth Ed25519 verification, MCP Security Gateway (OAuth RFC 9728, mandatory JWT verifier when claim policies are set, JSON-RPC batch/depth/size bounds, tool-level RBAC + `tools/list` filtering), `llms.txt` & Markdown negotiation. |
| `miraserve-wasm` | TB-3 | Wasmtime `wasi:http` sandbox, CPU fuel, memory ceiling, timeouts, explicit host allow-list enforcement. |
| `miraserve-sandbox` | OS Boundary | Linux Landlock LSM + seccomp-bpf dangerous-syscall denylist worker policy, exact UID/GID privilege-state verification against `sandbox.user`/`sandbox.group`, cross-platform confinement report. |
| `miraserve-migrate` | Operator CLI | Nginx, Caddy, Apache, OpenLiteSpeed → KDL importers with security-downgrade fail-closed gate for recognized auth, Lua, matcher, and access directives (`--allow-insecure` required when unsupported security rules or scoped binds cannot be translated 1:1). |
| `miraserve-telemetry` | Observability | Secret-redacting access/audit logs, Prometheus exposition, OTLP/HTTP v1 JSON exporter. |
| `miraserve-core` | Process Lifecycle | Dual-stack IPv4+IPv6 TCP/QUIC listeners (`IPV6_V6ONLY`), lazy SNI TLS acceptor, per-connection supervisor, SIGHUP atomic hot reload, graceful drain. |
| `miraserve-bin` | Operator CLI | CLI dispatch (`run`, `check`, `reload`, `cert`, `import`, `publish`, `keyd`, `service`, `version`), anti-injection service unit generator. |

---

## 3. Continuous Fuzzing Coverage (Threat Model T1)

Standalone `fuzz/` workspace provides 8 `cargo-fuzz` (`libFuzzer`) targets covering untrusted parser boundaries (compile-checked on every PR and smoke-fuzzed weekly in `.github/workflows/ci.yml`):

1. `fuzz_kdl_config` — KDL parser & validator (`miraserve-config`)
2. `fuzz_http_smuggling` — RFC 9110/9112/9113/9114 request normalizer across H1/H2/H3 & preset guards (`miraserve-security`)
3. `fuzz_fastcgi_codec` — FastCGI v1.0 header/record/params & CGI response parser (`miraserve-fastcgi`)
4. `fuzz_rfc9421_bot_auth` — RFC 9421 `Signature-Input` / `Signature` header parser (with a pre-registered test key for Ed25519 verification when inputs supply matching valid headers; `miraserve-ai`)
5. `fuzz_mcp_jsonrpc` — MCP Gateway duplicate-key JSON parser, depth bounds, tool RBAC & `tools/list` filter (`miraserve-ai`)
6. `fuzz_telemetry_redact` — Secret redaction & structured log formatter (`miraserve-telemetry`)
7. `fuzz_migrate_parsers` — Nginx/Caddy/Apache/OLS config importers (`miraserve-migrate`)
8. `fuzz_publish_preflight` — Publish HTML inline-script, CSP, secret, and filename preflight scanner (`miraserve-publish`)

Run locally (requires nightly Rust + `cargo-fuzz`):

```bash
cd fuzz
cargo +nightly fuzz run fuzz_http_smuggling -- -max_total_time=60
```

---

## 4. Pre-Release Internal Review Record

Prior to Milestone 5 packaging, MiraServe went through **three internal whole-codebase and focused security review rounds**, with every confirmed finding fixed and locked down with regression tests:

1. **Review Round 1 — Systematic Security Review:**
   - Full-workspace review of TLS/keyd IPC, WASM sandbox, HTTP smuggling/router, AI/MCP gateway, publish endpoint, and platform sandbox.
   - Remediated keyd Unix peer-UID + LoopbackTcp HMAC auth, WASM memory/fuel bounds, MCP batch & JSON depth limits, and added the 7 `cargo-fuzz` targets.
2. **Review Round 2 — Independent Whole-Codebase Review:**
   - Hardened canonical path & script-extension handling (blocking `/wp-config.php/` source disclosure and `/wp-content//uploads/shell.php` bypasses).
   - Hardened `miraserve-publish` authentication (verified Ed25519 / JWT / mTLS — zero unauthenticated deploy/rollback).
   - Implemented real ACME v2 issuance/renewal + reload certificate preservation, real multi-thread Landlock application via Tokio `on_thread_start`, and fail-closed security-downgrade detection in `miraserve import`.
   - Enforced strict config rejection for unsupported/partially configured security directives.
3. **Review Round 3 — Focused Cross-Boundary Verification (and Recheck Hardening):**
   - **PHP source disclosure (`try-files`, directory index, and symlinks):** Separated path and query string in `miraserve-static` `try-files` resolution and enforced the script-extension guard inside `StaticServer::resolve_target` on every final selected file (direct paths, `try-files`, directory indexes such as `index.php`, precompressed siblings, and symlink targets).
   - **Cross-site client CA authorization:** Bound client certificate verification strictly to the selected site's CA on both TCP (`miraserve-tls` + `miraserve-core`) and QUIC/HTTP3 (`miraserve-http`), preventing site A's client CA from authorizing site B's publisher.
   - **MCP claim policy without verifier:** Rejected configurations setting required JWT `scope`, `issuer`, or `audience` without an active verifier.
   - **Bot-auth key revocation on reload:** Replaced live mutation with fresh `BotKeyRegistry` construction swapped atomically on successful reload.
   - **Release manifest re-verification on key rotation & legacy upgrade path:** Persisted signed release manifests and re-verified signatures against the active Ed25519 key policy during startup, restore, and rollback, and added `miraserve publish resign` (verifying on-disk `manifest_sha256` integrity first) to migrate legacy pre-manifest releases or rotate keys cleanly.
   - **Concurrent publish / reload / list synchronization:** Made read-only store opens side-effect free and replaced wall-clock lockfile expiry with an OS kernel-backed exclusive lock (`std::fs::File::try_lock`) held for the writer's full lifetime so slow publishes can never be interrupted by startup or reload.

---

## 5. Verification Commands for External Auditors

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo deny check
./scripts/verify-vendor-h2.sh
./scripts/verify-h2-graph.sh
./scripts/audit-vendor-h2.sh
cargo check --manifest-path fuzz/Cargo.toml --bins
```

The three vendored-`h2` verification scripts above are release-blocking in CI (`.github/workflows/ci.yml`) and the single-archive release pipeline (`.github/workflows/release.yml`, which generates and freezes one source archive and its job-output SHA-256 before compiling any project code, verifies provenance/graph/advisories and the tamper suite on the extracted archive, builds every matrix target and package from that archive after verifying against the frozen job-output digest, and publishes that same archive); downstream hosting-panel builders should run `./scripts/verify-vendor-h2.sh` before `cargo +1.95.0 build --release --locked --bin miraserve` because `cargo build --locked` alone does not invoke the scripts. `.github/CODEOWNERS` designates `@tibeemts` as code owner for `vendor/`, `Cargo.toml`, `Cargo.lock`, `deny.toml`, the `scripts/*h2*.sh` gates, `packaging/homebrew/miraserve.rb`, `.github/workflows/{ci,release}.yml`, and `.github/CODEOWNERS` itself; actual merge-blocking enforcement depends on enabling required Code Owners review in the GitHub repository's branch-protection or ruleset settings (which the Git checkout alone cannot prove). Run `./scripts/test-vendor-h2.sh` on every adoption or upstream refresh.
