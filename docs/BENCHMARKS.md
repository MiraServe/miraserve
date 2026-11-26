# MiraServe Benchmarks & Baseline Methodology

This document records reproducible benchmark methodology and observed local release-build baselines for MiraServe.

---

## 1. Local Release-Build Smoke Baseline (Observed — Not a Production Benchmark)

Recorded as a single-run local smoke baseline via [`scripts/bench.sh`](../scripts/bench.sh) on an Apple Silicon developer workstation (`Darwin 25.6.0 arm64`, release profile: `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`, full feature set including `wasmtime 48` Cranelift JIT, `aws-lc-rs` PQC, `quinn`/`h3`, `cap-std`, and `instant-acme`). Note that Linux Landlock and seccomp-bpf sandbox policies are no-ops on macOS.

| Metric | Observed Smoke Baseline | Notes |
| :--- | :--- | :--- |
| **Stripped release binary size** | **24.46 MiB** (`25,648,832` bytes) | Single binary containing HTTP/1.1/2/3, PQC TLS 1.3, FastCGI, AI/MCP gateway, atomic publisher, `keyd`, and Wasmtime Cranelift runtime. |
| **Cold `miraserve check --strict`** | **4.59 ms median** (`4.18 ms` min / `6.21 ms` max) | 10 cold process invocations parsing & strictly validating KDL v2. |
| **Startup to first TLS 1.3 response** | **~121 ms** | Single run; includes ephemeral ECDSA P-256 dev-TLS cert generation, TCP+UDP bind, and first TLS 1.3 handshake. |
| **Idle RSS (post-startup)** | **14.25 MiB** (`14,592 KiB`) | Single run with HTTP/3 + HTTP/2 + HTTP/1.1 listeners bound (`pqc-hybrid #true` configured). |
| **Single-connection `curl` smoke check** | **~7.3k req/s** (`500/500` in `0.068 s`) | Single-process sequential keep-alive `curl -sk --tlsv1.3 --http2` loop (`127.0.0.1`); verifies responsiveness and steady RSS only (no variance or multi-client saturation). |
| **Post-load RSS** | **14.41 MiB** (`14,752 KiB`) | `+160 KiB` delta after 500 sequential requests. |

> **Note:** These macOS loopback figures are a **smoke baseline** for binary footprint, startup overhead, and steady-state RSS (with Linux sandbox confinement inactive on macOS). They are **not** competitive throughput measurements; use the two-host Linux methodology below (`oha` / `h2load`, multi-run variance, Landlock + seccomp active) for publishable performance comparisons.

---

## 2. Reproducing the Baseline

```bash
# Build stripped release binary and run the local baseline harness
./scripts/bench.sh
```

If `oha`, `h2load`, or `wrk` is installed in `PATH`, `scripts/bench.sh` automatically runs a multi-client HTTP/2 or HTTP/1.1 TLS 1.3 saturation run instead of the single-connection `curl` fallback.

---

## 3. Linux Production Benchmark Methodology (vs. Nginx & Caddy)

For reproducible head-to-head server evaluations (e.g., MiraServe vs. Nginx 1.28+ vs. Caddy 2.9+):

### 3.1 Test Harness Topology
- **Two dedicated Linux hosts** (client load generator + server under test) on a 10 GbE+ isolated VLAN to avoid loopback scheduler contention.
- **Kernel tuning (identical across all servers):**
  - `net.core.somaxconn = 65535`
  - `net.core.rmem_max = 7500000`, `net.core.wmem_max = 7500000` (for HTTP/3 QUIC)
  - `LimitNOFILE = 1048576`
- **Comparable TLS policy:** TLS 1.3 with `X25519MLKEM768` (or `X25519` baseline comparison) and identical ECDSA P-256 leaf certificates.

### 3.2 Benchmark Workloads

| Workload | Tool & Parameters | What It Measures |
| :--- | :--- | :--- |
| **1. Static Small Asset (1 KiB HTML, H2 TLS 1.3)** | `oha --http2 -z 30s -c 256 https://<host>/` | `cap-std` confined file lookup, ETag generation, H2 multiplexing, p50/p95/p99 latency. |
| **2. Static Compressed Asset (64 KiB text, `Accept-Encoding: br, gzip`)** | `h2load -n 200000 -c 64 -m 32 -H 'Accept-Encoding: br'` | Precompressed `.br`/`.gz` serving and on-the-fly pure-Rust compression cost. |
| **3. HTTP/3 over QUIC (UDP 443)** | `h2load --alpn-list=h3 -n 100000 -c 64 -m 16` | `quinn` + `h3` UDP throughput, 0-RTT/1-RTT handshake latency, and packet loss resilience. |
| **4. Post-Quantum Handshake Cost (`X25519MLKEM768` vs `X25519`)** | `oha --disable-keepalive -z 20s -c 64` | New TLS 1.3 connection rate with hybrid PQC key exchange (`aws-lc-rs`). |
| **5. Split-Privilege `miraserve-keyd` Overhead** | Same as Workload 4 with `key-isolation "split-daemon"` | Additional p99 handshake latency from Unix-socket IPC signing vs in-process keys. |
| **6. Reverse Proxy & Zero-Buffer SSE Streaming** | Upstream mock emitter sending 100 SSE tokens/s across 500 concurrent streams | Time-to-first-token (TTFT) overhead and RSS under long-lived LLM streams. |
| **7. WordPress / PHP-FPM FastCGI** | `oha --http2 -z 30s -c 64` against isolated `php8.3-fpm` Unix socket | Pure-Rust FastCGI framing + `wordpress-hardened` preset overhead. |
| **8. Hot Reload Zero-Drop Verification** | Continuous `oha` run while executing `systemctl reload miraserve` 10× | Confirms 0 dropped/5xx responses across atomic `ArcSwap` reloads. |
