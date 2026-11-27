# Measuring MiraServe yourself

MiraServe does not publish benchmark figures or comparisons with other servers. Results depend on hardware, kernel version, configuration, and workload. This page describes the local harness in the repository and a method for measuring MiraServe on your own hardware.

## Running the harness

The repository includes [`scripts/bench.sh`](../scripts/bench.sh) for a local loopback run:

```bash
./scripts/bench.sh
```

To test an existing binary without building, set `MIRASERVE_BIN`:

```bash
MIRASERVE_BIN=/path/to/miraserve ./scripts/bench.sh
```

The script requires `python3` and `curl`, and behaves as follows:

- **Binary build:** By default it uses `target/release/miraserve` (or the path in `MIRASERVE_BIN`). If that binary is missing or not executable, the script runs `cargo build --release --locked --bin miraserve` in the repository root; otherwise it runs the existing binary without rebuilding.
- **Temporary workspace and cleanup:** It creates a temporary directory under `${TMPDIR:-/tmp}/miraserve-bench.XXXXXX` containing `www/index.html`, a generated `www/64k.txt` file, a generated `bench.kdl` configuration, and `server.log`. An `EXIT` trap stops the server with `SIGTERM`, waits for it to exit, and removes the temporary directory. Only the Cargo build output under `target/` remains if the script had to build the binary.
- **Server started:** It starts `miraserve run <work_dir>/bench.kdl --dev-tls --log-level warn`, listening on `127.0.0.1:18443` with `protocols="h3,h2,h1"`, TLS `min-version "1.3"`, `pqc-hybrid #true`, `key-isolation "in-process"`, `sandbox { landlock #true; seccomp "strict" }` (active on Linux only), and a `localhost` site with `security-headers "strict"` serving `<work_dir>/www`.
- **Measurements printed:**
  1. Host `uname -srm`, `miraserve version`, and the binary path and size in bytes and MiB.
  2. Cold configuration check duration across 10 invocations of `miraserve check --strict --dev-tls`, printed as minimum, median, and maximum milliseconds.
  3. Approximate elapsed milliseconds from process start until `curl -sk --max-time 1` succeeds against `https://127.0.0.1:18443/` (polled up to 100 times with a 0.05 s pause between failed attempts), followed by idle resident set size (`ps -o rss=`) in KiB and MiB.
  4. A static HTTPS pass against `https://127.0.0.1:18443/` (serving `index.html`) using the first tool found in `PATH`:
     - `oha`: `oha --insecure --http2 -z 5s -c 64` (HTTP/2 over TLS 1.3, 5 s, 64 concurrent clients).
     - `h2load`: `h2load -n 10000 -c 32 -m 16` (HTTP/2 over TLS 1.3, 10,000 requests, 32 clients, 16 concurrent streams per client).
     - `wrk`: `wrk -t4 -c32 -d5s` (HTTP/1.1 over TLS 1.3, 5 s, 4 threads, 32 connections).
     - Fallback when none of those tools is installed: a single `curl -sk --tlsv1.3 --http2` invocation issuing 500 sequential keep-alive requests, verifying HTTP/2 status `200` on every response and printing total time and request rate.
  5. Post-load resident set size (`ps -o rss=`) in KiB and MiB.
- **Run time:** When the binary already exists, the script runs 10 `check` invocations, waits for startup readiness (up to 100 probes spaced 0.05 s apart), and executes one static pass of 5 seconds (`oha` or `wrk`), 10,000 requests (`h2load`), or 500 sequential loopback requests (`curl`). When no release binary exists yet, compiling `miraserve` in release mode accounts for most of the wall-clock time.

Because `scripts/bench.sh` runs client and server on loopback with `--dev-tls`, treat it as a local check only. Use separate Linux hosts for measurements you plan to compare or share.

## Measuring on Linux hosts

To compare MiraServe with another server, run the same workloads against both on the same hosts with the same kernel settings and TLS policy.

### Test harness topology

- **Two dedicated Linux hosts** (client load generator and server under test) on a 10 GbE+ isolated VLAN to avoid loopback scheduler contention.
- **Kernel tuning (identical across all servers):**
  - `net.core.somaxconn = 65535`
  - `net.core.rmem_max = 7500000`, `net.core.wmem_max = 7500000` (for HTTP/3 QUIC)
  - `LimitNOFILE = 1048576`
- **Comparable TLS policy:** TLS 1.3 with `X25519MLKEM768` (or `X25519` baseline comparison) and identical ECDSA P-256 leaf certificates.

### Workloads

All commands below assume the client host trusts the server's test CA (add `--insecure` to `oha` only if using an untrusted certificate) and target the server hostname `<host>`.

| Workload | Tool and parameters | What is exercised and what to observe |
| :--- | :--- | :--- |
| **1. Static small asset (1 KiB HTML, HTTP/2 over TLS 1.3)** | `oha --http2 -z 30s -c 256 https://<host>/` | Confined static file lookup, ETag generation, and HTTP/2 multiplexing; observe request rate, latency percentiles (p50/p95/p99), and error count. |
| **2. Static compressed asset (64 KiB text, `Accept-Encoding: br` or `gzip`)** | `h2load -n 200000 -c 64 -m 32 -H 'Accept-Encoding: br' https://<host>/64k.txt` *(repeat with `gzip` if testing both)* | Serving precompressed `.br`/`.gz` files and on-the-fly Brotli or gzip compression; observe request rate, transfer rate, latency percentiles, and server CPU use. |
| **3. HTTP/3 over QUIC (UDP 443)** | `h2load --alpn-list=h3 -n 100000 -c 64 -m 16 https://<host>/` *(requires an `h2load` build compiled with HTTP/3 support)* | `quinn` and `h3` UDP serving and QUIC handshakes; observe request rate, latency percentiles, and connection or error counts (optionally with injected packet loss via `tc netem`). |
| **4. Post-quantum TLS 1.3 handshakes (`X25519MLKEM768` vs. `X25519`)** | `oha --disable-keepalive -z 20s -c 64 https://<host>/` *(example to adapt: `oha` has no CLI flag to choose TLS key-exchange groups; confirm your client build negotiates `X25519MLKEM768` against `pqc-hybrid #true`)* | New TLS 1.3 connections over HTTP/1.1 with `pqc-hybrid #true` versus `pqc-hybrid #false`; observe connection rate, handshake latency percentiles, and server CPU use. |
| **5. Split-privilege `miraserve-keyd` handshakes** | Same client invocation as Workload 4, comparing `key-isolation "split-daemon"` against `key-isolation "in-process"` | TLS 1.3 handshakes using Unix-socket IPC signing in `miraserve-keyd` versus in-process keys; observe connection rate, handshake latency percentiles, and error count. |
| **6. Reverse proxy and SSE streaming** | *Example to adapt:* an upstream mock emitter sending 100 Server-Sent Events per second across 500 concurrent client streams through a `reverse-proxy` route | Long-lived reverse-proxied SSE streams; observe time to first event, per-event delivery latency, server RSS, and open file descriptors. |
| **7. WordPress / PHP-FPM FastCGI** | `oha --http2 -z 30s -c 64 https://<host>/` against a site using `fastcgi-pass` to a local `php8.3-fpm` Unix socket *(example to adapt to your URL and PHP-FPM pool)* | FastCGI request handling over a Unix socket with `preset "wordpress-hardened"` active; observe request rate, latency percentiles, error count, and PHP-FPM worker usage. |
| **8. Hot reload under load** | *Example to adapt:* run `oha --http2 -z 60s -c 64 https://<host>/` while running `systemctl reload miraserve` 10 times | Configuration reload while serving concurrent requests; observe latency percentiles, connection errors, and non-2xx or 5xx response counts while reloading. |

Notes on tool options:

- In `oha`, `--http2` (shorthand for `--http-version=2`), `-z <duration>`, `-c <workers>`, `--disable-keepalive`, and `--insecure` are documented CLI options; `--disable-keepalive` is not supported with `--http2` and applies to HTTP/1.1 runs such as Workload 4.
- In `h2load`, `-n`, `-c`, `-m`, `-H`, and `--alpn-list` (`--h3` is shorthand for `--alpn-list=h3`) are documented CLI options; HTTP/3 requires an `h2load` binary built with `ngtcp2` and `nghttp3`, which many distribution packages omit.

## Reporting results

If you publish numbers, include enough detail for someone else to reproduce the run:

- The exact commit hash (or release tag) and the output of `miraserve version`.
- The full `miraserve.kdl` configuration (including `workers`, `file-cache`, TLS, and sandbox directives) and any CLI flags passed to `miraserve run`.
- The Linux kernel version (`uname -a`) and relevant `sysctl` values on both hosts.
- The `systemd` unit or container settings — in particular the Landlock and seccomp sandbox configuration and whether `RestrictSUIDSGID` is set, because both affect file serving paths (such as `openat2` and `file-cache`; see [`docs/DEPLOYMENT.md`](DEPLOYMENT.md)).
- The exact load-generator commands, tool versions, and whether results come from a single run or multiple runs.
