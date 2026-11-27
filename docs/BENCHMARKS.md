# Measuring MiraServe yourself

MiraServe does not publish benchmark figures or comparisons with other servers. Results depend on hardware, kernel version, configuration, and workload. This page describes the local harness in the repository and a method for measuring MiraServe on your own hardware.

## Running the harness

The repository includes [`scripts/bench.sh`](../scripts/bench.sh) for a local loopback run:

```bash
./scripts/bench.sh
```

To test an existing executable binary without building, set `MIRASERVE_BIN` to its path:

```bash
MIRASERVE_BIN=/path/to/miraserve ./scripts/bench.sh
```

The script requires `python3` and `curl`, and behaves as follows:

- **Binary and build step:** Uses `target/release/miraserve` by default, or `MIRASERVE_BIN` when set. Set `MIRASERVE_BIN` only to an existing executable binary: if the selected path is missing or not executable, the script runs `cargo build --release --locked --bin miraserve` in the repository root and then still invokes the configured path. If the binary already exists and is executable, Cargo is not run.
- **Files created and removed:** Creates a temporary work directory at `${TMPDIR:-/tmp}/miraserve-bench.XXXXXX` containing `www/index.html`, `www/64k.txt`, `bench.kdl`, and `server.log`. An `EXIT` trap sends `SIGTERM` to the server process if it is still running, waits for it to exit, and removes the temporary work directory it created.
- **Server started:** Starts `miraserve run <work_dir>/bench.kdl --dev-tls --log-level warn` with stdout and stderr redirected to `server.log`. The generated configuration binds `127.0.0.1:18443` with `protocols="h3,h2,h1"`, TLS `min-version "1.3"`, `pqc-hybrid #true`, `key-isolation "in-process"`, `sandbox { landlock #true; seccomp "strict" }` (Linux only), and a `localhost` site with `security-headers "strict"` serving `<work_dir>/www`.
- **What it prints:**
  1. Host (`uname -srm`), `miraserve version`, and the binary path and size in bytes and MiB.
  2. Ten runs of `miraserve check --strict --dev-tls <work_dir>/bench.kdl`, each in a new process (filesystem caches may be warm), printed in milliseconds as `min`, `median` (the sixth of the ten sorted runs), and `max`.
  3. Readiness and idle RSS: polls `https://127.0.0.1:18443/` up to 100 times with `curl -sk --max-time 1`, sleeping `0.05` s after each failed attempt and succeeding when `curl` exits `0` (without requiring HTTP `200`; if all 100 attempts fail, it prints `server.log` and exits non-zero). It prints elapsed milliseconds from before launch to loop exit, followed by resident set size (`ps -o rss=`) in KiB and MiB.
  4. A load step against `https://127.0.0.1:18443/` using the first command found in `PATH`:
     - `oha`: `oha --insecure --http2 -z 5s -c 64 https://127.0.0.1:18443/`
     - `h2load`: `h2load -n 10000 -c 32 -m 16 https://127.0.0.1:18443/`
     - `wrk`: `wrk -t4 -c32 -d5s https://127.0.0.1:18443/`
     - Fallback when none of those is in `PATH`: one `curl -sk --tlsv1.3 --http2` invocation with 500 `https://127.0.0.1:18443/` URL arguments, counting exact `200 2` output lines (exiting non-zero if the count is not 500) and printing elapsed seconds and requests per second.
  5. After a successful load step, post-load resident set size (`ps -o rss=`) in KiB and MiB.

Because `scripts/bench.sh` runs client and server on loopback with `--dev-tls`, treat it as a local check only. Use separate Linux hosts for measurements you plan to compare or share.

## Measuring on Linux hosts

To compare MiraServe with another server, run the same workloads against both on the same hosts with the same kernel settings, process limits, and TLS policy.

### Test harness topology

- **Two dedicated Linux hosts** (client load generator and server under test) on a 10 GbE+ isolated VLAN so client and server do not compete for the same host scheduler.
- **Kernel sysctls (identical across tested servers):**
  - `net.core.somaxconn = 65535` (listen backlog cap)
  - `net.core.rmem_max = 7500000` and `net.core.wmem_max = 7500000` (socket buffer size caps)
- **Process file-descriptor limit (identical across tested servers):** `LimitNOFILE=1048576` in the `systemd` unit's `[Service]` section.
- **Comparable TLS policy:** TLS 1.3 with `X25519MLKEM768` (or `X25519` for a classical comparison) and identical ECDSA P-256 leaf certificates.

### Workloads

The workloads below are **examples to adapt** to your hostnames, paths, separately provisioned test fixtures (for example, a 1 KiB `index.html` and a 64 KiB `64k.txt` on the server), and client builds. All commands assume the client host trusts the server's test CA (pass `--insecure` to `oha` only if using an untrusted certificate) and target `<host>`.

| Workload | Example command and setup | What to record |
| :--- | :--- | :--- |
| **1. Static small asset (1 KiB HTML, HTTP/2 over TLS 1.3)** | `oha --http2 -z 30s -c 32 -p 8 https://<host>/` (32 connections × 8 parallel HTTP/2 streams = 256 concurrent requests) | Request rate, latency percentiles (p50/p95/p99), and error count. |
| **2. Static compressed asset (64 KiB text, `Accept-Encoding: br` or `gzip`)** | `h2load -n 200000 -c 64 -m 32 -H 'Accept-Encoding: br' https://<host>/64k.txt` (repeat with `gzip` if testing both). Run separate fixtures **with** and **without** a precompressed `.br`/`.gz` sibling (an eligible sibling takes precedence); repeated requests may be served from cache. Check the `Content-Encoding` response header. | Request rate, transfer rate, latency (use `--log-file` if your `h2load` build omits percentiles), error count, sibling and cache state, and server CPU from a server-side observer. |
| **3. HTTP/3 over QUIC (UDP 443)** | `h2load --alpn-list=h3 -n 100000 -c 64 -m 16 https://<host>/` (requires an `h2load` build compiled with `ngtcp2` and `nghttp3`; optionally inject packet loss with `tc netem`) | Request rate, latency (use `--log-file` if your `h2load` build omits percentiles), and connection or error counts. |
| **4. Post-quantum TLS 1.3 new connections (`pqc-hybrid #true` vs. `#false`)** | `oha --disable-keepalive -z 20s -c 64 https://<host>/` against `pqc-hybrid #true` and `pqc-hybrid #false`. `oha` has no CLI flag to choose TLS key-exchange groups; verify the negotiated group on **both** runs, because `pqc-hybrid #false` permits `X25519`, `P-256`, and `P-384`. | Request rate, whole-request latency percentiles on new connections (not handshake-only time), error count, negotiated group, and server CPU from a server-side observer. |
| **5. Split-privilege `miraserve-keyd` new connections** | Same `oha` command as Row 4, comparing `key-isolation "split-daemon"` (requires a running `miraserve-keyd` daemon and `keyd-socket` in `miraserve.kdl`; see [`docs/DEPLOYMENT.md`](DEPLOYMENT.md)) against `key-isolation "in-process"`. Verify connections perform full certificate handshakes rather than session resumptions. | Request rate, whole-request latency percentiles on new connections (not handshake-only time), and error count. |
| **6. Reverse proxy and SSE streaming** | Upstream mock emitter sending 100 Server-Sent Events per second across 500 concurrent client streams through a `reverse-proxy` route (no fixed CLI tool) | Time to first event, per-event delivery latency, error count, and server RSS and open file descriptors (from a server-side observer). |
| **7. WordPress / PHP-FPM FastCGI** | `oha --http2 -z 30s -c 64 https://<host>/<php-path>` targeting a URL that dispatches to PHP via `fastcgi-pass` over a local `php8.3-fpm` Unix socket (for example with `preset "wordpress-hardened"`) | Request rate, latency percentiles, error count, and PHP-FPM worker usage (from a server-side observer). |
| **8. Hot reload under load** | Run `oha --http2 -z 60s -c 64 https://<host>/` while running `systemctl reload miraserve` 10 times | Latency percentiles, connection errors, and non-2xx response counts during reloads. |

Notes on tool options:

- In `oha`, `--http2` (shorthand for `--http-version=2`), `-z <duration>`, `-c <connections>`, `-p <streams>` (parallel requests per HTTP/2 connection; default `1`), `--disable-keepalive`, and `--insecure` are documented CLI options. `--disable-keepalive` applies to HTTP/1.1 runs (not `--http2`), and `oha` reports whole-request latency rather than handshake-only time.
- In `h2load`, `-n`, `-c`, `-m`, `-H`, `--alpn-list` (`--h3` is shorthand for `--alpn-list=h3`), and `--log-file` (for per-request durations when a build's summary omits percentiles) are documented CLI options. HTTP/3 requires an `h2load` binary built with `ngtcp2` and `nghttp3`, which many distribution packages omit.

## Reporting results

If you publish numbers, include enough detail for someone else to reproduce the run:

- The exact commit hash (or release tag) and the output of `miraserve version`.
- The full `miraserve.kdl` configuration (including `workers`, `file-cache`, TLS, and Linux Landlock/seccomp sandbox directives) and any CLI flags passed to `miraserve run`.
- The Linux kernel version (`uname -a`) and relevant `sysctl` values on both hosts.
- The `systemd` unit or container settings — in particular whether `RestrictSUIDSGID` is effectively enabled (an omitted setting can inherit `yes`; when enabled, systemd's filter can refuse `openat2`, forcing a fallback and preventing `file-cache` admission; see [`docs/DEPLOYMENT.md`](DEPLOYMENT.md)).
- The exact load-generator commands, tool versions, and whether results come from a single run or multiple runs.
