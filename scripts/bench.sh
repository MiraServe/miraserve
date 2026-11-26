#!/usr/bin/env bash
# Reproducible MiraServe benchmark & baseline measurement harness.
# Measures:
#   1. Stripped release binary size
#   2. Cold CLI config validation latency (`miraserve check --strict`)
#   3. Live server startup time & idle RSS (dual-stack TLS 1.3 + X25519MLKEM768 PQC)
#   4. Live HTTPS throughput & latency (uses `oha`, `h2load`, or `wrk` if installed,
#      otherwise runs a bounded `curl` HTTP/2 keep-alive micro-baseline)
#
# Usage:
#   ./scripts/bench.sh
#   MIRASERVE_BIN=./target/release/miraserve ./scripts/bench.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${MIRASERVE_BIN:-${ROOT_DIR}/target/release/miraserve}"

if [[ ! -x "${BIN}" ]]; then
    echo "Building release binary (cargo build --release --locked --bin miraserve)..."
    (cd "${ROOT_DIR}" && cargo build --release --locked --bin miraserve)
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/miraserve-bench.XXXXXX")"
SERVER_PID=""
cleanup() {
    if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill -TERM "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

mkdir -p "${WORK_DIR}/www"
printf '<!doctype html><html><body><h1>MiraServe Benchmark</h1></body></html>\n' > "${WORK_DIR}/www/index.html"
# 64 KiB compressible payload for gzip/brotli & transfer baseline
python3 -c "print('miraserve-pqc-benchmark-line-' * 2200)" > "${WORK_DIR}/www/64k.txt"

PORT=18443
cat > "${WORK_DIR}/bench.kdl" <<EOF
server {
    listen "127.0.0.1:${PORT}" protocols="h3,h2,h1"

    tls {
        min-version "1.3"
        pqc-hybrid #true
        key-isolation "in-process"
    }

    sandbox {
        landlock #true
        seccomp "strict"
    }
}

site "localhost" {
    security-headers "strict"
    root "${WORK_DIR}/www"
}
EOF

echo "=== MiraServe Benchmark Baseline ==="
echo "Host:     $(uname -srm)"
echo "Version:  $("${BIN}" version | tr '\n' ' ')"
if stat -f %z "${BIN}" >/dev/null 2>&1; then
    BYTES="$(stat -f %z "${BIN}")"
else
    BYTES="$(stat -c %s "${BIN}")"
fi
MB="$(python3 -c "print(f'{${BYTES} / (1024 * 1024):.2f}')")"
echo "Binary:   ${BIN} (${BYTES} bytes / ${MB} MiB)"

echo ""
echo "--- 1. Cold KDL Config Validation (10 runs of miraserve check --strict --dev-tls) ---"
python3 - "${BIN}" "${WORK_DIR}/bench.kdl" <<'PY'
import subprocess, sys, time
bin_path, cfg_path = sys.argv[1], sys.argv[2]
times = []
for _ in range(10):
    t0 = time.perf_counter()
    res = subprocess.run([bin_path, "check", "--strict", "--dev-tls", cfg_path], capture_output=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr.decode())
        sys.exit(1)
    times.append((time.perf_counter() - t0) * 1000.0)
times.sort()
print(f"min={times[0]:.2f}ms  median={times[len(times)//2]:.2f}ms  max={times[-1]:.2f}ms")
PY

echo ""
echo "--- 2. Server Startup, Idle RSS & Live TLS 1.3 Loopback Check ---"
START_MS="$(python3 -c 'import time; print(int(time.perf_counter()*1000))')"
"${BIN}" run "${WORK_DIR}/bench.kdl" --dev-tls --log-level warn > "${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!

READY=0
for _ in $(seq 1 100); do
    if curl -sk --max-time 1 "https://127.0.0.1:${PORT}/" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.05
done
END_MS="$(python3 -c 'import time; print(int(time.perf_counter()*1000))')"

if [[ "${READY}" -ne 1 ]]; then
    echo "ERROR: MiraServe did not become ready on 127.0.0.1:${PORT}" >&2
    cat "${WORK_DIR}/server.log" >&2
    exit 1
fi

RSS_KB="$(ps -o rss= -p "${SERVER_PID}" | tr -d ' ')"
RSS_MB="$(python3 -c "print(f'{${RSS_KB} / 1024.0:.2f}')")"
echo "Time to first TLS 1.3 response: ~$((END_MS - START_MS)) ms"
echo "Idle RSS after dev-TLS startup: ${RSS_KB} KiB (${RSS_MB} MiB)"

echo ""
echo "--- 3. HTTPS Static Serving Baseline ---"
if command -v oha >/dev/null 2>&1; then
    echo "Running oha (HTTP/2 + TLS 1.3, 5s, 64 concurrent clients)..."
    oha --insecure --http2 -z 5s -c 64 "https://127.0.0.1:${PORT}/"
elif command -v h2load >/dev/null 2>&1; then
    echo "Running h2load (HTTP/2 + TLS 1.3, 10000 reqs, 32 clients, 16 streams)..."
    h2load -n 10000 -c 32 -m 16 "https://127.0.0.1:${PORT}/"
elif command -v wrk >/dev/null 2>&1; then
    echo "Running wrk (HTTP/1.1 + TLS 1.3, 5s, 4 threads, 32 connections)..."
    wrk -t4 -c32 -d5s "https://127.0.0.1:${PORT}/"
else
    echo "oha/h2load/wrk not installed; running 500 sequential keep-alive HTTPS requests via curl (smoke baseline)..."
    python3 - "${PORT}" <<'PY'
import subprocess, sys, time
port = sys.argv[1]
urls = [f"https://127.0.0.1:{port}/"] * 500
t0 = time.perf_counter()
res = subprocess.run(
    ["curl", "-sk", "--tlsv1.3", "--http2", "-o", "/dev/null", "-w", "%{http_code} %{http_version}\n"] + urls,
    capture_output=True, text=True
)
dt = time.perf_counter() - t0
lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]
ok = sum(1 for l in lines if l == "200 2")
if ok != len(urls):
    sys.stderr.write(f"ERROR: expected {len(urls)} HTTP/2 TLS 1.3 200 responses, got {ok} (sample: {lines[:3]})\n")
    sys.exit(1)
print(f"Smoke baseline: {ok}/{len(urls)} verified HTTP/2 TLS 1.3 requests in {dt:.3f}s ({ok/dt:.1f} req/s single-connection curl)")
PY
fi

RSS_AFTER_KB="$(ps -o rss= -p "${SERVER_PID}" | tr -d ' ')"
RSS_AFTER_MB="$(python3 -c "print(f'{${RSS_AFTER_KB} / 1024.0:.2f}')")"
echo "Post-load RSS: ${RSS_AFTER_KB} KiB (${RSS_AFTER_MB} MiB)"
