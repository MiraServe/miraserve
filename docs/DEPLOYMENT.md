# MiraServe Production Deployment Guide

This guide covers hardened production deployments across Linux (`systemd` + `.deb`/`.rpm`), rootless distroless OCI containers, macOS (`launchd` + Homebrew), and development/non-production Windows setups (boot-time Scheduled Task under `NT AUTHORITY\LOCAL SERVICE`).

---

## 1. Security Defaults Checklist

Before deploying to production, verify that your deployment preserves MiraServe's hardened defaults:

- **TLS 1.3 only + Post-Quantum Hybrid KEX (`X25519MLKEM768`)** by default. Only enable `compat-tls-1-2 #true` on legacy sites that explicitly require TLS 1.2.
- **Dual-Stack IPv4 + IPv6 by default:** Bare `":443"` and `":80"` listeners automatically bind both `0.0.0.0:<port>` and `[::]:<port>` (`IPV6_V6ONLY = true`) on TCP and QUIC UDP, with graceful fallback to IPv4-only if the host kernel has IPv6 disabled.
- **Never run as `root`:** Bind `:80`/`:443` via Linux `AmbientCapabilities=CAP_NET_BIND_SERVICE` under a dedicated unprivileged `miraserve` service account.
- **Always pre-validate configs and on-disk files as the worker user:** Run `sudo -u miraserve miraserve check --fs --strict --acme-dir /var/lib/miraserve/acme /etc/miraserve/conf/miraserve.kdl` in CI and before `systemctl reload miraserve`.
- **Connection Caps, Trusted Proxies & Timeouts:** By default MiraServe enforces `max-connections 16384` globally, `max-connections-per-ip 128` per IPv4 / IPv6 `/64` (with an automatic `4x` IPv6 `/48` aggregate cap), `max-body-duration "1h"`, and global upstream timeouts (`upstream-connect-timeout "10s"`, `upstream-response-timeout "60s"`, `upstream-body-idle-timeout "60s"`). When deployed behind a CDN or load balancer, configure `server { limits { trusted-proxies "127.0.0.1/32" "10.0.1.10/32" } }` with your exact front proxy IPs (or narrow CIDRs `>= /24` IPv4 / `>= /64` IPv6) so trusted proxies are exempt from per-IP connection caps and rate limiting derives the client IP via right-to-left `X-Forwarded-For` peeling. For long-lived SSE routes, override `upstream-body-idle-timeout` directly inside the route's `reverse-proxy { ... }` block (up to `24h`), and for shared NAT API-key rate limits tune `ip-ceiling-multiplier` (default `10`) and `max-keys-per-ip` (default `64`) on `rate-limit`.
- **Upstream Connection Sizing with `server { workers ... }` (Linux):** When `workers <N>` or `workers "auto"` is enabled (with in-process TLS), each `reverse-proxy` route keeps one upstream connection pool per worker loop (`0..N`) plus the shared pool (used by active health checks, HTTP/3, and plain-HTTP `http "serve"` listeners) so proxied connections stay on their worker loop's core. Because `hyper-util`'s per-host idle limit (`pool_max_idle_per_host`) is unbounded (`usize::MAX`) per pool today and the configured `60 s` (normal pool) / `30 s` (upgrade/`preserve-host` pool) idle ages are **checkout-only** (`pool_timer` is unset, so idle sockets are checked only when reached on checkout rather than reaped in the background), idle HTTP/1.1 keep-alive connections to a single upstream can reach up to **`N` times** the single-pool count (plus the shared pool if used) and linger past 60 s / 30 s while quiet. For upstream HTTP/2, **1** multiplexed connection per active request pool describes **steady-state reuse** (up to **`N`** per upstream across workers, plus 1 if shared-runtime traffic or probes also use it, while concurrent TCP/TLS handshakes can precede ALPN selection). Multiply your upstream server's connection limits (`worker_connections`, `max_connections`, file-descriptor limits) by the configured worker count `N` when enabling `workers` in front of a backend.
- **Verifying Release Artifacts:** Every tagged release generates one canonical source archive (`miraserve-<tag>-src.tar.gz`, carrying `vendor/`) from the tag, verifies `vendor/h2` provenance, per-target Cargo graph, and RustSec advisories on the extracted archive *before* compiling anything, builds every platform binary, `.deb`/`.rpm`, and OCI image from that same verified archive, and publishes that exact archive (never a regenerated copy) alongside binary archives, a stamped Homebrew formula (`miraserve.rb`), `SHA256SUMS.txt`, a Sigstore Cosign keyless bundle (`SHA256SUMS.txt.sigstore.json`), a CycloneDX SBOM (`miraserve-sbom.cdx.json`), and SLSA Build Level 2 GitHub build provenance attestations. When building from a source checkout or source archive (`Cargo.toml`, `Cargo.lock`, `crates/`, and `vendor/` are all required), run `./scripts/verify-vendor-h2.sh` and `./scripts/verify-h2-graph.sh` before `cargo +1.95.0 build --release --locked --bin miraserve` to authenticate the vendored `h2` patch.

### 1.1 Release Checklist (Tag & Formula Verification)

Before tagging or publishing a release, confirm every gate passes on the extracted source archive:

1. **Tag ancestry & ownership:** The tag commit is reachable from `origin/main`, and any changes under `vendor/`, `Cargo.toml`, `Cargo.lock`, `deny.toml`, `scripts/*h2*.sh`, `packaging/homebrew/miraserve.rb`, `.github/workflows/{ci,release}.yml`, or `.github/CODEOWNERS` have been reviewed by the owner designated in `.github/CODEOWNERS` (note: `.github/CODEOWNERS` declares ownership rules and covers itself, while merge-blocking enforcement requires enabling required Code Owners review in the GitHub repository's branch-protection or ruleset settings, which the Git checkout alone cannot prove).
2. **Pre-compile archive freeze & provenance/graph/tamper gates:** `.github/workflows/release.yml` creates and uploads `miraserve-<tag>-src.tar.gz` and records its SHA-256 as a job output *before* compiling any project code, then runs `./scripts/verify-vendor-h2.sh`, `./scripts/verify-h2-graph.sh` (all five release targets), `./scripts/audit-vendor-h2.sh` (actual RustSec advisory-db revision + crates.io sparse index check), and `./scripts/test-verify-vendor-h2.sh` on the extracted archive; every downstream job (and a post-build re-check in `verify`) verifies the archive against that frozen job-output digest rather than trusting a digest file that travelled with it.
3. **Exact panel build from extracted archive root:** `cargo +1.95.0 build --release --locked --bin miraserve` succeeds from the extracted `miraserve-<tag>-src.tar.gz` root.
4. **Homebrew formula check (fail closed):** Refuse any Homebrew formula whose `homepage`, `url`, `head`, or `sha256` does not match the publishing repository (`github.repository`) and tag being released (never leave `packaging/homebrew/miraserve.rb` pointing at pre-fork `v0.1.3` or a different repository now that it installs `vendor/h2/LICENSE` as `LICENSE-h2-MIT`). `.github/workflows/release.yml` enforces this check in `verify`, stamps the exact `github.repository` into `homepage`, `url`, and `head` alongside the tag and frozen source-archive SHA-256 into the published `miraserve.rb` release asset, and refuses the release if any placeholder remains or any field disagrees with the publishing repository or frozen digest. Update any external Homebrew tap from that published `miraserve.rb`.

```bash
# Verify checksums via Cosign keyless (Sigstore)
cosign verify-blob \
  --bundle SHA256SUMS.txt.sigstore.json \
  --certificate-identity-regexp "^https://github\.com/miraserve/miraserve/\.github/workflows/release\.yml@" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS.txt

sha256sum -c SHA256SUMS.txt --ignore-missing

# Or verify SLSA Build Level 2 provenance via GitHub CLI
gh attestation verify miraserve-v0.1.1-x86_64-unknown-linux-gnu.tar.gz --repo miraserve/miraserve
```

---

## 2. Hardened Linux Deployment (`systemd`)

### 2.1 Package Installation (`.deb` / `.rpm`)

```bash
# Debian / Ubuntu
sudo apt install ./miraserve_*_amd64.deb

# RHEL / Fedora / AlmaLinux / Rocky Linux
sudo dnf install ./miraserve-*.x86_64.rpm
```

The packages automatically create the unprivileged `miraserve` and `miraserve-keyd` accounts (`sysusers.d`), restricted state/runtime/key directories (`tmpfiles.d`: `/run/miraserve`, `/run/miraserve-keyd` `2750 miraserve-keyd:miraserve`, `/var/lib/miraserve/acme` `0700`, `/var/lib/miraserve/releases`, `/etc/miraserve/conf`, `/etc/miraserve/certs`, `/etc/miraserve/keys` `0700 miraserve-keyd:miraserve-keyd`), install the starter KDL config at `/etc/miraserve/conf/miraserve.kdl` (migrating any legacy `/etc/miraserve/miraserve.kdl`), generate a unique per-host self-signed localhost starter certificate under `/etc/miraserve/certs/starter.{crt,key}` so `systemctl start miraserve` works immediately, and install hardened systemd unit files under `/usr/lib/systemd/system/`.

### 2.2 Generating Custom Hardened Units (`miraserve service`)

You can regenerate customized unit files at any time:

```bash
# Unprivileged HTTP/QUIC worker (with Wasmtime JIT support)
sudo miraserve service generate --target systemd \
  --binary /usr/bin/miraserve \
  --config /etc/miraserve/conf/miraserve.kdl \
  --acme-dir /var/lib/miraserve/acme \
  --output /etc/systemd/system/miraserve.service --force

# If WASM plugins are NOT used, pass --no-wasm to enforce MemoryDenyWriteExecute=yes:
sudo miraserve service generate --target systemd --no-wasm \
  --output /etc/systemd/system/miraserve.service --force

# Opt-in: omit systemd's RestrictSUIDSGID=yes so Linux openat2(2) works (enables single-call
# whole-path lookups, opt-in `file-cache` admission, and inline `workers` lookups). MiraServe's
# in-process seccomp-bpf set-ID policy (including io_uring denial) remains active under seccomp
# "strict"/"standard" (confirm the worker ExecStart does not pass `--no-sandbox`). On systemd
# 258+ hosts with DefaultRestrictSUIDSGID=yes in systemd-system.conf, add a drop-in with
# RestrictSUIDSGID=no; note that `miraserve check` from a shell observes the shell's seccomp
# policy (and cannot see `ExecStart ... --no-sandbox`) while ExecStartPre observes the unit's.
# See docs/SPEC.md §4 for the documented `openat2` residual (named O_CREAT and unnamed O_TMPFILE
# / socket-tree scope): a root-controlled non-searchable ancestor limits pathname traversal only,
# while `nosuid` on every mount used for execution is the credential guarantee:
sudo miraserve service generate --target systemd --allow-openat2 \
  --output /etc/systemd/system/miraserve.service --force

# Inspect writable paths before enabling --allow-openat2 (pass the EXACT same grant-affecting
# flags, working directory, user, and LimitNOFILE as the service's ExecStart: --acme-dir,
# --log-file, --access-log, --log-max-bytes, --keyd-auth-secret-file, --no-sandbox;
# `miraserve version` advertises `writable-set`):
miraserve check --writable-set --acme-dir /var/lib/miraserve/acme /etc/miraserve/conf/miraserve.kdl
miraserve service generate --target systemd --allow-openat2 --print-writable-set
```

**Writable-set output format (`0.1.x` stable, available on every platform):**

- Run `check --writable-set` with the unit's exact `ExecStart` flags, as the service user: without the log flags the log directory is missing from the list; run as root it exits non-zero on the ACME directory's ownership check; with a very low descriptor limit (48 or lower on a small Solo box) it exits non-zero with empty stdout.
- One record per line; fields are separated by a single ASCII space; the path is everything after the second space (paths may contain spaces in Landlock records). Write/flush errors on the report's stdout exit non-zero.
- **`miraserve check --writable-set <config>` is a policy report, not a mount attestation.** It runs an inspection startup classification and policy preparation pass mirroring `miraserve run`'s quarantine, policy, and CLI log-binding steps (run it with the exact same `--acme-dir`, `--log-file`, `--access-log`, `--log-max-bytes`, `--keyd-auth-secret-file`, and `--no-sandbox` flags, working directory, user, and `LimitNOFILE` as `ExecStart`; relative log destinations resolve against the process working directory) and reports every directory `run` would ask Landlock to make writable — **nothing about host mounts**.
  - **State line (first line):** `landlock enforced abi=<n>`, `landlock partial abi=<n>` (note: on ABI 1 / Linux 5.13–5.18, cross-directory rename/link is **denied** — ABI 2 added `REFER` to allow it — and on ABI 1–2 / Linux 5.13–6.1, file truncation via `truncate`/`ftruncate`/`O_TRUNC` is **not** restricted by Landlock; ABI 3–4 enforce truncation and omit only ABI 5 device `ioctl`), `landlock disabled` (Linux only, no ABI probe), or `landlock unavailable` (always on non-Linux regardless of config). The state line is a **capability prediction**: an outer policy can still deny `landlock_restrict_self(2)` at startup (in which case `run` fails closed), and the state line says nothing about seccomp.
  - **Superset rule:** when enforcing, `check --writable-set` may list a candidate path that `run` ultimately does not grant (for example, a quarantined tenant site's publish store or FastCGI socket, or an absent directory that `run` cannot create), and **never** omits a directory that `run` can grant, including directories startup itself creates (such as an initially absent `socket-tree` whose parent is created for a non-rotating log):
    - `writable landlock <path>` for existing pinned directories/sockets: on Linux, `<path>` is derived from the pinned descriptor (`/proc/self/fd`) and verified by `(st_dev, st_ino)` against the current pathname. If `/proc/self/fd` is unavailable or the pinned descriptor's name lookup cannot be resolved, the command fails (non-zero exit, empty stdout) — an unresolvable name lookup is an inspection failure, not a `writable-missing` record. This is a **point-in-time snapshot**: a rename or replacement after the command exits is outside the contract.
    - `writable-missing landlock <path>` strictly for absent or unopenable candidate writable grants (`ENOENT`, `EACCES`, `ELOOP`, `ENOTDIR`) and candidate writable paths of sites quarantined during classification (printed as their absolute lexical paths; no candidate is ever dropped silently or filtered by the inspecting account's permissions).
  - **ACME directory validation, resource failures, and hard errors:** `check --writable-set` validates the effective `--acme-dir` unconditionally (refusing forbidden directories such as `/etc` with the inspection's own diagnostic, and refusing symlinked leaves/ancestors, unsafe group/world-writable ancestors, and wrong ownership via read-only private-directory checks; these ancestor and ownership checks are Unix-only). Documented hard rejections — unsafe non-tenant docroot, rotating-log overlap (when the overlapped document root belongs to an `owner-dir` tenant, that tenant can be quarantined instead and the inspection completes), forbidden `--acme-dir`, forbidden `read-tree`/`socket-tree`, a forbidden `ai-publish.storage` target (including a symlink to a forbidden directory) on a site that is **not** quarantined (a quarantined site's forbidden store target gets no grant and may produce no diagnostic), pin identity mismatch, unavailable `/proc/self/fd` name lookup, non-UTF-8 paths, or control characters in path-valued CLI options or writable-candidate config paths — exit non-zero with empty stdout. The report never omits a candidate writable path because of a resource failure it detects; a detected resource failure (`EMFILE`/`ENFILE`/`ENOMEM`) while building the reported policy fails the inspection (non-zero exit, empty stdout). Inspection may also fail under a low descriptor limit where `run` would succeed, so run the inspection with the service's `LimitNOFILE`. Every line written by the two report command handlers to stderr and stdout escapes all C0, DEL, and C1 control characters (argument-parser errors for malformed flag values are printed directly by the CLI argument parser).
- **`miraserve service generate --target systemd` (and `--target systemd-keyd`) `--print-writable-set` reports the rendered unit's directives only — no host filesystem scanning (and takes the report branch before reading `--config`, so a FIFO `--config` does not block it).** Plain `miraserve service generate` (without `--print-writable-set`, across every target) is unaffected: it runs the same validation and rendering as before the report mode existed (every input 0.1.4 accepted is accepted and rendered as in 0.1.4). When `--print-writable-set` is given, the report refuses path spellings it cannot represent exactly, including some systemd would normalise, such as a trailing slash, duplicate slashes, or `.` segments, and also `..` segments, which systemd refuses as well (non-zero exit, empty stdout; plain generation is unaffected): `--binary`, `--config`, `--auth-secret-file`, and the full `--keyd-socket` endpoint in `ExecStart` accept quoted spaces; `--acme-dir` on `systemd` is quoted in every directive (`ExecStart*` and `ReadWritePaths=-"..."`) so spaced normalized absolute paths (such as `"/var/lib/custom acme/state"`) are accepted while relative paths, `/`, trailing/`//` slashes, and `.`/`..` segments are refused; strict unquoted path validation (additionally refusing whitespace including non-ASCII whitespace, quotes, backslashes, and globs `*`, `?`, `[`, `]`) applies only to the **parent directory** of Unix `--keyd-socket` on `systemd-keyd` (so a space confined to the socket filename under a clean parent such as `"/run/miraserve-keyd/signer A.sock"` is accepted, and `/`, `/run`, or `/var/run` parents are refused — passing this check does not prove the parent directory is dedicated, so the operator must ensure the `--keyd-socket` parent directory is dedicated to `miraserve-keyd` because `tmpfiles.d` sets `2750` and the ownership of the keyd service account (`--user`, default `miraserve-keyd`) on it); loopback `tcp://...` endpoints are validated with `KeydEndpoint::parse` without whitespace, quotes, or backslashes. With `--print-writable-set`, it prints `writable unit <path>` for every rendered unit writable directive and `writable unit-private-tmp /tmp` and `writable unit-private-tmp /var/tmp` when `PrivateTmp=yes` (note: systemd normally bind-mounts service-private directories for `PrivateTmp=yes`, not a guaranteed tmpfs, and its backing differs from host `/tmp` and `/var/tmp`). An unused `--log-dir` on `--target systemd` is omitted, and the default main worker unit does not list `/run/php` (passing `--acme-dir /run/php` explicitly adds `/run/php` to `ReadWritePaths=`).
- **What remains the installer's job (not attested by MiraServe):**
  - Check mount options (such as `nosuid`) for every reported path **inside the service's own mount namespace** (not the installer's shell namespace), **at and below** each path, and through **every bind alias** of that filesystem, including child filesystems with a **different** `MAJ:MIN` device number mounted under an alias.
  - Treat every `writable-missing` record as **unverified**: either fail closed, or provision the missing target first (create a missing directory, or let its producer — such as PHP-FPM or `miraserve-keyd` — provision an exact socket path) and re-run `check --writable-set`.
  - When operating **without Landlock**, include `/dev/shm` in the writable inventory (`PrivateDevices=yes` leaves `/dev/shm` writable inside the service namespace) alongside `PrivateTmp` (`/tmp`, `/var/tmp`) and `ReadWritePaths`.
  - When decoding mount paths, remember that `findmnt -r` uses **hexadecimal** `\xHH` escapes (e.g. `\x20` for space), whereas Linux kernel `/proc/self/mountinfo` uses **octal** `\NNN` escapes (e.g. `\040` for space); decode escaped output before comparing against literal paths. No single host-side `findmnt` invocation is a complete attestation for the service's mount namespace.

**Opt-in static file cache (`file-cache "<window>"`) notes:**

- `file-cache` **stores nothing unless the unit allows `openat2` (`--allow-openat2`)** — i.e., it stores nothing under `RestrictSUIDSGID=yes` (nor on macOS/Windows or on symlinked paths).
- Documented rename-window limit: during a concurrent directory rename inside a document root, a lookup can select a file that never had the requested pathname (including under a dotfile-denied ancestor) and serve it under the requested URL for up to the configured cache window. Common real-world operations that rename folders inside a docroot include **WordPress plugin and theme updates** (WordPress 6.3 and later move the old folder to `wp-content/upgrade-temp-backup/` and move the new folder into place) and **security clean-ups that move a plugin or theme folder away**. Sites deployed as immutable release trees replaced atomically outside the served directory are not exposed to in-place docroot renames.

```bash
# Optional: Split-privilege TLS signing vault (Threat Model T2; runs under distinct UID/GID `miraserve-keyd`)
sudo miraserve service generate --target systemd-keyd \
  --config /etc/miraserve/conf/miraserve.kdl \
  --keyd-socket /run/miraserve-keyd/keyd.sock \
  --output /etc/systemd/system/miraserve-keyd.service --force

sudo systemctl daemon-reload
```

### 2.3 Split-Privilege `miraserve-keyd` Mode (Threat Model T2)

In split-daemon mode, TLS private keys stay inside `miraserve-keyd` (distinct OS UID & primary GID `miraserve-keyd`, zero capabilities, `PrivateNetwork=yes`, `MemoryDenyWriteExecute=yes`) and never enter the HTTP/QUIC worker's address space. The socket directory `/run/miraserve-keyd` is `2750` (setgid `miraserve`), while `keyd` runs with `--allow-peer-user miraserve` so kernel `SO_PEERCRED` authorizes ONLY the exact `miraserve` worker UID (not the entire `miraserve` group). Three independent barriers isolate `/etc/miraserve/keys` from the worker:

- **OS DAC:** `/etc/miraserve/keys` is `0700 miraserve-keyd:miraserve-keyd` (worker runs as UID `miraserve`).
- **systemd mount namespace:** The shipped `miraserve.service` unit unconditionally sets `InaccessiblePaths=-/etc/miraserve/keys` (starter/in-process certs live under `/etc/miraserve/certs/` instead).
- **Linux Landlock LSM:** MiraServe stores its default config under `/etc/miraserve/conf/miraserve.kdl` (not an ancestor of `/etc/miraserve/keys`) so atomic-rename `SIGHUP` reloads work cleanly under Landlock. In `split-daemon` mode, MiraServe refuses to widen any parent directory rule that is an ancestor of `/etc/miraserve/keys` or any configured `tls.key`, and logs a startup advisory whenever a reloadable file falls back to an exact-file rule. (When pairing Certbot with `split-daemon` mode, use a Certbot `--deploy-hook` to copy `fullchain.pem` into `/etc/miraserve/certs/` and `privkey.pem` into `/etc/miraserve/keys/` with `0600 miraserve-keyd:miraserve-keyd`, rather than pointing both `cert` and `key` at the same `/etc/letsencrypt/live/<site>/` directory.)

> **Upgrade note for pre-0.1.0 split-daemon installs:** The package `postinstall` script automatically migrates `/etc/miraserve/miraserve.kdl` → `/etc/miraserve/conf/miraserve.kdl` and re-owns `/etc/miraserve/keys` to `miraserve-keyd:miraserve-keyd` (`0700` dir, `0600` files). If your config still references the legacy `/run/miraserve/keyd.sock` path, update `keyd-socket` to `/run/miraserve-keyd/keyd.sock` and restart both `miraserve-keyd` and `miraserve`.

1. Place private keys in `/etc/miraserve/keys/` (`chown miraserve-keyd:miraserve-keyd` and `chmod 0600`) and public certificate chains in `/etc/miraserve/certs/`.
2. Configure `key-isolation "split-daemon"` and `keyd-socket "/run/miraserve-keyd/keyd.sock"` in `server { tls { ... } }`.
3. Regenerate the worker unit with `--split-keyd` (for `Wants=miraserve-keyd.service`) and enable both units:

```bash
sudo miraserve service generate --target systemd --split-keyd \
  --output /etc/systemd/system/miraserve.service --force
sudo systemctl daemon-reload
sudo -u miraserve miraserve check --fs --strict --acme-dir /var/lib/miraserve/acme /etc/miraserve/conf/miraserve.kdl
sudo systemctl enable --now miraserve-keyd.service miraserve.service
```

> **Optional Loopback TCP Mode:** On platforms without Unix socket `SO_PEERCRED` or across containers, bind `keyd` on loopback TCP (`--keyd-socket tcp://127.0.0.1:9444 --user miraserve-keyd`) and pass a shared 32-byte HMAC-SHA256 secret file via `--auth-secret-file` (to `miraserve keyd`) and `--keyd-auth-secret-file` (to `miraserve run` and `miraserve check --fs`). Two different users read this file (`miraserve-keyd` and `miraserve`), so a `0600` file cannot work: create it as `0640 root:miraserve` (the generated keyd unit carries `SupplementaryGroups=miraserve` in this mode too), keep it outside every document root, and never make it world-readable.

### 2.3a Hosting-Panel Layout (many sites under `/home`, added without restart)

Two defaults fit a single-site server and need changing when a panel manages many accounts:

- **`/home` is hidden.** The generated unit sets `ProtectHome=yes`. `miraserve service generate --target systemd` now emits `ProtectHome=read-only` when the config on disk has a site root or sandbox `read-tree` under `/home`, or when `--home-docroots` is passed. The `miraserve` user still needs ordinary Unix access (group or ACL) to each account's home.
- **Landlock rules are fixed at startup.** A site added by a reload whose document root, PHP socket or certificate is outside the startup policy cannot be served until a restart. An uncovered path needed only by a tenant (`owner-dir`) site quarantines that tenant site (it answers `503` while the rest of the reload succeeds); an uncovered server-wide or non-tenant path refuses the reload (`restart required: path(s) outside the startup Landlock policy: ...`) and the previous configuration keeps serving. List the parent directories once:

```kdl
server {
    sandbox {
        landlock #true
        seccomp "strict"
        read-tree "/home" "/opt/panel/ssl/certs"   // document roots and certificate files
        socket-tree "/run/php"                      // per-account PHP-FPM sockets
    }
}
```

Sites, sockets and certificates created later under those trees work after a plain `miraserve reload`. A tree may not be `/`, and may not equal, contain or sit inside `/etc`, `/root`, `/proc`, `/sys`, `/dev`, `/boot`, `/var/lib/miraserve`, `/run/miraserve*`, `/run/secrets`, `/run/credentials`, `/var/backups`, `/var/mail` or `/var/spool` (`E202`); `check --fs` and startup also refuse a tree that is a symlink into one of them. The trees widen what Landlock permits, not what Unix permissions permit: the worker can open only what its user and groups can.

**Keep operator-configured grant paths and their ancestors out of tenant-writable directories.** The operator-configured paths that MiraServe grants (publish stores, FastCGI socket paths and `socket-tree` directories, the ACME directory, and log directories) and every ancestor directory of them must not be writable by tenant accounts. MiraServe resolves these names during start-up, and a tenant who can replace a component at that moment can redirect a grant.

**Opt-in trusted-path diagnostic (`miraserve check --fs --trusted-paths`, Linux only).** With `--fs --trusted-paths`, on Linux, `check` walks the directories on the way to five kinds of configured paths and stops at the first component it reports or does not find: `server.sandbox` `socket-tree` roots, exact `fastcgi-pass` Unix sockets, `server.tls.keyd-socket` (the path of the endpoint the server connects to), the ACME directory (`--acme-dir` or default `.miraserve-acme`), and rotating log parent directories (`--log-file` and `--access-log` when `--log-max-bytes > 0`). Other configured paths, including `ai-publish` storage, are not looked at yet. For each path it considers untrusted or cannot verify, it reports warning `W034`; the warning text gives the component (when a component is reported), its owner and mode (when known), and the reason. A warning means the check found something to fix on that path, or could not verify it; the reason in the warning says which, and the usual fixes are to correct the ownership, mode or type of the named component, or to move the path. No warning is not a guarantee. The check sees the filesystem as the checking process sees it. It assumes: the server runs with the same root directory and mount view as the check (the packaged unit gives the server a private `/tmp` and a restricted view of `/home`, so paths there are not covered); ordinary local filesystems without identity mapping, stacking, encryption that hides names, or another writable view of the same directories; nothing changes mounts during the check; no other process shares the service account. Run it as the service account (as the unit `ExecStartPre` does), or as root with `server.sandbox.user` set; when no service account is configured, the check trusts the account that runs it (only root when run as root), so run it as the service account. It is opt-in, reports only, and does not change what the server does. Without the flag, the processing of a configuration is the same as in 0.1.6, apart from the Linux `--fs` Landlock availability probe (`W035`). With the flag, the existing `--fs` probes still run as before (they are described where they are documented today). It can wait on an unresponsive network or userspace filesystem, like the other `--fs` probes. It writes nothing to the configured paths and does not read their contents; reading a symbolic link can update its access time; it reads a few system files to learn the uid mapping and symlink protection setting, and the account database when `server.sandbox.user` is a name.

**Exact Unix socket paths must be sockets (Linux only).** On Linux, a real Unix socket at an exact `fastcgi-pass "unix:..."` or `server.tls.keyd-socket` endpoint (and an explicitly configured `socket-tree` directory) is granted `ReadFile | WriteFile` quietly. When an installed exact socket endpoint is not a `socket-tree` directory and its descriptor is not a socket, three outcomes apply: (a) a non-socket whose path spelling is not itself an entry of another grant list (for example, a TLS certificate file such as `/etc/miraserve/certs/site.pem` in a dedicated certificate directory covered only by its parent directory's read-only grant `/etc/miraserve/certs`): no socket rule is installed and one `WARN` per path per process is logged naming the path and type found, while the site keeps running and FastCGI or `keyd` requests to that path fail while it is not a socket (an active split-daemon server still requires its `keyd` socket); (b) a directory whose exact path spelling is itself an entry of another grant list (site or route root, `read-tree`, publish storage, ACME directory, config or certificate parent, or rotating-log directory): the 0.1.5 `ReadFile | WriteFile` socket-class rule is kept and one `WARN` per path per process is logged advising you to give the socket its own path; (c) a non-directory whose exact path spelling is itself an entry of another grant list (for example, an individually granted file such as a TLS certificate file in `split-daemon` mode sharing a directory with its private key, where parent widening is refused and the file path itself enters the read-only grant list, also configured as `fastcgi-pass "unix:..."`): its socket rule is reduced to read access (`ReadFile` only) and one `WARN` per path per process is logged advising you to give the socket its own path. This behaviour is Linux-only; start-up quarantine, missing-socket notices, and `miraserve check` output are unchanged from 0.1.5. A path that was skipped at start-up because it is not a socket does not gain access by a later reload that gives the same path, or files under it, a new use (certificate, configuration, root). Fix the socket path and restart.

**Two start conditions packagers meet.** The ACME state directory (`--acme-dir`) must sit under parents that only root or the service user can write: a group- or world-writable parent without the sticky bit is refused (`private state path ... has unsafe ancestor component`), because whoever can write the parent can swap the directory. With log rotation enabled (`--log-max-bytes` above 0) the log directory gets a write grant, so it must not overlap the ACME state directory, a document root, or a directory holding keys, certificates or the config (`resolved log rotation directory ... overlaps ...`); give logs their own directory.

**Do not replace the configuration directory while the server runs.** The sandbox grant for it is bound to the directory that existed at startup. After `rm -rf /etc/miraserve` and a restore, every reload fails with `failed to read configuration file ...: Permission denied` until the service is restarted. Replace files inside the directory (write a new file and rename it over the old one) instead of the directory itself.

**Access log timing.** The access log (`--access-log <file>`) is written in batches: when 64 KiB of lines have collected, and every 100 ms. A line therefore reaches the file up to 100 ms after its request finished. A normal stop writes everything out; lines from the last 100 ms can be lost if the process is killed outright (`SIGKILL`, power loss). If the file cannot be written (a full disk, a quota), up to 1 MiB of lines is kept and retried in the background (100 ms, doubling to every 5 s; requests are never slowed by the retries), older whole lines beyond that are dropped, and the failure and later the recovery with the number of dropped lines are reported on stderr (at most once a minute). A line interrupted by a failed write is completed in the same file before anything else. If lines are still unwritten when the server stops, it says how many bytes and lines are lost and exits with a failure status. With rotation, a batch is split between complete lines so each file stays within the size limit, and an empty file is never rotated. The runtime log (`--log-file`) is not batched.

**Validators.** The `ETag` of a static file includes its inode change time as well as its size and modification time, so a file rewritten with the same size and its old modification time put back (`rsync -t`, `tar`) gets a new tag and clients do not keep the old copy. `If-Range` with a date is never honoured (the full file is sent); resuming works with the entity tag. All `ETag`s change once with this version, so clients fetch each file once more. Where the platform gives no inode change time (Windows) no `ETag` is sent: clients revalidate by date or fetch the file again, and `If-None-Match`/`If-Range` with an entity tag never match.

### 2.3b Redirects

A route can answer with a redirect instead of serving content:

```kdl
site "www.example.com" {
    route "/*" { redirect "https://example.com{uri}" }          // www to bare domain, 301
}
site "example.com" {
    route "/old-page" { redirect "/new-page" status=302 }
    route "/blog/*"   { redirect "https://blog.example.com{path}" status=308 }
}
```

`status` is 301 (default), 302, 307 or 308. The target is an absolute `http://`/`https://` URL with the host written out, or a path starting with a single `/`. After the host or the literal path prefix it may use `{path}` (request path), `{query}` (query string without `?`) and `{uri}` (path plus `?query` when present). `{path}` is always the **full** request path, also on a prefix route: `route "/old/*" { redirect "https://new.example.com{path}" }` sends `/old/a/b` to `https://new.example.com/old/a/b`. On a prefix route, `{rest}` is the part after the prefix without its leading `/`: `route "/old/*" { redirect "/new/{rest}" }` sends `/old/a/b` to `/new/a/b` (and `/old` to `/new/`). `{rest}` on a route that is not a prefix route is rejected (`E306`). A target without `{uri}` or `{query}` **drops** the query string (like Nginx `return`, unlike Apache `Redirect`); write `{uri}`, or `?{query}`, to keep it. Targets where the request could choose the destination host (`//...`, `/{path}`, a placeholder in the host) are rejected (`E306`).

How the target is built:

- The template is split into path, query and fragment **before** anything from the request is inserted, and it is read once: text in the request that looks like a placeholder is never expanded.
- `{query}` must come after a `?` (`E306` otherwise). A query item that is only `{query}` disappears together with its separator when the request has no query: `"/new?{query}&a=1"` gives `/new?a=1`, never `/new?&a=1` or `/new&a=1`.
- `{path}`, `{rest}` and `{uri}` used inside the query or fragment are percent-encoded so they stay one value: `"/login?next={uri}"` gives `/login?next=/a%3Fx%3D1`.
- A target longer than 8192 bytes is answered with `414`.

### 2.3c Suspended sites and tools under a path

```kdl
site "suspended.example.com" {
    root "/var/panel/suspended"
    error-pages { page 503 "suspended.html" }
    route "/*" { respond 503 }                      // every path, including *.php
}
site "panel.example.com" {
    route "/code/*" {
        reverse-proxy {
            upstream "http://127.0.0.1:8080"
            strip-prefix #true                       // /code/a/b?x=1 is forwarded as /a/b?x=1
        }
    }
}
```

`respond` takes a status from 400 to 599 and answers with the site's error page for it (or the built-in page). `401`, `405`, `407` and `426` are rejected (`E306`): HTTP requires a header with them (`WWW-Authenticate`, `Allow`, `Proxy-Authenticate`, `Upgrade`) that a fixed response cannot send. Use `403` to refuse, `404` to hide, `503` for a suspended site. `strip-prefix` needs a prefix route (`"/code/*"`); `/code` and `/code/` are forwarded as `/`. A request whose path, as sent, does not literally start with the prefix gets 400.

FastCGI retries (a graceful PHP-FPM reload refuses and drops connections for a moment):

- A connection that **cannot be made** is tried once more, for every method. PHP never saw the request, so nothing can run twice.
- A connection that is **lost after the request was handed over** is answered with 502 by default, because PHP may already have run the request. `fastcgi-pass "unix:/run/php/php8.3-fpm.sock" replay-safe-methods=#true` sends a `GET`, `HEAD` or `OPTIONS` request once more in that case. Other methods are never sent twice. Leave it off for applications that change something on `GET` (one-time download links, for example).

### 2.3e Rewrite rules

A site may have one or more `rewrite` blocks. Rules are checked in order, once per request, **after** the site's security preset, bot policy and rate limit and before its routes; the first rule whose pattern and conditions match is applied, and its result is not run through the rules again (no loops).

```kdl
site "example.com" {
    root "/home/user/public_html"
    rewrite {
        rule "\\.(bak|sql|env)$" deny=404                        // refuse
        rule "^/blog/(\\d+)$" to="/blog.php?id=$1"                // internal, address unchanged
        rule "^/old/(.*)$" redirect="/new/$1" status=301          // redirect
        rule "^/(.*)$" to="/index.php" if-not-file=#true          // front controller
        rule "^/m/(.*)$" to="/mobile/$1" header="User-Agent=Mobile"
    }
}
```

- **Pattern:** a regular expression matched against the request path after normalisation (decoded, duplicate slashes collapsed), the same form routes match. At most 512 bytes; at most 200 rules per site. Matching time is linear in the address length, so a crafted address cannot stall a pattern.
- **Actions (exactly one):** `to="<path>"` serves another path of the same site; `redirect="<path or http(s) URL>"` with `status` 301 (default), 302, 303, 307 or 308; `deny=403|404|410`; `pass=#true` stops the list and leaves the request unchanged (use it for exceptions placed before a broader rule). `status` is only valid with `redirect`.
- **Targets** may use `$0`..`$9`. An internal target must start with `/` and a literal character and must not contain `#`. A redirect to another site needs its host written out. Text taken from the request is percent-encoded when inserted. An internal target has to pass the same checks as a request a visitor sends (length, `.`/`..` segments in any spelling, control characters), and a redirect whose path would contain a `.` or `..` segment is refused; both are answered with 400. A target longer than 8192 bytes is answered with 414.
- **Query string:** kept and appended by default; `keep-query=#false` drops it. A fragment in a redirect target stays last: `redirect="/help#intro"` with `?lang=lo` gives `/help?lang=lo#intro`.
- **Limits:** a target is at most 2048 bytes. A condition line takes no properties and no child block (`E306`).
- **Conditions (all optional):** `if-not-file=#true` (nothing exists at the request path under the site root), `host="name"`, `method="GET"`, `query="<regex>"`, `header="Name=<regex>"`.
- **File tests:** `if-not-file=#true` holds when neither a file nor a directory exists (Apache `!-f` together with `!-d`); `if-not-regular-file=#true` holds when no regular file exists, so a directory is rewritten too (Apache `!-f` alone). The positive forms: `if-file=#true` holds when a file or a directory exists, `if-regular-file=#true` when a regular file exists (Apache `-f`). A regular file named with a trailing slash (`/a.txt/`) counts as absent, as it is never served.
- **More conditions, negation:** a rule may have a child block with any number (up to 16) of `header "Name" "<regex>"`, `query "<regex>"`, `host "<regex>"` and `client-ip "<ip or cidr>"` lines, each also as `not-header`, `not-query`, `not-host`, `not-client-ip`. `client-ip` is the visitor's address after `trusted-proxies`. All must hold. `not-header` holds when no value of that header matches, including when the header is absent. Hotlink protection: `rule "(?i)\\.(png|jpe?g|gif)$" deny=403 { header "Referer" "."; not-header "Referer" "^https://(www\\.)?example\\.com/" }`.
- **Case:** patterns are case-sensitive; start one with `(?i)` to ignore case.
- **Differs from Apache:** rules are NOT run again after an internal rewrite (Apache re-runs them in per-directory context). A converted rule set that relies on a second pass behaves differently.
- **ACME:** the built-in HTTP-01 responder answers `/.well-known/acme-challenge/` before rewrite rules run. For an external webroot client (certbot, lego), set `server { acme-webroot "/var/lib/acme-webroot" }` instead of a per-site route: MiraServe then answers `GET`/`HEAD /.well-known/acme-challenge/<token>` from `<dir>/.well-known/acme-challenge/<token>` (the layout certbot and lego write; nothing else under the directory is served) for every configured host, before the site check, `owner-dir` and routes (so tenant sites need no root outside their `owner-dir`). The token must be base64url characters only; the token file must be a small regular file reached without links; it and the directory must belong to root or the MiraServe user and not be writable by group or others. MiraServe's own ACME challenges take precedence. The directory is granted read-only in the sandbox, so create it before MiraServe starts (`check --fs` reports a missing one as W028). Every parent directory of the challenge directory (and of each users file) must be root-owned and not writable by group or others (sticky directories excepted), or another account could rename the tree away and put its own in place: `check --fs` reports such a parent as W029 and MiraServe logs it at start-up. Tokens are opened component by component without following links. A token file is answered only when its content is the HTTP-01 key authorization for that token (`<token>.<43-character base64url thumbprint>`, an optional trailing newline is dropped), as certbot and lego write it; any other content is never returned. A configured credential file (key, users file) must not sit directly in the challenge directory under a token-style name: validation refuses an absolute path there (E202), and the name of any credential that resolves there (relative paths, a file still missing) is never answered (`check --fs` W030).
- **Order of checks:** the security preset, Web Bot Auth and the site rate limit see the address the visitor sent (a bot's signature is verified against that address). Rules run after them, so a rule's redirect or file test is never free of those controls.
- **After an internal rewrite** the request is handled like a direct request for the new path: the security preset is applied to the new path as well, a route that protects it still applies, and **a `deny` rule that matches the new path refuses the request**. A `deny` rule also applies to destinations the server dispatches again: a rewrite alias, a script chosen as directory index or `try-files` fallback (`/admin/` does not run a denied `/admin/index.php`), and the script of a PHP request with extra path (`/admin/index.php/x` is refused when `/admin/index.php` is; earlier versions ran it). It does NOT cover a static file that a `try-files` route serves directly as its fallback: to keep files private, keep them outside the document root or on a protected site. To publish one file from a denied directory, copy or link it outside that directory; an alias into it will not work. Path problems in the visitor's own address (an encoded `/`, invalid UTF-8) still count after the rewrite. PHP still receives the visitor's original address in `REQUEST_URI`.
- **Not supported:** `.htaccess` files are not read; translate them at import. No rule chaining, no environment variables, no backreferences to conditions.

Invalid rules are rejected at load with `E308`.

### 2.3f Response headers

A site, and a route, may change the headers of its responses:

```kdl
site "example.com" {
    headers {
        set "Cache-Control" "public, max-age=600"     // replace (Apache Header set)
        add "Vary" "Cookie"                           // add a value (Apache Header append)
        remove "X-Powered-By"                         // remove (Apache Header unset)
    }
    route "/admin/*" {
        fastcgi-pass "unix:/run/php/php8.3-fpm.sock"
        headers { set "Cache-Control" "no-store" }
    }
}
```

- Applied to every response of the site, error pages included (Apache `Header always`), after the security headers, so a site can replace or remove one of them. A route's changes come after the site's.
- Not allowed (`E309`): headers that describe the message framing or the connection (`Content-Length`, `Content-Encoding`, `Content-Range`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `Upgrade`, `TE`, `Trailer`, `Proxy-Connection`), invalid names, values with control characters or longer than 4096 bytes, more than 64 changes in one block.
- Not supported: conditions (Apache `env=`, `expr=`), `Header edit`, `Header merge`.

### 2.3g Visitor address allow/deny

```kdl
site "admin.example.com" {
    access {
        allow "198.51.100.0/24"
        allow "2001:db8::/32"
        deny "all"
    }
}
```

- In this release `access` applies to a **whole site** and is checked before anything else looks at the request. Route-level lists are refused (E311) and will come in a later release. Do not rely on a rewrite `deny` rule to protect one directory: a `try-files` fallback or directory index can still serve its files. Put such content on its own site (subdomain) with a site-level list.
- Each line is `allow` or `deny` with an IP address, a CIDR range or `"all"`. The first line that matches the visitor decides; a visitor no line matches is allowed (as in Nginx), so a closed list ends with `deny "all"`. Refused visitors get 403 with the built-in error page (never the site's own pages).
- The visitor's address is the one after `trusted-proxies` (an `X-Forwarded-For` from an untrusted peer is ignored). If a trusted proxy names no usable client address, a list that names addresses refuses the request.
- At most 256 lines per block; invalid lines are `E310`.

### 2.3h Password-protected sites

```kdl
site "staging.example.com" {
    basic-auth "/etc/miraserve/auth/staging.htpasswd" realm="Staging"
}
```

- In this release `basic-auth` (and `access`, section 2.3g) apply to a **whole site**: every request to the site's hosts is checked first, before rewrites, routes, PHP, proxies or built-in endpoints run. Route-level (per-directory) protection is refused by the configuration (E311) and will come in a later release.
- HTTP Basic authentication against an htpasswd file (`user:hash` per line, `#` comments). Only complete **bcrypt** records are accepted (`$2y$`, `$2b$`, `$2a$`; `htpasswd -B`), cost 4 to 12, the same cost for every user of a file, each user once.
- The users file is a server credential, like a TLS key: an absolute path whose file and directory are owned by root (or the MiraServe user), are not symbolic links, and are not writable by group or others (for example `/etc/miraserve/auth/<site>.htpasswd`, owner root, group `miraserve`, mode 0640, in a 0750 directory). Otherwise that site answers 503 and `check --fs` reports W024 (`check --fs` runs as root, so keep the files owned by root). Tenants therefore cannot replace, link or move it. Keep `fs.protected_hardlinks=1` (the Ubuntu default) so no tenant can hard-link it into a public directory. The static server also refuses to send a configured users file under any name, link or linked document root (it compares the identity of the file it opened). It must be outside every served document root; a configured path inside one is refused (E301). A custom error page that points at a users file or into its directory is not used (that site gets the built-in page for that status). A replacement file is refused from the reload that loads it on, so never link users files into a public directory, not even for a moment. The file is read at start and on reload (edit it, then `miraserve reload`), never through a symbolic link, and granted read-only in the sandbox; create its directory before referencing it. A users file outside the startup sandbox makes only its own site answer 503 until a restart; the reload still applies to every other site.
- `/etc/miraserve/auth` is granted read-only whenever it exists when MiraServe starts, so the first protected site added later loads on reload. A users file that cannot be used (missing, unreadable, malformed, changed again and again while it is loaded, or the same file as one configured under another name, such as a hard link or another case: use one name for a file in every site) does not stop the server or a reload: that site answers **503** until the file is fixed and the configuration reloaded; every other site keeps working. `check --fs` reports it as warning **W024** (an error with `--strict`).
- A request that fails the site check (401, 403, 429, 503 from `access` or `basic-auth`) gets the built-in error page, never the site's custom error pages; after it passes, the site's own error pages apply as usual. ACME challenges and the HTTP-to-HTTPS redirect are answered before the site check (they carry no site content). Wrong or missing credentials get 401 with `WWW-Authenticate: Basic realm="...", charset="UTF-8"` (configured header rules cannot remove it). Each attempt that carries credentials counts before the password check and is given back when the password is right or got no answer in time (full queue, no bcrypt slot: 503), so only wrong passwords lead to a 429; a request held back only by checks of its address that still run waits for one to end (within its own 5 s). A comparison with the remembered logins that ends in such a 503 is counted separately: an address that has used its attempts between failures and these comparisons is no longer compared with the remembered logins (its requests go through bcrypt, and get 503 while the queue is full, a password just proved right included) until they expire, so a full queue cannot be used to test passwords (a request without credentials gets the 401 challenge without counting; a recently verified login is not re-checked and not counted, but is refused like any other attempt while its address is throttled); after 10 counted failures that address gets 429, before any check, a remembered login included (an IPv6 address counts by its /64, and its /48 also counts, up to 50; addresses that cannot be established share one bucket). A failure counts until its minute and the next are over (one to two minutes); the 429's `Retry-After` gives the time until the block lifts if nothing else is counted (1 second when only checks still running hold it). Failures (and, apart from them, the unanswered comparisons) are kept per protected area in fixed-size counting sketches (four rows of 32 768 counters, keyed at random per area; at most 256 KiB a minute each, a small map while few addresses fail): nothing is ever evicted, so a block is never lifted early and memory stays bounded; an address's count can only be too high, when each of its four counters also holds enough failures of other addresses to reach the limit (one blocked address, or several that failed less). As a guide, for an address that never failed: under 0.01 % while 3 000 addresses are blocked within two minutes, about 2 % at 16 000 (more when many other addresses failed a few times each). A successful check is remembered for 10 minutes after its last use (each use renews it). Requests with the same credentials that arrive while their check runs (a page's parallel requests, one HTTP/2 connection's streams) from the same address wait for that one check, which counts once; each address has its own checks, and one that another address's check has proved right before its own bcrypt starts needs none (at most 512 waiting requests per area, each within its own 5 s; if the check runs out of its own time, one of them runs it). The failure counts, the waiting limits, the bcrypt slots and the remembered logins carry over a reload (an area is the path of its users file: no host-name edit and no replacing of the file resets it, and sites sharing a users file share it all; a restart, or configuring another path, starts anew); a remembered login is bound to the user's stored hash, so a user removed or given another hash by the reload gets 401 at once. bcrypt work is bounded: at most 16 requests of a site wait for a check (more get 503 at once), two checks run at once per site and four for the server, and a request waits at most 5 s for the check (then 503).
- The `Authorization` header the site's check consumed stays available to MiraServe's own rewrite rules, bot signatures and limiters, and is removed at the hand-off to PHP, the MCP gateway, a proxied application or a WebAssembly component.
- Every answer of a site with `access`, `basic-auth`, or rewrite rules on the visitor address gets `Cache-Control: private` (configured `public`/`s-maxage` dropped, and `Surrogate-Control`, `CDN-Cache-Control` and every vendor `*-CDN-Cache-Control` removed); refusals get `no-store`.
- Behind a trusted proxy that sends no usable `X-Forwarded-For`, the visitor's address is unknown: `access` lists that name addresses refuse the request, and a rewrite rule whose result depends on the address refuses it (403, or a `deny` rule's own status).
- Over HTTP/3 every request is attributed to the address the connection's handshake validated, as before this release (applications, rate limits, logs and visitor lists see it). QUIC connection migration stays on. On a site with `access` or `client-ip` rewrite rules, a request on a connection that has since moved to another address gets 421 Misdirected Request and the browser retries it on a new connection; other sites serve it as before.
- Send credentials only over HTTPS.

### 2.3i Site ownership (`owner-dir`) and unsafe document roots

```kdl
site "shop.example.com" {
    owner-dir "/home/usr_shop"
    root "/home/usr_shop/public_html/shop.example.com/current/public"
}
```

- `owner-dir` names the account directory that owns the site. When the configuration is loaded, every document root of the site (the site root and route roots) is opened and the location of the opened directory itself is checked: it must be inside `owner-dir`. Links inside the account (for example `current -> releases/v2`) keep working; a root that really leads elsewhere, such as another account's web root, makes **only this site** answer 503 (logged), and every other site loads normally. Panels should set `owner-dir` on every tenant site, and should grant `/home` as a sandbox `read-tree` so tenant roots and pages are always covered by the startup policy. `owner-dir` draws an account boundary: two sites given the same `owner-dir` can serve each other's files, so give each account its own. On an `owner-dir` site an absolute custom error page must also be inside the account (otherwise the built-in page is used), and PHP is given the real location of the directory MiraServe opened and checked.
- On a tenant site, every credential file the configuration names (its TLS certificate, key and client CA, upstream TLS files, bot key file) must be the server's, like the users files: owned by root or the MiraServe user, not writable by others, not a link; otherwise the site answers 503. A tenant site that cannot be loaded for any other reason (an unreadable CA or certificate, an unusable publish store) also answers 503 on its own, and `check --fs` reports its problems as W026 instead of errors, so one account never stops the start or reload of the others.
- On a tenant site (one with `owner-dir`), a document root that is unsafe in itself (it resolves into a forbidden system directory, the configuration, TLS keys, ACME state, publish stores or log directories), that exists but cannot be opened (permissions, a link loop), or any sandbox grant inside the site's `owner-dir` that fails or lies outside the sandbox granted at start (document roots, error pages), quarantines **only that account's sites**: it answers 503, its roots are not opened or granted, and the start or reload applies to all other sites (a root outside the startup sandbox stays quarantined until a restart). `check --fs` reports it as warning **W026** (an error with `--strict`). Sites without `owner-dir` keep the previous behaviour: such a root refuses the start or reload (E301). A server log file placed (as configured) inside any document root always refuses it.
- `miraserve reload --config <file>` reports quarantined tenant sites before signaling (`--format json` writes `{"reloaded", "quarantined", "errors"}` to stdout for hosting panels, while the default `--format text` writes a `quarantined:` line per site to stderr). Pass `--dry-run` to run the same preflight and quarantine classification without signaling a running daemon (useful for panels and tests).

#### Trust boundary: the configuration is the operator's

MiraServe trusts its configuration file: every path in it (certificates, keys, CA bundles,
users files, sockets, roots) is chosen by the operator or the hosting panel, never by a tenant.
A tenant must not be able to edit the configuration or choose paths in it. Files outside the
tenants' directories are the operator's too: a second name (hard link) for a credential file
inside a document root can be created only by the file's owner or root while the kernel's
`fs.protected_hardlinks` is 1 (the default on current Linux distributions; MiraServe warns at
start-up when it is 0). MiraServe additionally refuses to serve the configured credential files
under any name it can identify, but an alias an operator creates is the operator's mistake, not
a tenant capability. Within that boundary
MiraServe protects tenants from each other: a tenant controls only the files inside its own
`owner-dir`, and nothing a tenant does there can expose another account's content or a
credential, or (in the panel configuration below) hold back another site's start or reload.

#### Availability isolation: what is guaranteed

Security does not depend on the points below: a protected site's `access` and `basic-auth`
always apply, one account cannot read another account's files through MiraServe, and users files
are never served. The points below concern **availability** only: whether one account's broken
setup can delay another site's start or reload.

Guaranteed for the hosting-panel configuration: tenant sites with `owner-dir`, a `/home`
sandbox `read-tree`, server log files and their rotation (`--log-max-bytes`) in a server-owned
directory that no tenant reference points into, users files and site certificates written by the panel as server-owned
files, one PHP-FPM pool per account. In that configuration a missing or unusable tenant root, an unusable
certificate pair or any other dependency that stops the site from loading makes that whole site
answer 503 (a tenant site's certificate serves only its own hosts and is never the fallback for
others), and every other site's changes (including password revocations) apply. A broken users
file makes that site answer 503 too (W024); a valid users file without users is W027 (the site
asks everyone for a password and nobody can sign in). `miraserve reload --format json` prints
`outcome` (`committed`, `committed_running_config` when the server committed its own file whose
content differs from `--config`, `refused`, `unknown` when it did not acknowledge in time,
`dry_run_passed`, `dry_run_refused`), `reloaded` (`true`, `false` or `null`), the `quarantined`
sites with `quarantined_source` (`server`: what the committed configuration actually serves as a
503, reported by the server itself; `preflight`: a prediction from `--config`), and every
per-site `warnings` entry, and `restart_required`: settings of the committed configuration
(`server.listen`, `server.sandbox`, `server.limits.max-connections`, ...) that the running
process applies only after a restart; restart MiraServe when it is not empty. `--dry-run --config <file>` predicts without signaling;
`check --fs --format json` lists the same issues.

Known limitations (outside that configuration, one site's problem can still refuse the whole
start or reload, as with Nginx or OpenLiteSpeed): credential paths a tenant can choose or
change (TLS, upstream TLS, bot or publish keys), the split key daemon (`keyd`) loading a broken
tenant key pair, server log rotation (`--log-max-bytes`) whose directory overlaps a tenant
credential or key reference, publishing or MCP verification keys on tenant sites, and sites without `owner-dir`.

### 2.3d AI publishing: what is trusted, and upgrades

- **The release store directory is trusted.** Published files are served from it as they are on disk; there is no per-request integrity check. Anyone who can write that directory can change what the site serves. Keep it writable by the MiraServe service user only, never by site owners or other services.
- **Startup and reload use the same strict rule.** A stored release is served only if its signature verifies and it passes the checks configured NOW. There is no exception for a release that "was verified before": after an upgrade that tightens the scanner, or after adding a `preflight-checks` entry, a release that no longer passes is not served. The newest older release that passes is served in its place; if none passes, the site answers 503 until a corrected release is published. The log names the release and the reason (`active ai-publish release failed verification with the current checks and is NOT served`).
- **Before upgrading a server with live AI-published sites**, check the releases against the new version on a copy of the store, and republish any that fail.
- **Padded filesystem paths (0.1.8):** Configuration load rejects leading or trailing Unicode whitespace in host-filesystem path directives (and file-relative `root` or `ai-publish.storage` values such as `"app /."` whose resolved directory name ends in whitespace) with `E202`. If an existing 0.1.7 installation has a padded path (for example `storage "/srv/publish/app "`), **do not** edit the directive or unconditionally rename directories before inspecting disk: identify which directory (padded or unpadded sibling) holds the live releases and `active.json`, stop or coordinate publishers writing to that store, and reconcile or move the live store cleanly before removing the whitespace from the configuration. A one-line path edit or unconditional rename is insufficient when both siblings exist.

### 2.4 Zero-Downtime Hot Reload

```bash
# Pre-validates KDL, sends SIGHUP, and waits for the server to report reload success or failure
sudo systemctl reload miraserve.service
# Or invoke directly:
sudo miraserve reload --pid-file /run/miraserve/miraserve.pid --config /etc/miraserve/conf/miraserve.kdl
```

**Configuration load errors during reload vs. cold start (hosting panels):** Because a KDL load error (including `E202` for leading or trailing path whitespace) runs before tenant isolation and before applying any change, one invalid path rejects the entire candidate configuration:

- **Refused candidate:** `miraserve check`, `miraserve reload --config` (preflight, before signaling `SIGHUP`), and direct `SIGHUP` file reload reject the candidate with `E202` and exit non-zero without provisioning or opening any candidate path.
- **Still-serving old generation:** On a failed live reload (`reload --config` or direct `SIGHUP`), the running process leaves its previous configuration generation, HTTP content, TLS certificates, and active publish state serving unchanged.
- **Failed cold start:** Stopping the old process before validating (or restarting onto an unvalidated configuration after upgrading to 0.1.8) fails startup for every site until the path is fixed. Panels should run `miraserve check --fs` with the target version before replacing the active config or restarting, and keep the last accepted configuration on disk.

### 2.4a What changed in 0.1.1 (after the security audit of 0.1.0)

Behaviour an operator or a client can notice; everything else in 0.1.1 is internal.

- **HTTP/3 connections end without requests.** A connection that sends no request within `header-read`, or none for `idle-keepalive` after its last one, is closed, also while the client keeps it alive with QUIC PINGs. QUIC flow-control credit is 256 KiB a stream and 4 MiB a connection, as for HTTP/2, and QUIC datagrams are not accepted.
- **Request targets.** An HTTP/1.1 request needs a `Host` header also in absolute form (`GET http://site/ HTTP/1.1`), and an authority with user information (`user@site`) or a non-numeric port is refused with 400 on every protocol.
- **Markdown for agents.** `Accept: text/markdown` gets `page.md` for `page.html` only when `page.md` could be requested itself: a `route` or a rewrite `deny` rule that covers the `.md` path applies. Otherwise the HTML page is converted as before.
- **PHP and WASM memory.** Request bodies and answers of FastCGI and WASM routes are held in memory. One visitor address may hold 128 MiB of them at a time (or two uploads of `max-body-bytes`, if that is more), the server four such shares; a request beyond that gets 503 with `Retry-After`. At most 64 WASM executions run at once.
- **PHP answers.** A `HEAD` request to a script gets no body on any protocol. A script that answers before it has read its request body no longer stalls until the 30 s timeout.
- **`try-files`.** On a site without a PHP route, a leftover `index.php` is skipped and the next index (`index.html`) is served. `{path}` inside the query of a template is percent-encoded as a parameter value; `{query}` is unchanged.
- **Rate limits survive a reload.** A site or route `rate-limit`, and the WordPress login throttle of the preset, keep their counts when a reload leaves their settings as they were (sites are matched by host names, routes by pattern).
- **Stream resets.** HTTP/2 and HTTP/3 streams that are reset after their request was accepted count against `max-h2-rst-stream-per-sec`; a connection above it is closed.
- **`max-connections-per-ip`.** Evicted idle connections count until they have ended, so an address holds at most twice its limit while they drain.
- **Access log.** With `redact-logs`, the user and password of an absolute URL, credentials in a URL fragment, and path segments that look like tokens are redacted too.
- **`miraserve reload`.** The reload status file has a first line `format=2` and a last line `end=1`. Use `miraserve reload` 0.1.1 with a 0.1.1 server (an older `reload` binary still reads the new file).

### 2.5 Linux Firewall & Kernel Tuning (HTTP/3 + Dual-Stack)

- Allow **TCP 80**, **TCP 443**, and **UDP 443** (HTTP/3 QUIC) on both IPv4 and IPv6.
- Increase kernel UDP socket buffers for high-throughput QUIC:

```bash
sudo sysctl -w net.core.rmem_max=7500000 net.core.wmem_max=7500000
```

---

## 3. Rootless Distroless OCI Container

MiraServe ships a multi-stage `Containerfile` built onto `gcr.io/distroless/cc-debian12:nonroot` (UID/GID `65532:65532`, zero shell, zero package manager), and publishes prebuilt `linux/amd64` and `linux/arm64` images on Docker Hub as `miraserve/miraserve`. Replace `0.1.x` below with the current release tag.

```bash
# Build locally
docker build -f Containerfile -t miraserve:local .

# Run rootless out of the box (default CMD generates an ephemeral development TLS certificate;
# port 8080 redirects to HTTPS on port 8443, so publish 8443 unchanged)
docker run --rm -p 8443:8443/tcp -p 8443:8443/udp -p 8080:8080/tcp miraserve/miraserve:0.1.x
```

For production, the redirect from HTTP to HTTPS points at the port the server listens on inside the container. Let your configuration listen on `:443` and `:80` with `redirect-https` and publish `443:443` (TCP and UDP) and `80:80` unchanged:

```kdl
server {
    listen ":443" protocols="h3,h2,h1"
    listen ":80" redirect-https=#true
    // tls and sandbox as in the documentation
}
// site blocks are top-level (outside server { ... })
```

```bash
# Production container with read-only rootfs, dropped capabilities, and persistent state volumes
docker run -d --name miraserve \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  -p 443:443/tcp -p 443:443/udp -p 80:80/tcp \
  -v /etc/miraserve/miraserve.kdl:/etc/miraserve/miraserve.kdl:ro \
  -v miraserve-acme:/var/lib/miraserve/acme \
  -v miraserve-releases:/var/lib/miraserve/releases \
  miraserve/miraserve:0.1.x \
  run /etc/miraserve/miraserve.kdl --acme-dir /var/lib/miraserve/acme
```

With this example configuration and without `--dev-tls`, the server refuses to start unless a certificate, an ACME block, or split-daemon `miraserve-keyd` is configured. Mount any host certificate, key, or site files that the worker itself reads read-only and readable by UID `65532`; with `key-isolation "split-daemon"`, keep the signing keys accessible only to `miraserve-keyd` and give the worker access to the `keyd` endpoint. Binding `:80` and `:443` as UID `65532` with `--cap-drop=ALL` requires the container network namespace to permit unprivileged binding to port 80 and above (for example, `net.ipv4.ip_unprivileged_port_start=80` or `0`). The `miraserve-acme` volume holds ACME state at `/var/lib/miraserve/acme`, and `miraserve-releases` persists `ai-publish` release stores configured under `/var/lib/miraserve/releases`. The Docker Hub image and release downloads do not carry signatures.

---

## 4. WordPress / PHP-FPM Production Hardening

MiraServe runs PHP strictly out-of-process over FastCGI (`php-fpm`) and pairs with `preset "wordpress-hardened"`:

1. Keep `php-fpm` under its own OS user with its Unix socket mode `0660` and group access granted only to `miraserve`. On shared hosting (sites with `owner-dir`) use **one pool per account, running as that account's user**: MiraServe checks the script through the directory it opened, but PHP opens the script by name, and only an account-confined pool guarantees that name cannot lead into another account. A shared `www-data` pool is acceptable only on single-tenant servers. Running `miraserve check --fs` as the service account verifies without connecting that each existing `fastcgi-pass "unix:..."` socket is reachable (search permission on its parent directories) and grants read and write permission on the socket for the account running the check (`uid/gid`), emitting warning **`W033`** (an error with `--strict`, accepted with `--allow-warning W033`, non-blocking for `miraserve reload --config`) on `EACCES` — including when an unsearchable parent directory makes the path unreachable (type and owner unknown, also under root); an existing non-socket gives no `W033`; when `check --fs` runs as `root` (`uid = euid = 0`), when real and effective IDs differ, or when `faccessat` fails with an error other than `EACCES` (such as `EPERM` or `ENOSYS`), it emits no `W033` and records one plain note per distinct cause (included in JSON `notes`; in text mode, printed on stdout on valid runs unless `--quiet` or `--writable-set` is passed, and on stderr after warnings on failed `--fs`/`--strict` runs even with `--quiet`, though a note can be missing when `--writable-set` inspection fails late).
2. Ensure `site` includes `preset "wordpress-hardened"` (blocks dotfiles like `.git`/`.env`, blocks `wp-config.php`, blocks `xmlrpc.php`, blocks PHP execution inside `wp-content/uploads/`, and applies GCRA rate limiting to `wp-login.php`).
3. Ensure `try-files` passes PHP script resolution through the `*.php` FastCGI route; MiraServe automatically blocks static fallback from serving `.php` / `.phtml` / `.phar` source code.

---

## 5. AI-Native Edge: Atomic Publish, MCP Gateway & Per-Site mTLS

- **Atomic Signed Publishing (`miraserve-publish`):**
  1. Generate an offline Ed25519 keypair: `miraserve publish keygen --secret deploy.key --public deploy.pub`.
  2. Configure an explicit immutable `site-id "<unique-id>"` and `require-signature "ed25519:/etc/miraserve/deploy.pub"` in `ai-publish { ... }` so host list reordering or wildcard hosts never break signatures or JWT audiences (`R4-PUB-3`). When adding or changing `site-id` on an existing site with signed v3 releases, either set `site-id` equal to the site's current primary host (lowercased), OR update `site-id` in `miraserve.kdl` first and then rebind the stored releases BEFORE reloading/restarting with `miraserve publish resign --config /etc/miraserve/conf/miraserve.kdl --site <NEW_SITE_ID> --rebind-site-id --from-site-id <OLD_SITE_ID> --old-pubkey <PUBKEY> --key <SECRET_KEY>` (`R5-PUB-1`, `R6-PUB-4`).
  3. **Separated auth policies:** In `auth="oauth-jwt"` mode, configure dedicated `jwt-public-key "ed25519:/etc/miraserve/publish-jwt.pub"` and `jwt-issuer "https://auth.example.com"` so Bearer JWTs are verified independently of the bundle signing key. In `auth="mtls"` mode, configure a per-site `client-ca` under `site.tls` AND restrict authorized client certificates via `allowed-subjects` using the full certificate Subject DN in **ASN.1 RDN sequence order** (the order encoded in the certificate, e.g. `O=Corp, CN=deploy-agent`, matching `openssl x509 -noout -subject -nameopt sep_multiline` rather than reversed RFC 2253 order; RFC 4514 escaping, `emailAddress`/`E`, and `#HEX` values are supported, `R5-PUB-2`).
  4. **Upgrading v2 release stores & key rotation:** Stored v2 releases (predating v3 `site_id` binding) continue to activate on startup and rollback with a warning provided their stored signature verifies under the active key (`R4-PUB-2`), while new network publishes require v3 `site_id` binding. To migrate stored releases to v3 or rotate Ed25519 keys, run `miraserve publish resign --config /etc/miraserve/conf/miraserve.kdl --site <SITE> --old-pubkey <OLD_PUBKEY> --key <NEW_SECRET_KEY>`. For CLI deployments pass `--config <KDL> --site <SITE>` (pass `--allow-timestamp-reset` if recovering from forward clock skew).
  5. **Anti-replay cache (`<storage>/replay-cache.json`) & recovery (`R7-PUB-4`):** Signed MCP publish requests persist SHA-256 signature fingerprints in `<storage>/replay-cache.json` (bounded to 8,192 entries, 2 MiB max file size, and 720 s max entry TTL; abnormally distant timestamps are automatically clamped on load). Genuine duplicate requests receive HTTP `401 Unauthorized`; corrupt, oversized, locked, or saturated caches fail closed with HTTP `503 Service Unavailable` and log an error/warning. If `<storage>/replay-cache.json` is corrupted on disk (or you need to clear a saturated cache immediately rather than waiting up to 720 s for entries to expire), stop or restart `miraserve` after removing the file (`rm <storage>/replay-cache.json && systemctl restart miraserve` — restarting is required to clear in-memory fingerprints).
- **MCP Security Gateway (`miraserve-ai`):**
  - Always configure `jwt-public-key "ed25519:/path/to/pub"` (or `oauth-resource-metadata #true` + verifier) alongside `allow-tools` / `deny-tools`.
  - Keep `audit-log "structured-json"` enabled; secret headers and tokens are redacted automatically.
- **RFC 9421 Web Bot Auth:**
  - Updating `bot-auth` keys and triggering `miraserve reload` swaps in a fresh `BotKeyRegistry`, immediately revoking any removed key IDs.

---

## 6. macOS (`Homebrew` + `launchd`)

```bash
# Build & install from a tagged release using that release's published `miraserve.rb` asset
# (whose url and sha256 match that tag's verified `miraserve-<tag>-src.tar.gz`):
brew install --build-from-source ./miraserve.rb

# Or, to install from HEAD of the publishing repository using that stamped formula:
brew install --HEAD --build-from-source ./miraserve.rb

# Run as a user agent via Homebrew services (non-privileged ports, e.g. :8443)
brew services start miraserve

# Or install as a system LaunchDaemon for ports 80/443
sudo miraserve service generate --target launchd \
  --binary /opt/homebrew/bin/miraserve \
  --config /opt/homebrew/etc/miraserve/miraserve.kdl \
  --output /Library/LaunchDaemons/app.miraserve.server.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/app.miraserve.server.plist
```

---

## 7. Windows (`WinGet` + Boot-Time Scheduled Task — Development / Non-Production)

> **Non-production notice:** Stopping a Windows Scheduled Task performs a hard process termination rather than graceful Win32 SCM drain (`R3-PKG-4`). On Windows the owner and access rights of credential files (users files, keys) are **not** checked: keep them in a directory only administrators and the service account can write to. Treat the Windows Scheduled Task installer as a **development / non-production** option until native Windows Server SCM support is added (or wrap `miraserve.exe run ...` with NSSM/WinSW if you need graceful service stop semantics on Windows).

Because every shipped MiraServe crate enforces `#![forbid(unsafe_code)]` (and therefore does not embed unsafe Win32 Service Control Manager FFI macros), Windows background operation runs as a boot-time **Scheduled Task** under `NT AUTHORITY\LOCAL SERVICE` (`*S-1-5-19`), avoiding Win32 SCM Error 1053 with zero third-party wrappers:

```powershell
# Install the binary into a machine-readable directory accessible to NT AUTHORITY\LOCAL SERVICE
New-Item -ItemType Directory -Force -Path 'C:\Program Files\MiraServe' | Out-Null
Copy-Item -Force "$((Get-Command miraserve).Source)" 'C:\Program Files\MiraServe\miraserve.exe'

# Generate and execute the hardened boot-time task installer (Administrator PowerShell)
& 'C:\Program Files\MiraServe\miraserve.exe' service generate --target windows --binary 'C:\Program Files\MiraServe\miraserve.exe' --output .\install-miraserve-service.ps1
.\install-miraserve-service.ps1
```

The installer:
1. Pre-validates `C:\ProgramData\MiraServe\miraserve.kdl` via `miraserve.exe check`.
2. Removes any legacy `MiraServe` Win32 SCM service before registering the task.
3. Creates `C:\ProgramData\MiraServe\{acme,releases,logs}` with restricted ACLs granting access only to `SYSTEM` (`*S-1-5-18`), `Administrators` (`*S-1-5-32-544`), and `NT AUTHORITY\LOCAL SERVICE` (`*S-1-5-19`) and aborts if `icacls` fails.
4. Registers an `AtStartup` Scheduled Task (`MiraServe`) running as `NT AUTHORITY\LOCAL SERVICE` with limited run level, unlimited execution time, log persistence (`--log-file C:\ProgramData\MiraServe\logs\miraserve.log`), and automatic restart on failure (`-RestartCount 999`). (If you specifically need native Win32 SCM integration, wrap `miraserve.exe run ...` with NSSM or WinSW.)
