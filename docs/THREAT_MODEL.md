# MiraServe — Threat Model & Security Architecture

This document defines the assets, trust boundaries, adversary classes, and concrete security invariants that govern every design and code change in MiraServe.

---

## 1. Protected Assets

| Asset | Sensitivity | Consequence of Compromise |
| :--- | :--- | :--- |
| **TLS Private Keys & ACME Account Keys** | Critical | Full traffic impersonation, MITM, unauthorized cert issuance |
| **Upstream Credentials (mTLS keys, OAuth secrets, API tokens)** | Critical | Lateral movement into internal backends, databases, and MCP servers |
| **AI Deployment Signing Keys & Release Store** | Critical | Unauthorized site defacement, malicious JS injection into self-updating sites |
| **Host Filesystem outside Configured Document Roots** | High | Arbitrary file disclosure (`/etc/passwd`, `.env`, SSH keys) |
| **Worker Process Availability & Memory** | High | Denial of service, cross-tenant data leakage |
| **MCP Tool Access Policies (RBAC)** | High | Prompt-injected or over-privileged agents invoking destructive backend tools |
| **Request / Response Confidentiality & Privacy** | Medium–High | Exposure of PII, session cookies, SNI metadata, or secret headers in logs |

---

## 2. Trust Boundaries

```text
[ Untrusted Internet Clients / Bots / Attackers ]
        │
        ▼  TB-1: Network Edge (TCP/UDP, TLS 1.3 + PQC, QUIC anti-amplification)
[ Sandboxed Worker Process (No Private Keys, Landlock + seccomp, cap-std) ]
        │
        ├──► TB-2: IPC to miraserve-keyd (Restricted Unix socket / named pipe: sign-only API)
        ├──► TB-3: WASM Plugin Sandbox (Wasmtime wasi:http: strict fuel + RAM + capability caps)
        ├──► TB-4: Kernel Filesystem Boundary (cap-std / openat2 RESOLVE_BENEATH)
        ├──► TB-5: AI Publish Gate (Ed25519 signature + pre-flight checks -> Atomic Release Swap)
        └──► TB-6: Backend Boundary (mTLS Reverse Proxy / Isolated PHP-FPM FastCGI / MCP Server)
```

---

## 3. Threat Analysis & Mandatory Mitigations

### T1. Memory Corruption & Crash-Induced Denial of Service
- **Vector:** Malformed HTTP/1.1, HTTP/2, HTTP/3, QUIC, FastCGI, or KDL inputs triggering buffer overflows, UAF, integer overflows, or panics.
- **Mitigations:**
  - `#![forbid(unsafe_code)]` across every shipped MiraServe crate (15 of 16 workspace members, including `miraserve-sandbox`); the tests-only 16th member (`miraserve-alloc-tests`) contains one audited `unsafe impl GlobalAlloc`, and third-party dependencies — including the vendored `h2` crate and the `aws-lc-rs` cryptography library — contain `unsafe` Rust or C/assembly code.
  - `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` in all library and runtime crates — malformed network bytes must always produce typed `Result::Err`, never unwind.
  - No OpenSSL C linkage (`cargo-deny` explicitly bans `openssl` / `openssl-sys`); TLS handled by memory-safe `rustls` + `aws-lc-rs`.
  - Continuous `cargo-fuzz` targets on every untrusted parser boundary.

### T2. TLS Private Key Exfiltration (Heartbleed-Class)
- **Vector:** A vulnerability in a worker, dependency, or extension reads worker heap memory.
- **Mitigations:**
  - Split-privilege `miraserve-keyd` mode keeps TLS private keys in a minimal isolated signing daemon; workers implement `rustls::sign::SigningKey` over IPC and never hold raw private key bytes.
  - Short-lived ACME certificates (6 days) + RFC 9773 ARI minimize blast radius even if a leaf key were ever compromised.
  - Zeroize secret buffers in memory (`zeroize` crate) on drop.

### T3. Harvest-Now-Decrypt-Later & SNI Metadata Surveillance
- **Vector:** Passive network adversary records TLS handshakes for future quantum decryption or tracks visited domains via plaintext SNI.
- **Mitigations:**
  - TLS 1.3 only by default; `X25519MLKEM768` (RFC 10024) post-quantum hybrid key exchange prioritized by default.
  - Encrypted Client Hello (ECH / RFC 9849) rotation & DNS `HTTPS` record helper architecture.

### T4. HTTP Request Smuggling & Protocol-Level DoS
- **Vector:** Ambiguous `Content-Length` / `Transfer-Encoding` headers causing proxy/backend desync; HTTP/2 Rapid Reset (`RST_STREAM` floods) or `CONTINUATION` floods; QUIC UDP amplification; Slowloris header trickles.
- **Mitigations:**
  - Strict RFC 9110/9112 normalizer rejecting duplicate `Content-Length`, simultaneous `CL`+`TE`, obs-fold lines, and invalid header bytes.
  - Hard per-connection caps on H2 `RST_STREAM` rate, `CONTINUATION` bursts, HPACK memory, and concurrent streams.
  - Mandatory timeouts for TLS handshake, header read, minimum body read rate, and idle keep-alive.
  - QUIC 3x anti-amplification and cryptographic retry tokens enforced via `quinn`.

### T5. Path Traversal, Symlink Escape & Legacy CMS Compromise
- **Vector:** `../` traversal, URL-encoded tricks, symlink races, or WordPress upload directory PHP execution (`/wp-content/uploads/shell.php`).
- **Mitigations:**
  - Static file serving exclusively opens files via **`cap-std::fs::Dir`** (`openat2` + `RESOLVE_BENEATH` on Linux; equivalent handle confinement on macOS/Windows), preventing symlink escapes at the OS level.
  - FastCGI runs PHP strictly out-of-process (`php-fpm`), never in MiraServe's process.
  - `preset "wordpress-hardened"` denies dotfile access (`.git`, `.env`), blocks `xmlrpc.php`, blocks `.php` execution under uploads, and applies GCRA rate limits on `wp-login.php`.

### T6. Malicious or Compromised AI Agent Publishing & MCP Tool Abuse
- **Vector:** A prompt-injected or unauthorized AI agent attempts to overwrite a self-updating website with phishing/XSS payloads or invoke privileged MCP backend tools (`db_drop`, `shell_exec`).
- **Mitigations:**
  - `miraserve-publish` requires cryptographic deployment authentication (Ed25519 signature or scoped OAuth JWT), runs mandatory pre-flight checks (secret scanning, size quotas, optional strict CSP validation), stores immutable versioned bundles, and supports instant rollback.
  - Scope of `no-inline-scripts` (`R5-PUB-10`): enforces zero inline `<script>` execution, zero `on*` event handlers, zero `javascript:`/`vbscript:`/`data:` executable URIs, and same-origin-only `<script src>` / `<base href>` references. It does **not** prohibit a signed bundle from shipping a same-origin `.js` file; deployments that must forbid all JavaScript from prompt-injected agents should additionally set a site-level `Content-Security-Policy: script-src 'none'` header or review `.js` files before signing.
  - `miraserve-ai` MCP Gateway enforces OAuth 2.1 (`RFC 9728`), per-principal JSON-RPC tool allowlists/denylists (default-deny recommended), strict JSON nesting/size bounds, and structured audit logging with secret redaction.
  - RFC 9421 / Web Bot Auth cryptographically verifies bot identity rather than trusting spoofable `User-Agent` strings.

### T7. Malicious or Buggy Third-Party Plugins
- **Vector:** Infinite loop, memory exhaustion, or host file exfiltration inside a community plugin.
- **Mitigations:**
  - Plugins run exclusively as WebAssembly components (`wasmtime` + `wasi:http`) with deterministic memory ceilings, CPU fuel limits, and zero ambient filesystem/network/env capabilities.

---

## 4. Explicit Security Non-Goals
- MiraServe does **not** guarantee security of arbitrary backend application logic (e.g., SQL injection inside an upstream PHP or Node app), though its deterministic edge WAF and presets reduce common exploit surfaces.
- MiraServe does **not** protect against a compromised host root user or compromised kernel.
- MiraServe does **not** eliminate L3/L4 volumetric network DDoS that saturates physical NIC bandwidth (requires upstream BGP/anycast scrubbing).
