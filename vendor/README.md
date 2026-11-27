# Vendored `h2` (`vendor/h2`)

MiraServe carries a minimal, audited local patch to the upstream `h2` crate via
workspace-root `[patch.crates-io]` (`h2 = { path = "vendor/h2" }`).

## Provenance & Pinned Digests

- **Upstream crate:** `h2` `0.4.21`
- **Upstream licence:** MIT (`vendor/h2/LICENSE`)
- **Upstream crates.io archive:** `https://static.crates.io/crates/h2/h2-0.4.21.crate`
- **Upstream archive SHA-256:** `b634322c4924093fe6a6e05ecbe5717cd3c6014934455f4ae8e5cf14ba3264a8`
- **Upstream git revision:** `ea0a5d529280a74f133f9b2ab7ca689f2e378820`
- **Patch file:** `vendor/h2.patch`
- **Patch SHA-256:** `79224a3fe1f8dd3b7ef2cc13205da93a83a09c3644ec5d819da42459a1ff2ff3`
- **Vendor tree SHA-256:** `f894599822e7f2b6f357f90ae58b6ffbbbf828c8b98abfc313473f4f15df405c`
- **Selected constant:** `COPY_LIMIT = 4096` (initial encoder buffer stays `DEFAULT_BUFFER_CAPACITY = 16 * 1_024`, prefix thresholds stay `CHAIN_THRESHOLD = 256` and `CHAIN_THRESHOLD_WITHOUT_VECTORED_IO = 1024`)
- **Dependency owner:** MiraServe maintainer

### Vendored Version History

- **`0.4.20`** (first vendored version; archive SHA-256 `7d29020232d6aa3fb1daca64c1127cf662cf97f254ae16c18c05b8ab635fc118`, upstream git rev `b0e890842ac16d3c76836fd4fcc06421acb15fa7`, patched tree SHA-256 `60ee394cc4270b31c53729a370af6ae311f6de58a4d3a6cfad711c14b475f7c0`): initial adoption of the `COPY_LIMIT = 4096` encoder patch.
- **`0.4.21`** (`2026-11-25`, current; archive SHA-256 `b634322c4924093fe6a6e05ecbe5717cd3c6014934455f4ae8e5cf14ba3264a8`, upstream git rev `ea0a5d529280a74f133f9b2ab7ca689f2e378820`, patched tree SHA-256 `f894599822e7f2b6f357f90ae58b6ffbbbf828c8b98abfc313473f4f15df405c`): refreshed so 100 uploads with an empty non-final DATA frame no longer close the HTTP/2 connection with `GOAWAY(ENHANCE_YOUR_CALM)`; `src/codec/framed_write.rs` and `vendor/h2.patch` were byte-identical across `0.4.20` and `0.4.21`.

`vendor/h2` is unpacked directly from the checksum-verified crates.io `.crate`
archive (never from Cargo's registry `src` directory, which adds `.cargo-ok`
markers), then patched with `vendor/h2.patch` (modifying only
`src/codec/framed_write.rs`). No other files, formatting, warnings, or version
numbers in `h2` are altered.

Both `vendor/h2` and `vendor/h2-audit` are listed in `[workspace].exclude` in
the root `Cargo.toml` so neither is a workspace member and neither is formatted
by `cargo fmt --all` or linted by MiraServe's workspace Clippy / rustdoc gates.

## Reason

In upstream `h2 0.4.21` (unchanged from `0.4.20`, the first vendored version),
`FramedWrite` chains any selected `DATA` piece of 256 bytes or more on vectored
transports (1,024 bytes on scalar transports) into `Next::Data`, which forces a
codec flush before the next frame can enter the encoder. With
`COPY_LIMIT = 4096`, each selected `DATA` piece (already bounded by
`max_frame_size` and flow-control credit) strictly smaller than 4,096 bytes uses
`h2`'s existing copy path into its encoder write buffer (16 KiB initial
capacity) so that several ready small responses can share one transport write,
reducing the number of write calls for small responses. `DATA` pieces of 4,096
bytes or more stay on the chained path. This applies to both downstream HTTP/2
response `DATA` and upstream HTTP/2 reverse-proxy request `DATA`, with zero
changes to MiraServe's own runtime code and no batching timer or added wait for
a lone response.

## Invariants to Recheck on Every Refresh

Before reapplying `vendor/h2.patch` to any newer upstream `h2` release, manually
verify every invariant below against the new upstream source:

1. **Single completion slot & immediate reclamation (`src/proto/streams/prioritize.rs`):**
   `Prioritize::buffer_pending` must reclaim `last_data_frame` on entry **and
   immediately after every `dst.buffer(frame)`**, before selecting another
   frame. Reclaim must clear the matching in-flight state and requeue any
   remainder of the original body buffer on its own stream. A chained chunk
   must still occupy `next` and block further framing until drained.
2. **Constant relationships (`src/codec/framed_write.rs`):**
   Enforced by compile-time assertions in the patch:
   - `CHAIN_THRESHOLD <= COPY_LIMIT && CHAIN_THRESHOLD_WITHOUT_VECTORED_IO <= COPY_LIMIT`
     (`max(prefix thresholds) <= COPY_LIMIT`).
   - `COPY_LIMIT + frame::HEADER_LEN <= DEFAULT_BUFFER_CAPACITY` (liveness
     invariant: an empty encoder must always satisfy `has_capacity()`, or
     `poll_ready` can return `Pending` after a flush with no wake source).
3. **Flow control, `END_STREAM`, and cancellation:**
   `pop_frame` still bounds each selected chunk by `max_frame_size` and stream
   credit, charges stream and connection windows before encoding, clears
   `END_STREAM` on non-final split pieces and restores it on requeued
   remainders, preserves in-flight `Drop` cancellation and scheduled `NO_ERROR`
   reset semantics, and keeps the chained-path prefix copy on
   `self.chain_threshold`.
4. **Genuine flush & shutdown barriers (`src/codec/framed_write.rs`):**
   `FramedWrite::flush` still drains all buffered bytes and polls inner
   `poll_flush` before reporting `Ready(Ok(()))`, and `FramedWrite::shutdown`
   sets `final_flush_done` only after that real flush completes.

## Refresh Procedure

All changes to `vendor/h2/`, `vendor/h2.patch`, `vendor/README.md`,
`vendor/h2-audit/`, root `[patch.crates-io]`, `Cargo.lock`, and the
`scripts/*h2*.sh` gates require dependency-owner review.

1. Download the target crates.io archive `h2-<version>.crate` and verify its
   SHA-256 against the crates.io index / `Cargo.lock`.
2. Unpack the archive into a clean directory and re-verify all invariants above.
3. Update `vendor/h2/` from the clean archive, reapply and review the minimal
   `src/codec/framed_write.rs` diff, and regenerate `vendor/h2.patch` with
   stable relative paths (`a/src/codec/framed_write.rs`,
   `b/src/codec/framed_write.rs`).
4. Update the pinned version, archive SHA-256, git revision, vendor tree
   SHA-256, and patch SHA-256 in `vendor/h2-source.env`, `vendor/README.md`,
   and `vendor/h2-audit/Cargo.toml` + `vendor/h2-audit/Cargo.lock` (all gate
   scripts and `h2_batching_tests.rs` read the vendored version, digest, and
   upstream revision from `vendor/` so no script or test edits are required).
5. Regenerate the workspace root `Cargo.lock` and confirm only the `h2` entry
   changed (unless an intentional transitive update was reviewed).
6. Run all gates:
   - `scripts/verify-vendor-h2.sh` (requires only POSIX base utilities `sh`, `awk`, `cat`, `cmp`, `cp`, `diff`, `dirname`, `find`, `grep`, `ls`, `mkdir`, `pwd`, `rm`, `sed`, `sort`, `wc`, plus `mktemp`, `curl`, `tar`, `patch`, and `sha256sum` or `shasum`; no `cargo`, no `python`; enforces a strict canonical unified diff and `## Patch New-File Allow-List`, rejects regular files with filesystem link count `!= 1`, checks every manifest producer exit status, and compares what Git records — regular files and directories including the root directory, file executable bit, and exact byte contents — under physical path containment)
   - `scripts/test-verify-vendor-h2.sh` (negative and positive tamper checks)
   - `scripts/verify-h2-graph.sh`
   - `scripts/audit-vendor-h2.sh`
   - `scripts/test-vendor-h2.sh` (record the result and vendor tree digest below)
   - Full MiraServe format, Clippy (stable + MSRV 1.95.0), rustdoc, `cargo deny`,
     workspace tests (macOS + Linux), and clean `git archive` release build.
7. Re-measure performance before releasing.

## Security Release Rule

When upstream `h2` publishes a security release or a newer `0.4.x` version
appears in the crates.io sparse index (`https://index.crates.io/2/h2`):

1. Refresh from the verified fixed crates.io archive, re-verify the invariants,
   reapply and review the minimal patch, update `vendor/h2-source.env` and
   `vendor/README.md`, and run all provenance, graph, advisory, upstream `h2`,
   MiraServe, and archive-build gates.
2. **Emergency fallback path (scripted):** If refreshing and re-verifying the patch
   would delay a security release, switch directly to the fixed crates.io
   release with:
   ```sh
   ./scripts/h2-use-registry.sh <fixed-version>
   ```
   This edits root `Cargo.toml` (removing `[patch.crates-io]`), updates root
   `Cargo.lock`, updates `vendor/h2-audit/Cargo.toml` + `Cargo.lock`, and
   records `H2_SOURCE_MODE=registry` with the pinned version and crates.io
   checksum in `vendor/h2-source.env`. All three gates
   (`scripts/verify-vendor-h2.sh`, `scripts/verify-h2-graph.sh`, and
   `scripts/audit-vendor-h2.sh`) read `vendor/h2-source.env` and verify the
   pinned registry identity across all five release targets rather than
   rejecting it. For the **root `Cargo.lock`** in both directions (switching to
   a registry release and returning with `--vendored`), where the target release
   has the same dependency names as the currently locked one, the switch
   rewrites only the `h2` entry (`version`, plus `source` and `checksum` for
   registry mode or neither for vendored mode) and validates with
   `cargo metadata --locked`; only if that is inconsistent does it fall back to
   Cargo re-resolution and print a `NOTE:` advising review of the whole
   `Cargo.lock` diff. The isolated **`vendor/h2-audit/Cargo.lock`** is not
   text-rewritten: the script updates `vendor/h2-audit/Cargo.toml` to
   `h2 = "=<version>"` and refreshes, updates, or regenerates
   `vendor/h2-audit/Cargo.lock` via Cargo (`cargo metadata` when the version
   already matches, otherwise `cargo update -p h2 --precise <version>`, falling
   back to `cargo generate-lockfile`), printing no re-resolution notice.
   Before renaming the five tracked files into place, the switch writes a
   checksummed rollback journal in `.h2-switch-journal` (marking
   `state=COMMITTING` before the first rename and removing the directory after
   the fifth). If interrupted mid-rename, `scripts/verify-vendor-h2.sh` and
   `scripts/verify-h2-graph.sh` fail closed (`[switch-journal]`), and running
   `./scripts/h2-use-registry.sh --recover` (or re-running any switch command,
   which auto-recovers first) rolls all five tracked files back to their saved
   pre-switch originals. In registry mode
   `scripts/test-verify-vendor-h2.sh` runs a reduced suite: it verifies the
   pinned release against that release's own archive and rejects a selector
   naming another digest; the vendored-tree, switch and audit-policy fixtures
   test the vendored state and run in vendored mode only, and no advisory scan
   of any other version than the pinned one is required to release. The
   vendored-mode suite proves this path on every run: it switches a copy to
   registry mode, runs itself there to the end, and repeats that with a
   different compatible release (provisioned in CI via `H2_ALT_CRATE_ARCHIVE`
   with `H2_REQUIRE_ALT_PIN=1`, or discovered in the local Cargo cache) and
   verifies all five tracked files round-trip identically. To restore the
   vendored patch later (once refreshed or no longer bypassed), run:
   ```sh
   ./scripts/h2-use-registry.sh --vendored
   ```
   **Effect of switching to the registry crate:** Removing the
   `[patch.crates-io]` override disables MiraServe's `COPY_LIMIT = 4096` patch,
   reverting to upstream `h2`'s own `FramedWrite` chaining thresholds (in
   `0.4.21`, chaining `DATA` pieces of 256 bytes or more on vectored transports
   and 1,024 bytes on scalar transports instead of copying pieces smaller than
   4,096 bytes into the encoder write buffer; a future upstream release may
   change `h2`'s encoder behaviour).

## Patch New-File Allow-List

Every destination in `vendor/h2.patch` must be an existing regular file inside
the unpacked upstream crate unless explicitly listed below. This list is empty
today (the committed patch modifies only `src/codec/framed_write.rs`):

<!-- Format: - `path/relative/to/h2` -->

## Upstream Release Review Log

`scripts/audit-vendor-h2.sh` queries `https://index.crates.io/2/h2` on every CI
run, daily schedule, and release. It fails if the pinned version is yanked or if
any newer non-yanked `0.4.x` release exists without a dated review record below.
If the maintainer reviews a newer `0.4.x` release and determines re-vendoring is
not needed, add one line here (which makes the check pass again):

<!-- Format: - `0.4.X` (YYYY-MM-DD): reviewed, not needed — <reason> -->

## Verification & Adoption Evidence

### Advisory Gate Proof (`vendor/h2-audit` & `scripts/audit-vendor-h2.sh`)

`cargo-deny` skips path dependencies during RustSec advisory matching.
`vendor/h2-audit/` holds an isolated registry-only manifest (`h2 = "=0.4.21"`)
with its own `Cargo.lock`. `scripts/audit-vendor-h2.sh` verifies version parity
with `vendor/h2/Cargo.toml` and runs `cargo deny --locked check advisories`
with MiraServe's root `deny.toml` policy (enforced on every push and daily in
`.github/workflows/ci.yml`).

- **Current vendored version (`h2 = "=0.4.21"`):** `advisories ok` against
  RustSec `advisory-db` commit `10db6998b5d7` (`2026-11-24T22:47:44+01:00`).
- **Historical affected-version proof (`h2 = "=0.4.3"`):** Running the exact
  same `cargo deny --locked --config deny.toml check advisories` gate on a
  temporary isolated manifest pinned to `h2 = "=0.4.3"` failed closed with exit
  code `1` and reported:
  - `RUSTSEC-2024-0332` (*Degradation of service in h2 servers with CONTINUATION Flood*)
  - `RUSTSEC-2026-0258` (*h2 unbounded empty DATA frames*)

### Upstream `h2` Test Suite (`scripts/test-vendor-h2.sh`)

Recorded on `2026-11-25` against upstream `hyperium/h2` commit
`ea0a5d529280a74f133f9b2ab7ca689f2e378820` (verified pre-patch `src/` identical
to `h2-0.4.21.crate`) with `src/` replaced by `vendor/h2/src/` (vendor tree
SHA-256 `f894599822e7f2b6f357f90ae58b6ffbbbf828c8b98abfc313473f4f15df405c`):

- Unit tests (`cargo test --lib`, including HPACK fixtures): **448 passed, 0 failed, 1 ignored**
- Integration workspace (`tests/h2-tests`, 13 test binaries): **237 passed, 0 failed, 12 ignored**
- Total: **685 passed, 0 failed, 13 ignored** (all ignored tests are upstream's own `#[ignore]` cases)

