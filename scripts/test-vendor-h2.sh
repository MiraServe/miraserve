#!/bin/sh
# Upstream h2 adoption & refresh test gate (documented, not run on every CI push).
#
# Reads the vendored h2 version and archive digest from vendor/h2-source.env and
# the pinned upstream git revision from vendor/README.md, checks out upstream
# hyperium/h2 at that exact commit, verifies its `src/` equals the
# checksum-verified crates.io archive's `src/` before patching, replaces its
# `src/` with `vendor/h2/src/`, and runs both h2's unit tests (`cargo test --lib`)
# and its `tests/h2-tests` workspace.

set -eu

H2_UPSTREAM_REPO="https://github.com/hyperium/h2.git"

fail() {
    printf 'ERROR: test-vendor-h2: %s\n' "$*" >&2
    exit 1
}

for cmd in git cargo tar diff find grep sed sort awk mktemp rm cp; do
    command -v "$cmd" >/dev/null 2>&1 || fail "required command '$cmd' not found"
done

if command -v sha256sum >/dev/null 2>&1; then
    sha256_file() { sha256sum "$1" | awk '{print $1}'; }
    sha256_stdin() { sha256sum | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
    sha256_stdin() { shasum -a 256 | awk '{print $1}'; }
else
    fail "neither 'sha256sum' nor 'shasum' found"
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
VENDOR_DIR="$REPO_ROOT/vendor/h2"
SOURCE_ENV="$REPO_ROOT/vendor/h2-source.env"
README_FILE="$REPO_ROOT/vendor/README.md"

# 1. Verify vendor/h2 provenance first.
"$SCRIPT_DIR/verify-vendor-h2.sh"

[ -f "$SOURCE_ENV" ] || fail "missing $SOURCE_ENV"
[ -f "$README_FILE" ] || fail "missing $README_FILE"

H2_SOURCE_MODE=$(sed -n 's/^H2_SOURCE_MODE=//p' "$SOURCE_ENV")
[ "$H2_SOURCE_MODE" = "vendored" ] || \
    fail "test-vendor-h2.sh requires H2_SOURCE_MODE=vendored (got '$H2_SOURCE_MODE')"
H2_VERSION=$(sed -n 's/^H2_VERSION=//p' "$SOURCE_ENV")
H2_ARCHIVE_SHA256=$(sed -n 's/^H2_ARCHIVE_SHA256=//p' "$SOURCE_ENV")
[ -n "$H2_VERSION" ] && [ -n "$H2_ARCHIVE_SHA256" ] || \
    fail "vendor/h2-source.env missing H2_VERSION or H2_ARCHIVE_SHA256"
H2_ARCHIVE_URL="https://static.crates.io/crates/h2/h2-${H2_VERSION}.crate"

REV_MATCHES=$(grep -F -- "- **Upstream git revision:**" "$README_FILE" || true)
REV_COUNT=$(printf '%s\n' "$REV_MATCHES" | awk 'NF > 0 { c++ } END { print c + 0 }')
[ "$REV_COUNT" -eq 1 ] || \
    fail "vendor/README.md must contain exactly one '- **Upstream git revision:**' line (found $REV_COUNT)"
H2_UPSTREAM_REV=$(printf '%s\n' "$REV_MATCHES" | sed -n 's/.*`\([0-9a-f]\{40\}\)`[[:space:]]*$/\1/p')
[ "${#H2_UPSTREAM_REV}" -eq 40 ] || \
    fail "could not parse 40-char upstream git revision from vendor/README.md"

# Compute canonical digest of vendor/h2 tree (sorted relative path + file SHA-256).
VENDOR_TREE_DIGEST=$(
    cd "$VENDOR_DIR"
    find . -type f | LC_ALL=C sort | while IFS= read -r rel; do
        printf '%s  %s\n' "$(sha256_file "$rel")" "$rel"
    done | sha256_stdin
)
printf 'vendor/h2 tree sha256: %s\n' "$VENDOR_TREE_DIGEST"

TMPDIR_WORK=$(mktemp -d "${TMPDIR:-/tmp}/test-vendor-h2.XXXXXX")
cleanup() {
    rm -rf "$TMPDIR_WORK"
}
trap cleanup EXIT HUP INT TERM

# 2. Obtain & verify crates.io archive.
ARCHIVE_LOCAL="$TMPDIR_WORK/h2-${H2_VERSION}.crate"
ARCHIVE_FOUND=0
if [ -n "${H2_CRATE_ARCHIVE:-}" ]; then
    [ -f "$H2_CRATE_ARCHIVE" ] || fail "H2_CRATE_ARCHIVE='$H2_CRATE_ARCHIVE' does not exist"
    cp "$H2_CRATE_ARCHIVE" "$ARCHIVE_LOCAL"
    ARCHIVE_FOUND=1
else
    CARGO_CACHE_BASE="${CARGO_HOME:-$HOME/.cargo}/registry/cache"
    if [ -d "$CARGO_CACHE_BASE" ]; then
        for candidate in "$CARGO_CACHE_BASE"/*/"h2-${H2_VERSION}.crate"; do
            if [ -f "$candidate" ]; then
                cand_sha=$(sha256_file "$candidate")
                [ "$cand_sha" = "$H2_ARCHIVE_SHA256" ] || \
                    fail "cached archive '$candidate' has SHA-256 '$cand_sha', expected '$H2_ARCHIVE_SHA256'"
                cp "$candidate" "$ARCHIVE_LOCAL"
                ARCHIVE_FOUND=1
                break
            fi
        done
    fi
fi
if [ "$ARCHIVE_FOUND" -eq 0 ]; then
    command -v curl >/dev/null 2>&1 || fail "archive not in cache and 'curl' not found"
    curl -fsSL --proto '=https' --tlsv1.2 -o "$ARCHIVE_LOCAL" "$H2_ARCHIVE_URL" || \
        fail "failed to download $H2_ARCHIVE_URL"
fi
ACTUAL_ARCHIVE_SHA=$(sha256_file "$ARCHIVE_LOCAL")
[ "$ACTUAL_ARCHIVE_SHA" = "$H2_ARCHIVE_SHA256" ] || \
    fail "archive SHA-256 '$ACTUAL_ARCHIVE_SHA' != pinned '$H2_ARCHIVE_SHA256'"

CRATE_UNPACK="$TMPDIR_WORK/crate"
mkdir -p "$CRATE_UNPACK"
tar -xzf "$ARCHIVE_LOCAL" -C "$CRATE_UNPACK"
CRATE_SRC="$CRATE_UNPACK/h2-${H2_VERSION}/src"
[ -d "$CRATE_SRC" ] || fail "unpacked archive missing src/"

# 3. Checkout exact upstream revision (shallow fetch of pinned commit).
UPSTREAM_DIR="$TMPDIR_WORK/upstream-h2"
mkdir -p "$UPSTREAM_DIR"
git -C "$UPSTREAM_DIR" init -q
git -C "$UPSTREAM_DIR" remote add origin "$H2_UPSTREAM_REPO"
git -C "$UPSTREAM_DIR" fetch -q --depth 1 origin "$H2_UPSTREAM_REV"
git -C "$UPSTREAM_DIR" checkout -q --detach FETCH_HEAD
ACTUAL_REV=$(git -C "$UPSTREAM_DIR" rev-parse HEAD)
[ "$ACTUAL_REV" = "$H2_UPSTREAM_REV" ] || \
    fail "checked out revision '$ACTUAL_REV' != pinned '$H2_UPSTREAM_REV'"

# 4. Verify upstream revision's src/ equals crates.io archive's src/ BEFORE patching.
if ! diff -ruN "$CRATE_SRC" "$UPSTREAM_DIR/src" > "$TMPDIR_WORK/src-pre.diff"; then
    cat "$TMPDIR_WORK/src-pre.diff" >&2
    fail "upstream rev $H2_UPSTREAM_REV src/ differs from crates.io h2-${H2_VERSION} archive src/"
fi
printf 'Verified upstream rev %s src/ == crates.io h2-%s archive src/\n' "$H2_UPSTREAM_REV" "$H2_VERSION"

# 5. Replace upstream src/ with vendor/h2/src/ and verify exact match.
rm -rf "$UPSTREAM_DIR/src"
cp -R "$VENDOR_DIR/src" "$UPSTREAM_DIR/src"
if ! diff -ruN "$VENDOR_DIR/src" "$UPSTREAM_DIR/src" >/dev/null 2>&1; then
    fail "copied src/ does not match vendor/h2/src/"
fi

# 6. Run h2 unit tests and tests/h2-tests workspace using an isolated temporary target dir.
TEST_TARGET="$TMPDIR_WORK/target"
export CARGO_TARGET_DIR="$TEST_TARGET"
export CARGO_PROFILE_DEV_DEBUG=0

printf '=== Running upstream h2 unit tests (cargo test --lib) ===\n'
(cd "$UPSTREAM_DIR" && cargo test --lib)

printf '=== Running upstream h2 tests/h2-tests workspace ===\n'
(cd "$UPSTREAM_DIR/tests/h2-tests" && cargo test)

printf 'test-vendor-h2 OK: upstream rev %s + vendor/h2 tree sha256 %s\n' \
    "$H2_UPSTREAM_REV" "$VENDOR_TREE_DIGEST"
