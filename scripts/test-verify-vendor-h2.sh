#!/bin/sh
# Positive & negative tamper-detection suite for scripts/verify-vendor-h2.sh,
# scripts/verify-h2-graph.sh, scripts/audit-vendor-h2.sh, and scripts/h2-use-registry.sh.
#
# Every negative fixture differs from an explicitly passing positive control in
# exactly the one property under test, and `expect_fail` requires a stable
# stage diagnostic substring so a failure for any other reason fails the suite.

set -eu

fail() {
    printf 'ERROR: test-verify-vendor-h2: %s\n' "$*" >&2
    exit 1
}

for cmd in awk basename cat chmod cp diff find grep ln mkdir mkfifo mktemp mv rm sed tar; do
    command -v "$cmd" >/dev/null 2>&1 || fail "required command '$cmd' not found"
done

if command -v sha256sum >/dev/null 2>&1; then
    sha256_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    fail "neither 'sha256sum' nor 'shasum' found"
fi

SCRIPT_DIR=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -P -- "$SCRIPT_DIR/.." && pwd -P)

TMPDIR_WORK=$(mktemp -d "${TMPDIR:-/tmp}/test-verify-vendor-h2.XXXXXX")
cleanup() {
    rm -rf "$TMPDIR_WORK"
}
trap cleanup EXIT HUP INT TERM

# resolve_archive <version> <sha256> <dest>: the h2 archive with exactly that digest, taken from
# $H2_CRATE_ARCHIVE (only if its digest matches), the cargo registry cache, or crates.io.
resolve_archive() {
    ra_ver="$1"; ra_sha="$2"; ra_dest="$3"
    if [ -n "${H2_CRATE_ARCHIVE:-}" ] && [ -f "$H2_CRATE_ARCHIVE" ] && \
       [ "$(sha256_file "$H2_CRATE_ARCHIVE")" = "$ra_sha" ]; then
        cp "$H2_CRATE_ARCHIVE" "$ra_dest"
        return 0
    fi
    ra_base="${CARGO_HOME:-$HOME/.cargo}/registry/cache"
    if [ -d "$ra_base" ]; then
        for ra_cand in "$ra_base"/*/h2-"$ra_ver".crate; do
            if [ -f "$ra_cand" ] && [ "$(sha256_file "$ra_cand")" = "$ra_sha" ]; then
                cp "$ra_cand" "$ra_dest"
                return 0
            fi
        done
    fi
    command -v curl >/dev/null 2>&1 || fail "archive h2-$ra_ver not cached and curl not found"
    curl -fsSL --proto '=https' --tlsv1.2 -o "$ra_dest" \
        "https://static.crates.io/crates/h2/h2-$ra_ver.crate"
    [ "$(sha256_file "$ra_dest")" = "$ra_sha" ] || fail "archive h2-$ra_ver checksum mismatch"
}

# The selector of the checkout this suite runs in. A checkout switched to a registry release
# (scripts/h2-use-registry.sh) takes the reduced path below: its own archive, never the vendored one.
SELECTOR="$REPO_ROOT/vendor/h2-source.env"
[ -f "$SELECTOR" ] || fail "vendor/h2-source.env not found"
ACTIVE_MODE=$(sed -n 's/^H2_SOURCE_MODE=//p' "$SELECTOR")
ACTIVE_VERSION=$(sed -n 's/^H2_VERSION=//p' "$SELECTOR")
ACTIVE_SHA=$(sed -n 's/^H2_ARCHIVE_SHA256=//p' "$SELECTOR")
case "$ACTIVE_MODE" in
    vendored|registry) ;;
    *) fail "vendor/h2-source.env: unknown H2_SOURCE_MODE '$ACTIVE_MODE'" ;;
esac
[ -n "$ACTIVE_VERSION" ] && [ -n "$ACTIVE_SHA" ] || fail "vendor/h2-source.env: version or digest missing"

# In vendored mode, vendor/h2-source.env is the single source of truth for the vendored version
# and its crates.io archive digest; no version or digest is hard-coded anywhere in this script.
VENDORED_VERSION="$ACTIVE_VERSION"
VENDORED_SHA="$ACTIVE_SHA"
ARCHIVE_CACHE="$TMPDIR_WORK/h2-${VENDORED_VERSION}.crate"
if [ "$ACTIVE_MODE" = vendored ]; then
    resolve_archive "$VENDORED_VERSION" "$VENDORED_SHA" "$ARCHIVE_CACHE"
fi

# Bump the patch component of a semver triple by an offset (for synthetic version fixtures).
bump_patch_version() {
    printf '%s\n' "$1" | awk -F. -v add="$2" 'NF == 3 { printf "%d.%d.%d\n", $1, $2, $3 + add }'
}

# Find another compatible real h2 0.4.x release (>= 0.4.14, != VENDORED_VERSION) from
# H2_ALT_CRATE_ARCHIVE (if set) or the local cargo registry cache. Prints "<version> <path>"
# or empty string if none is available. Does not assume which release is newest.
find_alt_cached_h2() {
    fa_exclude="$1"
    if [ -n "${H2_ALT_CRATE_ARCHIVE:-}" ]; then
        [ -f "$H2_ALT_CRATE_ARCHIVE" ] || fail "H2_ALT_CRATE_ARCHIVE='$H2_ALT_CRATE_ARCHIVE' does not exist"
        fa_base=$(basename -- "$H2_ALT_CRATE_ARCHIVE")
        fa_ver=$(printf '%s\n' "$fa_base" | sed -n 's/^h2-\(0\.4\.[0-9][0-9]*\)\.crate$/\1/p')
        [ -n "$fa_ver" ] || fail "H2_ALT_CRATE_ARCHIVE basename '$fa_base' does not match h2-0.4.<n>.crate"
        fa_patch="${fa_ver##*.}"
        if [ "$fa_ver" = "$fa_exclude" ] || [ "$fa_patch" -lt 14 ]; then
            fail "H2_ALT_CRATE_ARCHIVE version '$fa_ver' must be >= 0.4.14 and != '$fa_exclude'"
        fi
        printf '%s %s\n' "$fa_ver" "$H2_ALT_CRATE_ARCHIVE"
        return 0
    fi
    fa_cache="${CARGO_HOME:-$HOME/.cargo}/registry/cache"
    [ -d "$fa_cache" ] || return 0
    for fa_cand in "$fa_cache"/*/h2-0.4.*.crate; do
        [ -f "$fa_cand" ] || continue
        fa_base=$(basename -- "$fa_cand")
        fa_ver=$(printf '%s\n' "$fa_base" | sed -n 's/^h2-\(0\.4\.[0-9][0-9]*\)\.crate$/\1/p')
        [ -n "$fa_ver" ] || continue
        fa_patch="${fa_ver##*.}"
        if [ "$fa_ver" != "$fa_exclude" ] && [ "$fa_patch" -ge 14 ]; then
            printf '%s %s\n' "$fa_ver" "$fa_cand"
            return 0
        fi
    done
}

# Create a minimal repo copy sufficient for verify-vendor-h2.sh in BOTH vendored
# and registry modes (carries root Cargo.toml and Cargo.lock that registry mode needs).
make_vendor_copy() {
    dest="$1"
    mkdir -p "$dest/scripts" "$dest/vendor"
    cp "$REPO_ROOT/Cargo.toml" "$dest/Cargo.toml"
    cp "$REPO_ROOT/Cargo.lock" "$dest/Cargo.lock"
    cp "$REPO_ROOT/scripts/verify-vendor-h2.sh" "$dest/scripts/"
    chmod +x "$dest/scripts/verify-vendor-h2.sh"
    cp -R "$REPO_ROOT/vendor/h2" "$dest/vendor/h2"
    cp "$REPO_ROOT/vendor/h2.patch" "$dest/vendor/h2.patch"
    cp "$REPO_ROOT/vendor/h2-source.env" "$dest/vendor/h2-source.env"
    cp "$REPO_ROOT/vendor/README.md" "$dest/vendor/README.md"
}

# Create a repo copy forced into vendored mode for vendored-tree/patch tamper tests
# even when the active checkout is currently in registry mode.
make_vendored_mode_copy() {
    dest="$1"
    make_vendor_copy "$dest"
    cat > "$dest/vendor/h2-source.env" <<EOF
# Tracked source-mode selector for h2 (managed by scripts/h2-use-registry.sh).
# Read by scripts/verify-vendor-h2.sh, scripts/verify-h2-graph.sh, and scripts/audit-vendor-h2.sh.
H2_SOURCE_MODE=vendored
H2_VERSION=${VENDORED_VERSION}
H2_ARCHIVE_SHA256=${VENDORED_SHA}
EOF
}

# Create a repo copy sufficient for verify-h2-graph.sh (links crates/ to keep copy fast).
make_graph_copy() {
    dest="$1"
    make_vendor_copy "$dest"
    cp "$REPO_ROOT/scripts/verify-h2-graph.sh" "$dest/scripts/"
    chmod +x "$dest/scripts/verify-h2-graph.sh"
    ln -s "$REPO_ROOT/crates" "$dest/crates"
}

expect_pass() {
    name="$1"
    shift
    out="$TMPDIR_WORK/case.out"
    if ! "$@" > "$out" 2>&1; then
        cat "$out" >&2
        fail "case '$name' unexpectedly FAILED"
    fi
    printf '  PASS (expected ok):          %s\n' "$name"
}

# Require BOTH nonzero exit AND the expected stage diagnostic substring.
expect_fail() {
    name="$1"
    expected_diag="$2"
    shift 2
    out="$TMPDIR_WORK/case.out"
    if "$@" > "$out" 2>&1; then
        cat "$out" >&2
        fail "case '$name' unexpectedly PASSED (expected failure matching '$expected_diag')"
    fi
    if ! grep -Fq -- "$expected_diag" "$out"; then
        cat "$out" >&2
        fail "case '$name' failed for WRONG reason (expected diagnostic '$expected_diag')"
    fi
    printf '  PASS (rejected %-14s): %s\n' "$expected_diag" "$name"
}

# Require nonzero exit AND TWO substrings (e.g. scan succeeded + specific stage failed).
expect_fail_with_both() {
    name="$1"
    diag_a="$2"
    diag_b="$3"
    shift 3
    out="$TMPDIR_WORK/case.out"
    if "$@" > "$out" 2>&1; then
        cat "$out" >&2
        fail "case '$name' unexpectedly PASSED (expected '$diag_a' and '$diag_b')"
    fi
    if ! grep -Fq -- "$diag_a" "$out"; then
        cat "$out" >&2
        fail "case '$name' missing expected output '$diag_a'"
    fi
    if ! grep -Fq -- "$diag_b" "$out"; then
        cat "$out" >&2
        fail "case '$name' failed for WRONG reason (missing diagnostic '$diag_b')"
    fi
    printf '  PASS (rejected %-14s): %s\n' "$diag_b" "$name"
}

repin_archive_sha() {
    copy="$1"
    new_sha="$2"
    sed "s/$VENDORED_SHA/$new_sha/g" "$copy/vendor/h2-source.env" > "$copy/vendor/h2-source.env.tmp"
    mv "$copy/vendor/h2-source.env.tmp" "$copy/vendor/h2-source.env"
    sed "s/$VENDORED_SHA/$new_sha/g" "$copy/vendor/README.md" > "$copy/vendor/README.md.tmp"
    mv "$copy/vendor/README.md.tmp" "$copy/vendor/README.md"
}

repin_patch_sha() {
    copy="$1"
    old_sha=$(sha256_file "$REPO_ROOT/vendor/h2.patch")
    new_sha=$(sha256_file "$copy/vendor/h2.patch")
    sed "s/$old_sha/$new_sha/g" "$copy/vendor/README.md" > "$copy/vendor/README.md.tmp"
    mv "$copy/vendor/README.md.tmp" "$copy/vendor/README.md"
}

if [ "$ACTIVE_MODE" = registry ]; then
    # A release that has been switched to a registry h2 (the emergency path) links no vendored code.
    # What must hold here: the gates accept exactly the pinned registry identity, with that
    # version's own archive, and reject a selector that names another digest. The vendored-tree
    # fixtures, the switch round trip and the audit-policy fixtures below test the vendored state
    # and its transitions; they run in vendored mode (every CI run) and are not repeated here, and
    # no live advisory scan of another version than the active one is required here. The live
    # advisory gate for the active version is scripts/audit-vendor-h2.sh in the release workflow.
    printf 'Registry mode (h2 %s): reduced suite...\n' "$ACTIVE_VERSION"
    ACTIVE_ARCHIVE="$TMPDIR_WORK/h2-active.crate"
    resolve_archive "$ACTIVE_VERSION" "$ACTIVE_SHA" "$ACTIVE_ARCHIVE"
    C_REG="$TMPDIR_WORK/c_registry"
    make_graph_copy "$C_REG"
    expect_pass "registry baseline: verify-vendor-h2 with the active pin's own archive" \
        env H2_CRATE_ARCHIVE="$ACTIVE_ARCHIVE" "$C_REG/scripts/verify-vendor-h2.sh"
    sed "s/$ACTIVE_SHA/0000000000000000000000000000000000000000000000000000000000000000/" \
        "$SELECTOR" > "$C_REG/vendor/h2-source.env"
    expect_fail "registry selector with another digest rejected (verify-vendor-h2)" "[registry-lock]" \
        env H2_CRATE_ARCHIVE="$ACTIVE_ARCHIVE" "$C_REG/scripts/verify-vendor-h2.sh"
    if command -v cargo >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
        expect_fail "registry selector with another digest rejected (verify-h2-graph)" "[graph-lock]" \
            "$C_REG/scripts/verify-h2-graph.sh"
        cp "$SELECTOR" "$C_REG/vendor/h2-source.env"
        expect_pass "registry baseline: verify-h2-graph (all 5 targets)" "$C_REG/scripts/verify-h2-graph.sh"
    fi
    printf 'test-verify-vendor-h2 OK (registry mode, reduced): h2 %s verified with its own archive; vendored-tree, switch and audit-policy fixtures run in vendored mode only\n' "$ACTIVE_VERSION"
    exit 0
fi

printf 'Running verifier positive & negative tamper tests...\n'

# 0. Clean baseline (active mode, vendored or registry) & group-write umask 0002 compatibility.
C_BASE="$TMPDIR_WORK/c_base"
make_vendor_copy "$C_BASE"
expect_pass "clean baseline (active mode)" env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_BASE/scripts/verify-vendor-h2.sh"

C_BASE_V="$TMPDIR_WORK/c_base_vendored"
make_vendored_mode_copy "$C_BASE_V"
expect_pass "clean baseline (vendored mode)" env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_BASE_V/scripts/verify-vendor-h2.sh"
chmod g+w "$C_BASE_V/vendor/h2/LICENSE"
expect_pass "group-write bit (umask 0002, not recorded by git)" env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_BASE_V/scripts/verify-vendor-h2.sh"

# 1(a). Executable bit mismatch (0644 -> 0755; differs from C_BASE_V only in owner exec bit).
C_EXEC="$TMPDIR_WORK/c_exec"
make_vendored_mode_copy "$C_EXEC"
chmod 0755 "$C_EXEC/vendor/h2/LICENSE"
expect_fail "(a) executable bit changed on regular file" "[manifest-diff]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_EXEC/scripts/verify-vendor-h2.sh"

# 1(a). Symlink replacing a regular file with IDENTICAL CONTENTS & mode (differs only in symlink type).
C_SYM_FILE="$TMPDIR_WORK/c_sym_file"
make_vendored_mode_copy "$C_SYM_FILE"
IDENTICAL_README="$TMPDIR_WORK/identical_readme.md"
cp "$C_SYM_FILE/vendor/h2/README.md" "$IDENTICAL_README"
chmod 0644 "$IDENTICAL_README"
rm "$C_SYM_FILE/vendor/h2/README.md"
ln -s "$IDENTICAL_README" "$C_SYM_FILE/vendor/h2/README.md"
expect_fail "(a) symlink replacing regular file (identical bytes)" "[tree-symlink]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_SYM_FILE/scripts/verify-vendor-h2.sh"

# 1(a). Special file (FIFO) replacing a regular file at the same pathname (same pathname count).
C_FIFO="$TMPDIR_WORK/c_fifo"
make_vendored_mode_copy "$C_FIFO"
rm "$C_FIFO/vendor/h2/README.md"
mkfifo "$C_FIFO/vendor/h2/README.md"
expect_fail "(a) special file (FIFO) inside vendor/h2" "[tree-type]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_FIFO/scripts/verify-vendor-h2.sh"

# 1(a). Special mode bit (sticky) on a subdirectory (differs from C_BASE_V only in sticky bit).
C_STICKY="$TMPDIR_WORK/c_sticky"
make_vendored_mode_copy "$C_STICKY"
chmod 1755 "$C_STICKY/vendor/h2/src"
expect_fail "(a) special mode bit (sticky) on directory" "[tree-mode]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_STICKY/scripts/verify-vendor-h2.sh"

# 1(b). Root directory tampering (sticky bit on root `.`; differs only in root `.` sticky bit).
C_ROOT_MODE="$TMPDIR_WORK/c_root_mode"
make_vendored_mode_copy "$C_ROOT_MODE"
chmod 1755 "$C_ROOT_MODE/vendor/h2"
expect_fail "(b) root directory special mode bit" "[tree-mode]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_ROOT_MODE/scripts/verify-vendor-h2.sh"

# 2(b). Regular file with filesystem link count != 1 (identical tree, modes, bytes; only nlink=2).
C_NLINK="$TMPDIR_WORK/c_nlink"
make_vendored_mode_copy "$C_NLINK"
ln "$C_NLINK/vendor/h2/LICENSE" "$TMPDIR_WORK/outside_hardlink_license"
expect_fail "(2b) regular file with link count != 1 in vendor/h2" "[tree-nlink]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_NLINK/scripts/verify-vendor-h2.sh"

# 1(c). Physical containment: symlinked `vendor` parent directory (differs only in symlinked parent).
C_SYM_PARENT="$TMPDIR_WORK/c_sym_parent"
OUTSIDE_PARENT="$TMPDIR_WORK/outside_vendor"
make_graph_copy "$C_SYM_PARENT"
expect_pass "(c) positive control: real vendor parent (verify-vendor-h2)" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_SYM_PARENT/scripts/verify-vendor-h2.sh"
mv "$C_SYM_PARENT/vendor" "$OUTSIDE_PARENT"
ln -s "$OUTSIDE_PARENT" "$C_SYM_PARENT/vendor"
expect_fail "(c) symlinked vendor parent (verify-vendor-h2)" "[containment]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_SYM_PARENT/scripts/verify-vendor-h2.sh"
expect_fail "(c) symlinked vendor parent (verify-h2-graph)" "[containment]" \
    "$C_SYM_PARENT/scripts/verify-h2-graph.sh"

# 1(c). Physical containment: symlinked `vendor/h2` directory (differs only in symlinked leaf).
C_SYM_H2="$TMPDIR_WORK/c_sym_h2"
OUTSIDE_H2="$TMPDIR_WORK/outside_h2"
make_graph_copy "$C_SYM_H2"
cat > "$C_SYM_H2/vendor/h2-source.env" <<EOF
H2_SOURCE_MODE=vendored
H2_VERSION=${VENDORED_VERSION}
H2_ARCHIVE_SHA256=${VENDORED_SHA}
EOF
mv "$C_SYM_H2/vendor/h2" "$OUTSIDE_H2"
ln -s "$OUTSIDE_H2" "$C_SYM_H2/vendor/h2"
expect_fail "(c) symlinked vendor/h2 (verify-vendor-h2)" "[containment]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_SYM_H2/scripts/verify-vendor-h2.sh"
expect_fail "(c) symlinked vendor/h2 (verify-h2-graph)" "[containment]" \
    "$C_SYM_H2/scripts/verify-h2-graph.sh"

# 1(d). Archive symlink & hardlink controls with IDENTICAL PATHNAME COUNT & BYTES:
# Positive control: both archive and vendor/h2 carry regular file `extra-copy` (copy of LICENSE, nlink=1).
C_TAR_EXTRA_POS="$TMPDIR_WORK/c_tar_extra_pos"
make_vendored_mode_copy "$C_TAR_EXTRA_POS"
GOOD_TREE_EXTRA="$TMPDIR_WORK/good_tree_extra"
mkdir -p "$GOOD_TREE_EXTRA"
tar -xzf "$ARCHIVE_CACHE" -C "$GOOD_TREE_EXTRA"
cp "$GOOD_TREE_EXTRA/h2-${VENDORED_VERSION}/LICENSE" "$GOOD_TREE_EXTRA/h2-${VENDORED_VERSION}/extra-copy"
cp "$C_TAR_EXTRA_POS/vendor/h2/LICENSE" "$C_TAR_EXTRA_POS/vendor/h2/extra-copy"
GOOD_TAR_EXTRA="$TMPDIR_WORK/good-extra.crate"
tar -czf "$GOOD_TAR_EXTRA" -C "$GOOD_TREE_EXTRA" "h2-${VENDORED_VERSION}"
repin_archive_sha "$C_TAR_EXTRA_POS" "$(sha256_file "$GOOD_TAR_EXTRA")"
expect_pass "(d) positive control: archive + vendor with regular extra-copy" \
    env H2_CRATE_ARCHIVE="$GOOD_TAR_EXTRA" "$C_TAR_EXTRA_POS/scripts/verify-vendor-h2.sh"

# Negative: archive replaces `extra-copy` with a symlink -> LICENSE (same pathname count, same target bytes).
C_TAR_SYM="$TMPDIR_WORK/c_tar_sym"
make_vendored_mode_copy "$C_TAR_SYM"
cp "$C_TAR_SYM/vendor/h2/LICENSE" "$C_TAR_SYM/vendor/h2/extra-copy"
BAD_TREE_SYM="$TMPDIR_WORK/bad_tree_sym"
mkdir -p "$BAD_TREE_SYM"
tar -xzf "$ARCHIVE_CACHE" -C "$BAD_TREE_SYM"
ln -s "LICENSE" "$BAD_TREE_SYM/h2-${VENDORED_VERSION}/extra-copy"
BAD_TAR_SYM="$TMPDIR_WORK/bad-sym.crate"
tar -czf "$BAD_TAR_SYM" -C "$BAD_TREE_SYM" "h2-${VENDORED_VERSION}"
repin_archive_sha "$C_TAR_SYM" "$(sha256_file "$BAD_TAR_SYM")"
expect_fail "(d) archive containing symlink member (same pathname count)" "[archive-type]" \
    env H2_CRATE_ARCHIVE="$BAD_TAR_SYM" "$C_TAR_SYM/scripts/verify-vendor-h2.sh"

# Negative: archive replaces `extra-copy` with a hardlink to LICENSE (same pathname count, same bytes).
C_TAR_HLINK="$TMPDIR_WORK/c_tar_hlink"
make_vendored_mode_copy "$C_TAR_HLINK"
cp "$C_TAR_HLINK/vendor/h2/LICENSE" "$C_TAR_HLINK/vendor/h2/extra-copy"
BAD_TREE_HLINK="$TMPDIR_WORK/bad_tree_hlink"
mkdir -p "$BAD_TREE_HLINK"
tar -xzf "$ARCHIVE_CACHE" -C "$BAD_TREE_HLINK"
ln "$BAD_TREE_HLINK/h2-${VENDORED_VERSION}/LICENSE" "$BAD_TREE_HLINK/h2-${VENDORED_VERSION}/extra-copy"
BAD_TAR_HLINK="$TMPDIR_WORK/bad-hlink.crate"
tar -czf "$BAD_TAR_HLINK" -C "$BAD_TREE_HLINK" "h2-${VENDORED_VERSION}"
repin_archive_sha "$C_TAR_HLINK" "$(sha256_file "$BAD_TAR_HLINK")"
expect_fail "(d) archive containing hardlink member (same pathname count)" "[archive-type]" \
    env H2_CRATE_ARCHIVE="$BAD_TAR_HLINK" "$C_TAR_HLINK/scripts/verify-vendor-h2.sh"

# 1(d) & 2(a). Patch validation negatives (all appended/prepended to the FULL legitimate patch!):
# Traversal (..) appended after legitimate patch.
C_PATCH_ESC="$TMPDIR_WORK/c_patch_esc"
make_vendored_mode_copy "$C_PATCH_ESC"
{
    cat "$REPO_ROOT/vendor/h2.patch"
    cat <<'PATCH'
--- a/../escape.txt
+++ b/../escape.txt
@@ -0,0 +1 @@
+evil
PATCH
} > "$C_PATCH_ESC/vendor/h2.patch"
repin_patch_sha "$C_PATCH_ESC"
expect_fail "(d) patch with .. traversal appended to legitimate patch" "[patch-syntax]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_PATCH_ESC/scripts/verify-vendor-h2.sh"

# Absolute path appended after legitimate patch.
C_PATCH_ABS="$TMPDIR_WORK/c_patch_abs"
make_vendored_mode_copy "$C_PATCH_ABS"
{
    cat "$REPO_ROOT/vendor/h2.patch"
    cat <<'PATCH'
--- /tmp/escape.txt
+++ /tmp/escape.txt
@@ -0,0 +1 @@
+evil
PATCH
} > "$C_PATCH_ABS/vendor/h2.patch"
repin_patch_sha "$C_PATCH_ABS"
expect_fail "(d) patch with absolute destination appended to legitimate patch" "[patch-syntax]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_PATCH_ABS/scripts/verify-vendor-h2.sh"

# Index: header prepended to legitimate patch (patch(1) would succeed cleanly if validator were off).
C_PATCH_IDX="$TMPDIR_WORK/c_patch_idx"
make_vendored_mode_copy "$C_PATCH_IDX"
{
    printf 'Index: src/codec/framed_write.rs\n'
    cat "$REPO_ROOT/vendor/h2.patch"
} > "$C_PATCH_IDX/vendor/h2.patch"
repin_patch_sha "$C_PATCH_IDX"
expect_fail "(d) patch with Index: header prepended to legitimate patch" "[patch-syntax]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_PATCH_IDX/scripts/verify-vendor-h2.sh"

# 2(a). Non-canonical patch syntax: 2-space indented unified diff (patch(1) applies it cleanly if validator is off!).
C_PATCH_INDENT="$TMPDIR_WORK/c_patch_indent"
make_vendored_mode_copy "$C_PATCH_INDENT"
sed 's/^/  /' "$REPO_ROOT/vendor/h2.patch" > "$C_PATCH_INDENT/vendor/h2.patch"
repin_patch_sha "$C_PATCH_INDENT"
expect_fail "(2a) non-canonical indented unified diff" "[patch-syntax]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_PATCH_INDENT/scripts/verify-vendor-h2.sh"

# 2(a). Non-canonical patch syntax: leading prose before legitimate patch (patch(1) ignores prose if validator is off!).
C_PATCH_PROSE="$TMPDIR_WORK/c_patch_prose"
make_vendored_mode_copy "$C_PATCH_PROSE"
{
    printf 'Non-canonical prose header line\n\n'
    cat "$REPO_ROOT/vendor/h2.patch"
} > "$C_PATCH_PROSE/vendor/h2.patch"
repin_patch_sha "$C_PATCH_PROSE"
expect_fail "(2a) non-canonical leading prose in patch" "[patch-syntax]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_PATCH_PROSE/scripts/verify-vendor-h2.sh"

# 2(a). Patch new-file allow-list positive control & negative (differs ONLY in allow-list entry).
C_PATCH_NEW_POS="$TMPDIR_WORK/c_patch_new_pos"
make_vendored_mode_copy "$C_PATCH_NEW_POS"
{
    cat "$REPO_ROOT/vendor/h2.patch"
    cat <<'PATCH'
--- /dev/null
+++ b/src/allowed_new.rs
@@ -0,0 +1 @@
+pub const ALLOWED_NEW_TEST: u8 = 1;
PATCH
} > "$C_PATCH_NEW_POS/vendor/h2.patch"
printf 'pub const ALLOWED_NEW_TEST: u8 = 1;\n' > "$C_PATCH_NEW_POS/vendor/h2/src/allowed_new.rs"
repin_patch_sha "$C_PATCH_NEW_POS"
awk '
{ print }
/^## Patch New-File Allow-List$/ {
    print ""
    print "- `src/allowed_new.rs`"
}
' "$C_PATCH_NEW_POS/vendor/README.md" > "$C_PATCH_NEW_POS/vendor/README.md.tmp"
mv "$C_PATCH_NEW_POS/vendor/README.md.tmp" "$C_PATCH_NEW_POS/vendor/README.md"
expect_pass "(2a) positive control: allow-listed new file in vendor/h2.patch" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_PATCH_NEW_POS/scripts/verify-vendor-h2.sh"

C_PATCH_NEW_NEG="$TMPDIR_WORK/c_patch_new_neg"
cp -R "$C_PATCH_NEW_POS" "$C_PATCH_NEW_NEG"
grep -vF -- '- `src/allowed_new.rs`' "$C_PATCH_NEW_POS/vendor/README.md" > "$C_PATCH_NEW_NEG/vendor/README.md"
expect_fail "(2a) unlisted new-file destination rejected before patch(1)" "[patch-dest]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_PATCH_NEW_NEG/scripts/verify-vendor-h2.sh"

# 2(a). Non-existent existing-file destination appended to legitimate patch (rejected before patch(1)).
C_PATCH_NOEXIST="$TMPDIR_WORK/c_patch_noexist"
make_vendored_mode_copy "$C_PATCH_NOEXIST"
{
    cat "$REPO_ROOT/vendor/h2.patch"
    cat <<'PATCH'
--- a/src/does_not_exist.rs
+++ b/src/does_not_exist.rs
@@ -1 +1 @@
-old
+new
PATCH
} > "$C_PATCH_NOEXIST/vendor/h2.patch"
repin_patch_sha "$C_PATCH_NOEXIST"
expect_fail "(2a) non-existent existing-file destination rejected before patch(1)" "[patch-dest]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_PATCH_NOEXIST/scripts/verify-vendor-h2.sh"

# 1(d) & 2(d). Member name containing a literal newline with ZERO unmatched entries:
# Positive control: both archive and vendor/h2 carry regular empty file `good_name`.
NL=$(printf '\n_')
NL=${NL%_}
C_NL_POS="$TMPDIR_WORK/c_nl_pos"
make_vendored_mode_copy "$C_NL_POS"
GOOD_TREE_NL="$TMPDIR_WORK/good_tree_nl"
mkdir -p "$GOOD_TREE_NL"
tar -xzf "$ARCHIVE_CACHE" -C "$GOOD_TREE_NL"
: > "$GOOD_TREE_NL/h2-${VENDORED_VERSION}/good_name"
: > "$C_NL_POS/vendor/h2/good_name"
GOOD_TAR_NL="$TMPDIR_WORK/good-nl.crate"
tar -czf "$GOOD_TAR_NL" -C "$GOOD_TREE_NL" "h2-${VENDORED_VERSION}"
repin_archive_sha "$C_NL_POS" "$(sha256_file "$GOOD_TAR_NL")"
expect_pass "(d) positive control: matched regular filename in archive + vendor" \
    env H2_CRATE_ARCHIVE="$GOOD_TAR_NL" "$C_NL_POS/scripts/verify-vendor-h2.sh"

# Negative: identical matched setup EXCEPT filename in BOTH archive and vendor/h2 contains a literal newline (no unmatched entries!).
C_NL_BOTH="$TMPDIR_WORK/c_nl_both"
make_vendored_mode_copy "$C_NL_BOTH"
BAD_TREE_NL="$TMPDIR_WORK/bad_tree_nl"
mkdir -p "$BAD_TREE_NL"
tar -xzf "$ARCHIVE_CACHE" -C "$BAD_TREE_NL"
: > "$BAD_TREE_NL/h2-${VENDORED_VERSION}/bad${NL}name"
: > "$C_NL_BOTH/vendor/h2/bad${NL}name"
BAD_TAR_NL="$TMPDIR_WORK/bad-nl.crate"
tar -czf "$BAD_TAR_NL" -C "$BAD_TREE_NL" "h2-${VENDORED_VERSION}"
repin_archive_sha "$C_NL_BOTH" "$(sha256_file "$BAD_TAR_NL")"
expect_fail "(d) literal newline member name (matched in archive + vendor, no unmatched entries)" "[tree-raw]" \
    env H2_CRATE_ARCHIVE="$BAD_TAR_NL" "$C_NL_BOTH/scripts/verify-vendor-h2.sh"

# Negative: literal newline inside vendor/h2 only (proves vendor-tree raw check triggers before manifest diff).
C_NL_VENDOR="$TMPDIR_WORK/c_nl_vendor"
make_vendored_mode_copy "$C_NL_VENDOR"
: > "$C_NL_VENDOR/vendor/h2/bad${NL}name"
expect_fail "(d) literal newline member name in vendor/h2" "[tree-raw]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_NL_VENDOR/scripts/verify-vendor-h2.sh"

# 2(c). Failing `sort` producer in manifest pipeline (would silently pass under `find | sort | while`).
FAKE_SORT_BIN="$TMPDIR_WORK/fake_sort_bin"
mkdir -p "$FAKE_SORT_BIN"
cat > "$FAKE_SORT_BIN/sort" <<'SH'
#!/bin/sh
exit 1
SH
chmod +x "$FAKE_SORT_BIN/sort"
expect_fail "(2c) failing sort producer in manifest generation" "[manifest-sort]" \
    env PATH="$FAKE_SORT_BIN:$PATH" H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_BASE_V/scripts/verify-vendor-h2.sh"

# Extra file, missing file, and single-byte content mutation (all differ from C_BASE_V in one property).
C_EXTRA="$TMPDIR_WORK/c_extra"
make_vendored_mode_copy "$C_EXTRA"
: > "$C_EXTRA/vendor/h2/.cargo-ok"
expect_fail "extra file (.cargo-ok) in vendor/h2" "[manifest-diff]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_EXTRA/scripts/verify-vendor-h2.sh"

C_MISS="$TMPDIR_WORK/c_miss"
make_vendored_mode_copy "$C_MISS"
rm "$C_MISS/vendor/h2/README.md"
expect_fail "missing file in vendor/h2" "[manifest-diff]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_MISS/scripts/verify-vendor-h2.sh"

C_MUT="$TMPDIR_WORK/c_mut"
make_vendored_mode_copy "$C_MUT"
printf ' ' >> "$C_MUT/vendor/h2/README.md"
expect_fail "single-byte content mutation in vendor/h2" "[content-diff]" \
    env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_MUT/scripts/verify-vendor-h2.sh"

# 2. Per-target linkage tests (verify-h2-graph.sh):
#    Positive control (normal dep) must pass; dev-only edge and other-target-only edge must fail.
make_synthetic_graph_ws() {
    dest="$1"
    dep_section="$2"
    mkdir -p "$dest/scripts" "$dest/vendor" "$dest/crates/miraserve-bin/src"
    cp "$REPO_ROOT/scripts/verify-h2-graph.sh" "$dest/scripts/"
    chmod +x "$dest/scripts/verify-h2-graph.sh"
    cp -R "$REPO_ROOT/vendor/h2" "$dest/vendor/h2"
    cat > "$dest/vendor/h2-source.env" <<EOF
H2_SOURCE_MODE=vendored
H2_VERSION=${VENDORED_VERSION}
H2_ARCHIVE_SHA256=${VENDORED_SHA}
EOF
    cp "$REPO_ROOT/vendor/README.md" "$dest/vendor/README.md"
    cat > "$dest/Cargo.toml" <<'TOML'
[workspace]
resolver = "3"
exclude = ["vendor/h2"]
members = ["crates/miraserve-bin"]

[patch.crates-io]
h2 = { path = "vendor/h2" }
TOML
    cat > "$dest/crates/miraserve-bin/Cargo.toml" <<TOML
[package]
name = "miraserve-bin"
version = "0.1.3"
edition = "2024"

${dep_section}
TOML
    printf 'fn main() {}\n' > "$dest/crates/miraserve-bin/src/main.rs"
    cargo generate-lockfile --offline --manifest-path "$dest/Cargo.toml" >/dev/null 2>&1 || \
        cargo generate-lockfile --manifest-path "$dest/Cargo.toml" >/dev/null 2>&1 || \
        fail "failed to generate lockfile for synthetic workspace '$dest'"
}

if command -v cargo >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    WS_NORMAL="$TMPDIR_WORK/ws_normal"
    make_synthetic_graph_ws "$WS_NORMAL" "$(printf '[dependencies]\nh2 = "%s"' "$VENDORED_VERSION")"
    expect_pass "(2) synthetic normal dep reachable across all 5 release targets" "$WS_NORMAL/scripts/verify-h2-graph.sh"

    WS_DEV="$TMPDIR_WORK/ws_dev"
    make_synthetic_graph_ws "$WS_DEV" "$(printf '[dev-dependencies]\nh2 = "%s"' "$VENDORED_VERSION")"
    expect_fail "(2) dev-only h2 edge rejected by verify-h2-graph" "[graph-reach]" "$WS_DEV/scripts/verify-h2-graph.sh"

    WS_OTHER_TARGET="$TMPDIR_WORK/ws_other_target"
    make_synthetic_graph_ws "$WS_OTHER_TARGET" "$(printf '[target.\047cfg(target_os = "freebsd")\047.dependencies]\nh2 = "%s"' "$VENDORED_VERSION")"
    expect_fail "(2) non-shipped-target-only h2 edge rejected by verify-h2-graph" "[graph-target]" "$WS_OTHER_TARGET/scripts/verify-h2-graph.sh"

    # 3. Emergency registry switch (both directions), release tests in BOTH modes,
    #    atomic failure rollback, higher-version return trip, & upstream signal tests.
    C_SWITCH="$TMPDIR_WORK/c_switch"
    make_vendor_copy "$C_SWITCH"
    cp "$REPO_ROOT/scripts/verify-h2-graph.sh" "$REPO_ROOT/scripts/h2-use-registry.sh" "$REPO_ROOT/scripts/audit-vendor-h2.sh" "$C_SWITCH/scripts/"
    chmod +x "$C_SWITCH/scripts/verify-h2-graph.sh" "$C_SWITCH/scripts/h2-use-registry.sh" "$C_SWITCH/scripts/audit-vendor-h2.sh"
    cp -R "$REPO_ROOT/vendor/h2-audit" "$C_SWITCH/vendor/h2-audit"
    cp "$REPO_ROOT/deny.toml" "$C_SWITCH/deny.toml"
    # Copy crates/ (never symlink!) so CARGO_MANIFEST_DIR/../../vendor/h2-source.env resolves
    # inside C_SWITCH rather than back into the parent repository.
    cp -R "$REPO_ROOT/crates" "$C_SWITCH/crates"

    TEST_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"

    SYNTH_HIGHER_VER=$(bump_patch_version "$VENDORED_VERSION" 1)
    SYNTH_UNRESOLVABLE_VER=$(bump_patch_version "$VENDORED_VERSION" 970)
    SYNTH_NEWER_VER=$(bump_patch_version "$VENDORED_VERSION" 978)

    IDX_OK="$TMPDIR_WORK/index-ok.ndjson"
    printf '{"name":"h2","vers":"%s","cksum":"%s","yanked":false}\n' "$VENDORED_VERSION" "$VENDORED_SHA" > "$IDX_OK"

    expect_pass "(3c) ensure vendored starting state" \
        "$C_SWITCH/scripts/h2-use-registry.sh" --vendored
    cp "$C_SWITCH/Cargo.toml" "$TMPDIR_WORK/orig.Cargo.toml"
    cp "$C_SWITCH/Cargo.lock" "$TMPDIR_WORK/orig.Cargo.lock"
    cp "$C_SWITCH/vendor/h2-audit/Cargo.toml" "$TMPDIR_WORK/orig.audit.Cargo.toml"
    cp "$C_SWITCH/vendor/h2-audit/Cargo.lock" "$TMPDIR_WORK/orig.audit.Cargo.lock"
    cp "$C_SWITCH/vendor/h2-source.env" "$TMPDIR_WORK/orig.h2-source.env"

    # Atomic failure test: an unresolvable version in the sparse index fails at [switch-resolve]
    # and leaves all five tracked files byte-for-byte unchanged.
    IDX_BAD_VER="$TMPDIR_WORK/index-bad-ver.ndjson"
    printf '{"name":"h2","vers":"%s","cksum":"1111111111111111111111111111111111111111111111111111111111111111","yanked":false}\n' "$SYNTH_UNRESOLVABLE_VER" > "$IDX_BAD_VER"
    expect_fail "(1d) failed forward switch leaves tracked files intact" "[switch-resolve]" \
        env H2_SPARSE_INDEX_FILE="$IDX_BAD_VER" "$C_SWITCH/scripts/h2-use-registry.sh" "$SYNTH_UNRESOLVABLE_VER"
    for pair in \
        "Cargo.toml:orig.Cargo.toml" \
        "Cargo.lock:orig.Cargo.lock" \
        "vendor/h2-audit/Cargo.toml:orig.audit.Cargo.toml" \
        "vendor/h2-audit/Cargo.lock:orig.audit.Cargo.lock" \
        "vendor/h2-source.env:orig.h2-source.env"; do
        rel="${pair%%:*}"
        sav="${pair##*:}"
        if ! diff -u "$TMPDIR_WORK/$sav" "$C_SWITCH/$rel" >/dev/null 2>&1; then
            fail "(1d) failed forward switch mutated tracked file '$rel'"
        fi
    done
    printf '  PASS (expected ok):          (1d) failed forward switch preserved all 5 tracked files\n'

    expect_pass "(3c) switch vendored -> registry (${VENDORED_VERSION})" \
        env H2_SPARSE_INDEX_FILE="$IDX_OK" "$C_SWITCH/scripts/h2-use-registry.sh" "$VENDORED_VERSION"
    expect_pass "(3c) verify-vendor-h2 passes in registry mode" \
        env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_SWITCH/scripts/verify-vendor-h2.sh"
    expect_pass "(3c) verify-h2-graph passes in registry mode (all 5 targets)" \
        "$C_SWITCH/scripts/verify-h2-graph.sh"
    if cargo deny --version >/dev/null 2>&1; then
        expect_pass "(3c) audit-vendor-h2 passes in registry mode" \
            env H2_SPARSE_INDEX_FILE="$IDX_OK" "$C_SWITCH/scripts/audit-vendor-h2.sh"
    fi

    # 3(d). Acceptance for the emergency path: this suite, run in the registry-mode checkout as the
    #       tag workflow runs it, reaches its end.
    cp "$REPO_ROOT/scripts/test-verify-vendor-h2.sh" "$C_SWITCH/scripts/"
    expect_pass "(3d) the suite reaches its end in a registry-mode checkout" \
        env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" sh "$C_SWITCH/scripts/test-verify-vendor-h2.sh"
    grep -Fq "OK (registry mode, reduced): h2 ${VENDORED_VERSION}" "$TMPDIR_WORK/case.out" || \
        fail "(3d) nested suite did not take the registry-mode path"
    rm -f "$C_SWITCH/scripts/test-verify-vendor-h2.sh"

    # 1(c). Real release test command for affected crates in registry mode.
    expect_pass "(1c) cargo test --locked -p miraserve-http -p miraserve-proxy passes in registry mode" \
        sh -c 'cd "$1" && CARGO_TARGET_DIR="$2" cargo test --locked -p miraserve-http -p miraserve-proxy' \
        sh "$C_SWITCH" "$TEST_TARGET_DIR"

    # Tamper checksum in vendor/h2-source.env while in registry mode -> both gates must fail.
    cp "$C_SWITCH/vendor/h2-source.env" "$TMPDIR_WORK/source.env.saved"
    sed "s/$VENDORED_SHA/0000000000000000000000000000000000000000000000000000000000000000/" \
        "$TMPDIR_WORK/source.env.saved" > "$C_SWITCH/vendor/h2-source.env"
    expect_fail "(3c) registry mode rejects checksum tamper (verify-vendor-h2)" "[registry-lock]" \
        env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_SWITCH/scripts/verify-vendor-h2.sh"
    expect_fail "(3c) registry mode rejects checksum tamper (verify-h2-graph)" "[graph-lock]" \
        "$C_SWITCH/scripts/verify-h2-graph.sh"
    cp "$TMPDIR_WORK/source.env.saved" "$C_SWITCH/vendor/h2-source.env"

    # Switch back registry -> vendored and verify full parity across all 5 tracked files.
    expect_pass "(3c) switch registry -> --vendored" \
        "$C_SWITCH/scripts/h2-use-registry.sh" --vendored
    expect_pass "(3c) verify-vendor-h2 passes after switch back to vendored" \
        env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_SWITCH/scripts/verify-vendor-h2.sh"
    expect_pass "(3c) verify-h2-graph passes after switch back to vendored" \
        "$C_SWITCH/scripts/verify-h2-graph.sh"
    for pair in \
        "Cargo.toml:orig.Cargo.toml" \
        "Cargo.lock:orig.Cargo.lock" \
        "vendor/h2-audit/Cargo.toml:orig.audit.Cargo.toml" \
        "vendor/h2-audit/Cargo.lock:orig.audit.Cargo.lock" \
        "vendor/h2-source.env:orig.h2-source.env"; do
        rel="${pair%%:*}"
        sav="${pair##*:}"
        if ! diff -u "$TMPDIR_WORK/$sav" "$C_SWITCH/$rel" >/dev/null 2>&1; then
            fail "(3c) tracked file '$rel' differed after round-trip registry -> vendored switch"
        fi
    done
    printf '  PASS (expected ok):          (3c) round-trip switch preserved all 5 tracked files\n'

    # 1(c). Run the real release test command again after switching back to vendored mode.
    expect_pass "(1c) cargo test --locked -p miraserve-http -p miraserve-proxy passes after switch back to vendored" \
        sh -c 'cd "$1" && CARGO_TARGET_DIR="$2" cargo test --locked -p miraserve-http -p miraserve-proxy' \
        sh "$C_SWITCH" "$TEST_TARGET_DIR"

    # 3(e). The same acceptance with a registry pin that DIFFERS from the vendored version, using
    #       another compatible real release (>= 0.4.14) from H2_ALT_CRATE_ARCHIVE or cargo cache.
    #       When H2_REQUIRE_ALT_PIN=1 (set in CI), a missing alternate archive fails closed.
    ALT_INFO=$(find_alt_cached_h2 "$VENDORED_VERSION")
    H2_ALT_VER=$(printf '%s\n' "$ALT_INFO" | awk '{print $1}')
    H2_ALT_CRATE=$(printf '%s\n' "$ALT_INFO" | awk '{print $2}')
    if [ -n "$H2_ALT_VER" ] && [ -n "$H2_ALT_CRATE" ]; then
        H2_ALT_SHA=$(sha256_file "$H2_ALT_CRATE")
        IDX_ALT="$TMPDIR_WORK/index-alt.ndjson"
        printf '{"name":"h2","vers":"%s","cksum":"%s","yanked":false}\n{"name":"h2","vers":"%s","cksum":"%s","yanked":false}\n' \
            "$H2_ALT_VER" "$H2_ALT_SHA" "$VENDORED_VERSION" "$VENDORED_SHA" > "$IDX_ALT"
        expect_pass "(3e) switch vendored -> registry (${H2_ALT_VER}, a pin other than the vendored version)" \
            env H2_SPARSE_INDEX_FILE="$IDX_ALT" "$C_SWITCH/scripts/h2-use-registry.sh" "$H2_ALT_VER"
        cp "$REPO_ROOT/scripts/test-verify-vendor-h2.sh" "$C_SWITCH/scripts/"
        expect_pass "(3e) the suite reaches its end with that different registry pin" \
            env H2_CRATE_ARCHIVE="$H2_ALT_CRATE" sh "$C_SWITCH/scripts/test-verify-vendor-h2.sh"
        grep -Fq "OK (registry mode, reduced): h2 ${H2_ALT_VER}" "$TMPDIR_WORK/case.out" || \
            fail "(3e) nested suite did not verify the ${H2_ALT_VER} pin"
        rm -f "$C_SWITCH/scripts/test-verify-vendor-h2.sh"
        expect_pass "(3e) switch registry ${H2_ALT_VER} -> --vendored" \
            "$C_SWITCH/scripts/h2-use-registry.sh" --vendored
        for pair in \
            "Cargo.toml:orig.Cargo.toml" \
            "Cargo.lock:orig.Cargo.lock" \
            "vendor/h2-audit/Cargo.toml:orig.audit.Cargo.toml" \
            "vendor/h2-audit/Cargo.lock:orig.audit.Cargo.lock" \
            "vendor/h2-source.env:orig.h2-source.env"; do
            rel="${pair%%:*}"
            sav="${pair##*:}"
            if ! diff -u "$TMPDIR_WORK/$sav" "$C_SWITCH/$rel" >/dev/null 2>&1; then
                fail "(3e) tracked file '$rel' differed after the ${H2_ALT_VER} round trip"
            fi
        done
        printf '  PASS (expected ok):          (3e) round trip through a different registry pin (%s) preserved all 5 tracked files\n' "$H2_ALT_VER"
    elif [ "${H2_REQUIRE_ALT_PIN:-0}" = "1" ]; then
        fail "(3e) H2_REQUIRE_ALT_PIN=1 but no alternate compatible h2 archive was provided or cached"
    else
        printf '  SKIP:                        (3e) no other compatible h2 release in the cargo cache; the different-pin acceptance did not run\n'
    fi

    # 3(f). Interrupted switch recovery after rename #2 of 5 (rollback journal `.h2-switch-journal`):
    #       (i) interrupt after rename #2 -> mixed state rejected with [switch-journal];
    #           `--recover` restores all 5 tracked files byte-for-byte and removes the journal.
    #       (ii) interrupt again after rename #2 -> directly re-running the switch auto-recovers
    #            first and completes cleanly to the target mode.
    expect_fail "(3f) interrupted switch after rename 2 leaves journal intact" "[switch-interrupted]" \
        env H2_SPARSE_INDEX_FILE="$IDX_OK" H2_SWITCH_TEST_FAIL_AFTER_RENAME=2 \
            "$C_SWITCH/scripts/h2-use-registry.sh" "$VENDORED_VERSION"
    [ -f "$C_SWITCH/.h2-switch-journal/state" ] || \
        fail "(3f) missing .h2-switch-journal/state after simulated interruption"
    [ "$(awk 'NR==1 { print $1 }' "$C_SWITCH/.h2-switch-journal/state")" = "COMMITTING" ] || \
        fail "(3f) expected COMMITTING journal state after rename 2"
    if diff -u "$TMPDIR_WORK/orig.Cargo.toml" "$C_SWITCH/Cargo.toml" >/dev/null 2>&1 || \
       diff -u "$TMPDIR_WORK/orig.Cargo.lock" "$C_SWITCH/Cargo.lock" >/dev/null 2>&1; then
        fail "(3f) expected Cargo.toml and Cargo.lock to be modified after rename 2"
    fi
    if ! diff -u "$TMPDIR_WORK/orig.h2-source.env" "$C_SWITCH/vendor/h2-source.env" >/dev/null 2>&1; then
        fail "(3f) expected vendor/h2-source.env to remain untouched after rename 2"
    fi
    expect_fail "(3f) verify-vendor-h2 rejects interrupted switch checkout" "[switch-journal]" \
        env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_SWITCH/scripts/verify-vendor-h2.sh"
    expect_fail "(3f) verify-h2-graph rejects interrupted switch checkout" "[switch-journal]" \
        "$C_SWITCH/scripts/verify-h2-graph.sh"
    expect_pass "(3f) --recover rolls back interrupted switch cleanly" \
        "$C_SWITCH/scripts/h2-use-registry.sh" --recover
    [ ! -e "$C_SWITCH/.h2-switch-journal" ] || \
        fail "(3f) .h2-switch-journal still exists after --recover"
    for pair in \
        "Cargo.toml:orig.Cargo.toml" \
        "Cargo.lock:orig.Cargo.lock" \
        "vendor/h2-audit/Cargo.toml:orig.audit.Cargo.toml" \
        "vendor/h2-audit/Cargo.lock:orig.audit.Cargo.lock" \
        "vendor/h2-source.env:orig.h2-source.env"; do
        rel="${pair%%:*}"
        sav="${pair##*:}"
        if ! diff -u "$TMPDIR_WORK/$sav" "$C_SWITCH/$rel" >/dev/null 2>&1; then
            fail "(3f) --recover did not restore tracked file '$rel' byte-for-byte"
        fi
    done
    expect_pass "(3f) verify-vendor-h2 passes after --recover" \
        env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_SWITCH/scripts/verify-vendor-h2.sh"
    expect_pass "(3f) verify-h2-graph passes after --recover" \
        "$C_SWITCH/scripts/verify-h2-graph.sh"

    expect_fail "(3f) second interruption after rename 2 for auto-recovery check" "[switch-interrupted]" \
        env H2_SPARSE_INDEX_FILE="$IDX_OK" H2_SWITCH_TEST_FAIL_AFTER_RENAME=2 \
            "$C_SWITCH/scripts/h2-use-registry.sh" "$VENDORED_VERSION"
    expect_pass "(3f) re-running switch after rename-2 interruption auto-recovers and completes" \
        env H2_SPARSE_INDEX_FILE="$IDX_OK" "$C_SWITCH/scripts/h2-use-registry.sh" "$VENDORED_VERSION"
    [ ! -e "$C_SWITCH/.h2-switch-journal" ] || \
        fail "(3f) .h2-switch-journal still exists after auto-recovery"
    expect_pass "(3f) verify-vendor-h2 passes after auto-recovered switch" \
        env H2_CRATE_ARCHIVE="$ARCHIVE_CACHE" "$C_SWITCH/scripts/verify-vendor-h2.sh"
    expect_pass "(3f) verify-h2-graph passes after auto-recovered switch" \
        "$C_SWITCH/scripts/verify-h2-graph.sh"
    expect_pass "(3f) return to vendored after auto-recovery check" \
        "$C_SWITCH/scripts/h2-use-registry.sh" --vendored

    # 3(g). Successful Cargo re-resolution fallback when h2's dependencies differ (both directions):
    #       synthetic workspace whose vendored h2 carries one extra local path dependency
    #       (`h2-extra-dep`). Both forward switch (vendored -> registry) and return (--vendored)
    #       must reject the minimal rewrite, re-resolve via Cargo, print the re-resolution NOTE,
    #       and pass verify-h2-graph across all 5 release targets.
    WS_FALLBACK="$TMPDIR_WORK/ws_fallback"
    mkdir -p "$WS_FALLBACK/scripts" "$WS_FALLBACK/vendor" "$WS_FALLBACK/crates/miraserve-bin/src"
    cp "$REPO_ROOT/scripts/h2-use-registry.sh" "$REPO_ROOT/scripts/verify-h2-graph.sh" "$WS_FALLBACK/scripts/"
    chmod +x "$WS_FALLBACK/scripts/h2-use-registry.sh" "$WS_FALLBACK/scripts/verify-h2-graph.sh"
    cp -R "$REPO_ROOT/vendor/h2" "$WS_FALLBACK/vendor/h2"
    cp -R "$REPO_ROOT/vendor/h2-audit" "$WS_FALLBACK/vendor/h2-audit"
    cp "$REPO_ROOT/vendor/README.md" "$WS_FALLBACK/vendor/README.md"
    cat > "$WS_FALLBACK/vendor/h2-source.env" <<EOF
H2_SOURCE_MODE=vendored
H2_VERSION=${VENDORED_VERSION}
H2_ARCHIVE_SHA256=${VENDORED_SHA}
EOF
    mkdir -p "$WS_FALLBACK/vendor/h2/extra-dep/src"
    cat > "$WS_FALLBACK/vendor/h2/extra-dep/Cargo.toml" <<'TOML'
[package]
name = "h2-extra-dep"
version = "0.1.0"
edition = "2021"
TOML
    : > "$WS_FALLBACK/vendor/h2/extra-dep/src/lib.rs"
    python3 - "$WS_FALLBACK/vendor/h2/Cargo.toml" <<'PY'
import sys
p = sys.argv[1]
with open(p, "r", encoding="utf-8") as f:
    text = f.read()
marker = "\n[dependencies."
idx = text.find(marker)
if idx == -1:
    raise SystemExit("could not locate [dependencies.*] in synthetic vendor/h2/Cargo.toml")
extra = '\n[dependencies.h2-extra-dep]\npath = "extra-dep"\n'
text = text[:idx] + extra + text[idx:]
with open(p, "w", encoding="utf-8") as f:
    f.write(text)
PY
    cat > "$WS_FALLBACK/Cargo.toml" <<'TOML'
[workspace]
resolver = "3"
exclude = ["vendor/h2", "vendor/h2-audit"]
members = ["crates/miraserve-bin"]

[patch.crates-io]
h2 = { path = "vendor/h2" }
TOML
    cat > "$WS_FALLBACK/crates/miraserve-bin/Cargo.toml" <<TOML
[package]
name = "miraserve-bin"
version = "0.1.3"
edition = "2024"
[dependencies]
h2 = "${VENDORED_VERSION}"
TOML
    printf 'fn main() {}\n' > "$WS_FALLBACK/crates/miraserve-bin/src/main.rs"
    cargo generate-lockfile --offline --manifest-path "$WS_FALLBACK/Cargo.toml" >/dev/null 2>&1 || \
        cargo generate-lockfile --manifest-path "$WS_FALLBACK/Cargo.toml" >/dev/null 2>&1 || \
        fail "(3g) failed to generate lockfile for synthetic fallback workspace"
    grep -Fq 'name = "h2-extra-dep"' "$WS_FALLBACK/Cargo.lock" || \
        fail "(3g) synthetic fallback lockfile did not include h2-extra-dep"

    expect_pass "(3g) forward switch with changed h2 dependencies succeeds via Cargo re-resolution fallback" \
        env H2_SPARSE_INDEX_FILE="$IDX_OK" "$WS_FALLBACK/scripts/h2-use-registry.sh" "$VENDORED_VERSION"
    grep -Fq "cargo re-resolved the root lock" "$TMPDIR_WORK/case.out" || \
        fail "(3g) forward fallback did not print expected re-resolution NOTE"
    if grep -Fq 'name = "h2-extra-dep"' "$WS_FALLBACK/Cargo.lock"; then
        fail "(3g) forward fallback left stale h2-extra-dep in Cargo.lock"
    fi
    expect_pass "(3g) verify-h2-graph passes after forward changed-dependency fallback" \
        "$WS_FALLBACK/scripts/verify-h2-graph.sh"

    expect_pass "(3g) return --vendored with changed h2 dependencies succeeds via Cargo re-resolution fallback" \
        "$WS_FALLBACK/scripts/h2-use-registry.sh" --vendored
    grep -Fq "cargo re-resolved the root lock" "$TMPDIR_WORK/case.out" || \
        fail "(3g) return fallback did not print expected re-resolution NOTE"
    grep -Fq 'name = "h2-extra-dep"' "$WS_FALLBACK/Cargo.lock" || \
        fail "(3g) return fallback did not restore h2-extra-dep in Cargo.lock"
    expect_pass "(3g) verify-h2-graph passes after return changed-dependency fallback" \
        "$WS_FALLBACK/scripts/verify-h2-graph.sh"

    # 1(d). Return trip from a HIGHER locked registry version (fixture simulating lock state
    #       locked at a higher synthetic version returning to vendored VENDORED_VERSION, plus a
    #       real cached-index downgrade test between two cached releases without assuming newest).
    C_HIGHER="$TMPDIR_WORK/c_higher_return"
    make_graph_copy "$C_HIGHER"
    cp "$REPO_ROOT/scripts/h2-use-registry.sh" "$C_HIGHER/scripts/"
    chmod +x "$C_HIGHER/scripts/h2-use-registry.sh"
    cp -R "$REPO_ROOT/vendor/h2-audit" "$C_HIGHER/vendor/h2-audit"
    expect_pass "(1d) prepare registry-mode base for higher-version lock fixture" \
        env H2_SPARSE_INDEX_FILE="$IDX_OK" "$C_HIGHER/scripts/h2-use-registry.sh" "$VENDORED_VERSION"
    python3 - "$C_HIGHER/Cargo.lock" "$C_HIGHER/vendor/h2-audit/Cargo.toml" "$C_HIGHER/vendor/h2-audit/Cargo.lock" "$C_HIGHER/vendor/h2-source.env" "$VENDORED_VERSION" "$SYNTH_HIGHER_VER" <<'PY'
import re, sys
root_lock, audit_toml, audit_lock, source_env, base_ver, high_ver = sys.argv[1:7]
fake_sha = "2222222222222222222222222222222222222222222222222222222222222222"
base_re = re.escape(base_ver)
for lp in (root_lock, audit_lock):
    with open(lp, "r", encoding="utf-8") as f:
        text = f.read()
    text, n = re.subn(
        rf'(\[\[package\]\]\nname = "h2"\nversion = "){base_re}("\nsource = "registry\+https://github\.com/rust-lang/crates\.io-index"\nchecksum = ")[0-9a-f]{{64}}(")',
        rf'\g<1>{high_ver}\g<2>{fake_sha}\g<3>',
        text,
        count=1,
    )
    if n != 1:
        raise SystemExit(f"failed to rewrite h2 entry in {lp}")
    with open(lp, "w", encoding="utf-8") as f:
        f.write(text)
with open(audit_toml, "r", encoding="utf-8") as f:
    at = f.read().replace(f'h2 = "={base_ver}"', f'h2 = "={high_ver}"')
with open(audit_toml, "w", encoding="utf-8") as f:
    f.write(at)
with open(source_env, "w", encoding="utf-8") as f:
    f.write(f"H2_SOURCE_MODE=registry\nH2_VERSION={high_ver}\nH2_ARCHIVE_SHA256={fake_sha}\n")
PY
    expect_pass "(1d) --vendored returns cleanly from higher locked registry version (${SYNTH_HIGHER_VER} -> vendored ${VENDORED_VERSION})" \
        "$C_HIGHER/scripts/h2-use-registry.sh" --vendored
    expect_pass "(1d) verify-h2-graph confirms vendored ${VENDORED_VERSION} resolved after higher-version return trip" \
        "$C_HIGHER/scripts/verify-h2-graph.sh"

    if [ -n "$H2_ALT_VER" ] && [ -n "$H2_ALT_CRATE" ]; then
        VEN_PATCH="${VENDORED_VERSION##*.}"
        ALT_PATCH="${H2_ALT_VER##*.}"
        if [ "$ALT_PATCH" -lt "$VEN_PATCH" ]; then
            LOW_VER="$H2_ALT_VER"
            LOW_CRATE="$H2_ALT_CRATE"
            HIGH_VER="$VENDORED_VERSION"
            HIGH_SHA="$VENDORED_SHA"
        else
            LOW_VER="$VENDORED_VERSION"
            LOW_CRATE="$ARCHIVE_CACHE"
            HIGH_VER="$H2_ALT_VER"
            HIGH_SHA=$(sha256_file "$H2_ALT_CRATE")
        fi
        LOW_SHA=$(sha256_file "$LOW_CRATE")
        for mode_case in compat incompat; do
            WS_RET="$TMPDIR_WORK/ws_ret_${mode_case}"
            mkdir -p "$WS_RET/scripts" "$WS_RET/vendor/h2-audit/src" "$WS_RET/crates/miraserve-bin/src"
            : > "$WS_RET/vendor/h2-audit/src/lib.rs"
            cp "$REPO_ROOT/scripts/h2-use-registry.sh" "$REPO_ROOT/scripts/verify-h2-graph.sh" "$WS_RET/scripts/"
            chmod +x "$WS_RET/scripts/h2-use-registry.sh" "$WS_RET/scripts/verify-h2-graph.sh"
            tar -xzf "$LOW_CRATE" -C "$TMPDIR_WORK"
            mv "$TMPDIR_WORK/h2-${LOW_VER}" "$WS_RET/vendor/h2"
            cat > "$WS_RET/vendor/README.md" <<EOF
- **Upstream crate:** \`h2\` \`${LOW_VER}\`
- **Upstream archive SHA-256:** \`${LOW_SHA}\`
EOF
            cat > "$WS_RET/vendor/h2-source.env" <<EOF
H2_SOURCE_MODE=registry
H2_VERSION=${HIGH_VER}
H2_ARCHIVE_SHA256=${HIGH_SHA}
EOF
            cat > "$WS_RET/vendor/h2-audit/Cargo.toml" <<EOF
[package]
name = "miraserve-h2-audit"
version = "0.0.0"
edition = "2024"
publish = false
[workspace]
[dependencies]
h2 = "=${HIGH_VER}"
EOF
            if [ "$HIGH_VER" = "$VENDORED_VERSION" ]; then
                cp "$REPO_ROOT/vendor/h2-audit/Cargo.lock" "$WS_RET/vendor/h2-audit/Cargo.lock"
            else
                cargo generate-lockfile --offline --manifest-path "$WS_RET/vendor/h2-audit/Cargo.toml" >/dev/null 2>&1 || \
                    cargo generate-lockfile --manifest-path "$WS_RET/vendor/h2-audit/Cargo.toml" >/dev/null 2>&1 || \
                    fail "(1d) failed to generate audit lockfile for ${HIGH_VER}"
            fi
            cat > "$WS_RET/Cargo.toml" <<'EOF'
[workspace]
resolver = "3"
exclude = ["vendor/h2", "vendor/h2-audit"]
members = ["crates/miraserve-bin"]
EOF
            if [ "$mode_case" = "compat" ]; then
                dep_req="h2 = \"${LOW_VER}\""
            else
                dep_req="h2 = \"${HIGH_VER}\""
            fi
            cat > "$WS_RET/crates/miraserve-bin/Cargo.toml" <<EOF
[package]
name = "miraserve-bin"
version = "0.1.3"
edition = "2024"
[dependencies]
${dep_req}
EOF
            printf 'fn main() {}\n' > "$WS_RET/crates/miraserve-bin/src/main.rs"
            cargo generate-lockfile --offline --manifest-path "$WS_RET/Cargo.toml" >/dev/null 2>&1 || \
                cargo generate-lockfile --manifest-path "$WS_RET/Cargo.toml" >/dev/null 2>&1 || \
                fail "(1d) failed to generate starting lockfile for ${mode_case}"
            cargo update --offline --manifest-path "$WS_RET/Cargo.toml" -p h2 --precise "$HIGH_VER" >/dev/null 2>&1 || \
                cargo update --manifest-path "$WS_RET/Cargo.toml" -p h2 --precise "$HIGH_VER" >/dev/null 2>&1 || \
                fail "(1d) failed to pin starting lockfile to h2 ${HIGH_VER} (${mode_case})"
            if [ "$mode_case" = "compat" ]; then
                expect_pass "(1d) real cached higher registry ${HIGH_VER} -> vendored ${LOW_VER} switches lock cleanly" \
                    "$WS_RET/scripts/h2-use-registry.sh" --vendored
                expect_pass "(1d) verify-h2-graph confirms vendored ${LOW_VER} resolved after real ${HIGH_VER} downgrade" \
                    "$WS_RET/scripts/verify-h2-graph.sh"
            else
                cp "$WS_RET/Cargo.toml" "$TMPDIR_WORK/incompat.Cargo.toml"
                cp "$WS_RET/Cargo.lock" "$TMPDIR_WORK/incompat.Cargo.lock"
                cp "$WS_RET/vendor/h2-audit/Cargo.toml" "$TMPDIR_WORK/incompat.audit.Cargo.toml"
                cp "$WS_RET/vendor/h2-audit/Cargo.lock" "$TMPDIR_WORK/incompat.audit.Cargo.lock"
                cp "$WS_RET/vendor/h2-source.env" "$TMPDIR_WORK/incompat.h2-source.env"
                expect_fail "(1d) --vendored fails when higher locked ${HIGH_VER} leaves ${LOW_VER} patch unused" "[switch-resolve]" \
                    "$WS_RET/scripts/h2-use-registry.sh" --vendored
                for pair in \
                    "Cargo.toml:incompat.Cargo.toml" \
                    "Cargo.lock:incompat.Cargo.lock" \
                    "vendor/h2-audit/Cargo.toml:incompat.audit.Cargo.toml" \
                    "vendor/h2-audit/Cargo.lock:incompat.audit.Cargo.lock" \
                    "vendor/h2-source.env:incompat.h2-source.env"; do
                    rel="${pair%%:*}"
                    sav="${pair##*:}"
                    if ! diff -u "$TMPDIR_WORK/$sav" "$WS_RET/$rel" >/dev/null 2>&1; then
                        fail "(1d) failed --vendored rollback mutated tracked file '$rel'"
                    fi
                done
                printf '  PASS (expected ok):          (1d) failed --vendored preserved all 5 tracked files intact\n'
            fi
        done
    fi

    # Upstream sparse-index signal & advisory-db revision checks (when cargo-deny is installed).
    if cargo deny --version >/dev/null 2>&1; then
        expect_pass "(3a/b) audit-vendor-h2 passes with matching sparse index and real DB rev" \
            env H2_SPARSE_INDEX_FILE="$IDX_OK" "$C_SWITCH/scripts/audit-vendor-h2.sh"

        IDX_YANKED="$TMPDIR_WORK/index-yanked.ndjson"
        printf '{"name":"h2","vers":"%s","cksum":"%s","yanked":true}\n' "$VENDORED_VERSION" "$VENDORED_SHA" > "$IDX_YANKED"
        expect_fail "(3a) audit-vendor-h2 rejects yanked pinned version" "[audit-yank]" \
            env H2_SPARSE_INDEX_FILE="$IDX_YANKED" "$C_SWITCH/scripts/audit-vendor-h2.sh"

        IDX_NEWER="$TMPDIR_WORK/index-newer.ndjson"
        printf '{"name":"h2","vers":"%s","cksum":"%s","yanked":false}\n' "$VENDORED_VERSION" "$VENDORED_SHA" > "$IDX_NEWER"
        # A synthetic version strictly greater than VENDORED_VERSION that no real release or review
        # entry carries, keeping this fixture independent of vendor/README.md's real review log.
        printf '{"name":"h2","vers":"%s","cksum":"1111111111111111111111111111111111111111111111111111111111111111","yanked":false}\n' "$SYNTH_NEWER_VER" >> "$IDX_NEWER"
        expect_fail "(3a) audit-vendor-h2 rejects unreviewed newer 0.4.x release" "[audit-newer]" \
            env H2_SPARSE_INDEX_FILE="$IDX_NEWER" "$C_SWITCH/scripts/audit-vendor-h2.sh"

        # Recording a dated review entry in vendor/README.md makes the check pass again.
        cp "$C_SWITCH/vendor/README.md" "$TMPDIR_WORK/readme.saved"
        awk -v newver="$SYNTH_NEWER_VER" '
        { print }
        /^## Upstream Release Review Log$/ {
            print ""
            printf "- `%s` (2026-11-25): reviewed, not needed -- synthetic test review entry for verifier\n", newver
        }
        ' "$TMPDIR_WORK/readme.saved" > "$C_SWITCH/vendor/README.md"
        expect_pass "(3a) audit-vendor-h2 accepts newer 0.4.x once dated review is recorded in vendor/README.md" \
            env H2_SPARSE_INDEX_FILE="$IDX_NEWER" "$C_SWITCH/scripts/audit-vendor-h2.sh"
        cp "$TMPDIR_WORK/readme.saved" "$C_SWITCH/vendor/README.md"

        # Advisory-db revision check: positive control runs cargo-deny against a temp db-path
        # containing ONE real RustSec checkout (passes); negative fixture adds a second git dir
        # with the same origin URL so cargo-deny STILL SUCCEEDS (`advisories ok`) and ONLY the
        # revision verification stage (`[audit-db-rev]`) fails!
        cp "$C_SWITCH/deny.toml" "$TMPDIR_WORK/deny.saved"
        TEMP_DB_DIR="$TMPDIR_WORK/temp-advisory-db"
        mkdir -p "$TEMP_DB_DIR"
        if [ -d "$HOME/.cargo/advisory-db" ]; then
            cp -R "$HOME/.cargo/advisory-db/." "$TEMP_DB_DIR/"
        fi
        sed "s|db-path = \"~/.cargo/advisory-db\"|db-path = \"$TEMP_DB_DIR\"|" "$TMPDIR_WORK/deny.saved" \
            > "$C_SWITCH/deny.toml"
        expect_pass "(3b) positive control: audit-vendor-h2 with single valid advisory-db checkout" \
            env H2_SPARSE_INDEX_FILE="$IDX_OK" "$C_SWITCH/scripts/audit-vendor-h2.sh"

        # Add a second git directory with the same origin URL inside TEMP_DB_DIR:
        # cargo-deny still scans its hashed checkout and prints `advisories ok`, while
        # audit-vendor-h2 fails strictly at [audit-db-rev] because revision attribution is ambiguous.
        AMBIG_CLONE="$TEMP_DB_DIR/extra-ambiguous-db"
        mkdir -p "$AMBIG_CLONE"
        git -C "$AMBIG_CLONE" init -q
        git -C "$AMBIG_CLONE" remote add origin "https://github.com/rustsec/advisory-db"
        expect_fail_with_both "(3b) audit-vendor-h2 scan succeeds ('advisories ok') but fails when DB revision is unverifiable" \
            "advisories ok" "[audit-db-rev]" \
            env H2_SPARSE_INDEX_FILE="$IDX_OK" "$C_SWITCH/scripts/audit-vendor-h2.sh"
        cp "$TMPDIR_WORK/deny.saved" "$C_SWITCH/deny.toml"
    fi
fi

printf 'test-verify-vendor-h2 OK: all positive and negative tamper checks passed\n'
