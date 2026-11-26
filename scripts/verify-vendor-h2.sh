#!/bin/sh
# Fail-closed provenance & integrity gate for vendor/h2 (and emergency registry mode).
#
# Reads vendor/h2-source.env:
#   - H2_SOURCE_MODE=vendored: verifies that vendor/h2 equals the exact
#     checksum-verified crates.io archive of h2 plus vendor/h2.patch, and
#     cross-checks vendor/h2-source.env and vendor/h2.patch against
#     vendor/README.md.
#
#     What is checked on archive members BEFORE extraction (`tar -tzf`/`-tvzf`):
#       * Non-empty archive; every member has POSIX regular-file (`-`) or
#         directory (`d`) mode (no symlinks `l`, hardlinks `h`, devices, FIFOs,
#         sockets, or special mode bits `sStT`).
#       * Member paths contain no tabs or CRs, no leading `/`, no `..` segments,
#         and stay inside `h2-<version>/`.
#       * Note: neither macOS `bsdtar` nor Linux GNU `tar` offers a portable
#         NUL-delimited listing format for `-t`, and both escape newlines in
#         text listings; therefore newline-in-filename rejection is NOT inferred
#         from tar listing line counts — it is enforced authoritatively by the
#         argv-safe post-extraction `find . -exec` check before patch(1) runs.
#
#     What is checked on vendor/h2.patch BEFORE patch(1) runs:
#       * Strict canonical unified diff grammar: every line must belong to a
#         `--- a/<path>` (or `--- /dev/null` for allow-listed new files) /
#         `+++ b/<path>` header pair, a `@@ -a,b +c,d @@` hunk header with exact
#         line-count accounting, a context (` `), add (`+`), remove (`-`), or
#         `\ No newline at end of file` line. Indented or alternative diff
#         syntax, extra headers, prose, binary hunks, CR bytes, traversal, and
#         absolute paths all fail before patch(1) runs.
#       * Every destination must be an existing regular (non-symlink) file with
#         non-symlink ancestor directories inside the extracted tree; new files
#         are permitted only if listed under `## Patch New-File Allow-List` in
#         vendor/README.md (empty today).
#
#     What is and is NOT checked on the filesystem trees (extracted reference
#     tree and checked-out vendor/h2):
#       * Checked: physical containment (`vendor` and `vendor/h2` must be real
#         non-symlink directories resolving to `<physical repo root>/vendor` and
#         `<physical repo root>/vendor/h2`); argv-safe raw `find` check rejecting
#         literal newlines, tabs, symlinks, and any non-regular/non-directory
#         member (including root `.`); `ls -ld` check rejecting special mode bits
#         (`sStT`) on all members and rejecting any regular file with link count
#         (`st_nlink`) != 1; Git-recorded member types and owner execute bit
#         (`d`, `f:100755`, `f:100644`); required root `.` record in both
#         manifests; and byte-for-byte content equality (`cmp -s`) across a
#         non-zero count of regular files equal to the manifest's file count.
#       * Not compared: group-write/other permission bits (e.g. umask 0002 vs
#         0022), owner/group IDs, timestamps, and extended attributes/ACLs (none
#         of which Git records).
#
#   - H2_SOURCE_MODE=registry: emergency fallback mode (entered via
#     scripts/h2-use-registry.sh <version>). Verifies root Cargo.toml has no
#     vendor/h2 patch override, root Cargo.lock resolves a single crates.io h2
#     matching the pinned version and checksum in vendor/h2-source.env, and the
#     crates.io archive matches that exact SHA-256.
#
# Required tools (no cargo, no python):
#   - POSIX base utilities: sh, awk, cat, cmp, cp, diff, dirname, find, grep,
#     ls, mkdir, pwd, rm, sed, sort, wc
#   - Plus: mktemp, tar, patch, curl (when archive is not cached/provided),
#     and sha256sum or shasum
#
# On success, prints a single attestation line.

set -eu

fail() {
    printf 'ERROR: verify-vendor-h2: %s\n' "$*" >&2
    exit 1
}

for cmd in awk cat cmp cp diff dirname find grep ls mkdir mktemp patch pwd rm sed sort tar wc; do
    command -v "$cmd" >/dev/null 2>&1 || fail "[tools] required command '$cmd' not found"
done

if command -v sha256sum >/dev/null 2>&1; then
    HASH_TOOL="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    HASH_TOOL="shasum"
else
    fail "[tools] neither 'sha256sum' nor 'shasum' found"
fi

# Resolve repository root physically and enforce physical containment of vendor/.
SCRIPT_DIR=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -P -- "$SCRIPT_DIR/.." && pwd -P)

if [ -e "$REPO_ROOT/.h2-switch-journal" ] || [ -L "$REPO_ROOT/.h2-switch-journal" ]; then
    fail "[switch-journal] interrupted h2 switch detected ($REPO_ROOT/.h2-switch-journal exists); run ./scripts/h2-use-registry.sh --recover"
fi

VENDOR_PARENT="$REPO_ROOT/vendor"
SOURCE_ENV="$VENDOR_PARENT/h2-source.env"
VENDOR_DIR="$VENDOR_PARENT/h2"
PATCH_FILE="$VENDOR_PARENT/h2.patch"
README_FILE="$VENDOR_PARENT/README.md"

[ -d "$VENDOR_PARENT" ] && [ ! -L "$VENDOR_PARENT" ] || \
    fail "[containment] vendor must be a real directory (not a symlink)"
PHYS_VENDOR_PARENT=$(CDPATH= cd -P -- "$VENDOR_PARENT" && pwd -P)
[ "$PHYS_VENDOR_PARENT" = "$REPO_ROOT/vendor" ] || \
    fail "[containment] vendor physical path '$PHYS_VENDOR_PARENT' != '$REPO_ROOT/vendor'"

[ -f "$SOURCE_ENV" ] && [ ! -L "$SOURCE_ENV" ] || \
    fail "[source-env] vendor/h2-source.env must be a regular file (not a symlink)"

# Strictly parse vendor/h2-source.env without executing it (mawk/POSIX-awk safe: no {n} quantifiers).
if ! awk '
/^[ \t]*#/ || /^[ \t]*$/ { next }
/^H2_SOURCE_MODE=(vendored|registry)$/ { mode++; next }
/^H2_VERSION=[0-9]+\.[0-9]+\.[0-9]+$/ { ver++; next }
/^H2_ARCHIVE_SHA256=[0-9a-f]+$/ {
    if (length($0) == 82) {
        sha++
        next
    }
}
{
    printf("ERROR: verify-vendor-h2: [source-env] invalid line %d in vendor/h2-source.env: %s\n", NR, $0) > "/dev/stderr"
    exit 1
}
END {
    if (mode != 1 || ver != 1 || sha != 1) {
        printf("ERROR: verify-vendor-h2: [source-env] vendor/h2-source.env must define H2_SOURCE_MODE, H2_VERSION, H2_ARCHIVE_SHA256 exactly once\n") > "/dev/stderr"
        exit 1
    }
}
' "$SOURCE_ENV"; then
    fail "[source-env] vendor/h2-source.env validation failed"
fi

H2_SOURCE_MODE=$(sed -n 's/^H2_SOURCE_MODE=//p' "$SOURCE_ENV")
H2_VERSION=$(sed -n 's/^H2_VERSION=//p' "$SOURCE_ENV")
H2_ARCHIVE_SHA256=$(sed -n 's/^H2_ARCHIVE_SHA256=//p' "$SOURCE_ENV")
H2_ARCHIVE_URL="https://static.crates.io/crates/h2/h2-${H2_VERSION}.crate"

TMPDIR_WORK=$(mktemp -d "${TMPDIR:-/tmp}/verify-vendor-h2.XXXXXX")
cleanup() {
    rm -rf "$TMPDIR_WORK"
}
trap cleanup EXIT HUP INT TERM

sha256_file() {
    target="$1"
    out_file="$TMPDIR_WORK/sha.out"
    if [ "$HASH_TOOL" = "sha256sum" ]; then
        sha256sum "$target" > "$out_file" || fail "[hash] sha256sum failed on $target"
    else
        shasum -a 256 "$target" > "$out_file" || fail "[hash] shasum failed on $target"
    fi
    IFS=' ' read -r digest _rest < "$out_file" || fail "[hash] failed to read digest for $target"
    [ "${#digest}" -eq 64 ] || fail "[hash] unexpected digest length for $target: '$digest'"
    printf '%s\n' "$digest"
}

obtain_and_verify_archive() {
    dest="$1"
    archive_found=0
    if [ -n "${H2_CRATE_ARCHIVE:-}" ]; then
        [ -f "$H2_CRATE_ARCHIVE" ] || fail "[archive-fetch] H2_CRATE_ARCHIVE='$H2_CRATE_ARCHIVE' does not exist"
        cp "$H2_CRATE_ARCHIVE" "$dest"
        archive_found=1
    else
        cargo_cache_base="${CARGO_HOME:-$HOME/.cargo}/registry/cache"
        if [ -d "$cargo_cache_base" ]; then
            for candidate in "$cargo_cache_base"/*/"h2-${H2_VERSION}.crate"; do
                if [ -f "$candidate" ]; then
                    cand_sha=$(sha256_file "$candidate")
                    if [ "$cand_sha" = "$H2_ARCHIVE_SHA256" ]; then
                        cp "$candidate" "$dest"
                        archive_found=1
                        break
                    else
                        fail "[archive-sha] cached archive '$candidate' has SHA-256 '$cand_sha', expected '$H2_ARCHIVE_SHA256'"
                    fi
                fi
            done
        fi
    fi

    if [ "$archive_found" -eq 0 ]; then
        command -v curl >/dev/null 2>&1 || fail "[archive-fetch] upstream archive not in cargo cache and 'curl' not found"
        curl -fsSL --proto '=https' --tlsv1.2 -o "$dest" "$H2_ARCHIVE_URL" || \
            fail "[archive-fetch] failed to download $H2_ARCHIVE_URL"
    fi

    actual_sha=$(sha256_file "$dest")
    [ "$actual_sha" = "$H2_ARCHIVE_SHA256" ] || \
        fail "[archive-sha] upstream archive SHA-256 '$actual_sha' != pinned '$H2_ARCHIVE_SHA256'"
}

if [ "$H2_SOURCE_MODE" = "registry" ]; then
    CARGO_TOML="$REPO_ROOT/Cargo.toml"
    CARGO_LOCK="$REPO_ROOT/Cargo.lock"
    [ -f "$CARGO_TOML" ] && [ ! -L "$CARGO_TOML" ] || fail "[registry-toml] missing $CARGO_TOML"
    [ -f "$CARGO_LOCK" ] && [ ! -L "$CARGO_LOCK" ] || fail "[registry-lock] missing $CARGO_LOCK"

    if grep -E '^[[:space:]]*h2[[:space:]]*=[[:space:]]*\{.*vendor/h2' "$CARGO_TOML" >/dev/null 2>&1; then
        fail "[registry-toml] Cargo.toml still contains vendor/h2 patch override while H2_SOURCE_MODE=registry"
    fi

    # Verify Cargo.lock records exactly one h2 entry matching the pinned registry identity.
    if ! awk -v exp_ver="$H2_VERSION" -v exp_sha="$H2_ARCHIVE_SHA256" '
    function flush_pkg() {
        if (in_pkg && name == "h2") {
            count++
            if (ver != exp_ver) {
                printf("ERROR: verify-vendor-h2: [registry-lock] Cargo.lock h2 version %s != %s\n", ver, exp_ver) > "/dev/stderr"
                bad = 1
            }
            if (src != "registry+https://github.com/rust-lang/crates.io-index") {
                printf("ERROR: verify-vendor-h2: [registry-lock] Cargo.lock h2 source %s != crates.io\n", src) > "/dev/stderr"
                bad = 1
            }
            if (chk != exp_sha) {
                printf("ERROR: verify-vendor-h2: [registry-lock] Cargo.lock h2 checksum %s != %s\n", chk, exp_sha) > "/dev/stderr"
                bad = 1
            }
        }
        in_pkg = 0; name = ""; ver = ""; src = ""; chk = ""
    }
    /^\[\[package\]\]/ { flush_pkg(); in_pkg = 1; next }
    /^\[/ { flush_pkg(); next }
    in_pkg && /^name = "/ { v = $0; sub(/^name = "/, "", v); sub(/"$/, "", v); name = v; next }
    in_pkg && /^version = "/ { v = $0; sub(/^version = "/, "", v); sub(/"$/, "", v); ver = v; next }
    in_pkg && /^source = "/ { v = $0; sub(/^source = "/, "", v); sub(/"$/, "", v); src = v; next }
    in_pkg && /^checksum = "/ { v = $0; sub(/^checksum = "/, "", v); sub(/"$/, "", v); chk = v; next }
    END {
        flush_pkg()
        if (bad) exit 1
        if (count != 1) {
            printf("ERROR: verify-vendor-h2: [registry-lock] expected exactly 1 h2 package in Cargo.lock, found %d\n", count) > "/dev/stderr"
            exit 1
        }
    }
    ' "$CARGO_LOCK"; then
        fail "[registry-lock] Cargo.lock registry verification failed"
    fi

    ARCHIVE_LOCAL="$TMPDIR_WORK/h2-${H2_VERSION}.crate"
    obtain_and_verify_archive "$ARCHIVE_LOCAL"

    printf 'vendor/h2 OK (registry mode): crates.io h2 %s sha256 %s (Cargo.lock + archive verified; COPY_LIMIT patch inactive)\n' \
        "$H2_VERSION" "$H2_ARCHIVE_SHA256"
    exit 0
fi

# Vendored mode: enforce physical containment of vendor/h2 and validate archive + patch + tree.
[ -d "$VENDOR_DIR" ] && [ ! -L "$VENDOR_DIR" ] || \
    fail "[containment] vendor/h2 must be a real directory (not a symlink)"
PHYS_VENDOR_DIR=$(CDPATH= cd -P -- "$VENDOR_DIR" && pwd -P)
[ "$PHYS_VENDOR_DIR" = "$REPO_ROOT/vendor/h2" ] || \
    fail "[containment] vendor/h2 physical path '$PHYS_VENDOR_DIR' != '$REPO_ROOT/vendor/h2'"

[ -f "$PATCH_FILE" ] && [ ! -L "$PATCH_FILE" ] || \
    fail "[patch-file] vendor/h2.patch must be a regular file (not a symlink)"
[ -f "$README_FILE" ] && [ ! -L "$README_FILE" ] || \
    fail "[readme] vendor/README.md must be a regular file (not a symlink)"

# Extract and cross-check pinned metadata in vendor/README.md (no unchecked producer pipes).
extract_readme_field() {
    label="$1"
    matches_file="$TMPDIR_WORK/readme.match"
    grep -F -- "$label" "$README_FILE" > "$matches_file" || true
    count=$(awk 'NF > 0 { c++ } END { print c + 0 }' "$matches_file")
    [ "$count" -eq 1 ] || fail "[readme] vendor/README.md must contain exactly one '$label' line (found $count)"
    sed -n 's/.*`\([^`]*\)`[[:space:]]*$/\1/p' "$matches_file"
}

README_VERSION=$(extract_readme_field "- **Upstream crate:**")
[ "$README_VERSION" = "$H2_VERSION" ] || \
    fail "[readme] vendor/README.md upstream version '$README_VERSION' != vendor/h2-source.env '$H2_VERSION'"

README_ARCHIVE_SHA=$(extract_readme_field "- **Upstream archive SHA-256:**")
[ "$README_ARCHIVE_SHA" = "$H2_ARCHIVE_SHA256" ] || \
    fail "[readme] vendor/README.md archive SHA-256 '$README_ARCHIVE_SHA' != vendor/h2-source.env '$H2_ARCHIVE_SHA256'"

README_PATCH_SHA=$(extract_readme_field "- **Patch SHA-256:**")
case "$README_PATCH_SHA" in
    *[!0-9a-f]*|"")
        fail "[readme] vendor/README.md patch SHA-256 is malformed: '$README_PATCH_SHA'"
        ;;
esac
[ "${#README_PATCH_SHA}" -eq 64 ] || \
    fail "[readme] vendor/README.md patch SHA-256 must be 64 hex characters (got ${#README_PATCH_SHA})"

ACTUAL_PATCH_SHA=$(sha256_file "$PATCH_FILE")
[ "$ACTUAL_PATCH_SHA" = "$README_PATCH_SHA" ] || \
    fail "[patch-sha] vendor/h2.patch SHA-256 '$ACTUAL_PATCH_SHA' != vendor/README.md '$README_PATCH_SHA'"

# Parse the explicit new-file allow-list from vendor/README.md (empty today).
PATCH_ALLOWLIST="$TMPDIR_WORK/patch.allowlist"
if ! awk -v out_file="$PATCH_ALLOWLIST" '
function check_rel(p,    n, i, parts) {
    if (p == "" || index(p, "\t") > 0 || index(p, "\r") > 0) return 0
    if (substr(p, 1, 1) == "/" || substr(p, length(p), 1) == "/") return 0
    if (index(p, "//") > 0) return 0
    n = split(p, parts, "/")
    for (i = 1; i <= n; i++) {
        if (parts[i] == "" || parts[i] == "." || parts[i] == "..") return 0
    }
    return 1
}
BEGIN {
    in_sec = 0
    found_sec = 0
    printf("") > out_file
}
/^## Patch New-File Allow-List[ \t]*$/ {
    found_sec++
    in_sec = 1
    next
}
/^## / {
    if (in_sec) in_sec = 0
    next
}
in_sec && /^- / {
    if ($0 !~ /^- `[^`]+`[ \t]*$/) {
        printf("ERROR: verify-vendor-h2: [readme-allowlist] malformed allow-list entry at line %d: %s\n", NR, $0) > "/dev/stderr"
        exit 1
    }
    p = $0
    sub(/^- `/, "", p)
    sub(/`[ \t]*$/, "", p)
    if (!check_rel(p)) {
        printf("ERROR: verify-vendor-h2: [readme-allowlist] unsafe allow-list path at line %d: %s\n", NR, p) > "/dev/stderr"
        exit 1
    }
    print p >> out_file
}
END {
    close(out_file)
    if (found_sec != 1) {
        printf("ERROR: verify-vendor-h2: [readme-allowlist] vendor/README.md must contain exactly one '\''## Patch New-File Allow-List'\'' section (found %d)\n", found_sec) > "/dev/stderr"
        exit 1
    }
}
' "$README_FILE"; then
    fail "[readme-allowlist] failed to parse Patch New-File Allow-List from vendor/README.md"
fi

# Strictly validate vendor/h2.patch as a canonical unified diff BEFORE invoking patch(1).
# Every single line must belong to:
#   - file header pair: `--- a/<relpath>` (or `--- /dev/null` for allow-listed new files)
#     followed immediately by `+++ b/<relpath>`
#   - hunk header: `@@ -a(,b)? +c(,d)? @@( ...)?`
#   - hunk body lines matching exact old/new counts (` `, `-`, `+`)
#   - `\ No newline at end of file` marker immediately after a hunk body line
# Anything else (indented/alternative diff syntax, prose, Index:, git headers, binary diffs,
# traversal, absolute paths, CR bytes, truncated hunks) fails closed before patch(1) runs.
PATCH_TARGETS="$TMPDIR_WORK/patch.targets"
if ! awk -v allow_file="$PATCH_ALLOWLIST" -v targets_file="$PATCH_TARGETS" '
function fail_syntax(msg) {
    printf("ERROR: verify-vendor-h2: [patch-syntax] line %d: %s\n", NR, msg) > "/dev/stderr"
    bad = 1
    exit 1
}
function fail_dest(msg) {
    printf("ERROR: verify-vendor-h2: [patch-dest] line %d: %s\n", NR, msg) > "/dev/stderr"
    bad = 1
    exit 1
}
function check_prefixed_path(raw, prefix,    rest, n, i, parts) {
    if (index(raw, "\t") > 0 || index(raw, "\r") > 0) fail_syntax("tab or CR in patch path: " raw)
    if (index(raw, prefix) != 1) fail_syntax("path must start with " prefix " (got " raw ")")
    rest = substr(raw, length(prefix) + 1)
    if (rest == "") fail_syntax("empty path after " prefix)
    if (substr(rest, 1, 1) == "/") fail_syntax("absolute path after " prefix ": " raw)
    if (substr(rest, length(rest), 1) == "/") fail_syntax("trailing slash in path: " raw)
    if (index(rest, "//") > 0) fail_syntax("double slash in path: " raw)
    n = split(rest, parts, "/")
    for (i = 1; i <= n; i++) {
        if (parts[i] == "" || parts[i] == "." || parts[i] == "..") {
            fail_syntax("unsafe path segment in " raw)
        }
    }
    return rest
}
function start_file(line,    raw) {
    raw = substr(line, 5)
    if (raw == "/dev/null") {
        cur_old = "/dev/null"
    } else {
        cur_old = check_prefixed_path(raw, "a/")
    }
    state = "EXPECT_PLUS"
}
function start_hunk(line,    hdr, n_sp, sp, n_o, op, n_n, np, old_start, old_count, new_start, new_count) {
    hdr = line
    sub(/^@@ -/, "", hdr)
    sub(/ @@.*$/, "", hdr)
    n_sp = split(hdr, sp, " ")
    if (n_sp != 2 || substr(sp[2], 1, 1) != "+") fail_syntax("malformed hunk header: " line)
    n_o = split(sp[1], op, ",")
    old_start = op[1] + 0
    old_count = (n_o == 2 ? op[2] + 0 : 1)
    n_n = split(substr(sp[2], 2), np, ",")
    new_start = np[1] + 0
    new_count = (n_n == 2 ? np[2] + 0 : 1)
    if (old_count == 0 && new_count == 0) fail_syntax("empty hunk header: " line)
    if (cur_is_new && (old_start != 0 || old_count != 0)) {
        fail_syntax("new-file hunk must begin at -0,0: " line)
    }
    hunks_in_file++
    rem_old = old_count
    rem_new = new_count
    prev_kind = ""
    no_nl_old = 0
    no_nl_new = 0
    state = "IN_HUNK"
}
BEGIN {
    while ((getline al < allow_file) > 0) {
        if (al != "") allow_new[al] = 1
    }
    close(allow_file)
    printf("") > targets_file
    state = "EXPECT_FILE"
    file_count = 0
    hunks_in_file = 0
    bad = 0
}
{
    if (index($0, "\r") > 0) fail_syntax("CR byte is forbidden in canonical unified diff")

    if (state == "EXPECT_FILE") {
        if ($0 ~ /^--- /) {
            start_file($0)
            next
        }
        fail_syntax("expected canonical '\''--- a/<path>'\'' file header (got: " $0 ")")
    }

    if (state == "EXPECT_PLUS") {
        if ($0 !~ /^\+\+\+ /) {
            fail_syntax("expected canonical '\''+++ b/<path>'\'' immediately after '\''---'\'' (got: " $0 ")")
        }
        cur_new = check_prefixed_path(substr($0, 5), "b/")
        if (cur_old == "/dev/null") {
            cur_is_new = 1
            if (!(cur_new in allow_new)) {
                fail_dest("new file destination '\''" cur_new "'\'' is not listed in vendor/README.md Patch New-File Allow-List")
            }
        } else {
            if (cur_old != cur_new) {
                fail_syntax("mismatched file header paths (" cur_old " vs " cur_new ")")
            }
            cur_is_new = 0
        }
        if (cur_new in seen_target) {
            fail_syntax("duplicate file section for " cur_new)
        }
        seen_target[cur_new] = 1
        printf("%s\t%s\n", (cur_is_new ? "new" : "existing"), cur_new) >> targets_file
        file_count++
        hunks_in_file = 0
        state = "EXPECT_HUNK"
        next
    }

    if (state == "EXPECT_HUNK" || state == "AFTER_HUNK") {
        if (state == "AFTER_HUNK" && $0 == "\\ No newline at end of file") {
            if (prev_kind == "del" && !no_nl_old) { no_nl_old = 1; prev_kind = ""; next }
            if (prev_kind == "add" && !no_nl_new) { no_nl_new = 1; prev_kind = ""; next }
            if (prev_kind == "ctx" && !no_nl_old && !no_nl_new) { no_nl_old = 1; no_nl_new = 1; prev_kind = ""; next }
            fail_syntax("misplaced '\''\\ No newline at end of file'\'' marker")
        }
        if ($0 ~ /^@@ -[0-9]+(,[0-9]+)? \+[0-9]+(,[0-9]+)? @@( .*)?$/) {
            start_hunk($0)
            next
        }
        if (state == "AFTER_HUNK" && $0 ~ /^--- /) {
            start_file($0)
            next
        }
        fail_syntax("non-canonical line outside hunk (got: " $0 ")")
    }

    if (state == "IN_HUNK") {
        if ($0 == "\\ No newline at end of file") {
            if (prev_kind == "del" && !no_nl_old) { no_nl_old = 1; prev_kind = ""; next }
            if (prev_kind == "add" && !no_nl_new) { no_nl_new = 1; prev_kind = ""; next }
            if (prev_kind == "ctx" && !no_nl_old && !no_nl_new) { no_nl_old = 1; no_nl_new = 1; prev_kind = ""; next }
            fail_syntax("misplaced '\''\\ No newline at end of file'\'' marker")
        }
        c = substr($0, 1, 1)
        if (c == " ") {
            if (rem_old <= 0 || rem_new <= 0) fail_syntax("excess context line in hunk")
            rem_old--; rem_new--; prev_kind = "ctx"
        } else if (c == "-") {
            if (rem_old <= 0) fail_syntax("excess removal line in hunk")
            rem_old--; prev_kind = "del"
        } else if (c == "+") {
            if (rem_new <= 0) fail_syntax("excess addition line in hunk")
            rem_new--; prev_kind = "add"
        } else {
            fail_syntax("non-canonical line inside hunk (expected '\'' '\'', '\''+'\'', '\''-'\'', or '\''\\ No newline'\''; got: " $0 ")")
        }
        if (rem_old == 0 && rem_new == 0) {
            state = "AFTER_HUNK"
        }
        next
    }
}
END {
    close(targets_file)
    if (bad) exit 1
    if (state != "AFTER_HUNK" || file_count < 1 || hunks_in_file < 1) {
        printf("ERROR: verify-vendor-h2: [patch-syntax] incomplete or empty canonical unified diff (state=%s, files=%d, hunks=%d)\n", state, file_count, hunks_in_file) > "/dev/stderr"
        exit 1
    }
}
' "$PATCH_FILE"; then
    fail "[patch-validate] vendor/h2.patch failed canonical unified diff validation"
fi

ARCHIVE_LOCAL="$TMPDIR_WORK/h2-${H2_VERSION}.crate"
obtain_and_verify_archive "$ARCHIVE_LOCAL"
ACTUAL_ARCHIVE_SHA="$H2_ARCHIVE_SHA256"

# Pre-extraction archive checks (`tar -tzf` / `tar -tvzf`):
#   - reject symlinks (l), hardlinks (h), devices/FIFOs/sockets, special mode bits
#   - reject absolute paths, '..' traversal, paths outside h2-<version>/, tabs, CRs
# Note: newline-in-filename rejection is NOT inferred from listing line counts (both BSD and
# GNU tar escape newlines in text listings); literal newline names are rejected authoritatively
# by the post-extraction argv-safe `find . -exec` check before patch(1) runs.
TAR_LIST="$TMPDIR_WORK/tar.list"
TAR_VLIST="$TMPDIR_WORK/tar.vlist"
LC_ALL=C tar -tzf "$ARCHIVE_LOCAL" > "$TAR_LIST" || fail "[archive-list] failed to list $ARCHIVE_LOCAL"
LC_ALL=C tar -tvzf "$ARCHIVE_LOCAL" > "$TAR_VLIST" || fail "[archive-list] failed to verbosely list $ARCHIVE_LOCAL"

TAR_COUNT=$(awk 'END { print NR + 0 }' "$TAR_LIST")
TAR_VCOUNT=$(awk 'END { print NR + 0 }' "$TAR_VLIST")
[ "$TAR_COUNT" -gt 0 ] || fail "[archive-list] archive is empty"
[ "$TAR_VCOUNT" -gt 0 ] || fail "[archive-list] verbose archive listing is empty"

if ! awk '
{
    m = substr($1, 1, 10)
    if (m !~ /^[-d][r-][w-][x-][r-][w-][x-][r-][w-][x-]$/) {
        printf("ERROR: verify-vendor-h2: [archive-type] archive contains disallowed member type/mode at entry %d: %s\n", NR, $0) > "/dev/stderr"
        exit 1
    }
}
' "$TAR_VLIST"; then
    fail "[archive-type] archive contains symlink, hardlink, special file, special mode bit, or malformed entry"
fi

if ! awk -v root="h2-${H2_VERSION}" '
{
    if ($0 == "" || index($0, "\t") > 0 || index($0, "\r") > 0) {
        printf("ERROR: verify-vendor-h2: [archive-path] archive member name contains disallowed control/tab char at entry %d\n", NR) > "/dev/stderr"
        exit 1
    }
    if (substr($0, 1, 1) == "/") {
        printf("ERROR: verify-vendor-h2: [archive-path] archive contains absolute path: %s\n", $0) > "/dev/stderr"
        exit 1
    }
    if ($0 != root && $0 != root "/" && index($0, root "/") != 1) {
        printf("ERROR: verify-vendor-h2: [archive-path] archive member escapes %s/: %s\n", root, $0) > "/dev/stderr"
        exit 1
    }
    n = split($0, parts, "/")
    for (i = 1; i <= n; i++) {
        if (parts[i] == "..") {
            printf("ERROR: verify-vendor-h2: [archive-path] archive contains traversal segment: %s\n", $0) > "/dev/stderr"
            exit 1
        }
    }
}
' "$TAR_LIST"; then
    fail "[archive-path] archive contains unsafe member path"
fi

UNPACK_DIR="$TMPDIR_WORK/unpack"
mkdir -p "$UNPACK_DIR"
tar -xzf "$ARCHIVE_LOCAL" -C "$UNPACK_DIR" || fail "[archive-unpack] failed to unpack $ARCHIVE_LOCAL"

EXPECTED_DIR="$UNPACK_DIR/h2-${H2_VERSION}"
[ -d "$EXPECTED_DIR" ] && [ ! -L "$EXPECTED_DIR" ] || \
    fail "[archive-unpack] unpacked archive missing expected real root directory 'h2-${H2_VERSION}'"

# Ensure archive unpacked only that single root directory (no unchecked producer pipe).
ROOT_ENTRIES_FILE="$TMPDIR_WORK/unpack.root.entries"
find "$UNPACK_DIR" -mindepth 1 -maxdepth 1 > "$ROOT_ENTRIES_FILE" || \
    fail "[archive-unpack] find failed on $UNPACK_DIR"
ROOT_ENTRIES=$(awk 'END { print NR + 0 }' "$ROOT_ENTRIES_FILE")
[ "$ROOT_ENTRIES" -eq 1 ] || fail "[archive-unpack] unpacked archive has $ROOT_ENTRIES top-level entries (expected 1)"

NL=$(printf '\n_')
NL=${NL%_}
TAB=$(printf '\t')

# Argv-safe raw member check (rejects literal newlines, tabs, symlinks, non-regular/non-dir).
check_raw_tree() {
    dir="$1"
    (
        CDPATH= cd -P -- "$dir"
        find . -exec sh -c '
            nl="$1"
            tab="$2"
            shift 2
            for p do
                case "$p" in
                    *"$nl"*)
                        printf "ERROR: verify-vendor-h2: [tree-raw] member name contains literal newline\n" >&2
                        exit 1
                        ;;
                    *"$tab"*)
                        printf "ERROR: verify-vendor-h2: [tree-raw] member name contains tab\n" >&2
                        exit 1
                        ;;
                esac
                if [ -L "$p" ]; then
                    printf "ERROR: verify-vendor-h2: [tree-symlink] symlink member forbidden: %s\n" "$p" >&2
                    exit 1
                fi
                if [ ! -f "$p" ] && [ ! -d "$p" ]; then
                    printf "ERROR: verify-vendor-h2: [tree-type] non-regular/non-directory member forbidden: %s\n" "$p" >&2
                    exit 1
                fi
            done
        ' sh "$NL" "$TAB" {} +
    ) || fail "[tree-raw] raw tree validation failed for $dir"
}

# Validate unpacked archive tree BEFORE patch(1) runs (authoritative check for newline names,
# symlinks, and special files from the archive).
check_raw_tree "$EXPECTED_DIR"

# Verify every patch destination inside the extracted tree BEFORE invoking patch(1):
#   - every ancestor component must be a real (non-symlink) directory inside EXPECTED_DIR
#   - existing targets must be existing regular (non-symlink) files
#   - new targets (already checked against vendor/README.md allow-list) must not already exist
PATCH_TARGET_COUNT=0
while IFS="$TAB" read -r pkind rel; do
    [ -n "$pkind" ] && [ -n "$rel" ] || fail "[patch-dest] malformed target record"
    cur="$EXPECTED_DIR"
    rem="$rel"
    while :; do
        case "$rem" in
            */*)
                seg=${rem%%/*}
                rem=${rem#*/}
                cur="$cur/$seg"
                [ -d "$cur" ] && [ ! -L "$cur" ] || \
                    fail "[patch-dest] destination ancestor '$cur' is not a real directory in unpacked tree"
                ;;
            *)
                break
                ;;
        esac
    done
    target="$EXPECTED_DIR/$rel"
    case "$pkind" in
        existing)
            [ -f "$target" ] && [ ! -L "$target" ] || \
                fail "[patch-dest] destination '$rel' is not an existing regular file in unpacked tree"
            ;;
        new)
            [ ! -e "$target" ] && [ ! -L "$target" ] || \
                fail "[patch-dest] allow-listed new-file destination '$rel' already exists in unpacked tree"
            ;;
        *)
            fail "[patch-dest] unknown patch target kind '$pkind'"
            ;;
    esac
    PATCH_TARGET_COUNT=$((PATCH_TARGET_COUNT + 1))
done < "$PATCH_TARGETS"
[ "$PATCH_TARGET_COUNT" -ge 1 ] || fail "[patch-dest] patch has zero validated destinations"

# Apply vendor/h2.patch strictly (batch/non-interactive, zero fuzz, reject reversed patches, no offsets).
PATCH_OUT="$TMPDIR_WORK/patch.out"
if ! patch -t -p1 -F 0 -N -d "$EXPECTED_DIR" < "$PATCH_FILE" > "$PATCH_OUT" 2>&1; then
    cat "$PATCH_OUT" >&2
    fail "[patch-apply] failed to apply vendor/h2.patch cleanly to upstream h2-${H2_VERSION}"
fi
if grep -iE 'fuzz|offset|reject|skip' "$PATCH_OUT" >/dev/null 2>&1; then
    cat "$PATCH_OUT" >&2
    fail "[patch-apply] vendor/h2.patch did not apply with zero fuzz and zero offset"
fi

# Confirm patch did not create anything beside EXPECTED_DIR.
POST_PATCH_FILE="$TMPDIR_WORK/postpatch.root.entries"
find "$UNPACK_DIR" -mindepth 1 -maxdepth 1 > "$POST_PATCH_FILE" || \
    fail "[patch-apply] find failed after patch"
POST_PATCH_ENTRIES=$(awk 'END { print NR + 0 }' "$POST_PATCH_FILE")
[ "$POST_PATCH_ENTRIES" -eq 1 ] || \
    fail "[patch-apply] patch created unexpected entries outside h2-${H2_VERSION} (found $POST_PATCH_ENTRIES)"

# Build a sorted manifest comparing exactly what Git records (including root `.`),
# plus link count == 1 on every regular file. Every producer's exit status is checked via
# temporary files (never `find | sort | while`).
build_manifest() {
    dir="$1"
    out="$2"
    tag="$3"
    raw_list="$TMPDIR_WORK/${tag}.find"
    sorted_list="$TMPDIR_WORK/${tag}.sorted"
    ls_out="$TMPDIR_WORK/${tag}.ls"

    check_raw_tree "$dir"

    (
        CDPATH= cd -P -- "$dir"
        find .
    ) > "$raw_list" || fail "[manifest-find] find failed for $dir"

    LC_ALL=C sort "$raw_list" > "$sorted_list" || fail "[manifest-sort] sort failed for $dir"

    : > "$out"
    saw_root=0
    entry_count=0
    while IFS= read -r rel; do
        [ -n "$rel" ] || fail "[manifest-build] empty path record in $dir"
        if [ "$rel" = "." ]; then
            saw_root=1
        fi
        LC_ALL=C ls -ld -- "$dir/$rel" > "$ls_out" || \
            fail "[manifest-ls] ls -ld failed for '$rel' in $dir"
        IFS=' ' read -r mode nlink _rest < "$ls_out" || \
            fail "[manifest-ls] failed to parse ls -ld output for '$rel' in $dir"
        # Keep only the 10-char POSIX mode string (strip macOS '@'/'+' or SELinux '.' suffix).
        mode10=$(printf '%.10s' "$mode")
        case "$mode10" in
            *[sStT]*)
                fail "[tree-mode] special mode bits forbidden on $rel ($mode10)"
                ;;
            d?????????)
                [ -d "$dir/$rel" ] && [ ! -L "$dir/$rel" ] || \
                    fail "[tree-type] directory check failed on $rel"
                printf 'd\t%s\n' "$rel" >> "$out"
                ;;
            -??x??????)
                [ -f "$dir/$rel" ] && [ ! -L "$dir/$rel" ] || \
                    fail "[tree-type] regular file check failed on $rel"
                [ "$nlink" = "1" ] || \
                    fail "[tree-nlink] regular file has link count $nlink != 1: $rel"
                printf 'f:100755\t%s\n' "$rel" >> "$out"
                ;;
            -??-??????)
                [ -f "$dir/$rel" ] && [ ! -L "$dir/$rel" ] || \
                    fail "[tree-type] regular file check failed on $rel"
                [ "$nlink" = "1" ] || \
                    fail "[tree-nlink] regular file has link count $nlink != 1: $rel"
                printf 'f:100644\t%s\n' "$rel" >> "$out"
                ;;
            *)
                fail "[tree-mode] disallowed member type/mode on $rel ($mode10)"
                ;;
        esac
        entry_count=$((entry_count + 1))
    done < "$sorted_list"

    [ "$saw_root" -eq 1 ] || fail "[manifest-root] manifest for $dir is missing required root record '.'"
    [ "$entry_count" -gt 0 ] || fail "[manifest-empty] manifest for $dir is empty"
}

EXPECTED_MANIFEST="$TMPDIR_WORK/expected.manifest"
ACTUAL_MANIFEST="$TMPDIR_WORK/actual.manifest"
build_manifest "$EXPECTED_DIR" "$EXPECTED_MANIFEST" "expected"
build_manifest "$PHYS_VENDOR_DIR" "$ACTUAL_MANIFEST" "actual"

# Require the root directory record `d\t.` in both manifests before comparing.
grep -Fqx "d${TAB}." "$EXPECTED_MANIFEST" || \
    fail "[manifest-root] expected manifest missing root record '.'"
grep -Fqx "d${TAB}." "$ACTUAL_MANIFEST" || \
    fail "[manifest-root] actual manifest missing root record '.'"

if ! diff -u "$EXPECTED_MANIFEST" "$ACTUAL_MANIFEST" > "$TMPDIR_WORK/manifest.diff"; then
    cat "$TMPDIR_WORK/manifest.diff" >&2
    fail "[manifest-diff] vendor/h2 tree, member types, or executable bits differ from patched upstream h2-${H2_VERSION}"
fi

MANIFEST_FILE_COUNT=$(awk -F '\t' '$1 == "f:100644" || $1 == "f:100755" { c++ } END { print c + 0 }' "$EXPECTED_MANIFEST")
[ "$MANIFEST_FILE_COUNT" -gt 0 ] || fail "[content-count] expected manifest contains zero regular files"

# Compare byte-for-byte contents of every regular file and verify the exact count compared.
CONTENT_FAILED=0
COMPARED_FILES=0
while IFS="$TAB" read -r kind rel; do
    case "$kind" in
        f:100644|f:100755)
            if ! cmp -s "$EXPECTED_DIR/$rel" "$PHYS_VENDOR_DIR/$rel"; then
                diff -u "$EXPECTED_DIR/$rel" "$PHYS_VENDOR_DIR/$rel" >&2 || true
                printf 'ERROR: verify-vendor-h2: [content-diff] content mismatch in %s\n' "$rel" >&2
                CONTENT_FAILED=1
            fi
            COMPARED_FILES=$((COMPARED_FILES + 1))
            ;;
        d)
            ;;
        *)
            fail "[manifest-build] unexpected manifest entry '$kind' for '$rel'"
            ;;
    esac
done < "$EXPECTED_MANIFEST"

[ "$CONTENT_FAILED" -eq 0 ] || fail "[content-diff] one or more files in vendor/h2 differ in content"
[ "$COMPARED_FILES" -gt 0 ] || fail "[content-count] zero regular files were compared"
[ "$COMPARED_FILES" -eq "$MANIFEST_FILE_COUNT" ] || \
    fail "[content-count] compared $COMPARED_FILES regular files != manifest file count $MANIFEST_FILE_COUNT"

printf 'vendor/h2 OK: upstream h2 %s sha256 %s + vendor/h2.patch sha256 %s (git tree: %d regular files nlink=1 + dirs incl. root, exec bit, byte contents)\n' \
    "$H2_VERSION" "$ACTUAL_ARCHIVE_SHA" "$ACTUAL_PATCH_SHA" "$COMPARED_FILES"
