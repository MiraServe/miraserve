#!/bin/sh
# Emergency source switch between MiraServe's vendored h2 patch and a fixed
# crates.io registry release (and back).
#
# Usage:
#   ./scripts/h2-use-registry.sh <version>    Switch to crates.io h2 <version>
#   ./scripts/h2-use-registry.sh --vendored   Switch back to vendored vendor/h2
#   ./scripts/h2-use-registry.sh --recover    Roll back an interrupted switch journal
#
# Stages updates to root Cargo.toml, root Cargo.lock, vendor/h2-audit/Cargo.toml,
# vendor/h2-audit/Cargo.lock, and vendor/h2-source.env in temporary files,
# verifies the RESOLVED h2 identity (`cargo metadata --locked`, unused-patch
# check, and lockfile check) BEFORE modifying any tracked file, and then commits
# all five files under a write-ahead rollback journal (`.h2-switch-journal`).
# If interrupted mid-rename, running `--recover` (or re-running any switch
# command) restores all five tracked files from their checksum-verified journal
# originals before proceeding.
#
# Switching to the registry crate disables MiraServe's COPY_LIMIT=4096 encoder
# patch (see vendor/README.md for what the patch changes).

set -eu

SPARSE_INDEX_URL="https://index.crates.io/2/h2"

fail() {
    printf 'ERROR: h2-use-registry: %s\n' "$*" >&2
    exit 1
}

usage() {
    printf 'Usage:\n  %s <version>    Switch to crates.io h2 <version>\n  %s --vendored   Switch back to vendored vendor/h2\n  %s --recover    Roll back an interrupted switch journal\n' "$0" "$0" "$0" >&2
    exit 2
}

[ "$#" -eq 1 ] || usage
ARG="$1"

for cmd in awk cargo cp grep ln mkdir mktemp mv python3 rm; do
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

CARGO_TOML="$REPO_ROOT/Cargo.toml"
CARGO_LOCK="$REPO_ROOT/Cargo.lock"
SOURCE_ENV="$REPO_ROOT/vendor/h2-source.env"
README_FILE="$REPO_ROOT/vendor/README.md"
VENDOR_DIR="$REPO_ROOT/vendor/h2"
VENDOR_TOML="$VENDOR_DIR/Cargo.toml"
AUDIT_TOML="$REPO_ROOT/vendor/h2-audit/Cargo.toml"
AUDIT_LOCK="$REPO_ROOT/vendor/h2-audit/Cargo.lock"
JOURNAL_DIR="$REPO_ROOT/.h2-switch-journal"

tracked_path_for_index() {
    case "$1" in
        1) printf '%s\n' "$CARGO_TOML" ;;
        2) printf '%s\n' "$CARGO_LOCK" ;;
        3) printf '%s\n' "$AUDIT_TOML" ;;
        4) printf '%s\n' "$AUDIT_LOCK" ;;
        5) printf '%s\n' "$SOURCE_ENV" ;;
        *) fail "[switch-journal] invalid tracked file index '$1'" ;;
    esac
}

same_dir_temp_for_index() {
    case "$1" in
        1) printf '%s\n' "$REPO_ROOT/.Cargo.toml.h2switch.$$" ;;
        2) printf '%s\n' "$REPO_ROOT/.Cargo.lock.h2switch.$$" ;;
        3) printf '%s\n' "$REPO_ROOT/vendor/h2-audit/.Cargo.toml.h2switch.$$" ;;
        4) printf '%s\n' "$REPO_ROOT/vendor/h2-audit/.Cargo.lock.h2switch.$$" ;;
        5) printf '%s\n' "$REPO_ROOT/vendor/.h2-source.env.h2switch.$$" ;;
        *) fail "[switch-journal] invalid temp file index '$1'" ;;
    esac
}

# Recover any interrupted transaction recorded in .h2-switch-journal before touching
# or staging tracked files. Idempotent: copies from orig/{1..5} via same-directory
# renames and removes the journal only after all five destinations match orig.sha256.
recover_interrupted_journal() {
    if [ ! -e "$JOURNAL_DIR" ] && [ ! -L "$JOURNAL_DIR" ]; then
        return 0
    fi
    [ -d "$JOURNAL_DIR" ] && [ ! -L "$JOURNAL_DIR" ] || \
        fail "[switch-journal] '$JOURNAL_DIR' must be a regular directory"

    if [ -f "$JOURNAL_DIR/pid" ]; then
        j_pid=$(awk 'NR==1 { print $1 }' "$JOURNAL_DIR/pid")
        case "$j_pid" in
            ''|*[!0-9]*) ;;
            *)
                if [ "$j_pid" != "$$" ] && kill -0 "$j_pid" 2>/dev/null; then
                    fail "[switch-lock] another h2-use-registry.sh process (pid $j_pid) owns $JOURNAL_DIR"
                fi
                ;;
        esac
    fi

    j_state=""
    if [ -f "$JOURNAL_DIR/state" ]; then
        j_state=$(awk 'NR==1 { print $1 }' "$JOURNAL_DIR/state")
    fi

    if [ "$j_state" = "COMMITTING" ]; then
        [ -f "$JOURNAL_DIR/orig.sha256" ] || \
            fail "[switch-journal] interrupted COMMITTING journal missing orig.sha256"
        for idx in 1 2 3 4 5; do
            orig_f="$JOURNAL_DIR/orig/$idx"
            [ -f "$orig_f" ] || fail "[switch-journal] missing backup file $orig_f"
            exp_sha=$(awk -v k="$idx" '$1 == k { print $2 }' "$JOURNAL_DIR/orig.sha256")
            [ "${#exp_sha}" -eq 64 ] || \
                fail "[switch-journal] missing/malformed backup digest for index $idx"
            got_sha=$(sha256_file "$orig_f")
            [ "$got_sha" = "$exp_sha" ] || \
                fail "[switch-journal] backup file $orig_f digest mismatch ($got_sha != $exp_sha)"
        done
        for idx in 1 2 3 4 5; do
            dest=$(tracked_path_for_index "$idx")
            tmp_r=$(same_dir_temp_for_index "$idx")
            exp_sha=$(awk -v k="$idx" '$1 == k { print $2 }' "$JOURNAL_DIR/orig.sha256")
            cp "$JOURNAL_DIR/orig/$idx" "$tmp_r"
            mv -f "$tmp_r" "$dest"
            got_sha=$(sha256_file "$dest")
            [ "$got_sha" = "$exp_sha" ] || \
                fail "[switch-journal] restored file '$dest' digest mismatch ($got_sha != $exp_sha)"
        done
        rm -rf "$JOURNAL_DIR"
        printf 'Recovered interrupted h2 switch: rolled back all 5 tracked files from .h2-switch-journal.\n'
    else
        rm -rf "$JOURNAL_DIR"
        printf 'Removed incomplete pre-commit .h2-switch-journal (no tracked files were modified).\n'
    fi
}

if [ "$ARG" = "--recover" ]; then
    if [ -e "$JOURNAL_DIR" ] || [ -L "$JOURNAL_DIR" ]; then
        recover_interrupted_journal
    else
        printf 'No interrupted h2 switch journal found (checkout is clean).\n'
    fi
    exit 0
fi

recover_interrupted_journal

[ -f "$CARGO_TOML" ] || fail "missing $CARGO_TOML"
[ -f "$CARGO_LOCK" ] || fail "missing $CARGO_LOCK"
[ -f "$README_FILE" ] || fail "missing $README_FILE"
[ -f "$AUDIT_TOML" ] || fail "missing $AUDIT_TOML"

TMPDIR_WORK=$(mktemp -d "${TMPDIR:-/tmp}/h2-use-registry.XXXXXX")
TMP_COMMIT_1=""
TMP_COMMIT_2=""
TMP_COMMIT_3=""
TMP_COMMIT_4=""
TMP_COMMIT_5=""
JOURNAL_OWNED=0
COMMIT_IN_PROGRESS=0
cleanup() {
    rm -f "$TMP_COMMIT_1" "$TMP_COMMIT_2" "$TMP_COMMIT_3" "$TMP_COMMIT_4" "$TMP_COMMIT_5" 2>/dev/null || true
    rm -rf "$TMPDIR_WORK"
    if [ "$JOURNAL_OWNED" -eq 1 ] && [ "$COMMIT_IN_PROGRESS" -eq 0 ]; then
        rm -rf "$JOURNAL_DIR" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

# Prepare an isolated staging workspace so tracked files are never mutated until
# the resolved h2 identity is verified.
STAGE="$TMPDIR_WORK/stage"
mkdir -p "$STAGE/vendor"
cp "$CARGO_TOML" "$STAGE/Cargo.toml"
cp "$CARGO_LOCK" "$STAGE/Cargo.lock"
cp "$README_FILE" "$STAGE/vendor/README.md"
cp -R "$REPO_ROOT/vendor/h2-audit" "$STAGE/vendor/h2-audit"
if [ -d "$VENDOR_DIR" ]; then
    cp -R "$VENDOR_DIR" "$STAGE/vendor/h2"
fi
if [ -d "$REPO_ROOT/crates" ]; then
    ln -s "$REPO_ROOT/crates" "$STAGE/crates"
fi

STAGE_TOML="$STAGE/Cargo.toml"
STAGE_LOCK="$STAGE/Cargo.lock"
STAGE_SOURCE_ENV="$STAGE/vendor/h2-source.env"
STAGE_AUDIT_TOML="$STAGE/vendor/h2-audit/Cargo.toml"
STAGE_AUDIT_LOCK="$STAGE/vendor/h2-audit/Cargo.lock"

locked_h2_version() {
    lock_file="$1"
    python3 - "$lock_file" <<'PY'
import re, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    text = f.read()
vers = []
for blk in re.split(r'\n(?=\[\[package\]\])', text):
    if not blk.lstrip().startswith("[[package]]"):
        continue
    nm = re.search(r'^name\s*=\s*"([^"]+)"', blk, re.MULTILINE)
    if nm and nm.group(1) == "h2":
        vm = re.search(r'^version\s*=\s*"([^"]+)"', blk, re.MULTILINE)
        if vm:
            vers.append(vm.group(1))
print(vers[0] if len(vers) == 1 else "")
PY
}

# rewrite_lock_h2_entry <lock> <version> <sha256 or "">: rewrite ONLY the header of the single h2
# [[package]] entry (version, and source + checksum for a registry identity; neither for the vendored
# path) and keep its dependency list. Fails if there is not exactly one h2 entry.
rewrite_lock_h2_entry() {
    python3 - "$1" "$2" "$3" <<'PY'
import re, sys
lock, version, sha = sys.argv[1:4]
with open(lock, "r", encoding="utf-8") as f:
    text = f.read()
pat = re.compile(
    r'(\[\[package\]\]\nname = "h2"\n)version = "[^"\n]+"\n'
    r'(?:source = "[^"\n]+"\n)?(?:checksum = "[0-9a-f]{64}"\n)?'
)
if len(pat.findall(text)) != 1:
    sys.exit(1)
head = f'version = "{version}"\n'
if sha:
    head += 'source = "registry+https://github.com/rust-lang/crates.io-index"\n' + f'checksum = "{sha}"\n'
text = pat.sub(lambda m: m.group(1) + head, text, count=1)
with open(lock, "w", encoding="utf-8") as f:
    f.write(text)
PY
}

# staged_lock_is_consistent: the staged manifest and lock agree as they stand (nothing to
# re-resolve), including exact parity between h2's resolved dependency names and its Cargo.lock
# dependencies list (catching both added dependencies and dropped stale dependencies).
staged_lock_is_consistent() {
    sc_meta="$TMPDIR_WORK/consistent-meta.json"
    if ! cargo metadata --locked --offline --format-version 1 --manifest-path "$STAGE_TOML" \
        > "$sc_meta" 2>/dev/null; then
        if ! cargo metadata --locked --format-version 1 --manifest-path "$STAGE_TOML" \
            > "$sc_meta" 2>/dev/null; then
            return 1
        fi
    fi
    python3 - "$sc_meta" "$STAGE_LOCK" <<'PY'
import json, re, sys
meta_path, lock_path = sys.argv[1:3]
with open(meta_path, "r", encoding="utf-8") as f:
    meta = json.load(f)
pkgs = meta.get("packages") or []
pkg_by_id = {p["id"]: p for p in pkgs}
h2_pkgs = [p for p in pkgs if p.get("name") == "h2"]
if len(h2_pkgs) != 1:
    sys.exit(1)
h2_id = h2_pkgs[0]["id"]
nodes = (meta.get("resolve") or {}).get("nodes") or []
h2_nodes = [n for n in nodes if n.get("id") == h2_id]
if len(h2_nodes) != 1:
    sys.exit(1)
resolved_deps = {
    pkg_by_id[d["pkg"]]["name"]
    for d in h2_nodes[0].get("deps", [])
    if d.get("pkg") in pkg_by_id
}

with open(lock_path, "r", encoding="utf-8") as f:
    lock_text = f.read()
h2_blocks = []
for blk in re.split(r'\n(?=\[\[package\]\])', lock_text):
    if not blk.lstrip().startswith("[[package]]"):
        continue
    nm = re.search(r'^name\s*=\s*"([^"]+)"', blk, re.MULTILINE)
    if nm and nm.group(1) == "h2":
        h2_blocks.append(blk)
if len(h2_blocks) != 1:
    sys.exit(1)
dm = re.search(r'^dependencies\s*=\s*\[(.*?)\]', h2_blocks[0], re.MULTILINE | re.DOTALL)
locked_deps = set()
if dm:
    for entry in re.findall(r'"([^"]+)"', dm.group(1)):
        locked_deps.add(entry.split()[0])
if resolved_deps != locked_deps:
    sys.exit(1)
PY
}

update_staged_audit_crate() {
    target_ver="$1"
    python3 - "$STAGE_AUDIT_TOML" "$target_ver" <<'PY'
import re
import sys

audit_toml, target_ver = sys.argv[1:3]
with open(audit_toml, "r", encoding="utf-8") as f:
    text = f.read()
new_text, n = re.subn(
    r'(?m)^h2\s*=\s*"=[^"]+"$',
    f'h2 = "={target_ver}"',
    text,
)
if n != 1:
    print(f"ERROR: h2-use-registry: expected 1 h2 pin in {audit_toml}, updated {n}", file=sys.stderr)
    sys.exit(1)
with open(audit_toml, "w", encoding="utf-8") as f:
    f.write(new_text)
PY
    cur_audit_ver=""
    if [ -f "$STAGE_AUDIT_LOCK" ]; then
        cur_audit_ver=$(locked_h2_version "$STAGE_AUDIT_LOCK")
    fi
    if [ "$cur_audit_ver" = "$target_ver" ]; then
        if ! cargo metadata --offline --format-version 1 --manifest-path "$STAGE_AUDIT_TOML" >/dev/null 2>&1; then
            cargo metadata --format-version 1 --manifest-path "$STAGE_AUDIT_TOML" >/dev/null || \
                fail "failed to refresh staged vendor/h2-audit/Cargo.lock for h2 =$target_ver"
        fi
    else
        if ! cargo update --offline --manifest-path "$STAGE_AUDIT_TOML" -p h2 --precise "$target_ver" >/dev/null 2>&1; then
            if ! cargo update --manifest-path "$STAGE_AUDIT_TOML" -p h2 --precise "$target_ver" >/dev/null 2>&1; then
                rm -f "$STAGE_AUDIT_LOCK"
                if ! cargo generate-lockfile --offline --manifest-path "$STAGE_AUDIT_TOML" >/dev/null 2>&1; then
                    cargo generate-lockfile --manifest-path "$STAGE_AUDIT_TOML" >/dev/null || \
                        fail "failed to generate staged vendor/h2-audit/Cargo.lock for h2 =$target_ver"
                fi
            fi
        fi
    fi
}

write_staged_source_env() {
    mode="$1"
    ver="$2"
    sha="$3"
    cat > "$STAGE_SOURCE_ENV" <<EOF
# Tracked source-mode selector for h2 (managed by scripts/h2-use-registry.sh).
# Read by scripts/verify-vendor-h2.sh, scripts/verify-h2-graph.sh, and scripts/audit-vendor-h2.sh.
H2_SOURCE_MODE=${mode}
H2_VERSION=${ver}
H2_ARCHIVE_SHA256=${sha}
EOF
}

verify_staged_identity() {
    exp_mode="$1"
    exp_ver="$2"
    exp_sha="$3"

    root_meta="$TMPDIR_WORK/stage-root-meta.json"
    root_err="$TMPDIR_WORK/stage-root-meta.err"
    if ! cargo metadata --locked --format-version 1 --manifest-path "$STAGE_TOML" \
        > "$root_meta" 2> "$root_err"; then
        cat "$root_err" >&2
        fail "staged root cargo metadata --locked failed"
    fi
    if grep -iE 'patch.*was not used|unused patch' "$root_err" >/dev/null 2>&1; then
        cat "$root_err" >&2
        fail "cargo reported an unused [patch] entry in staged workspace (h2 resolution did not apply)"
    fi

    audit_meta="$TMPDIR_WORK/stage-audit-meta.json"
    audit_err="$TMPDIR_WORK/stage-audit-meta.err"
    if ! cargo metadata --locked --format-version 1 --manifest-path "$STAGE_AUDIT_TOML" \
        > "$audit_meta" 2> "$audit_err"; then
        cat "$audit_err" >&2
        fail "staged vendor/h2-audit cargo metadata --locked failed"
    fi

    python3 - "$STAGE" "$exp_mode" "$exp_ver" "$exp_sha" "$root_meta" "$audit_meta" <<'PY'
import json
import os
import re
import sys

stage_dir, exp_mode, exp_ver, exp_sha, root_meta_path, audit_meta_path = sys.argv[1:7]
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"

def die(msg: str) -> None:
    print(f"ERROR: h2-use-registry: {msg}", file=sys.stderr)
    sys.exit(1)

def parse_lock_h2(lock_path: str):
    with open(lock_path, "r", encoding="utf-8") as f:
        text = f.read()
    entries = []
    for blk in re.split(r'\n(?=\[\[package\]\])', text):
        if not blk.lstrip().startswith("[[package]]"):
            continue
        nm = re.search(r'^name\s*=\s*"([^"]+)"', blk, re.MULTILINE)
        if nm and nm.group(1) == "h2":
            vm = re.search(r'^version\s*=\s*"([^"]+)"', blk, re.MULTILINE)
            sm = re.search(r'^source\s*=\s*"([^"]+)"', blk, re.MULTILINE)
            cm = re.search(r'^checksum\s*=\s*"([^"]+)"', blk, re.MULTILINE)
            entries.append((
                vm.group(1) if vm else None,
                sm.group(1) if sm else None,
                cm.group(1) if cm else None,
            ))
    return entries

# 1. Verify resolved root workspace h2 identity from cargo metadata --locked.
with open(root_meta_path, "r", encoding="utf-8") as f:
    meta = json.load(f)

packages = meta.get("packages") or []
pkg_by_id = {p["id"]: p for p in packages}
h2_pkgs = [p for p in packages if p.get("name") == "h2"]
if len(h2_pkgs) != 1:
    die(f"expected exactly 1 resolved h2 package in staged workspace, found {len(h2_pkgs)}")

h2 = h2_pkgs[0]
if h2.get("version") != exp_ver:
    die(f"resolved h2 version '{h2.get('version')}' != expected '{exp_ver}'")

nodes = (meta.get("resolve") or {}).get("nodes") or []
h2_nodes = [n for n in nodes if pkg_by_id.get(n["id"], {}).get("name") == "h2"]
if len(h2_nodes) != 1 or h2_nodes[0]["id"] != h2["id"]:
    die(f"expected exactly 1 resolved h2 graph node matching {h2['id']}, found {[n['id'] for n in h2_nodes]}")

if exp_mode == "vendored":
    if h2.get("source") is not None:
        die(f"expected vendored path h2 (source=null), got source={h2.get('source')!r}")
    expected_manifest = os.path.realpath(os.path.join(stage_dir, "vendor", "h2", "Cargo.toml"))
    actual_manifest = os.path.realpath(h2.get("manifest_path", ""))
    if actual_manifest != expected_manifest:
        die(f"resolved h2 manifest '{actual_manifest}' != expected '{expected_manifest}'")
else:
    if h2.get("source") != CRATES_IO:
        die(f"expected registry h2 source {CRATES_IO!r}, got {h2.get('source')!r}")

# 2. Verify staged root Cargo.lock h2 entry.
root_lock = parse_lock_h2(os.path.join(stage_dir, "Cargo.lock"))
expected_root_lock = [(exp_ver, None, None)] if exp_mode == "vendored" else [(exp_ver, CRATES_IO, exp_sha)]
if root_lock != expected_root_lock:
    die(f"staged Cargo.lock h2 entry {root_lock!r} != expected {expected_root_lock!r}")

# 3. Verify staged vendor/h2-audit resolved metadata and lockfile.
with open(audit_meta_path, "r", encoding="utf-8") as f:
    ameta = json.load(f)
ah2_pkgs = [p for p in (ameta.get("packages") or []) if p.get("name") == "h2"]
if len(ah2_pkgs) != 1:
    die(f"expected exactly 1 h2 package in staged vendor/h2-audit, found {len(ah2_pkgs)}")
if ah2_pkgs[0].get("version") != exp_ver or ah2_pkgs[0].get("source") != CRATES_IO:
    die(f"staged vendor/h2-audit resolved unexpected h2: {ah2_pkgs[0].get('version')} / {ah2_pkgs[0].get('source')}")
audit_lock = parse_lock_h2(os.path.join(stage_dir, "vendor", "h2-audit", "Cargo.lock"))
if audit_lock != [(exp_ver, CRATES_IO, exp_sha)]:
    die(f"staged vendor/h2-audit/Cargo.lock h2 entry {audit_lock!r} != [({exp_ver!r}, {CRATES_IO!r}, {exp_sha!r})]")
PY
}

commit_staged_files() {
    # Acquire an atomic rollback journal directory, save checksummed backups of all 5
    # pre-switch tracked files, stage all 5 new files into same-directory temp files,
    # atomically mark state=COMMITTING, then execute the 5 renames and remove the journal.
    if ! mkdir "$JOURNAL_DIR" 2>/dev/null; then
        fail "[switch-lock] could not acquire $JOURNAL_DIR (concurrent or interrupted switch)"
    fi
    JOURNAL_OWNED=1
    printf '%s\n' "$$" > "$JOURNAL_DIR/pid"
    printf 'PREPARING\n' > "$JOURNAL_DIR/state"
    mkdir -p "$JOURNAL_DIR/orig"

    : > "$JOURNAL_DIR/orig.sha256"
    for idx in 1 2 3 4 5; do
        src=$(tracked_path_for_index "$idx")
        [ -f "$src" ] || fail "[switch-journal] missing tracked file '$src' before commit"
        cp "$src" "$JOURNAL_DIR/orig/$idx"
        printf '%s %s\n' "$idx" "$(sha256_file "$JOURNAL_DIR/orig/$idx")" >> "$JOURNAL_DIR/orig.sha256"
    done

    TMP_COMMIT_1=$(same_dir_temp_for_index 1)
    TMP_COMMIT_2=$(same_dir_temp_for_index 2)
    TMP_COMMIT_3=$(same_dir_temp_for_index 3)
    TMP_COMMIT_4=$(same_dir_temp_for_index 4)
    TMP_COMMIT_5=$(same_dir_temp_for_index 5)

    cp "$STAGE_TOML" "$TMP_COMMIT_1"
    cp "$STAGE_LOCK" "$TMP_COMMIT_2"
    cp "$STAGE_AUDIT_TOML" "$TMP_COMMIT_3"
    cp "$STAGE_AUDIT_LOCK" "$TMP_COMMIT_4"
    cp "$STAGE_SOURCE_ENV" "$TMP_COMMIT_5"

    printf 'COMMITTING\n' > "$JOURNAL_DIR/state.tmp"
    mv -f "$JOURNAL_DIR/state.tmp" "$JOURNAL_DIR/state"
    COMMIT_IN_PROGRESS=1

    mv -f "$TMP_COMMIT_1" "$CARGO_TOML"
    [ "${H2_SWITCH_TEST_FAIL_AFTER_RENAME:-0}" != "1" ] || \
        fail "[switch-interrupted] test hook interrupted switch after rename 1 of 5"
    mv -f "$TMP_COMMIT_2" "$CARGO_LOCK"
    [ "${H2_SWITCH_TEST_FAIL_AFTER_RENAME:-0}" != "2" ] || \
        fail "[switch-interrupted] test hook interrupted switch after rename 2 of 5"
    mv -f "$TMP_COMMIT_3" "$AUDIT_TOML"
    [ "${H2_SWITCH_TEST_FAIL_AFTER_RENAME:-0}" != "3" ] || \
        fail "[switch-interrupted] test hook interrupted switch after rename 3 of 5"
    mv -f "$TMP_COMMIT_4" "$AUDIT_LOCK"
    [ "${H2_SWITCH_TEST_FAIL_AFTER_RENAME:-0}" != "4" ] || \
        fail "[switch-interrupted] test hook interrupted switch after rename 4 of 5"
    mv -f "$TMP_COMMIT_5" "$SOURCE_ENV"

    COMMIT_IN_PROGRESS=0
    rm -rf "$JOURNAL_DIR"
    JOURNAL_OWNED=0
}

if [ "$ARG" = "--vendored" ]; then
    [ -f "$VENDOR_TOML" ] || fail "missing $VENDOR_TOML"

    INFO=$(python3 - "$README_FILE" "$VENDOR_TOML" <<'PY'
import re
import sys

readme_path, vendor_toml = sys.argv[1:3]
with open(readme_path, "r", encoding="utf-8") as f:
    readme = f.read()

ver_m = re.findall(r'^- \*\*Upstream crate:\*\* `h2` `([^`]+)`\s*$', readme, re.MULTILINE)
sha_m = re.findall(r'^- \*\*Upstream archive SHA-256:\*\* `([0-9a-f]{64})`\s*$', readme, re.MULTILINE)
if len(ver_m) != 1 or len(sha_m) != 1:
    print("ERROR: h2-use-registry: could not parse pinned version/sha from vendor/README.md", file=sys.stderr)
    sys.exit(1)

vendor_ver = None
with open(vendor_toml, "r", encoding="utf-8") as f:
    in_pkg = False
    for line in f:
        s = line.strip()
        if s.startswith("["):
            in_pkg = (s == "[package]")
            continue
        if in_pkg:
            m = re.match(r'^version\s*=\s*"([^"]+)"$', s)
            if m:
                vendor_ver = m.group(1)
                break
if vendor_ver != ver_m[0]:
    print(f"ERROR: h2-use-registry: vendor/h2/Cargo.toml version '{vendor_ver}' != vendor/README.md '{ver_m[0]}'", file=sys.stderr)
    sys.exit(1)

print(f"{ver_m[0]} {sha_m[0]}")
PY
    )
    VENDOR_VER=$(printf '%s\n' "$INFO" | awk '{print $1}')
    VENDOR_SHA=$(printf '%s\n' "$INFO" | awk '{print $2}')

    # Restore [patch.crates-io] h2 = { path = "vendor/h2" } in staged Cargo.toml.
    python3 - "$STAGE_TOML" <<'PY'
import re
import sys

cargo_toml = sys.argv[1]
with open(cargo_toml, "r", encoding="utf-8") as f:
    text = f.read()

if re.search(r'(?m)^h2\s*=\s*\{\s*path\s*=\s*"vendor/h2"\s*\}\s*$', text):
    sys.exit(0)

if re.search(r'(?m)^\[patch\.crates-io\]\s*$', text):
    text = re.sub(
        r'(?m)^(\[patch\.crates-io\]\s*\n)',
        r'\1h2 = { path = "vendor/h2" }\n',
        text,
        count=1,
    )
else:
    if not text.endswith("\n"):
        text += "\n"
    text += '\n[patch.crates-io]\nh2 = { path = "vendor/h2" }\n'

with open(cargo_toml, "w", encoding="utf-8") as f:
    f.write(text)
PY

    # Refresh staged Cargo.lock so h2 resolves to the local vendored path.
    # Symmetric with the forward direction: first rewrite ONLY the h2 entry
    # (removing registry source + checksum and setting version = VENDOR_VER) and
    # validate with `--locked`; only if that is inconsistent (e.g. dependencies
    # differ) fall back to Cargo re-resolution and print a notice.
    cp "$STAGE_LOCK" "$TMPDIR_WORK/lock.before"
    if rewrite_lock_h2_entry "$STAGE_LOCK" "$VENDOR_VER" "" && staged_lock_is_consistent; then
        :
    else
        cp "$TMPDIR_WORK/lock.before" "$STAGE_LOCK"
        CUR_LOCKED_VER=$(locked_h2_version "$STAGE_LOCK")
        if [ "$CUR_LOCKED_VER" = "$VENDOR_VER" ]; then
            if ! cargo metadata --offline --format-version 1 --manifest-path "$STAGE_TOML" >/dev/null 2>&1; then
                cargo metadata --format-version 1 --manifest-path "$STAGE_TOML" >/dev/null || \
                    fail "[switch-resolve] failed to refresh staged Cargo.lock for vendored h2 $VENDOR_VER"
            fi
        else
            # When returning from a higher locked registry version (e.g. 0.4.22 -> 0.4.21),
            # plain `cargo metadata` leaves the higher registry version locked and ignores
            # the lower path patch; explicitly select VENDOR_VER via `cargo update -p h2 --precise`.
            if ! cargo update --offline --manifest-path "$STAGE_TOML" -p "h2" --precise "$VENDOR_VER" >/dev/null 2>&1; then
                cargo update --manifest-path "$STAGE_TOML" -p "h2" --precise "$VENDOR_VER" >/dev/null || \
                    fail "[switch-resolve] failed to switch staged Cargo.lock from h2 '${CUR_LOCKED_VER}' to vendored h2 $VENDOR_VER"
            fi
        fi
        printf 'NOTE: vendored h2 %s has other dependencies than the locked release; cargo re-resolved the root lock (review the whole Cargo.lock diff).\n' "$VENDOR_VER"
    fi

    update_staged_audit_crate "$VENDOR_VER"
    write_staged_source_env "vendored" "$VENDOR_VER" "$VENDOR_SHA"
    verify_staged_identity "vendored" "$VENDOR_VER" "$VENDOR_SHA"
    commit_staged_files

    printf 'Switched h2 back to vendored mode: vendor/h2 (%s, archive sha256 %s; resolved identity verified)\n' \
        "$VENDOR_VER" "$VENDOR_SHA"
    exit 0
fi

TARGET_VERSION="$ARG"
case "$TARGET_VERSION" in
    [0-9]*.[0-9]*.[0-9]*)
        ;;
    *)
        fail "invalid version '$TARGET_VERSION' (expected semver like 0.4.21, or --vendored)"
        ;;
esac

# Look up target version and its exact checksum in crates.io sparse index (fail if yanked/missing).
INDEX_FILE="$TMPDIR_WORK/h2.index"
if [ -n "${H2_SPARSE_INDEX_FILE:-}" ]; then
    [ -f "$H2_SPARSE_INDEX_FILE" ] || fail "H2_SPARSE_INDEX_FILE='$H2_SPARSE_INDEX_FILE' does not exist"
    cp "$H2_SPARSE_INDEX_FILE" "$INDEX_FILE"
else
    command -v curl >/dev/null 2>&1 || fail "'curl' not found to query $SPARSE_INDEX_URL"
    curl -fsSL --proto '=https' --tlsv1.2 -o "$INDEX_FILE" "$SPARSE_INDEX_URL" || \
        fail "failed to fetch crates.io sparse index from $SPARSE_INDEX_URL"
fi

TARGET_SHA=$(python3 - "$INDEX_FILE" "$TARGET_VERSION" <<'PY'
import json
import re
import sys

index_path, target_ver = sys.argv[1:3]
found = None
with open(index_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        entry = json.loads(line)
        if entry.get("name") == "h2" and entry.get("vers") == target_ver:
            found = entry
            break

if found is None:
    print(f"ERROR: h2-use-registry: h2 {target_ver} not found in crates.io sparse index", file=sys.stderr)
    sys.exit(1)
if found.get("yanked", False):
    print(f"ERROR: h2-use-registry: refusing to switch to yanked h2 {target_ver}", file=sys.stderr)
    sys.exit(1)
cksum = found.get("cksum", "")
if not re.fullmatch(r"[0-9a-f]{64}", cksum):
    print(f"ERROR: h2-use-registry: malformed checksum for h2 {target_ver}: {cksum!r}", file=sys.stderr)
    sys.exit(1)
print(cksum)
PY
)

# Remove [patch.crates-io] h2 = { path = "vendor/h2" } from staged Cargo.toml.
python3 - "$STAGE_TOML" <<'PY'
import re
import sys

cargo_toml = sys.argv[1]
with open(cargo_toml, "r", encoding="utf-8") as f:
    text = f.read()

lines = text.splitlines(keepends=True)
out = []
i = 0
removed = 0
while i < len(lines):
    if re.match(r'^\[patch\.crates-io\]\s*$', lines[i]):
        section_start = i
        i += 1
        body = []
        while i < len(lines) and not lines[i].lstrip().startswith("["):
            if re.match(r'^h2\s*=\s*\{\s*path\s*=\s*"vendor/h2"\s*\}\s*$', lines[i]):
                removed += 1
            else:
                body.append(lines[i])
            i += 1
        non_blank = [l for l in body if l.strip() and not l.lstrip().startswith("#")]
        if non_blank:
            out.append(lines[section_start])
            out.extend(body)
        else:
            while out and out[-1].strip() == "":
                out.pop()
    else:
        out.append(lines[i])
        i += 1

if removed > 1:
    print(f"ERROR: h2-use-registry: unexpected duplicate h2 patch entries ({removed})", file=sys.stderr)
    sys.exit(1)

new_text = "".join(out)
if not new_text.endswith("\n"):
    new_text += "\n"
with open(cargo_toml, "w", encoding="utf-8") as f:
    f.write(new_text)
PY

# Update the staged root Cargo.lock to the crates.io identity of TARGET_VERSION. First try to change
# ONLY the h2 entry (version, source, checksum) and keep its dependency list: that is exact when the
# release has the same dependency names as the vendored one, and nothing else in the lock moves. Do
# NOT let cargo resolve when the version is the same: with the patch removed the path entry matches no
# registry package, and cargo would pick the NEWEST compatible release instead of the requested one.
cp "$STAGE_LOCK" "$TMPDIR_WORK/lock.before"
if rewrite_lock_h2_entry "$STAGE_LOCK" "$TARGET_VERSION" "$TARGET_SHA" && staged_lock_is_consistent; then
    :
else
    # Its dependencies differ: let cargo resolve. The staged lock still records the vendored path
    # entry, which no registry package spec matches (`cargo update -p h2` alone fails with "did not
    # match any packages"), so resolve once without the patch, then select the exact version.
    cp "$TMPDIR_WORK/lock.before" "$STAGE_LOCK"
    if ! cargo metadata --offline --format-version 1 --manifest-path "$STAGE_TOML" >/dev/null 2>&1; then
        cargo metadata --format-version 1 --manifest-path "$STAGE_TOML" >/dev/null || \
            fail "[switch-resolve] failed to resolve staged Cargo.lock without the vendored patch"
    fi
    if [ "$(locked_h2_version "$STAGE_LOCK")" != "$TARGET_VERSION" ]; then
        if ! cargo update --offline --manifest-path "$STAGE_TOML" -p "h2" --precise "$TARGET_VERSION" >/dev/null 2>&1; then
            cargo update --manifest-path "$STAGE_TOML" -p "h2" --precise "$TARGET_VERSION" >/dev/null || \
                fail "[switch-resolve] failed to update staged Cargo.lock to crates.io h2 $TARGET_VERSION"
        fi
    fi
    printf 'NOTE: h2 %s has other dependencies than the vendored release; cargo re-resolved the root lock (review the whole Cargo.lock diff).\n' "$TARGET_VERSION"
fi

update_staged_audit_crate "$TARGET_VERSION"
write_staged_source_env "registry" "$TARGET_VERSION" "$TARGET_SHA"
verify_staged_identity "registry" "$TARGET_VERSION" "$TARGET_SHA"
commit_staged_files

printf 'Switched h2 to emergency registry mode: crates.io h2 %s (sha256 %s; resolved identity verified)\n' \
    "$TARGET_VERSION" "$TARGET_SHA"
printf 'NOTE: MiraServe COPY_LIMIT=4096 patch is inactive in registry mode (see vendor/README.md).\n'
printf 'Run ./scripts/h2-use-registry.sh --vendored to restore the vendored patch.\n'
