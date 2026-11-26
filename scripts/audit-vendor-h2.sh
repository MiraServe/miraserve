#!/bin/sh
# Fail-closed RustSec advisory & upstream release/yank gate for h2.
#
# 1. Reads vendor/h2-source.env and verifies vendor/h2-audit/Cargo.toml +
#    vendor/h2-audit/Cargo.lock resolve crates.io h2 at the exact pinned version
#    (also cross-checking vendor/h2/Cargo.toml in vendored mode).
# 2. Runs `cargo deny --locked check advisories` with MiraServe's deny.toml and
#    requires the actual RustSec advisory-db Git revision matching deny.toml's
#    db-path and db-urls (never prints OK without a verified DB commit).
# 3. Queries the crates.io sparse index (https://index.crates.io/2/h2, or
#    H2_SPARSE_INDEX_FILE for offline tests):
#    - fails if the pinned version is missing, yanked, or checksum-mismatched
#    - fails if any newer non-yanked 0.4.x release exists that is not recorded
#      with date and reason in vendor/README.md ("Upstream Release Review Log").

set -eu

SPARSE_INDEX_URL="https://index.crates.io/2/h2"

fail() {
    printf 'ERROR: audit-vendor-h2: %s\n' "$*" >&2
    exit 1
}

command -v cargo >/dev/null 2>&1 || fail "'cargo' not found"
command -v python3 >/dev/null 2>&1 || fail "'python3' not found"
command -v git >/dev/null 2>&1 || fail "'git' not found"
cargo deny --version >/dev/null 2>&1 || fail "'cargo-deny' is not installed (cannot run advisory gate)"

SCRIPT_DIR=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -P -- "$SCRIPT_DIR/.." && pwd -P)

SOURCE_ENV="$REPO_ROOT/vendor/h2-source.env"
VENDOR_MANIFEST="$REPO_ROOT/vendor/h2/Cargo.toml"
README_FILE="$REPO_ROOT/vendor/README.md"
AUDIT_MANIFEST="$REPO_ROOT/vendor/h2-audit/Cargo.toml"
AUDIT_LOCK="$REPO_ROOT/vendor/h2-audit/Cargo.lock"
DENY_CONFIG="$REPO_ROOT/deny.toml"

[ -f "$SOURCE_ENV" ] && [ ! -L "$SOURCE_ENV" ] || fail "missing $SOURCE_ENV"
[ -f "$README_FILE" ] && [ ! -L "$README_FILE" ] || fail "missing $README_FILE"
[ -f "$AUDIT_MANIFEST" ] || fail "missing $AUDIT_MANIFEST"
[ -f "$AUDIT_LOCK" ] || fail "missing $AUDIT_LOCK"
[ -f "$DENY_CONFIG" ] || fail "missing $DENY_CONFIG"

TMPDIR_WORK=$(mktemp -d "${TMPDIR:-/tmp}/audit-vendor-h2.XXXXXX")
cleanup() {
    rm -rf "$TMPDIR_WORK"
}
trap cleanup EXIT HUP INT TERM

AUDIT_META="$TMPDIR_WORK/audit-metadata.json"
if ! cargo metadata --locked --format-version 1 \
    --manifest-path "$AUDIT_MANIFEST" > "$AUDIT_META"; then
    fail "cargo metadata --locked failed on vendor/h2-audit"
fi

PIN_INFO=$(python3 - "$SOURCE_ENV" "$VENDOR_MANIFEST" "$AUDIT_MANIFEST" "$AUDIT_LOCK" "$AUDIT_META" <<'PY'
import json
import os
import re
import sys

source_env, vendor_toml, audit_toml, audit_lock, audit_meta = sys.argv[1:6]

def die(msg: str) -> None:
    print(f"ERROR: audit-vendor-h2: {msg}", file=sys.stderr)
    sys.exit(1)

cfg = {}
with open(source_env, "r", encoding="utf-8") as f:
    for lineno, raw in enumerate(f, 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if "=" not in s:
            die(f"[source-env] invalid line {lineno} in vendor/h2-source.env")
        k, v = s.split("=", 1)
        if k in cfg:
            die(f"[source-env] duplicate key '{k}' in vendor/h2-source.env")
        cfg[k] = v

mode = cfg.get("H2_SOURCE_MODE")
pinned_version = cfg.get("H2_VERSION")
pinned_sha = cfg.get("H2_ARCHIVE_SHA256")
if mode not in ("vendored", "registry"):
    die(f"[source-env] invalid H2_SOURCE_MODE {mode!r} in vendor/h2-source.env")
if not pinned_version or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", pinned_version):
    die(f"[source-env] invalid H2_VERSION {pinned_version!r} in vendor/h2-source.env")
if not pinned_sha or not re.fullmatch(r"[0-9a-f]{64}", pinned_sha):
    die(f"[source-env] invalid H2_ARCHIVE_SHA256 {pinned_sha!r} in vendor/h2-source.env")
if set(cfg.keys()) != {"H2_SOURCE_MODE", "H2_VERSION", "H2_ARCHIVE_SHA256"}:
    die(f"[source-env] unexpected keys in vendor/h2-source.env: {sorted(cfg.keys())}")

if mode == "vendored":
    if not os.path.isfile(vendor_toml):
        die(f"missing {vendor_toml}")
    vendor_version = None
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
                    vendor_version = m.group(1)
                    break
    if vendor_version != pinned_version:
        die(f"vendor/h2/Cargo.toml version '{vendor_version}' != vendor/h2-source.env '{pinned_version}'")

# Read vendor/h2-audit/Cargo.toml [dependencies].h2 exact pin.
audit_pin = None
with open(audit_toml, "r", encoding="utf-8") as f:
    in_deps = False
    for line in f:
        s = line.strip()
        if s.startswith("["):
            in_deps = (s == "[dependencies]")
            continue
        if in_deps:
            m = re.match(r'^h2\s*=\s*"([^"]+)"$', s)
            if m:
                audit_pin = m.group(1)
                break
expected_pin = f"={pinned_version}"
if audit_pin != expected_pin:
    die(f"vendor/h2-audit/Cargo.toml pins h2='{audit_pin}', expected '{expected_pin}'")

# Verify vendor/h2-audit metadata resolves h2 at exact pinned_version from crates.io.
with open(audit_meta, "r", encoding="utf-8") as f:
    meta = json.load(f)

h2_pkgs = [p for p in meta.get("packages", []) if p.get("name") == "h2"]
if len(h2_pkgs) != 1:
    die(f"expected exactly 1 h2 package in vendor/h2-audit graph, found {len(h2_pkgs)}")

h2 = h2_pkgs[0]
if h2.get("version") != pinned_version:
    die(f"vendor/h2-audit resolved h2 {h2.get('version')}, expected {pinned_version}")

expected_source = "registry+https://github.com/rust-lang/crates.io-index"
if h2.get("source") != expected_source:
    die(f"vendor/h2-audit h2 source is {h2.get('source')!r}, expected {expected_source!r}")

# Cross-check lockfile also records crates.io source & checksum for h2.
with open(audit_lock, "r", encoding="utf-8") as f:
    lock_text = f.read()
blocks = re.split(r'\n(?=\[\[package\]\])', lock_text)
lock_h2 = []
for blk in blocks:
    if not blk.lstrip().startswith("[[package]]"):
        continue
    name_m = re.search(r'^name\s*=\s*"([^"]+)"', blk, re.MULTILINE)
    if name_m and name_m.group(1) == "h2":
        ver_m = re.search(r'^version\s*=\s*"([^"]+)"', blk, re.MULTILINE)
        src_m = re.search(r'^source\s*=\s*"([^"]+)"', blk, re.MULTILINE)
        chk_m = re.search(r'^checksum\s*=\s*"([^"]+)"', blk, re.MULTILINE)
        lock_h2.append((
            ver_m.group(1) if ver_m else None,
            src_m.group(1) if src_m else None,
            chk_m.group(1) if chk_m else None,
        ))
if lock_h2 != [(pinned_version, expected_source, pinned_sha)]:
    die(f"vendor/h2-audit/Cargo.lock h2 entry {lock_h2!r} != [({pinned_version!r}, {expected_source!r}, {pinned_sha!r})]")

print(f"{mode} {pinned_version} {pinned_sha}")
PY
)

SOURCE_MODE=$(printf '%s\n' "$PIN_INFO" | awk '{print $1}')
PINNED_VERSION=$(printf '%s\n' "$PIN_INFO" | awk '{print $2}')
PINNED_SHA=$(printf '%s\n' "$PIN_INFO" | awk '{print $3}')

# Run cargo-deny advisories check with MiraServe's deny.toml policy (fails closed on any error).
cargo deny --locked \
    --manifest-path "$AUDIT_MANIFEST" \
    --config "$DENY_CONFIG" \
    check advisories

# Resolve and REQUIRE the actual RustSec advisory-db Git revision matching deny.toml.
# An "OK" without a verified DB revision is a failure.
DB_INFO=$(python3 - "$DENY_CONFIG" <<'PY'
import os
import re
import subprocess
import sys

deny_path = sys.argv[1]

def die(msg: str) -> None:
    print(f"ERROR: audit-vendor-h2: {msg}", file=sys.stderr)
    sys.exit(1)

with open(deny_path, "r", encoding="utf-8") as f:
    deny_text = f.read()

in_adv = False
db_path_raw = None
db_urls = []
for line in deny_text.splitlines():
    s = line.strip()
    if s.startswith("["):
        in_adv = (s == "[advisories]")
        continue
    if not in_adv:
        continue
    m_path = re.match(r'^db-path\s*=\s*"([^"]+)"$', s)
    if m_path:
        db_path_raw = m_path.group(1)
    m_urls = re.match(r'^db-urls\s*=\s*\[([^\]]+)\]$', s)
    if m_urls:
        db_urls = re.findall(r'"([^"]+)"', m_urls.group(1))

if not db_path_raw:
    die(f"missing [advisories].db-path in {deny_path}")
if not db_urls:
    die(f"missing [advisories].db-urls in {deny_path}")

def norm_url(u: str) -> str:
    u = u.strip().rstrip("/")
    if u.endswith(".git"):
        u = u[:-4]
    return u.lower()

expected_urls = {norm_url(u) for u in db_urls}
db_root = os.path.expanduser(db_path_raw)
if not os.path.isdir(db_root):
    die(f"advisory-db directory '{db_root}' does not exist after cargo-deny run")

candidates = [db_root]
try:
    for entry in sorted(os.listdir(db_root)):
        full = os.path.join(db_root, entry)
        if os.path.isdir(full):
            candidates.append(full)
except OSError as exc:
    die(f"failed to read advisory-db directory '{db_root}': {exc}")

matched = []
for cand in candidates:
    if not os.path.isdir(os.path.join(cand, ".git")):
        continue
    r = subprocess.run(
        ["git", "-C", cand, "config", "--get", "remote.origin.url"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        continue
    origin = norm_url(r.stdout)
    if origin in expected_urls:
        matched.append((cand, origin))

if len(matched) != 1:
    die(
        f"[audit-db-rev] expected exactly 1 RustSec advisory-db git checkout matching {sorted(expected_urls)} "
        f"under '{db_root}', found {len(matched)}: {matched}"
    )

db_dir = matched[0][0]
rev_res = subprocess.run(
    ["git", "-C", db_dir, "rev-parse", "--verify", "HEAD"],
    capture_output=True,
    text=True,
)
date_res = subprocess.run(
    ["git", "-C", db_dir, "log", "-1", "--format=%cI", "HEAD"],
    capture_output=True,
    text=True,
)
rev = rev_res.stdout.strip()
date = date_res.stdout.strip()
if rev_res.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", rev):
    die(f"[audit-db-rev] could not determine valid 40-char git HEAD revision in '{db_dir}'")
if date_res.returncode != 0 or not date:
    die(f"[audit-db-rev] could not determine commit timestamp in '{db_dir}'")

print(f"advisory-db {rev[:12]} ({date})")
PY
)

# Query crates.io sparse index for upstream yank and newer 0.4.x release checks.
INDEX_FILE="$TMPDIR_WORK/h2.index"
if [ -n "${H2_SPARSE_INDEX_FILE:-}" ]; then
    [ -f "$H2_SPARSE_INDEX_FILE" ] || fail "H2_SPARSE_INDEX_FILE='$H2_SPARSE_INDEX_FILE' does not exist"
    cp "$H2_SPARSE_INDEX_FILE" "$INDEX_FILE"
else
    command -v curl >/dev/null 2>&1 || fail "'curl' not found to query $SPARSE_INDEX_URL"
    curl -fsSL --proto '=https' --tlsv1.2 -o "$INDEX_FILE" "$SPARSE_INDEX_URL" || \
        fail "failed to fetch crates.io sparse index from $SPARSE_INDEX_URL"
fi

UPSTREAM_INFO=$(python3 - "$INDEX_FILE" "$PINNED_VERSION" "$PINNED_SHA" "$README_FILE" <<'PY'
import datetime
import json
import re
import sys

index_path, pinned_ver, pinned_sha, readme_path = sys.argv[1:5]

def die(msg: str) -> None:
    print(f"ERROR: audit-vendor-h2: {msg}", file=sys.stderr)
    sys.exit(1)

m_pin = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)", pinned_ver)
if not m_pin:
    die(f"unsupported non-numeric pinned version '{pinned_ver}'")
pin_major, pin_minor, pin_patch = (int(m_pin.group(1)), int(m_pin.group(2)), int(m_pin.group(3)))

entries = []
with open(index_path, "r", encoding="utf-8") as f:
    for lineno, raw in enumerate(f, 1):
        s = raw.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError as exc:
            die(f"malformed JSON at sparse index line {lineno}: {exc}")
        if obj.get("name") == "h2":
            entries.append(obj)

if not entries:
    die("crates.io sparse index contained zero entries for h2")

pinned_entry = None
newer_same_minor = []
for obj in entries:
    vers = obj.get("vers", "")
    if vers == pinned_ver:
        pinned_entry = obj
    m = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)", vers)
    if not m:
        continue
    maj, min_, pat = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    if maj == pin_major and min_ == pin_minor and pat > pin_patch and not obj.get("yanked", False):
        newer_same_minor.append((pat, vers))

if pinned_entry is None:
    die(f"[audit-index] pinned h2 {pinned_ver} not found in crates.io sparse index")
if pinned_entry.get("yanked", False):
    die(f"[audit-yank] pinned h2 {pinned_ver} is YANKED on crates.io — re-vendor or switch via scripts/h2-use-registry.sh")
if pinned_entry.get("cksum") != pinned_sha:
    die(
        f"[audit-checksum] crates.io sparse index checksum for h2 {pinned_ver} is {pinned_entry.get('cksum')!r}, "
        f"expected {pinned_sha!r}"
    )

newer_same_minor.sort()
newer_versions = [v for _, v in newer_same_minor]

# Parse dated review records in vendor/README.md under "## Upstream Release Review Log".
# Format: - `0.4.X` (YYYY-MM-DD): reviewed, not needed — <non-empty reason>
with open(readme_path, "r", encoding="utf-8") as f:
    readme_text = f.read()

reviewed = {}
in_log = False
for line in readme_text.splitlines():
    if re.match(r'^##\s+Upstream Release Review Log\s*$', line):
        in_log = True
        continue
    if in_log and line.startswith("## "):
        break
    if not in_log:
        continue
    m = re.match(
        r'^- `([0-9]+\.[0-9]+\.[0-9]+)` \(([0-9]{4}-[0-9]{2}-[0-9]{2})\): reviewed, not needed (?:\u2014|--|-) (.+)$',
        line.strip(),
    )
    if m:
        ver_s, date_s, reason = m.group(1), m.group(2), m.group(3).strip()
        try:
            datetime.date.fromisoformat(date_s)
        except ValueError:
            die(f"invalid review date '{date_s}' for h2 {ver_s} in vendor/README.md")
        if len(reason) < 8:
            die(f"review reason for h2 {ver_s} in vendor/README.md is too short: {reason!r}")
        reviewed[ver_s] = (date_s, reason)

unreviewed = [v for v in newer_versions if v not in reviewed]
if unreviewed:
    die(
        f"[audit-newer] newer {pin_major}.{pin_minor}.x h2 release(s) exist on crates.io than pinned {pinned_ver}: "
        f"{', '.join(unreviewed)}. Either re-vendor (or switch via ./scripts/h2-use-registry.sh <ver>) "
        f"or record a dated review entry in vendor/README.md under '## Upstream Release Review Log': "
        f"- `<version>` (YYYY-MM-DD): reviewed, not needed — <reason>"
    )

if newer_versions:
    latest = newer_versions[-1]
    waived = ", ".join(f"{v} ({reviewed[v][0]})" for v in newer_versions)
    print(f"upstream {pin_major}.{pin_minor}.x latest {latest}; reviewed not needed: {waived}")
else:
    print(f"upstream {pin_major}.{pin_minor}.x latest {pinned_ver}")
PY
)

printf 'vendor/h2 advisories OK (%s mode): crates.io h2 =%s (%s; %s)\n' \
    "$SOURCE_MODE" "$PINNED_VERSION" "$DB_INFO" "$UPSTREAM_INFO"
