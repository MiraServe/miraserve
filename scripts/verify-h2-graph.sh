#!/bin/sh
# Fail-closed Cargo dependency graph gate for h2 (vendored or emergency registry mode).
#
# Reads vendor/h2-source.env and verifies from `cargo metadata --locked`
# (unfiltered and per shipped release target via `--filter-platform`) and
# `Cargo.lock` that:
#   1. `vendor` (and `vendor/h2` in vendored mode) is physically contained
#      inside the physical repository root (no symlinks anywhere along the path).
#   2. Exactly one `h2` package exists in the resolved workspace graph, at the
#      pinned version.
#   3. In vendored mode: `h2` resolves from `<physical root>/vendor/h2/Cargo.toml`
#      with `source == null` and a path-patched `Cargo.lock` entry.
#      In emergency registry mode: `h2` resolves from crates.io with `Cargo.lock`
#      checksum matching `vendor/h2-source.env`.
#   4. On every shipped release target (the five targets in
#      .github/workflows/release.yml), `h2` is reachable from `miraserve-bin`
#      following ONLY normal and build dependencies (never dev-only or
#      non-shipped-target edges).

set -eu

SHIPPED_TARGETS="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu aarch64-apple-darwin x86_64-apple-darwin x86_64-pc-windows-msvc"

fail() {
    printf 'ERROR: verify-h2-graph: %s\n' "$*" >&2
    exit 1
}

command -v cargo >/dev/null 2>&1 || fail "'cargo' not found"
command -v python3 >/dev/null 2>&1 || fail "'python3' not found"

SCRIPT_DIR=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -P -- "$SCRIPT_DIR/.." && pwd -P)

if [ -e "$REPO_ROOT/.h2-switch-journal" ] || [ -L "$REPO_ROOT/.h2-switch-journal" ]; then
    fail "[switch-journal] interrupted h2 switch detected ($REPO_ROOT/.h2-switch-journal exists); run ./scripts/h2-use-registry.sh --recover"
fi

VENDOR_PARENT="$REPO_ROOT/vendor"
SOURCE_ENV="$VENDOR_PARENT/h2-source.env"
[ -d "$VENDOR_PARENT" ] && [ ! -L "$VENDOR_PARENT" ] || \
    fail "[containment] vendor must be a real directory (not a symlink)"
PHYS_VENDOR_PARENT=$(CDPATH= cd -P -- "$VENDOR_PARENT" && pwd -P)
[ "$PHYS_VENDOR_PARENT" = "$REPO_ROOT/vendor" ] || \
    fail "[containment] vendor physical path '$PHYS_VENDOR_PARENT' != '$REPO_ROOT/vendor'"
[ -f "$SOURCE_ENV" ] && [ ! -L "$SOURCE_ENV" ] || \
    fail "[source-env] vendor/h2-source.env must be a regular file (not a symlink)"

TMPDIR_WORK=$(mktemp -d "${TMPDIR:-/tmp}/verify-h2-graph.XXXXXX")
cleanup() {
    rm -rf "$TMPDIR_WORK"
}
trap cleanup EXIT HUP INT TERM

run_metadata() {
    out_json="$1"
    out_err="$2"
    shift 2
    if ! cargo metadata --locked --format-version 1 \
        --manifest-path "$REPO_ROOT/Cargo.toml" "$@" \
        > "$out_json" 2> "$out_err"; then
        cat "$out_err" >&2
        fail "cargo metadata --locked $* failed"
    fi
    if grep -iE 'patch.*was not used|unused patch' "$out_err" >/dev/null 2>&1; then
        cat "$out_err" >&2
        fail "cargo reported an unused [patch] entry ($*)"
    fi
}

ALL_META_JSON="$TMPDIR_WORK/metadata-all.json"
run_metadata "$ALL_META_JSON" "$TMPDIR_WORK/metadata-all.err"

TARGET_ARGS=""
for target in $SHIPPED_TARGETS; do
    t_json="$TMPDIR_WORK/metadata-${target}.json"
    t_err="$TMPDIR_WORK/metadata-${target}.err"
    run_metadata "$t_json" "$t_err" --filter-platform "$target"
    TARGET_ARGS="$TARGET_ARGS ${target}=${t_json}"
done

# shellcheck disable=SC2086
python3 - "$REPO_ROOT" "$ALL_META_JSON" $TARGET_ARGS <<'PY'
import json
import os
import re
import sys

repo_root = sys.argv[1]
all_meta_path = sys.argv[2]
target_specs = sys.argv[3:]

phys_repo_root = os.path.realpath(repo_root)
vendor_parent = os.path.join(phys_repo_root, "vendor")
source_env_path = os.path.join(vendor_parent, "h2-source.env")
vendor_dir = os.path.join(vendor_parent, "h2")
expected_manifest = os.path.join(vendor_dir, "Cargo.toml")
lock_path = os.path.join(phys_repo_root, "Cargo.lock")
readme_path = os.path.join(vendor_parent, "README.md")
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"

def die(msg: str) -> None:
    print(f"ERROR: verify-h2-graph: {msg}", file=sys.stderr)
    sys.exit(1)

for label, p in [("vendor", vendor_parent), ("vendor/h2-source.env", source_env_path)]:
    if os.path.islink(p):
        die(f"{label} must not be a symlink: {p}")
if os.path.realpath(source_env_path) != source_env_path:
    die(f"vendor/h2-source.env physical path '{os.path.realpath(source_env_path)}' != '{source_env_path}'")

cfg = {}
with open(source_env_path, "r", encoding="utf-8") as f:
    for lineno, raw in enumerate(f, 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if "=" not in s:
            die(f"invalid line {lineno} in vendor/h2-source.env")
        k, v = s.split("=", 1)
        if k in cfg:
            die(f"duplicate key '{k}' in vendor/h2-source.env")
        cfg[k] = v

mode = cfg.get("H2_SOURCE_MODE")
expected_version = cfg.get("H2_VERSION")
expected_sha = cfg.get("H2_ARCHIVE_SHA256")
if mode not in ("vendored", "registry"):
    die(f"invalid H2_SOURCE_MODE {mode!r} in vendor/h2-source.env")
if not expected_version or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", expected_version):
    die(f"invalid H2_VERSION {expected_version!r} in vendor/h2-source.env")
if not expected_sha or not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
    die(f"invalid H2_ARCHIVE_SHA256 {expected_sha!r} in vendor/h2-source.env")
if set(cfg.keys()) != {"H2_SOURCE_MODE", "H2_VERSION", "H2_ARCHIVE_SHA256"}:
    die(f"unexpected keys in vendor/h2-source.env: {sorted(cfg.keys())}")

if mode == "vendored":
    for label, p in [("vendor/h2", vendor_dir), ("vendor/h2/Cargo.toml", expected_manifest)]:
        if os.path.islink(p):
            die(f"[containment] {label} must not be a symlink: {p}")
    if os.path.realpath(expected_manifest) != expected_manifest:
        die(f"[containment] vendor/h2/Cargo.toml physical path '{os.path.realpath(expected_manifest)}' != '{expected_manifest}'")
    if not os.path.isfile(expected_manifest):
        die(f"[containment] missing {expected_manifest}")

    # Cross-check vendor/h2/Cargo.toml version.
    with open(expected_manifest, "r", encoding="utf-8") as f:
        in_pkg = False
        vendor_version = None
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
    if vendor_version != expected_version:
        die(f"vendor/h2/Cargo.toml version '{vendor_version}' != pinned '{expected_version}'")

    # Cross-check vendor/README.md version.
    with open(readme_path, "r", encoding="utf-8") as f:
        readme_text = f.read()
    m = re.findall(r'^- \*\*Upstream crate:\*\* `h2` `([^`]+)`\s*$', readme_text, re.MULTILINE)
    if len(m) != 1 or m[0] != expected_version:
        die(f"vendor/README.md upstream version {m!r} != pinned '{expected_version}'")

def check_metadata(label: str, meta_path: str, require_reachable: bool) -> str:
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    packages = meta.get("packages") or []
    pkg_by_id = {p["id"]: p for p in packages}
    h2_pkgs = [p for p in packages if p.get("name") == "h2"]

    if len(h2_pkgs) != 1:
        details = [(p.get("version"), p.get("source"), p.get("manifest_path")) for p in h2_pkgs]
        die(f"[graph-target] [{label}] expected exactly 1 h2 package in metadata, found {len(h2_pkgs)}: {details}")

    h2 = h2_pkgs[0]
    if h2.get("version") != expected_version:
        die(f"[{label}] resolved h2 version '{h2.get('version')}' != expected '{expected_version}'")

    if mode == "vendored":
        if h2.get("source") is not None:
            die(f"[{label}] resolved h2 has non-path source '{h2.get('source')}' (fallback to registry/git)")
        actual_manifest = os.path.realpath(h2.get("manifest_path", ""))
        if actual_manifest != expected_manifest:
            die(f"[{label}] resolved h2 manifest_path '{actual_manifest}' != physical '{expected_manifest}'")
        resolved_desc = actual_manifest
    else:
        if h2.get("source") != CRATES_IO_SOURCE:
            die(f"[{label}] registry-mode h2 source '{h2.get('source')}' != '{CRATES_IO_SOURCE}'")
        resolved_desc = CRATES_IO_SOURCE

    resolve = meta.get("resolve") or {}
    nodes = resolve.get("nodes") or []
    node_by_id = {n["id"]: n for n in nodes}
    h2_nodes = [n for n in nodes if pkg_by_id.get(n["id"], {}).get("name") == "h2"]
    if len(h2_nodes) != 1 or h2_nodes[0]["id"] != h2["id"]:
        die(f"[{label}] expected exactly 1 resolved h2 node matching {h2['id']}, found {[n['id'] for n in h2_nodes]}")

    if require_reachable:
        bin_pkgs = [p for p in packages if p.get("name") == "miraserve-bin"]
        if len(bin_pkgs) != 1:
            die(f"[{label}] expected 1 miraserve-bin package, found {len(bin_pkgs)}")
        bin_id = bin_pkgs[0]["id"]

        # Walk ONLY normal (kind == None) and build (kind == "build") dependency edges
        # on the target-filtered resolve graph; dev-only edges are ignored.
        seen = set()
        stack = [bin_id]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            node = node_by_id.get(cur)
            if not node:
                continue
            for dep in node.get("deps", []):
                dep_kinds = dep.get("dep_kinds") or []
                is_normal_or_build = any(dk.get("kind") in (None, "build") for dk in dep_kinds)
                if is_normal_or_build:
                    pkg_id = dep.get("pkg")
                    if pkg_id and pkg_id not in seen:
                        stack.append(pkg_id)

        if h2["id"] not in seen:
            die(f"[graph-reach] [{label}] h2 is not reachable from miraserve-bin via normal/build dependencies")

    return resolved_desc

resolved_desc = check_metadata("all-targets", all_meta_path, require_reachable=False)

if len(target_specs) != 5:
    die(f"expected 5 shipped release targets, got {len(target_specs)}")

checked_targets = []
for spec in target_specs:
    target, t_path = spec.split("=", 1)
    check_metadata(target, t_path, require_reachable=True)
    checked_targets.append(target)

# Verify Cargo.lock h2 entry matches active mode.
with open(lock_path, "r", encoding="utf-8") as f:
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

if len(lock_h2) != 1:
    die(f"expected exactly 1 h2 entry in Cargo.lock, found {len(lock_h2)}: {lock_h2}")
lock_ver, lock_src, lock_chk = lock_h2[0]
if lock_ver != expected_version:
    die(f"Cargo.lock h2 version '{lock_ver}' != expected '{expected_version}'")

if mode == "vendored":
    if lock_src is not None or lock_chk is not None:
        die(f"[graph-lock] Cargo.lock h2 entry must be path-patched (source={lock_src!r}, checksum={lock_chk!r})")
    print(
        f"h2 graph OK: single resolved h2 {expected_version} at {resolved_desc} "
        f"(normal/build reachable from miraserve-bin across {len(checked_targets)} release targets)"
    )
else:
    if lock_src != CRATES_IO_SOURCE or lock_chk != expected_sha:
        die(
            f"[graph-lock] Cargo.lock h2 entry mismatch in registry mode "
            f"(source={lock_src!r}, checksum={lock_chk!r}, expected checksum={expected_sha!r})"
        )
    print(
        f"h2 graph OK (registry mode): single resolved crates.io h2 {expected_version} "
        f"sha256 {expected_sha} (normal/build reachable from miraserve-bin across {len(checked_targets)} release targets)"
    )
PY
