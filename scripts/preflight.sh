#!/usr/bin/env bash
#
# preflight.sh — gate `make publish` against the regression mode that
# bit us on 2026-04-25 (see ../POSTMORTEM.md). Walks five checks:
#
#   1. live-catalog diff against the just-built dist-publish/apps/index.json
#      — abort if any appId disappears (set MELUSINA_PUBLISH_SHRINK_OK=1
#      to override when shrinking is actually intended).
#   2. manifest cross-check — compare each app in the Melusina deployer
#      approval-manifest against the local .spk SHA-256. FAIL on drift by
#      default (set MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT=1 to downgrade
#      to warn-only — only when reseat work is in flight and acknowledged).
#   3. authoritative-host gate — warn if MELUSINA_PUBLISH_AUTHORITATIVE
#      is unset. Makefile target `deploy` also hard-gates on this var, so
#      preflight here is informational; the Makefile is the abort point.
#   4. pre-push announce — print the added/removed/changed app summary.
#   5. exit code 0 on green, 1 on any abort condition.
#
# Run from the static_store root after `bash build-store.sh ...` has
# produced dist-publish/. Invoked by `make preflight` and as a
# dependency of `make deploy` / `make publish`.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

# --- Configuration -----------------------------------------------------------
LIVE_CATALOG_URL="${MELUSINA_LIVE_CATALOG_URL:-https://hrbrlife.github.io/melusina-static-store/apps/index.json}"
LOCAL_BUILD="dist-publish/apps/index.json"
DEPLOYER_MANIFEST="${MELUSINA_DEPLOYER_MANIFEST:-/home/user/Desktop/Melusina/deployer/config/approval-manifests/global-apps-2026-04-23.json}"
PACKAGES_DIR="packages"

# --- Colors / log helpers ----------------------------------------------------
ok()    { printf '\033[0;32m[OK]\033[0m    %s\n' "$*"; }
info()  { printf '\033[0;36m[INFO]\033[0m  %s\n' "$*"; }
warn()  { printf '\033[1;33m[WARN]\033[0m  %s\n' "$*"; }
fail()  { printf '\033[0;31m[FAIL]\033[0m  %s\n' "$*"; }

ABORT=0

# --- Pre-flight: artifact present? -------------------------------------------
if [[ ! -f "$LOCAL_BUILD" ]]; then
  fail "Local build artifact missing: $LOCAL_BUILD"
  fail "Run 'bash build-store.sh' first to populate dist-publish/."
  exit 1
fi

# --- 1. Live-catalog diff ----------------------------------------------------
info "Gate 1/4: live-catalog diff (vs $LIVE_CATALOG_URL)"
LIVE_TMP="$(mktemp /tmp/preflight-live.XXXXXX.json)"
trap 'rm -f "$LIVE_TMP"' EXIT

if curl -sL --max-time 20 -H 'Cache-Control: no-cache' "$LIVE_CATALOG_URL" -o "$LIVE_TMP" 2>/dev/null && [[ -s "$LIVE_TMP" ]]; then
  set +e
  python3 - "$LIVE_TMP" "$LOCAL_BUILD" <<'PY'
import json, sys
live = json.load(open(sys.argv[1])).get('apps', [])
local = json.load(open(sys.argv[2])).get('apps', [])
live_ids = {a['appId']: a.get('name', '?') for a in live}
local_ids = {a['appId']: a.get('name', '?') for a in local}
removed = [(aid, live_ids[aid]) for aid in live_ids if aid not in local_ids]
added = [(aid, local_ids[aid]) for aid in local_ids if aid not in live_ids]
changed = []
local_pkgs = {a['appId']: a.get('packageId', '') for a in local}
live_pkgs = {a['appId']: a.get('packageId', '') for a in live}
for aid in set(local_ids) & set(live_ids):
    if local_pkgs.get(aid) != live_pkgs.get(aid):
        changed.append((aid, local_ids[aid], live_pkgs.get(aid, ''), local_pkgs.get(aid, '')))
print(f"  live count:  {len(live_ids)}", flush=True)
print(f"  local count: {len(local_ids)}", flush=True)
if removed:
    print(f"  REMOVED ({len(removed)}):", flush=True)
    for aid, name in removed:
        print(f"    - {name} ({aid[:24]}...)", flush=True)
if added:
    print(f"  ADDED ({len(added)}):", flush=True)
    for aid, name in added:
        print(f"    + {name} ({aid[:24]}...)", flush=True)
if changed:
    print(f"  CHANGED packageId ({len(changed)}):", flush=True)
    for aid, name, old, new in changed:
        print(f"    ~ {name} ({aid[:24]}...): {old[:12]} -> {new[:12]}", flush=True)
sys.exit(2 if removed else 0)
PY
  RC=$?
  set -e
  if [[ "$RC" -eq 2 ]]; then
    if [[ "${MELUSINA_PUBLISH_SHRINK_OK:-}" == "1" ]]; then
      warn "Catalog SHRINK detected, allowed by MELUSINA_PUBLISH_SHRINK_OK=1"
    else
      fail "Catalog SHRINK detected — local build would drop apps from live."
      fail "Set MELUSINA_PUBLISH_SHRINK_OK=1 to override (only when removal is intentional)."
      ABORT=1
    fi
  else
    ok "No apps would be removed by this publish"
  fi
else
  warn "Could not fetch live catalog from $LIVE_CATALOG_URL — skipping live diff (network or first-publish)"
fi

# --- 2. Manifest cross-check -------------------------------------------------
info "Gate 2/4: manifest cross-check (vs $DEPLOYER_MANIFEST)"
if [[ -f "$DEPLOYER_MANIFEST" ]]; then
  set +e
  python3 - "$DEPLOYER_MANIFEST" "$PACKAGES_DIR" <<'PY'
import json, os, sys, hashlib
manifest_path = sys.argv[1]
packages = sys.argv[2]
manifest = json.load(open(manifest_path))
mapps = manifest.get('apps', manifest) if isinstance(manifest, dict) else manifest
drifts, missing = [], []
for m in mapps:
    name = m.get('app_name', '?')
    appid = m.get('app_id', '?')
    expected_hash = m.get('app_hash', '')
    # Find the corresponding .spk under packages/<repo>/<slug>/app.spk
    found_spk = None
    for repo in os.listdir(packages):
        repo_dir = os.path.join(packages, repo)
        if not os.path.isdir(repo_dir):
            continue
        for sub in os.listdir(repo_dir):
            sub_dir = os.path.join(repo_dir, sub)
            for slug in os.listdir(sub_dir) if os.path.isdir(sub_dir) else []:
                slug_dir = os.path.join(sub_dir, slug)
                if not os.path.isdir(slug_dir):
                    continue
                meta = os.path.join(slug_dir, 'metadata.json')
                if not os.path.isfile(meta):
                    continue
                try:
                    md = json.load(open(meta))
                    if md.get('appId') == appid:
                        spk = os.path.join(slug_dir, 'app.spk')
                        if os.path.isfile(spk):
                            found_spk = spk
                except Exception:
                    pass
    if not found_spk:
        missing.append((name, appid[:24]))
        continue
    h = hashlib.sha256()
    with open(found_spk, 'rb') as f:
        for chunk in iter(lambda: f.read(1<<20), b''):
            h.update(chunk)
    actual_hash = h.hexdigest()
    if actual_hash != expected_hash:
        drifts.append((name, expected_hash[:12], actual_hash[:12]))
print(f"  manifest entries: {len(mapps)}")
print(f"  missing local .spk: {len(missing)}")
for name, aid in missing:
    print(f"    ? {name} ({aid}...) — no local .spk found in packages/")
print(f"  hash drifts: {len(drifts)}")
for name, ex, ac in drifts:
    print(f"    ! {name}: manifest={ex}... local={ac}...")
sys.exit(2 if drifts or missing else 0)
PY
  RC=$?
  set -e
  if [[ "$RC" -eq 2 ]]; then
    if [[ "${MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT:-}" == "1" ]]; then
      warn "Manifest mismatch — proceeding under MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT=1 opt-out"
    else
      fail "Manifest mismatch — local .spk does not match deployer manifest's expected app_hash."
      fail "Reseat on-chain via Worf, or rebuild the .spk to match. Override with MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT=1 only if reseat is in flight."
      ABORT=1
    fi
  else
    ok "All manifest .spk hashes match local"
  fi
else
  warn "Deployer manifest not found at $DEPLOYER_MANIFEST — skipping cross-check"
fi

# --- 3. Authoritative-host gate ----------------------------------------------
info "Gate 3/4: authoritative-host check"
if [[ "${MELUSINA_PUBLISH_AUTHORITATIVE:-}" == "1" ]]; then
  ok "MELUSINA_PUBLISH_AUTHORITATIVE=1 — host declared canonical builder"
else
  warn "MELUSINA_PUBLISH_AUTHORITATIVE not set — set =1 in the canonical builder's env to silence this warning"
fi

# --- 4. Pre-push announce ----------------------------------------------------
info "Gate 4/4: pre-push announce"
LOCAL_COUNT="$(python3 -c "import json; print(len(json.load(open('$LOCAL_BUILD')).get('apps', [])))")"
echo "  Local catalog will publish $LOCAL_COUNT apps."
if [[ -s "$LIVE_TMP" ]]; then
  LIVE_COUNT="$(python3 -c "import json; print(len(json.load(open('$LIVE_TMP')).get('apps', [])))" 2>/dev/null || echo "?")"
  echo "  Live catalog currently has $LIVE_COUNT apps."
  echo "  Net delta: $((LOCAL_COUNT - LIVE_COUNT)) apps."
fi

# --- Final ------------------------------------------------------------------
echo ""
if [[ "$ABORT" -eq 1 ]]; then
  fail "Preflight FAILED — fix the issues above or set the documented override env vars."
  exit 1
fi
ok "Preflight PASSED — safe to deploy."
exit 0
