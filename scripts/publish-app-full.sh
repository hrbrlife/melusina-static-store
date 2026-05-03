#!/usr/bin/env bash
#
# publish-app-full.sh — one-shot end-to-end publish for a single app source.
# Implements the cardinal "make publish" pipeline:
#
#   1. Pre-flight (icon QC of the source, make pack ensure binary present)
#   2. Auto-bump version (patch by default)
#   3. make build  + make pack          (in source repo)
#   4. Pearl ceremony — propose-release + finalize-release
#      (Squads multisig sign on whatever multisig is wired in the app's
#      Pearl env; production today, test PDA when one is wired)
#   5. Push the publish branch in the app's origin (via spkmodule)
#   6. Update the deployer approval manifest with the new app_hash
#   7. Refresh the static_store packages submodule pointer
#   8. Rebuild + plan + apply the static_store catalog (gh-pages publish)
#
# Designed to be safe to re-run. Each step is idempotent or skip-when-up-to-date.
# Uses per-step env-var flags so an operator can opt out of a step (e.g.
# SKIP_CEREMONY=1 to publish offline-stub RELEASE.json).
#
# Usage:
#   publish-app-full.sh <app-source-dir> [--bump patch|minor|major|none]
#                                        [--skip ceremony,manifest,sync]
#                                        [--dry-run]
#
# Exit codes: 0 success; 1 step failure; 2 bad inputs.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATIC_STORE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

APP_DIR=""
BUMP="patch"
SKIP=""
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bump)    BUMP="$2"; shift 2 ;;
    --skip)    SKIP="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help)
      sed -n '/^# Usage:/,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
    *)
      [[ -z "$APP_DIR" ]] || { echo "unknown arg: $1" >&2; exit 2; }
      APP_DIR="$1"; shift ;;
  esac
done

[[ -n "$APP_DIR" ]] || { echo "FATAL: app dir required" >&2; exit 2; }
[[ -d "$APP_DIR" ]] || { echo "FATAL: not a directory: $APP_DIR" >&2; exit 2; }

skip_step() { [[ ",${SKIP}," == *",$1,"* ]]; }

ok()    { printf '\033[0;32m[OK]\033[0m   %s\n' "$*"; }
info()  { printf '\033[0;36m[INFO]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
fail()  { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*"; exit 1; }
step()  { printf '\033[1;36m[STEP %s]\033[0m %s\n' "$1" "$2"; }

run_or_dry() {
  if $DRY_RUN; then
    info "DRY RUN — would: $*"
  else
    "$@"
  fi
}

cd "$APP_DIR"
APP_SLUG="$(basename "$APP_DIR")"
info "App: $APP_SLUG ($APP_DIR)"
info "Static store: $STATIC_STORE_ROOT"
info "Bump: $BUMP   Skip: ${SKIP:-(none)}   Dry-run: $DRY_RUN"
echo

# ---- Step 1: bump version ---------------------------------------------------
step 1 "version bump"
if [[ "$BUMP" == "none" ]]; then
  info "  skipping version bump (--bump none)"
else
  if $DRY_RUN; then
    "$SCRIPT_DIR/version-bump.sh" "$APP_DIR" "$BUMP" --dry-run
  else
    "$SCRIPT_DIR/version-bump.sh" "$APP_DIR" "$BUMP"
  fi
fi
echo

# ---- Step 2: build + pack ---------------------------------------------------
step 2 "build + pack"
# Ensure spkmodule submodule is populated (apps store it as a submodule;
# `make pack` only resolves when spkmodule/mk/core.mk is present).
if [[ -f "$APP_DIR/.gitmodules" ]] \
   && grep -q '\[submodule "spkmodule"\]\|spkmodule\.path' "$APP_DIR/.gitmodules" 2>/dev/null \
   && [[ ! -f "$APP_DIR/spkmodule/mk/core.mk" ]]; then
  info "  spkmodule submodule not initialized — running git submodule update --init"
  run_or_dry git -C "$APP_DIR" submodule update --init --depth 1 spkmodule
fi
# Some apps keep sandstorm-pkgdef.capnp at .sandstorm/ instead of the repo
# root. spkmodule's pack target bind-mounts the repo root and expects the
# pkgdef at /opt/app/sandstorm-pkgdef.capnp; create a relative symlink so it
# resolves transparently. The symlink is reversible — leave it in place so
# subsequent invocations are idempotent.
if [[ ! -e "$APP_DIR/sandstorm-pkgdef.capnp" \
   && -f "$APP_DIR/.sandstorm/sandstorm-pkgdef.capnp" ]]; then
  info "  pkgdef lives at .sandstorm/ — adding root symlink so pack can find it"
  $DRY_RUN || ln -sf .sandstorm/sandstorm-pkgdef.capnp "$APP_DIR/sandstorm-pkgdef.capnp"
fi
if [[ ! -f "$APP_DIR/Makefile" ]]; then
  warn "  no Makefile in $APP_DIR — skipping build/pack (caller responsible)"
else
  has_target() {
    # Use --question (-q) to check target existence. Exit codes:
    #   0 = target up-to-date, 1 = needs rebuild, 2 = no rule for target.
    # Either 0 or 1 means the target is defined (even if from an included
    # spkmodule fragment).
    make -C "$APP_DIR" -q "$1" >/dev/null 2>&1
    rc=$?
    [[ $rc -eq 0 || $rc -eq 1 ]]
  }
  if has_target build; then
    run_or_dry make -C "$APP_DIR" build
  else
    info "  no 'build' target; skipping"
  fi
  if has_target pack; then
    run_or_dry make -C "$APP_DIR" pack
    # Confirm the SPK actually landed where downstream steps expect it.
    # spkmodule defaults to $APP_DIR/app.spk via SPK_OUT; some app
    # Makefiles override (e.g., openclaw-main writes melusina-openclaw.spk).
    if ! $DRY_RUN; then
      SPK_PATH="$APP_DIR/app.spk"
      if [[ ! -f "$SPK_PATH" ]]; then
        # Look for any .spk file produced in the last 60s as a fallback
        FOUND_SPK="$(find "$APP_DIR" -maxdepth 2 -name '*.spk' -mmin -1 -type f 2>/dev/null | head -1)"
        if [[ -n "$FOUND_SPK" && -f "$FOUND_SPK" ]]; then
          warn "  pack produced $FOUND_SPK (not $SPK_PATH) — symlinking for downstream"
          ln -sf "$(realpath "$FOUND_SPK")" "$SPK_PATH"
        else
          fail "  pack target ran but no app.spk produced at $SPK_PATH (and no recent *.spk found)"
        fi
      fi
    fi
  elif $DRY_RUN; then
    info "  no 'pack' target visible (likely spkmodule submodule pending init); would resolve after init"
  else
    fail "  no 'pack' target reachable from $APP_DIR/Makefile — cannot continue without an SPK"
  fi
fi
echo

# ---- Step 3: ceremony (Squads sign) -----------------------------------------
step 3 "Pearl ceremony"
# Regenerate offline RELEASE.json by default whenever the SPK was just packed,
# so downstream catalog consumers see a release manifest that matches the
# new app_hash. The release-json-stub is deterministic — re-running with
# the same SPK produces byte-identical output.
SPK_FOR_REL=""
if [[ -f "$APP_DIR/app.spk" ]]; then
  SPK_FOR_REL="$APP_DIR/app.spk"
else
  # find newest .spk in app dir as fallback (for apps with custom SPK_OUT)
  SPK_FOR_REL="$(find "$APP_DIR" -maxdepth 2 -name '*.spk' -mmin -10 -type f 2>/dev/null | head -1)"
fi

regen_stub_release() {
  if [[ -z "$SPK_FOR_REL" || ! -f "$SPK_FOR_REL" ]]; then
    warn "  no SPK found — cannot regenerate RELEASE.json"
    return
  fi
  if [[ ! -f "$APP_DIR/metadata.json" ]]; then
    warn "  no metadata.json at $APP_DIR — release-json-stub requires one"
    return
  fi
  local stub_bin="$APP_DIR/spkmodule/bin/release-json-stub"
  [[ -x "$stub_bin" ]] || stub_bin="$STATIC_STORE_ROOT/scripts/release-json-stub-fallback"
  if [[ ! -x "$stub_bin" ]]; then
    warn "  release-json-stub not found at $APP_DIR/spkmodule/bin/release-json-stub"
    return
  fi
  local VER
  VER="$(APP_DIR="$APP_DIR" python3 -c '
import json, os
print(json.load(open(os.path.join(os.environ["APP_DIR"], "metadata.json"))).get("marketingVersion", "0.0.0"))
')"
  run_or_dry "$stub_bin" \
    --spk "$SPK_FOR_REL" \
    --metadata "$APP_DIR/metadata.json" \
    --output "$APP_DIR/RELEASE.json" \
    --version "$VER"
}

if skip_step ceremony; then
  warn "  --skip ceremony — regenerating offline-stub RELEASE.json (so it matches the new SPK hash)"
  regen_stub_release
elif [[ ! -f "$APP_DIR/spkmodule/mk/pearl.mk" ]]; then
  warn "  no spkmodule/mk/pearl.mk — running release-json-stub instead"
  if [[ -f "$APP_DIR/app.spk" ]]; then
    # Read marketingVersion from metadata.json without shell-interpolating the
    # path (avoid quoting bugs / injection from APP_DIR).
    VER="$(APP_DIR="$APP_DIR" python3 -c '
import json, os
p = os.path.join(os.environ["APP_DIR"], "metadata.json")
try:
    print(json.load(open(p)).get("marketingVersion", "0.0.0"))
except FileNotFoundError:
    print("0.0.0")
')"
    run_or_dry "$APP_DIR/spkmodule/bin/release-json-stub" \
        --spk "$APP_DIR/app.spk" \
        --metadata "$APP_DIR/metadata.json" \
        --output "$APP_DIR/RELEASE.json" \
        --version "$VER"
  else
    warn "  no $APP_DIR/app.spk — pack must have been skipped"
  fi
elif ! command -v melusina-pearl-tool >/dev/null 2>&1; then
  warn "  melusina-pearl-tool NOT on PATH — falling back to offline stub"
  SKIP="${SKIP:+$SKIP,}ceremony"
else
  # Two-phase ceremony: propose-release writes state.json; finalize-release
  # consumes it. If state.json already exists, jump straight to finalize.
  STATE="$APP_DIR/.pearl/state.json"
  if [[ -f "$STATE" ]]; then
    info "  ceremony state present — running finalize-release"
    run_or_dry make -C "$APP_DIR" finalize-release || fail "finalize-release failed"
  else
    info "  proposing release (Phase A)"
    run_or_dry make -C "$APP_DIR" propose-release || warn "propose-release failed (may need wallet)"
    if [[ -f "$STATE" ]]; then
      info "  finalizing (Phase B)"
      run_or_dry make -C "$APP_DIR" finalize-release || warn "finalize-release deferred — re-run later"
    fi
  fi
fi
echo

# ---- Step 4: push publish branch --------------------------------------------
step 4 "push publish branch"
if skip_step push; then
  warn "  --skip push — local-only publish"
else
  has_target() { make -C "$APP_DIR" -q "$1" >/dev/null 2>&1; rc=$?; [[ $rc -eq 0 || $rc -eq 1 ]]; }
  if has_target publish; then
    run_or_dry make -C "$APP_DIR" publish || fail "make publish (push to origin) failed"
  else
    warn "  no 'publish' target — skipping branch push (use spkmodule)"
  fi
fi
echo

# ---- Step 5: update deployer approval manifest ------------------------------
step 5 "deployer approval manifest"
DEPLOYER_MANIFEST="${MELUSINA_DEPLOYER_MANIFEST:-/home/user/Desktop/Melusina/deployer/config/approval-manifests/global-apps-2026-04-23.json}"
if skip_step manifest; then
  warn "  --skip manifest"
elif [[ ! -f "$DEPLOYER_MANIFEST" ]]; then
  warn "  manifest not found at $DEPLOYER_MANIFEST"
elif ! make -C "$APP_DIR" -q approval-manifest-entry >/dev/null 2>&1 \
     && [[ "$(make -C "$APP_DIR" -q approval-manifest-entry >/dev/null 2>&1; echo $?)" == "2" ]]; then
  warn "  no approval-manifest-entry target — manifest unchanged"
else
  if $DRY_RUN; then
    info "  DRY RUN — would emit entry and merge into $DEPLOYER_MANIFEST"
  else
    ENTRY="$(make -C "$APP_DIR" approval-manifest-entry 2>/dev/null | sed -n '/^{/,/^}/p')"
    if [[ -z "$ENTRY" ]]; then
      warn "  approval-manifest-entry produced no output"
    else
      printf '%s\n' "$ENTRY" \
        | "$STATIC_STORE_ROOT/scripts/manifest-merge.sh" \
            --manifest "$DEPLOYER_MANIFEST" --stdin \
        || warn "  manifest-merge.sh exited non-zero"
    fi
  fi
fi
echo

# ---- Step 6: catalog sync ---------------------------------------------------
step 6 "static_store catalog sync"
if skip_step sync; then
  warn "  --skip sync — catalog NOT rebuilt"
else
  run_or_dry "$SCRIPT_DIR/sync-catalog.sh" --app "$APP_SLUG" \
    || fail "catalog sync failed"
fi
echo

ok "publish-app-full done for $APP_SLUG"
