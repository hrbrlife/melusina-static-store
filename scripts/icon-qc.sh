#!/usr/bin/env bash
#
# icon-qc.sh — pre-publish gate for app icon completeness.
#
# Walks packages/<author>/<repo>/<slug>/ and flags:
#   - missing icon.svg / icon.png
#   - tiny (placeholder) catalog icon (<1KB)
#   - SVG that fails to render with rsvg-convert/ImageMagick
#   - rendered icon that is effectively blank (single dominant color
#     covers >98% of the canvas — catches white/transparent placeholders)
#   - missing per-Sandstorm-slot icons in app_icons/<AppName>/
#     (appGrid/grain/market/marketBig per ICON_TAXONOMY.md)
#   - missing PNG raster set (icon-128x128.png etc.) when the app has an
#     app_icons/<AppName>/ entry that was previously populated
#
# Exits 0 with all-clear, 1 if any FAIL, 2 if WARN-only and
# MELUSINA_ICON_QC_STRICT=1.
#
# Usage:
#   scripts/icon-qc.sh                # full scan, table to stdout
#   scripts/icon-qc.sh --json         # machine-readable output
#   MELUSINA_ICON_QC_STRICT=1 scripts/icon-qc.sh  # warn-as-fail
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

PACKAGES_DIR="${PACKAGES_DIR:-packages}"
APP_ICONS_DIR="${APP_ICONS_DIR:-app_icons}"
# 500B catches the egregious "<text>ST</text>"-style stubs while letting
# small but real category-tile icons (~960-1100B) pass.
MIN_ICON_BYTES="${MIN_ICON_BYTES:-500}"
BLANK_DOMINANT_PCT="${BLANK_DOMINANT_PCT:-98}"
JSON_OUT=false
[[ "${1:-}" == "--json" ]] && JSON_OUT=true

ok()    { printf '\033[0;32m[OK]\033[0m   %s\n' "$*"; }
info()  { printf '\033[0;36m[INFO]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
fail()  { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*"; }

# --- prereqs ----------------------------------------------------------------
RENDER_CMD=""
if command -v rsvg-convert >/dev/null 2>&1; then
  RENDER_CMD="rsvg-convert"
elif command -v convert >/dev/null 2>&1; then
  RENDER_CMD="convert"
else
  fail "neither rsvg-convert nor ImageMagick 'convert' available — cannot render SVGs"
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

render_to_png() {
  local in="$1" out="$2"
  if [[ "$RENDER_CMD" == "rsvg-convert" ]]; then
    rsvg-convert -w 128 -h 128 -b white "$in" -o "$out" 2>/dev/null
  else
    convert -background white "$in" -resize 128x128 "$out" 2>/dev/null
  fi
}

# Returns the dominant-color coverage percentage as integer.
dominant_pct() {
  local png="$1"
  if ! command -v convert >/dev/null 2>&1; then
    echo "0"
    return
  fi
  convert "$png" -format "%c" histogram:info: 2>/dev/null \
    | awk '{print $1+0}' | sort -n | tail -1 \
    | awk -v total=$((128*128)) '{printf "%d", ($1*100)/total}'
}

# --- main scan --------------------------------------------------------------
ROWS_JSON="["
FIRST_ROW=true
TOTAL=0
FAILS=0
WARNS=0

declare -a FAIL_LINES
declare -a WARN_LINES

while IFS= read -r meta; do
  app_dir="$(dirname "$meta")"
  TOTAL=$((TOTAL+1))

  name="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('name','?'))" "$meta")"
  app_id="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('appId',''))" "$meta")"

  # Catalog-level icon
  catalog_icon=""
  catalog_status="ok"
  catalog_reason=""
  if [[ -f "$app_dir/icon.svg" ]]; then
    catalog_icon="$app_dir/icon.svg"
  elif [[ -f "$app_dir/icon.png" ]]; then
    catalog_icon="$app_dir/icon.png"
  fi

  if [[ -z "$catalog_icon" ]]; then
    catalog_status="fail"
    catalog_reason="no icon.svg or icon.png"
  else
    sz="$(stat -c%s "$catalog_icon")"
    if (( sz < MIN_ICON_BYTES )); then
      catalog_status="warn"
      catalog_reason="placeholder-sized ($sz B < ${MIN_ICON_BYTES} B)"
    fi
    rendered="$TMP/$(basename "$app_dir").png"
    if ! render_to_png "$catalog_icon" "$rendered"; then
      catalog_status="fail"
      catalog_reason="render failed"
    elif [[ -f "$rendered" ]]; then
      pct="$(dominant_pct "$rendered" 2>/dev/null || echo 0)"
      if (( pct >= BLANK_DOMINANT_PCT )); then
        catalog_status="fail"
        catalog_reason="blank — single color covers ${pct}% of canvas"
      fi
    fi
  fi

  # Per-Sandstorm-slot icon set (app_icons/<AppName>/).
  # Catalog name and app_icons dir often differ in spacing, casing, and
  # noun order ("Cal Bureau" vs "BureauCal"; "cca.sh Config" vs
  # "CcashConfig"). Resolve via a normalize() that lowercases, strips
  # non-alnum, and tries both orderings of two-word names.
  ss_status="ok"
  ss_reason=""
  norm() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9'; }
  needle="$(norm "$name")"
  # Build alternates. Handles:
  #   "X Bureau" -> "BureauX" (also tries singular: "Sheets Bureau" -> "BureauSheet")
  #   "cca.sh X" -> "CcashX"
  #   semantic split-bureau aliases (Paint -> BureauImage, Diagrams -> BureauGraph)
  alt=""
  alt2=""
  if [[ "$name" == *" Bureau" ]]; then
    head="${name% Bureau}"
    alt="$(norm "Bureau${head}")"
    # singularize: trailing s
    [[ "$head" == *s ]] && alt2="$(norm "Bureau${head%s}")"
    case "$head" in
      Paint)    alt2="$(norm "BureauImage")" ;;
      Diagrams) alt2="$(norm "BureauGraph")" ;;
    esac
  fi
  if [[ "$name" == "cca.sh "* ]]; then
    alt="$(norm "Ccash${name#cca.sh }")"
  fi

  ss_dir=""
  if [[ -d "$APP_ICONS_DIR/$name" ]]; then
    ss_dir="$APP_ICONS_DIR/$name"
  else
    while IFS= read -r d; do
      [[ -z "$d" ]] && continue
      base="$(basename "$d")"
      bn="$(norm "$base")"
      if [[ "$bn" == "$needle" ]] \
         || [[ -n "$alt"  && "$bn" == "$alt"  ]] \
         || [[ -n "$alt2" && "$bn" == "$alt2" ]]; then
        ss_dir="$d"; break
      fi
    done < <(find "$APP_ICONS_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
  fi

  if [[ -z "$ss_dir" ]]; then
    ss_status="warn"
    ss_reason="no app_icons/ dir matching '$name'"
  else
    missing=()
    for need in icon.svg icon-128x128.png icon-256x256.png icon-512x512.png; do
      [[ -f "$ss_dir/$need" ]] || missing+=("$need")
    done
    if (( ${#missing[@]} > 0 )); then
      ss_status="warn"
      ss_reason="missing: ${missing[*]}"
    fi
  fi

  if [[ "$catalog_status" == "fail" ]]; then
    FAILS=$((FAILS+1))
    FAIL_LINES+=("$(printf '%-32s catalog: %s' "$name" "$catalog_reason")")
  fi
  if [[ "$catalog_status" == "warn" ]]; then
    WARNS=$((WARNS+1))
    WARN_LINES+=("$(printf '%-32s catalog: %s' "$name" "$catalog_reason")")
  fi
  if [[ "$ss_status" == "warn" ]]; then
    WARNS=$((WARNS+1))
    WARN_LINES+=("$(printf '%-32s app_icons: %s' "$name" "$ss_reason")")
  fi

  if $JSON_OUT; then
    [[ $FIRST_ROW == false ]] && ROWS_JSON+=","
    FIRST_ROW=false
    ROWS_JSON+=$(printf '{"name":"%s","appId":"%s","catalog":{"status":"%s","reason":"%s"},"appIcons":{"status":"%s","reason":"%s"}}' \
      "$name" "$app_id" "$catalog_status" "$catalog_reason" "$ss_status" "$ss_reason")
  fi
done < <(find "$PACKAGES_DIR" -maxdepth 4 -name metadata.json | sort)

ROWS_JSON+="]"

if $JSON_OUT; then
  echo "$ROWS_JSON"
  exit 0
fi

# --- summary ----------------------------------------------------------------
info "Scanned $TOTAL apps"
echo

if (( FAILS > 0 )); then
  fail "FAIL ($FAILS):"
  for line in "${FAIL_LINES[@]}"; do echo "    $line"; done
  echo
fi
if (( WARNS > 0 )); then
  warn "WARN ($WARNS):"
  for line in "${WARN_LINES[@]}"; do echo "    $line"; done
  echo
fi

if (( FAILS > 0 )); then
  fail "Icon QC FAILED — $FAILS broken icons must be fixed before publish."
  exit 1
fi
if (( WARNS > 0 )) && [[ "${MELUSINA_ICON_QC_STRICT:-}" == "1" ]]; then
  fail "Icon QC FAILED in strict mode — $WARNS warnings (set MELUSINA_ICON_QC_STRICT=0 to downgrade)"
  exit 2
fi
ok "Icon QC PASSED ($TOTAL apps, $WARNS warnings, 0 fails)"
exit 0
