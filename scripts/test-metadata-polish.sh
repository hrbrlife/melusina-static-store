#!/bin/bash
# scripts/test-metadata-polish.sh
#
# Validates that every app under packages/hrbrlife/<repo>/<slug>/ carries
# the metadata polish baseline — author identity, license, description, icon,
# canonical terminology. Designed to run cheap (no network, no .spk hashing,
# no JSON pretty-print). Drift fails the script.
#
# Exit codes:
#   0 — all 25 apps green
#   1 — at least one app failed at least one check
#
# Run:   bash scripts/test-metadata-polish.sh
# CI:    invoke from preflight.sh after Gate 4 (or as a standalone CI step)

set -euo pipefail
cd "$(dirname "$0")/.."

PACKAGES_DIR="packages/hrbrlife"
EXPECTED_AUTHOR_EMAIL="ak@hrbr.life"
EXPECTED_AUTHOR_WEBSITE="https://hrbr.life"

# Terminology violations: brand-name "Sandstorm"/"grain"/"Powerbox" used in prose where
# we now write "Melusina"/"Pearl"/"Grapple". Literal identifiers — sandstorm-http-bridge,
# SandstormApi, GrainContext, capnp/graincontext.capnp — are technical references and
# stay verbatim. The regex below excludes them.
DEPRECATED_BRAND_REGEX='\b(grain|grains|Grains|Sandstorm|Powerbox)\b'
LITERAL_KEEP_REGEX='sandstorm-http-bridge|SandstormApi|GrainContext|graincontext\.capnp'

red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[0;33m%s\033[0m\n' "$*"; }

fail_count=0
pass_count=0
checked=0

for meta in $(find "$PACKAGES_DIR" -mindepth 3 -maxdepth 3 -name metadata.json -type f | sort); do
  slug_dir="$(dirname "$meta")"
  checked=$((checked + 1))

  slug_label="${slug_dir#$PACKAGES_DIR/}"
  slug_failed=0
  errors=()

  # Check 1: metadata.json parses as valid JSON
  if ! python3 -c "import json,sys; json.load(open('$meta'))" 2>/dev/null; then
    errors+=("metadata.json is not valid JSON")
    slug_failed=1
  fi

  # Pull all the fields we need in one Python call (parse once)
  if [[ "$slug_failed" -eq 0 ]]; then
    fields=$(python3 <<PY
import json
d = json.load(open("$meta"))
a = d.get("author", {}) or {}
print(repr(a.get("email", "")))
print(repr(a.get("website", "")))
print(repr(d.get("license", "")))
print(repr(d.get("description", "")))
print(repr(d.get("isOpenSource", None)))
PY
)
    email=$(printf '%s' "$fields" | sed -n '1p')
    website=$(printf '%s' "$fields" | sed -n '2p')
    license_val=$(printf '%s' "$fields" | sed -n '3p')
    description=$(printf '%s' "$fields" | sed -n '4p')
    is_open_source=$(printf '%s' "$fields" | sed -n '5p')

    # Check 2: author.email
    if [[ "$email" != "'$EXPECTED_AUTHOR_EMAIL'" ]]; then
      errors+=("author.email is $email (expected '$EXPECTED_AUTHOR_EMAIL')")
      slug_failed=1
    fi

    # Check 3: author.website
    if [[ "$website" != "'$EXPECTED_AUTHOR_WEBSITE'" ]]; then
      errors+=("author.website is $website (expected '$EXPECTED_AUTHOR_WEBSITE')")
      slug_failed=1
    fi

    # Check 4: license non-empty
    if [[ "$license_val" == "''" || "$license_val" == "None" ]]; then
      errors+=("license is empty / missing")
      slug_failed=1
    fi

    # Check 5: description present (either inline metadata.description OR description.md sidecar)
    desc_md="$slug_dir/description.md"
    if [[ "$description" == "''" || "$description" == "None" ]]; then
      if [[ ! -s "$desc_md" ]]; then
        errors+=("no description (neither metadata.description nor description.md present/non-empty)")
        slug_failed=1
      fi
    fi

    # Check 6: contradiction guard — if license is "Melusina Public License v1.0",
    # isOpenSource must NOT be true (the license is explicitly source-available, not OSS).
    if [[ "$license_val" == *"Melusina Public License v1.0"* && "$is_open_source" == "True" ]]; then
      errors+=("contradiction: isOpenSource=true but license is Melusina Public License v1.0 (source-available, not OSS)")
      slug_failed=1
    fi
  fi

  # Check 7: icon exists (svg preferred, png acceptable)
  if [[ ! -f "$slug_dir/icon.svg" && ! -f "$slug_dir/icon.png" ]]; then
    errors+=("no icon.svg or icon.png present")
    slug_failed=1
  fi

  # Check 8: no PGP detached signatures (HT13 / Janeway no-PGP rule)
  if compgen -G "$slug_dir/*.asc" > /dev/null || compgen -G "$slug_dir/*.gpg" > /dev/null; then
    errors+=("PGP file present in slug dir (HT13 / Janeway: no PGP allowed)")
    slug_failed=1
  fi

  # Check 9: app.spk exists (not validating its hash here — that's preflight Gate 2)
  if [[ ! -f "$slug_dir/app.spk" ]]; then
    errors+=("no app.spk present")
    slug_failed=1
  fi

  # Check 10: RELEASE.json exists
  if [[ ! -f "$slug_dir/RELEASE.json" ]]; then
    errors+=("no RELEASE.json present")
    slug_failed=1
  fi

  # Check 11: terminology — scan description.md for brand-name violations,
  # excluding the literal-identifier allowlist.
  if [[ -f "$slug_dir/description.md" ]]; then
    # Strip out lines containing any literal identifier first, then grep for brand violations
    if grep -E "$DEPRECATED_BRAND_REGEX" "$slug_dir/description.md" 2>/dev/null \
       | grep -vE "$LITERAL_KEEP_REGEX" \
       | head -1 | grep -q .; then
      hits=$(grep -nE "$DEPRECATED_BRAND_REGEX" "$slug_dir/description.md" \
             | grep -vE "$LITERAL_KEEP_REGEX" || true)
      errors+=("description.md uses deprecated brand terms: $(echo "$hits" | head -3 | tr '\n' '|')")
      slug_failed=1
    fi
  fi

  # Check 12: terminology — same gate for shortDescription in metadata.json.
  # The shortDescription is what the catalog UI shows in tile views; brand drift
  # there is more visible than in description.md prose.
  if [[ "$slug_failed" -eq 0 ]]; then
    short_text=$(python3 -c "import json; print(json.load(open('$meta')).get('shortDescription',''))" 2>/dev/null || echo "")
    if printf '%s' "$short_text" | grep -E "$DEPRECATED_BRAND_REGEX" 2>/dev/null \
         | grep -vE "$LITERAL_KEEP_REGEX" | head -1 | grep -q .; then
      errors+=("shortDescription uses deprecated brand terms: $short_text")
      slug_failed=1
    fi
  fi

  # Report
  if [[ "$slug_failed" -eq 1 ]]; then
    fail_count=$((fail_count + 1))
    red "✗ $slug_label"
    for e in "${errors[@]}"; do
      echo "    $e"
    done
  else
    pass_count=$((pass_count + 1))
  fi
done

echo
echo "Apps checked:  $checked"
green "Passed:        $pass_count"
if [[ "$fail_count" -gt 0 ]]; then
  red "Failed:        $fail_count"
  exit 1
fi
green "All $checked apps green."
exit 0
