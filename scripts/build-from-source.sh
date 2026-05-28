#!/bin/bash
# build-from-source.sh — Clean clone-and-rebuild of an upstream Sandstorm
# app SPK from a committed branch + SHA, using Melusina's patched bin/spk
# with the requestedMemoryGiB schema. Implements Captain Imperative idx 101
# (2026-04-30): "store-published SPK is the only test surface".
#
# Usage:
#   build-from-source.sh \
#     --slug <catalog-slug> \
#     --repo <git-url-or-local-path> \
#     --branch <branch> \
#     --sha <commit-sha> \
#     --build-cmd <bash-string-evaluated-in-checkout-dir> \
#     [--spk-output <relative-path-to-spk-after-build>] \
#     [--pkgdef <relative-path-to-pkgdef.capnp>]
#
# If --spk-output is given, that file is expected to exist after --build-cmd.
# If --spk-output is omitted, this script runs `spk pack` itself using
# --pkgdef and writes <slug>.spk in the checkout root.
#
# Output:
#   - Absolute path to the built .spk
#   - sha256 hex
#   - Path to captured `spk verify` text
#
# Side effects: creates /tmp/static_store-build-<slug>-<short-sha>/ with the
# clone + build artifacts. Re-running with the same slug+sha cleans the dir
# first.

set -euo pipefail

PATCHED_SPK=/home/user/Desktop/Melusina/sandstorm/bin/spk
SCHEMA_INCLUDE=/home/user/Desktop/Melusina/sandstorm/src

usage() {
  sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
  exit 1
}

SLUG="" ; REPO="" ; BRANCH="" ; SHA="" ; BUILD_CMD="" ; SPK_OUTPUT="" ; PKGDEF="" ; SUBMODULES=""

while [ $# -gt 0 ]; do
  case "$1" in
    --slug)        SLUG="$2"; shift 2 ;;
    --repo)        REPO="$2"; shift 2 ;;
    --branch)      BRANCH="$2"; shift 2 ;;
    --sha)         SHA="$2"; shift 2 ;;
    --build-cmd)   BUILD_CMD="$2"; shift 2 ;;
    --spk-output)  SPK_OUTPUT="$2"; shift 2 ;;
    --pkgdef)      PKGDEF="$2"; shift 2 ;;
    --submodules)  SUBMODULES="$2"; shift 2 ;;
    -h|--help)     usage ;;
    *)             echo "unknown arg: $1" >&2; usage ;;
  esac
done

for v in SLUG REPO BRANCH SHA BUILD_CMD; do
  if [ -z "${!v}" ]; then echo "ERROR: --${v,,} required" >&2; exit 2; fi
done

if [ ! -x "$PATCHED_SPK" ]; then
  echo "ERROR: patched spk binary missing at $PATCHED_SPK" >&2
  echo "       Coordinate with Melusina (idx 109): ekam-rebuild needed." >&2
  exit 3
fi

if [ ! -f "$SCHEMA_INCLUDE/sandstorm/package.capnp" ]; then
  echo "ERROR: patched schema include missing at $SCHEMA_INCLUDE/sandstorm/package.capnp" >&2
  exit 3
fi

SHORT_SHA="${SHA:0:8}"
SCRATCH=/tmp/static_store-build-"$SLUG"-"$SHORT_SHA"
echo "=== build-from-source: $SLUG @ $SHA ==="
echo "    repo:      $REPO"
echo "    branch:    $BRANCH"
echo "    scratch:   $SCRATCH"
echo "    build:     $BUILD_CMD"
echo "    spk-out:   ${SPK_OUTPUT:-<auto: spk pack>}"
echo "    pkgdef:    ${PKGDEF:-<n/a>}"
echo ""

# Clean scratch
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"

# Clone into scratch (full clone — depth shallow may miss the SHA on long
# branches; small enough for our apps to take the hit)
echo "=== clone ==="
if [[ "$REPO" =~ ^https?:// ]] || [[ "$REPO" =~ ^git@ ]]; then
  git clone "$REPO" "$SCRATCH/repo"
else
  # Local path — clone via file:// to keep checkout independent of working tree
  git clone "file://$(realpath "$REPO")" "$SCRATCH/repo"
fi

cd "$SCRATCH/repo"
echo ""
echo "=== checkout $SHA ==="
git fetch origin "$BRANCH" 2>/dev/null || true
git checkout "$SHA"

# Submodule init: if explicit list is given, init only those (best when the
# source crew knows exactly what their build needs and the parent repo has
# stale or unfetchable submodule pointers elsewhere). Otherwise try a full
# recursive init but never let a failure abort the build — let the build
# step itself tell us what's actually missing.
if [ -n "$SUBMODULES" ]; then
  echo "    selective submodule init: $SUBMODULES"
  for sm in $SUBMODULES; do
    git submodule update --init --recursive -- "$sm" 2>&1 | tail -3 || \
      echo "    WARN: submodule $sm failed to init (continuing — build will surface if essential)"
  done
else
  echo "    full recursive submodule init (best-effort)"
  git submodule update --init --recursive 2>&1 | tail -5 || \
    echo "    WARN: some submodules failed to init (continuing — build will surface if essential)"
fi

# Verify SHA matches (accept short-SHA prefixes since handoffs may use them)
ACTUAL_SHA=$(git rev-parse HEAD)
SHA_LOWER=$(echo "$SHA" | tr 'A-Z' 'a-z')
ACTUAL_LOWER=$(echo "$ACTUAL_SHA" | tr 'A-Z' 'a-z')
if [ "${ACTUAL_LOWER:0:${#SHA_LOWER}}" != "$SHA_LOWER" ]; then
  echo "ERROR: clone HEAD $ACTUAL_SHA does not match requested $SHA" >&2
  exit 4
fi
echo "   HEAD verified: $ACTUAL_SHA (matches requested $SHA)"
echo ""

# Run upstream build command (evaluated in the checkout root)
echo "=== build (in $PWD) ==="
echo "    \$ $BUILD_CMD"
echo ""
bash -c "$BUILD_CMD"
BUILD_EXIT=$?
if [ "$BUILD_EXIT" -ne 0 ]; then
  echo "ERROR: build command exited $BUILD_EXIT" >&2
  exit 5
fi
echo ""

# Locate built SPK
if [ -n "$SPK_OUTPUT" ]; then
  BUILT_SPK="$PWD/$SPK_OUTPUT"
  if [ ! -f "$BUILT_SPK" ]; then
    echo "ERROR: --spk-output $SPK_OUTPUT not found after build" >&2
    exit 6
  fi
else
  # Auto: run spk pack ourselves
  if [ -z "$PKGDEF" ]; then
    echo "ERROR: --pkgdef required when --spk-output omitted" >&2
    exit 2
  fi
  if [ ! -f "$PKGDEF" ]; then
    echo "ERROR: --pkgdef $PKGDEF not present after build" >&2
    exit 6
  fi
  BUILT_SPK="$PWD/$SLUG.spk"
  echo "=== spk pack ==="
  echo "    \$ $PATCHED_SPK pack -I$SCHEMA_INCLUDE -p $PKGDEF:pkgdef $BUILT_SPK"
  "$PATCHED_SPK" pack -I"$SCHEMA_INCLUDE" -p "$PKGDEF:pkgdef" "$BUILT_SPK"
  echo ""
fi

# Verify
echo "=== spk verify ==="
VERIFY_OUT="$SCRATCH/spk-verify-$SLUG.txt"
"$PATCHED_SPK" verify "$BUILT_SPK" > "$VERIFY_OUT" 2>&1
echo "    output captured: $VERIFY_OUT"
head -8 "$VERIFY_OUT" | sed 's/^/      /'
echo ""

# Compute sha256
SHA256_HEX=$(sha256sum "$BUILT_SPK" | cut -d' ' -f1)
SPK_SIZE=$(stat -c%s "$BUILT_SPK")

echo "=== RESULT ==="
echo "spk_path=$BUILT_SPK"
echo "spk_size=$SPK_SIZE"
echo "spk_sha256=$SHA256_HEX"
echo "spk_verify_text=$VERIFY_OUT"
echo "scratch_dir=$SCRATCH"
echo ""

# Machine-readable single-line summary on the last line
echo "RESULT_JSON={\"spk_path\":\"$BUILT_SPK\",\"sha256\":\"$SHA256_HEX\",\"size_bytes\":$SPK_SIZE,\"verify_text\":\"$VERIFY_OUT\",\"scratch\":\"$SCRATCH\",\"slug\":\"$SLUG\",\"sha\":\"$ACTUAL_SHA\",\"branch\":\"$BRANCH\",\"repo\":\"$REPO\"}"
