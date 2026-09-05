#!/usr/bin/env bash
# Build one immutable app candidate before any chain or Bazaar mutation.
set -euo pipefail

APP_DIR=""
METADATA=""
RECEIPT_OUT=""
SPK_OUT=""
METADATA_OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --metadata) METADATA="$2"; shift 2 ;;
    --receipt-out) RECEIPT_OUT="$2"; shift 2 ;;
    --spk-out) SPK_OUT="$2"; shift 2 ;;
    --metadata-out) METADATA_OUT="$2"; shift 2 ;;
    *) [[ -z "$APP_DIR" ]] || { echo "unknown argument: $1" >&2; exit 2; }; APP_DIR="$1"; shift ;;
  esac
done

[[ -n "$APP_DIR" && -d "$APP_DIR" ]] || { echo "app source directory required" >&2; exit 2; }
APP_DIR="$(cd "$APP_DIR" && pwd)"
METADATA="${METADATA:-$APP_DIR/metadata.json}"
SPK_OUT="${SPK_OUT:-$APP_DIR/app.spk}"
SPK_BIN="${MELUSINA_SPK_BIN:-spk}"
[[ -f "$METADATA" ]] || { echo "metadata not found: $METADATA" >&2; exit 2; }
command -v "$SPK_BIN" >/dev/null 2>&1 || { echo "spk verifier not found: $SPK_BIN" >&2; exit 2; }

if git -C "$APP_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  source_root="$(git -C "$APP_DIR" rev-parse --show-toplevel)"
  metadata_path="$(realpath -e "$METADATA")"
  case "$metadata_path" in
    "$source_root"/*) metadata_rel="${metadata_path#"$source_root"/}" ;;
    *) echo "source metadata must be inside the source Git tree: $METADATA" >&2; exit 2 ;;
  esac
  if ! git -C "$source_root" ls-files --error-unmatch -- "$metadata_rel" >/dev/null 2>&1; then
    echo "source metadata must be tracked at the candidate revision: $METADATA" >&2
    exit 2
  fi
  dirty="$(git -C "$APP_DIR" status --porcelain --untracked-files=normal)"
  [[ -z "$dirty" ]] || { echo "source tree is dirty before candidate build" >&2; printf '%s\n' "$dirty" >&2; exit 2; }
  source_revision="$(git -C "$APP_DIR" rev-parse HEAD)"
  mapfile -t source_remotes < <(git -C "$source_root" remote | LC_ALL=C sort)
  [[ ${#source_remotes[@]} -gt 0 ]] || { echo "candidate source has no remote" >&2; exit 2; }
  for remote in "${source_remotes[@]}"; do
    # A source cohort may have been created with --single-branch. Its default
    # remote fetchspec then omits dev-publish even when that exact committed
    # revision was pushed moments ago, causing a false "unpushed" refusal.
    # Refresh remote heads explicitly before the reachability check rather
    # than trusting a clone-local fetchspec or accepting an unverifiable tip.
    # This refresh proves source-ref reachability, not archived submodule
    # availability. The selected checkout's initialized submodules remain
    # build inputs; unrelated historical gitlinks must not be fetched here.
    git -C "$source_root" fetch --prune --recurse-submodules=no "$remote" "+refs/heads/*:refs/remotes/$remote/*" || {
      echo "cannot refresh source remote heads: $remote" >&2
      exit 2
    }
  done
  pushed_ref="$(git -C "$source_root" for-each-ref --format='%(refname)' --contains "$source_revision" refs/remotes/ \
    | grep -v '/HEAD$' | LC_ALL=C sort | head -1 || true)"
  [[ -n "$pushed_ref" ]] || { echo "candidate revision is not reachable from any fetched remote ref: $source_revision" >&2; exit 2; }
  source_commit_epoch="$(git -C "$APP_DIR" log -1 --format=%ct HEAD)"
else
  echo "candidate builds require a committed Git source tree" >&2
  exit 2
fi

# An explicitly supplied epoch is an operator-controlled reproducibility input
# and must survive intact.  In its absence, do NOT export the commit timestamp:
# several app Makefiles deliberately pin SOURCE_DATE_EPOCH with `?=` so their
# archived bytes stay stable across metadata-only commits. Exporting a default
# here silently defeated that app-level release policy (DueProcess v78 was the
# concrete failure). The shared pack core still has the source-commit fallback
# when neither caller nor Makefile supplies one.
caller_source_epoch="${SOURCE_DATE_EPOCH:-}"
if [[ -n "$caller_source_epoch" ]]; then
  [[ "$caller_source_epoch" =~ ^[0-9]+$ ]] || {
    echo "SOURCE_DATE_EPOCH must be a non-negative integer when supplied" >&2
    exit 2
  }
else
  unset SOURCE_DATE_EPOCH
fi

# A normal release builds first and then invokes the app's ordinary pack target.
# NamedCoin is the one reviewed exception: its devnet pkgdef deliberately
# contains already-disclosed test keybox inputs, and its *default* production
# build refuses them.  That candidate must use the app-owned, explicit
# `pack-msb-test` target.  Keep the exception here as a named profile rather
# than leaking build tags into a global GOFLAGS/BUILD_TAGS environment.
PACK_PROFILE="${MEL_RELEASE_PACK_PROFILE:-standard}"
case "$PACK_PROFILE" in
  standard) ;;
  namedcoin-msb-devnet)
    profile_app_id="$(python3 - "$METADATA" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("appId", ""))
PY
)"
    [[ "$profile_app_id" = "8kea8reanvm5cw7awrxj8udguh5hf3yfcns01fmq7vq42ps2hvuh" ]] || {
      echo "MEL_RELEASE_PACK_PROFILE=namedcoin-msb-devnet is valid only for the NamedCoin appId" >&2
      exit 2
    }
    [[ -z "${MEL_RELEASE_PACK_TARGET:-}" ]] || {
      echo "NamedCoin MSB devnet profile owns its pack target; MEL_RELEASE_PACK_TARGET is forbidden" >&2
      exit 2
    }
    ;;
  *)
    echo "unknown MEL_RELEASE_PACK_PROFILE: $PACK_PROFILE" >&2
    exit 2
    ;;
esac

# spkmodule's post-pack hook legitimately derives metadata.packageId from the
# exact new SPK. Preserve that generated metadata outside the source checkout
# and restore the committed source file afterwards. Any other mutation remains
# a hard failure: a release candidate is never allowed to smuggle a source edit.
METADATA_BASELINE="$(mktemp)"
cp "$METADATA" "$METADATA_BASELINE"
restore_metadata() {
  cp "$METADATA_BASELINE" "$METADATA"
  rm -f "$METADATA_BASELINE"
}
trap restore_metadata EXIT

rm -f "$SPK_OUT"
# The historic Pearl Make path requires a source-tree RELEASE.json before it
# will package. That release binds a mutable source tree, while the greenfield
# rail binds the exact files it serves: {app.spk, metadata.json}. Keep the old
# path available for legacy callers, but package greenfield candidates without
# embedding its incompatible ceremony.
MAKE_VARS=()
if [[ "${MEL_RELEASE_GREENFIELD_PACK:-}" == "1" ]]; then
  MAKE_VARS+=("APP_PEARL_ENABLED=no")
fi
# `make -q target` reports whether target is up-to-date, not whether it
# exists, so inspect Make's parsed rule database without executing a target.
make_target_exists() {
  # Do not use grep -q here: with pipefail it closes the pipe early, Make
  # receives SIGPIPE while dumping its database, and a real target looks
  # absent. Let grep consume the complete database instead.
  make -C "$APP_DIR" -prRn 2>/dev/null | grep -E "^$1:" >/dev/null
}

# Read Make's effective exported value without executing a build target. This
# is receipt evidence only; the build environment above remains untouched.
# If no Makefile declares it, spkmodule's documented fallback is the committed
# source epoch, which is recorded distinctly rather than masquerading as a
# caller override.
effective_source_epoch() {
  local make_epoch
  make_epoch="$(make -C "$APP_DIR" -prRn 2>/dev/null | awk '
    /^SOURCE_DATE_EPOCH[[:space:]]*[:?+]?=/ {
      value = $0
      sub(/^[^=]*=[[:space:]]*/, "", value)
      sub(/[[:space:]]*#.*/, "", value)
      if (value ~ /^[0-9]+$/) epoch = value
    }
    END { if (epoch != "") print epoch }
  ')"
  if [[ -n "$make_epoch" ]]; then
    printf '%s\tmakefile\n' "$make_epoch"
  else
    printf '%s\tspkmodule-default-source-commit\n' "$source_commit_epoch"
  fi
}

case "$PACK_PROFILE" in
  standard)
    make -C "$APP_DIR" "${MAKE_VARS[@]}" "SPK_OUT=$SPK_OUT" build
    # The historic helper target was only present in the hermetic fixture. Real
    # MSB apps expose the normal spkmodule `pack` target. Prefer an explicit
    # operator override, then retain pack-local compatibility for a repository
    # that deliberately provides it, then fall back to the common `pack` target.
    # Do not guess a target that Make does not declare: publishing must stop before
    # producing a candidate rather than treating an arbitrary artifact as an SPK.
    PACK_TARGET="${MEL_RELEASE_PACK_TARGET:-}"
    if [[ -z "$PACK_TARGET" ]]; then
      if make_target_exists pack-local; then
        PACK_TARGET="pack-local"
      elif make_target_exists pack; then
        PACK_TARGET="pack"
      else
        echo "app Makefile declares neither pack-local nor pack; set MEL_RELEASE_PACK_TARGET explicitly" >&2
        exit 2
      fi
    fi
    make -C "$APP_DIR" "${MAKE_VARS[@]}" "SPK_OUT=$SPK_OUT" "$PACK_TARGET"
    ;;
  namedcoin-msb-devnet)
    # Do NOT run `make build` first: that untagged production target is meant
    # to refuse this devnet-only pkgdef. The app-owned combined target selects
    # its exact tags and then packs, with no release-wide tag propagation.
    make_target_exists pack-msb-test || {
      echo "NamedCoin MSB devnet profile requires an app-owned pack-msb-test target" >&2
      exit 2
    }
    PACK_TARGET="pack-msb-test"
    make -C "$APP_DIR" "${MAKE_VARS[@]}" "$PACK_TARGET"
    ;;
esac
[[ -f "$SPK_OUT" ]] || { echo "$PACK_TARGET did not create $SPK_OUT" >&2; exit 2; }

IFS=$'\t' read -r source_epoch source_epoch_origin < <(effective_source_epoch)
[[ "$source_epoch" =~ ^[0-9]+$ ]] || {
  echo "could not determine an effective numeric SOURCE_DATE_EPOCH" >&2
  exit 2
}
if [[ -n "$caller_source_epoch" && "$source_epoch" == "$caller_source_epoch" ]]; then
  source_epoch_origin="caller-override"
fi

if ! cmp -s "$METADATA" "$METADATA_BASELINE"; then
  [[ -n "$METADATA_OUT" ]] || {
    echo "pack generated metadata.json; pass --metadata-out to preserve the exact staged metadata without dirtying source" >&2
    exit 2
  }
  generated_ok="$(python3 - "$METADATA_BASELINE" "$METADATA" "$SPK_OUT" <<'PY'
import hashlib, json, sys
before, after, spk = sys.argv[1:]
old = json.load(open(before, encoding="utf-8"))
new = json.load(open(after, encoding="utf-8"))
expected_sha256 = hashlib.sha256(open(spk, "rb").read()).hexdigest()
expected_package_id = expected_sha256[:32]

# A post-pack hook may derive only the package identity from the exact SPK:
# `packageId` is mandatory and `sha256` may either remain its authored value
# or be synchronised to the same artifact. Every other product-owned field
# must remain byte-for-byte equivalent as JSON data.
old.pop("packageId", "")
old_sha256 = old.pop("sha256", "")
package_id = new.pop("packageId", "")
new_sha256 = new.pop("sha256", "")
print("yes" if (
    old == new
    and package_id == expected_package_id
    and new_sha256 in (old_sha256, expected_sha256)
) else "no")
PY
)"
  [[ "$generated_ok" == yes ]] || {
    echo "pack mutated metadata beyond the generated packageId; refusing to publish" >&2
    exit 2
  }
  mkdir -p "$(dirname "$METADATA_OUT")"
  cp "$METADATA" "$METADATA_OUT"
fi

# Restore before examining Git state so a deterministic packageId update never
# dirties the committed source revision used to build this candidate.
restore_metadata
trap - EXIT

dirty="$(git -C "$APP_DIR" status --porcelain --untracked-files=normal)"
[[ -z "$dirty" ]] || {
  echo "candidate build mutated committed source; refusing to publish" >&2
  printf '%s\n' "$dirty" >&2
  exit 2
}

verify_out="$("$SPK_BIN" verify "$SPK_OUT" 2>&1)" || { echo "$verify_out" >&2; exit 2; }
app_id="$(printf '%s\n' "$verify_out" | grep -oE '"appId": "[^"]*"' | head -1 | cut -d'"' -f4 || true)"
package_id="$(printf '%s\n' "$verify_out" | grep -oE '"packageId": "[^"]*"' | head -1 | cut -d'"' -f4 || true)"
[[ -n "$app_id" && -n "$package_id" ]] || { echo "could not extract appId/packageId from package" >&2; exit 2; }

spk_sha="$(sha256sum "$SPK_OUT" | awk '{print $1}')"
[[ "$package_id" == "${spk_sha:0:32}" ]] || {
  echo "packageId $package_id does not match sha256 prefix ${spk_sha:0:32}" >&2
  exit 2
}

candidate_metadata="$METADATA"
if [[ -n "$METADATA_OUT" && -f "$METADATA_OUT" ]]; then
  candidate_metadata="$METADATA_OUT"
fi
readarray -t source_meta < <(python3 - "$candidate_metadata" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
print(d.get("appId", ""))
print(d.get("marketingVersion") or d.get("version") or "")
PY
)
[[ -z "${source_meta[0]:-}" || "${source_meta[0]}" == "$app_id" ]] || {
  echo "source metadata appId ${source_meta[0]} does not match package appId $app_id" >&2
  exit 2
}

if [[ -n "$RECEIPT_OUT" ]]; then
  mkdir -p "$(dirname "$RECEIPT_OUT")"
  python3 - "$RECEIPT_OUT" "$source_revision" "$pushed_ref" "$source_commit_epoch" "$source_epoch" \
    "$source_epoch_origin" "$app_id" "$package_id" "${source_meta[1]:-}" "$spk_sha" "$(stat -c%s "$SPK_OUT")" <<'PY'
import json, os, sys
out, revision, pushed_ref, commit_epoch, epoch, epoch_origin, app_id, package_id, version, sha, size = sys.argv[1:]
doc = {
    "schema": "melusina-app-candidate-receipt-v1",
    "source": {
        "revision": revision,
        "pushedRemoteRef": pushed_ref,
        "dirty": False,
        "sourceCommitEpoch": int(commit_epoch),
        "sourceDateEpoch": int(epoch),
        "sourceDateEpochOrigin": epoch_origin,
    },
    "app": {"appId": app_id, "packageId": package_id, "version": version},
    "artifact": {"sha256": sha, "size": int(size)},
    "verification": {"spk": "valid", "packageIdMatchesSha256": True},
}
tmp = out + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
os.chmod(tmp, 0o600)
os.replace(tmp, out)
PY
fi

printf 'candidate appId=%s packageId=%s sha256=%s revision=%s\n' \
  "$app_id" "$package_id" "$spk_sha" "$source_revision"
