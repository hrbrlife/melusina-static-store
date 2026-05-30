#!/usr/bin/env bash
#
# manifest-merge.sh — idempotently merge a `make approval-manifest-entry`
# JSON entry into the deployer's approval-manifest at
# Melusina/deployer/config/approval-manifests/global-apps-*.json.
#
# Replaces hand-editing the manifest. The entry is the JSON that
# spkmodule's `make approval-manifest-entry` target prints — usually
# captured to a file or piped via stdin.
#
# Behavior:
#   • If app_id is NOT in the manifest: appends the entry.
#   • If app_id IS in the manifest:
#       - if app_hash matches: no-op (idempotent)
#       - if app_hash differs: updates the existing entry's app_hash and
#         marks it `pending_reseat: true` (with a note documenting the
#         on-chain follow-up). Preserves any other fields already present
#         on the entry (e.g. existing `note`, `deferred_in_catalog`).
#
# Usage:
#   manifest-merge.sh [--manifest PATH] --entry FILE
#   make -C <app> approval-manifest-entry | manifest-merge.sh --manifest /path/to/manifest.json --stdin
#
# Output: prints what changed; exits 0 on success, 2 on bad input, 1 on
# write failure.
#
set -euo pipefail

MANIFEST="${MELUSINA_DEPLOYER_MANIFEST:-/home/user/Desktop/Melusina/deployer/config/approval-manifests/global-apps-2026-04-23.json}"
ENTRY_FILE=""
USE_STDIN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest) MANIFEST="$2"; shift 2 ;;
    --entry)    ENTRY_FILE="$2"; shift 2 ;;
    --stdin)    USE_STDIN=1; shift ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -f "$MANIFEST" ]] || { echo "FATAL: manifest not found: $MANIFEST" >&2; exit 2; }

# Read the entry from --entry FILE or stdin.
if [[ "$USE_STDIN" -eq 1 ]]; then
  ENTRY_JSON=$(cat)
elif [[ -n "$ENTRY_FILE" ]]; then
  [[ -f "$ENTRY_FILE" ]] || { echo "FATAL: entry file not found: $ENTRY_FILE" >&2; exit 2; }
  ENTRY_JSON=$(cat "$ENTRY_FILE")
else
  echo "FATAL: must specify --entry FILE or --stdin" >&2
  exit 2
fi

# Validate entry shape and resolve app_id / app_hash.
IFS=$'\t' read -r APP_ID APP_HASH APP_NAME APP_VERSION APP_AUTHOR <<<"$(printf '%s' "$ENTRY_JSON" | python3 -c '
import json, sys
e = json.load(sys.stdin)
required = ("app_id", "app_hash", "app_name", "version", "author")
missing = [k for k in required if not e.get(k)]
if missing:
    sys.stderr.write(f"FATAL: entry missing required keys: {missing}\n")
    sys.exit(2)
print(e["app_id"], e["app_hash"], e["app_name"], e["version"], e["author"], sep="\t")
')"

MANIFEST="$MANIFEST" \
ENTRY_JSON="$ENTRY_JSON" \
APP_ID="$APP_ID" \
APP_HASH="$APP_HASH" \
APP_NAME="$APP_NAME" \
APP_VERSION="$APP_VERSION" \
APP_AUTHOR="$APP_AUTHOR" \
python3 <<'PY'
import json, os, sys, datetime

manifest_path = os.environ['MANIFEST']
entry = json.loads(os.environ['ENTRY_JSON'])
app_id     = os.environ['APP_ID']
app_hash   = os.environ['APP_HASH']
app_name   = os.environ['APP_NAME']
app_version= os.environ['APP_VERSION']

with open(manifest_path) as f:
    m = json.load(f)

if isinstance(m, list):
    apps = m
    wrapped = False
elif isinstance(m, dict) and isinstance(m.get('apps'), list):
    apps = m['apps']
    wrapped = True
else:
    sys.stderr.write(f"FATAL: unexpected manifest shape at {manifest_path}\n")
    sys.exit(2)

today = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d')
existing = next((a for a in apps if a.get('app_id') == app_id), None)
action = ""

if existing is None:
    apps.append(entry)
    action = f"APPEND new entry for {app_name} ({app_id[:24]}...)"
elif existing.get('app_hash') == app_hash:
    action = f"NO-OP — {app_name} ({app_id[:24]}...) already at hash {app_hash[:12]}..."
else:
    old_hash = existing.get('app_hash', '')
    existing['app_hash'] = app_hash
    existing['version']  = app_version
    existing['pending_reseat'] = True
    existing['note'] = (
        f"Manifest hash updated {today} via manifest-merge.sh; "
        f"on-chain GlobalAppApproval reseat owed via Squads ceremony "
        f"(procedure: static_store/docs/M2_CYBERTELLER_CONFIG_PUBLISH_PATH.md §3)"
    )
    action = (
        f"UPDATE {app_name} ({app_id[:24]}...) "
        f"hash {old_hash[:12]}... → {app_hash[:12]}... + pending_reseat=true"
    )

# Stable serialization. Preserve original wrapping shape.
out = {'apps': apps} if wrapped else apps

# Write atomically to avoid partial-state on interruption.
tmp = manifest_path + '.tmp.' + str(os.getpid())
with open(tmp, 'w') as f:
    json.dump(out, f, indent=2, ensure_ascii=False)
    f.write('\n')
os.replace(tmp, manifest_path)

print(f"  [manifest-merge] {action}")
print(f"  [manifest-merge] wrote {manifest_path} ({len(apps)} entries)")
PY
