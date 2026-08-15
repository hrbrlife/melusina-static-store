#!/usr/bin/env bash
# Run `spk verify` in a private mount namespace whose /tmp is supplied by the
# caller. Sandstorm's verifier currently hard-codes /tmp/spk-verify-tmp and
# can otherwise fail before it validates a large signed package. This wrapper
# changes no host mount and performs no Store/release action.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <package.spk>" >&2
  exit 2
fi

: "${MELUSINA_SPK_VERIFY_TMPDIR:?check=spk_verify_tmp: set MELUSINA_SPK_VERIFY_TMPDIR to an empty private directory}"
case "$MELUSINA_SPK_VERIFY_TMPDIR" in
  /*) ;;
  *) echo "check=spk_verify_tmp: MELUSINA_SPK_VERIFY_TMPDIR must be absolute" >&2; exit 2 ;;
esac
[[ -d "$MELUSINA_SPK_VERIFY_TMPDIR" && ! -L "$MELUSINA_SPK_VERIFY_TMPDIR" ]] || {
  echo "check=spk_verify_tmp: private temporary directory must be an existing non-symlink directory" >&2
  exit 2
}

SPK_BIN="$(command -v spk)"
PACKAGE="$1"
exec unshare -Urnm -- sh -eu -c '
  mount --bind "$1" /tmp
  exec "$2" verify "$3"
' -- "$MELUSINA_SPK_VERIFY_TMPDIR" "$SPK_BIN" "$PACKAGE"
