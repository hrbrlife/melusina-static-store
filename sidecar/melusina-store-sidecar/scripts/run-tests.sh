#!/usr/bin/env bash
# Run this module's Go test suite in both build flavors: the standard build and
# the estatebootstrap build the Store bootstrap component ships.
#
#   scripts/run-tests.sh [--release] [--contracts-git-dir DIR] [--plan] [-- GO_TEST_ARGS...]
#
# Contracts checkout. testdata/contracts/ holds a copy of the contracts
# repository's sidecar PDA vector. Every run checks, offline, that the commit
# named in its provenance holds the copy's bytes. Only a melusina-os-smartcontract
# clone with origin/main fetched can show that the commit is on the contracts
# main line. The clone is taken from the first of:
#   --contracts-git-dir DIR
#   MELUSINA_CONTRACTS_GIT_DIR
#   git config melusina.contractsGitDir   (set once per Store checkout)
# and is exported to the tests as an absolute MELUSINA_CONTRACTS_GIT_DIR.
#
# Release mode. --release, MELUSINA_STORE_TEST_MODE=release, or CI=true (or 1)
# declares a release or CI run. Such a run refuses to start without a contracts
# clone, and exports MELUSINA_STORE_TEST_MODE=release so that the Go test also
# fails, rather than skips, if it is run without one.
#
# --plan prints the resolved mode, environment and commands, and runs nothing.
set -euo pipefail

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

refuse() {
  echo "run-tests: $*" >&2
  exit 2
}

release=0
plan=0
contracts=""
contracts_source=""
go_args=(-count=1)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release)
      release=1
      shift
      ;;
    --plan)
      plan=1
      shift
      ;;
    --contracts-git-dir)
      [[ $# -ge 2 && -n "$2" ]] || refuse "--contracts-git-dir requires a directory"
      contracts="$2"
      contracts_source="--contracts-git-dir"
      shift 2
      ;;
    --)
      shift
      go_args+=("$@")
      break
      ;;
    *)
      refuse "unknown argument: $1"
      ;;
  esac
done

case "${MELUSINA_STORE_TEST_MODE:-}" in
  release) release=1 ;;
  "") ;;
  *) refuse "store-test-mode-unknown: MELUSINA_STORE_TEST_MODE=${MELUSINA_STORE_TEST_MODE}; the only declared mode is \"release\"" ;;
esac
ci="${CI:-}"
ci="${ci,,}"
if [[ "$ci" == "true" || "$ci" == "1" ]]; then
  release=1
fi

if [[ -z "$contracts" && -n "${MELUSINA_CONTRACTS_GIT_DIR:-}" ]]; then
  contracts="$MELUSINA_CONTRACTS_GIT_DIR"
  contracts_source="MELUSINA_CONTRACTS_GIT_DIR"
fi
if [[ -z "$contracts" ]]; then
  contracts="$(git -C "$MODULE_DIR" config --type=path --get melusina.contractsGitDir || true)"
  if [[ -n "$contracts" ]]; then
    contracts_source="git config melusina.contractsGitDir"
    [[ "$contracts" == /* ]] || refuse "contracts-git-dir-not-absolute: $contracts_source is $contracts; configure an absolute path"
  fi
fi

if [[ -n "$contracts" ]]; then
  [[ -d "$contracts" ]] || refuse "contracts-git-dir-missing: $contracts_source names $contracts, which is not a directory"
  git -C "$contracts" rev-parse --git-dir >/dev/null 2>&1 \
    || refuse "contracts-git-dir-not-a-repository: $contracts_source names $contracts, which is not a git repository"
  # go test runs each package in its own directory, so a relative path would
  # name a different place for each package.
  contracts="$(cd "$contracts" && pwd -P)"
  export MELUSINA_CONTRACTS_GIT_DIR="$contracts"
else
  unset MELUSINA_CONTRACTS_GIT_DIR
  if [[ "$release" == 1 ]]; then
    refuse "contracts-clone-required: a release or CI run compares the contracts vector copy with a melusina-os-smartcontract clone; pass --contracts-git-dir, set MELUSINA_CONTRACTS_GIT_DIR, or run git config melusina.contractsGitDir <clone>"
  fi
fi

if [[ "$release" == 1 ]]; then
  export MELUSINA_STORE_TEST_MODE=release
  mode=release
else
  unset MELUSINA_STORE_TEST_MODE
  mode=dev
fi

flavors=("" "estatebootstrap")

if [[ "$plan" == 1 ]]; then
  echo "mode=$mode"
  echo "MELUSINA_CONTRACTS_GIT_DIR=${MELUSINA_CONTRACTS_GIT_DIR:-}"
  echo "MELUSINA_STORE_TEST_MODE=${MELUSINA_STORE_TEST_MODE:-}"
  for tags in "${flavors[@]}"; do
    if [[ -n "$tags" ]]; then
      echo "run: go test -tags $tags ${go_args[*]} ./..."
    else
      echo "run: go test ${go_args[*]} ./..."
    fi
  done
  exit 0
fi

cd "$MODULE_DIR"
status=0
for tags in "${flavors[@]}"; do
  if [[ -n "$tags" ]]; then
    echo "== go test -tags $tags ${go_args[*]} ./... (mode=$mode)" >&2
    go test -tags "$tags" "${go_args[@]}" ./... || status=1
  else
    echo "== go test ${go_args[*]} ./... (mode=$mode)" >&2
    go test "${go_args[@]}" ./... || status=1
  fi
done
exit "$status"
