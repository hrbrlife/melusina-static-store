# mel-release.mk — thin Make wrappers for the consolidated app-release CLI.
#
# Include from the module Makefile (`include mk/mel-release.mk`) or run directly:
#   make -f mk/mel-release.mk release-publish APP=popaye VERSION=0.3.132
#   make -f mk/mel-release.mk release-approve APP=popaye
#
# Config is env-only (MEL_RELEASE_*); signing material is supplied by the
# configured MEL_RELEASE_SIGNER_PROVIDER, never a plaintext keys directory.

MEL_RELEASE_PKG ?= ./cmd/mel-release
MEL_RELEASE_BIN ?= mel-release
APP     ?=
VERSION ?=

.PHONY: mel-release-build release-publish release-approve

## Build the mel-release binary.
mel-release-build:
	go build -o $(MEL_RELEASE_BIN) $(MEL_RELEASE_PKG)

## Stage + create the register proposal + write the immutable candidate receipt.
## Nothing is made Active or catalog-visible. Requires APP and VERSION.
release-publish:
	@test -n "$(APP)" || { echo "APP is required (appId, slug, or name)"; exit 2; }
	@test -n "$(VERSION)" || { echo "VERSION is required"; exit 2; }
	go run $(MEL_RELEASE_PKG) publish --app "$(APP)" --version "$(VERSION)"

## Execute the authorized approval: register Active -> promote pointer -> signed
## DesiredGeneration -> revoke stale last -> terminal receipt. Requires APP.
release-approve:
	@test -n "$(APP)" || { echo "APP is required (appId, slug, or name)"; exit 2; }
	go run $(MEL_RELEASE_PKG) approve --app "$(APP)"
