# Makefile — Build and deploy the Melusina App Bazaar
#
#   make test      Run the Store's Go suites; the sidecar in BOTH build flavors
#   make publish   Refresh + build + commit + deploy  (all-in-one, ~2 min)
#   make build     Build only (no submodule refresh, no deploy)
#   make refresh   Fetch latest submodule publish branches + stage pointers
#   make deploy    Deploy existing dist-publish/ to publish branch (no rebuild)
#   make clean     Remove build artifacts
#   make dev       Start Vite dev server
#
SHELL       := /bin/bash
.ONESHELL:
.SHELLFLAGS := -euo pipefail -c

REMOTE         := origin
MAIN_BRANCH    := main
PUBLISH_BRANCH := publish
OUTPUT_DIR     := dist-publish
MAX_FILE_SIZE  := $$((100 * 1024 * 1024 - 4096))
CHUNK_SIZE     := 90M

.PHONY: test publish build clean dev refresh deploy preflight doctor publish-check \
        plan apply publish-app sync bump-version icon-qc submit-build store-release

store-release:
	@test -n "$(OUT)" || { echo "ERROR: OUT=<empty output directory> required"; exit 2; }
	bash scripts/build-store-release.sh --version 1.0.4 --out-dir "$(OUT)"

# --- Sealed-v3 submit client (FEDERATED-STORE-MVP §C3) -----------------------
# The submit client REPLACES the gh-pages force-push: it wraps the canonical
# RELEASE.json in a signed artifact envelope and POSTs it (+ the SPK) to a store
# sidecar's gated POST /publish (the C2.3 single-writer). The sidecar verifies
# on-chain and returns a store-signed provenance receipt; the client verifies
# that receipt against the on-chain store_authority before declaring success.
SIDECAR_DIR  := sidecar/melusina-store-sidecar
SUBMIT_BIN   := $(SIDECAR_DIR)/bin/submit

# --- test: the Store's test entry point --------------------------------------
# Runs the Go suite of each Store module and fails if any of them fails. The
# store sidecar suite runs through its own entry point, scripts/run-tests.sh,
# in BOTH build flavors: the standard build and the estatebootstrap build the
# Store bootstrap component ships. A plain `go test ./...` in the sidecar
# compiles only the standard flavor, so it says nothing about the build that
# ships. Every suite runs even when an earlier one fails.
#
# The sidecar script reads its release declaration and contracts clone from
# the environment:
#   make test
#   CI=true MELUSINA_CONTRACTS_GIT_DIR=/abs/melusina-os-smartcontract make test
#
# run_tests_entrypoint_test.go runs this target with a stand-in go and fails
# by name (test-entrypoint-bootstrap-flavor-missing) if the estatebootstrap
# flavor stops reaching go test.
STORE_LINK_DIR := sidecar/bazaar-store-link
test:
	status=0
	bash "$(CURDIR)/$(SIDECAR_DIR)/scripts/run-tests.sh" || status=1
	(cd "$(CURDIR)/$(STORE_LINK_DIR)" && go test -count=1 ./...) || status=1
	exit "$$status"

# --- doctor: environment + readiness check ---------------------------------
# Single-pass health report: tools on PATH, submodule init state, deployer
# manifest reachability, gh-pages reachability, env-var overrides, working-
# tree drift, optional preflight dry-run. Run before `make publish` to
# catch fixable problems up front. See scripts/doctor.sh.
doctor:
	@bash scripts/doctor.sh

# Alias — `make publish-check` is the verb most people will reach for.
publish-check: doctor

# --- refresh: pull latest submodule commits -----------------------------------
refresh:
	@echo "=== Refreshing submodules ==="
	@UPDATED=0; FAILED=0; \
	while IFS= read -r sm_path; do \
		[ -z "$$sm_path" ] && continue; \
		sm_name=$$(basename "$$sm_path"); \
		sm_branch=$$(git config -f .gitmodules "submodule.$${sm_path}.branch" 2>/dev/null || echo "publish"); \
		if [ ! -d "$$sm_path/.git" ] && [ ! -f "$$sm_path/.git" ]; then \
			echo "  Cloning $$sm_name..."; \
			git submodule update --init --depth 1 "$$sm_path" 2>&1 | tail -1; \
		fi; \
		old=$$(git -C "$$sm_path" rev-parse --short HEAD 2>/dev/null || echo "none"); \
		if git -C "$$sm_path" fetch --depth 1 origin "$$sm_branch" 2>/dev/null; then \
			new=$$(git -C "$$sm_path" rev-parse --short FETCH_HEAD); \
			if [ "$$old" != "$$new" ]; then \
				if git -C "$$sm_path" merge-base --is-ancestor HEAD FETCH_HEAD 2>/dev/null; then \
					git -C "$$sm_path" checkout FETCH_HEAD 2>/dev/null; \
					echo "  ✓ $$sm_name: $$old → $$new"; \
					UPDATED=$$((UPDATED+1)); \
				else \
					echo "  ⚠ $$sm_name: local commits ahead — keeping $$old (K19; not discarding unpushed work)"; \
				fi; \
			else \
				echo "  ✓ $$sm_name: up to date ($$old)"; \
			fi; \
		else \
			echo "  ⚠ $$sm_name: fetch failed, using $$old"; \
			FAILED=$$((FAILED+1)); \
		fi; \
	done < <(git config --file .gitmodules --get-regexp 'submodule\..*\.path' | awk '{print $$2}'); \
	echo ""; \
	echo "  $$UPDATED updated, $$FAILED failed"
	@echo "=== Refresh complete ==="

# --- build: build without refreshing (uses current submodule state) -----------
build:
	@echo "=== Building store ==="
	bash build-store.sh --no-refresh
	@test -d "$(OUTPUT_DIR)" || { echo "Build failed — no $(OUTPUT_DIR)/"; exit 1; }
	@echo "=== Build complete ==="

# --- preflight: gate `make publish` against the 2026-04-25 regression mode ---
# Runs scripts/preflight.sh (live-catalog diff + manifest cross-check + pre-push
# announce). Exit 0 = safe to deploy. Exit 1 = abort. See POSTMORTEM.md.
preflight:
	@test -d "$(OUTPUT_DIR)" || { echo "No $(OUTPUT_DIR)/ — run 'make build' first"; exit 1; }
	bash scripts/preflight.sh

# --- Plan/Apply staging path (deterministic per repo checkout) ----------------
# One staging dir per static_store checkout, derived from repo root path so
# multiple checkouts on the same host don't collide. plan writes here and
# apply reads from the same place. Survives across processes.
PLAN_REPO_ID  := $(shell echo "$(CURDIR)" | sha1sum | cut -c1-8)
PLAN_DIR      := /tmp/melusina-publish-plan-$(PLAN_REPO_ID)
PLAN_STAGING  := $(PLAN_DIR)/staging
PLAN_MARKER   := $(PLAN_DIR)/marker.json

# --- plan: stage and validate; do not push ------------------------------------
# Refresh + build are NOT included — those are explicit prerequisites the
# operator runs first. plan stages dist-publish/, runs preflight, splits big
# files, and writes a marker. apply consumes the marker and force-pushes.
# This split lets the operator re-inspect the staged tree before any
# destructive (force-push) op happens. The marker captures the main HEAD
# at plan time so apply can detect drift.
plan: preflight
	@if [ "$${MELUSINA_PUBLISH_AUTHORITATIVE:-}" != "1" ]; then \
		echo ""; \
		echo "✗ plan aborted: MELUSINA_PUBLISH_AUTHORITATIVE is not set."; \
		echo "  This static_store checkout is a development mirror by default."; \
		echo "  See docs/M1_CCASH_CONFIG_PUBLISH_PATH.md and POSTMORTEM.md follow-up #1."; \
		echo "  To plan a publish from this host, set MELUSINA_PUBLISH_AUTHORITATIVE=1 explicitly."; \
		echo ""; \
		exit 1; \
	fi
	@test -d "$(OUTPUT_DIR)" || { echo "No $(OUTPUT_DIR)/ — run 'make build' first"; exit 1; }
	@test -d .git || { echo "Not a git repo"; exit 1; }
	@test "$$(git branch --show-current)" = "$(MAIN_BRANCH)" \
		|| { echo "Must be on $(MAIN_BRANCH)"; exit 1; }

	@# --- Reset staging dir cleanly ---
	@echo "=== plan: stage to $(PLAN_STAGING) ==="
	@rm -rf "$(PLAN_DIR)"
	@mkdir -p "$(PLAN_STAGING)"

	@# --- Stage dist-publish/ ---
	cp -a $(OUTPUT_DIR)/. "$(PLAN_STAGING)/"
	@if [ -d update ]; then \
		echo "  Merging update/ (repo root → staging, without overwriting build output)"; \
		mkdir -p "$(PLAN_STAGING)/update"; \
		for f in update/*; do \
			bn=$$(basename "$$f"); \
			[ -e "$(PLAN_STAGING)/update/$$bn" ] && continue; \
			case "$$bn" in *.tar.xz) \
				if ls "$(PLAN_STAGING)/update/$${bn}".part* >/dev/null 2>&1; then \
					echo "    Skipping $$bn (pre-split parts exist)"; \
					continue; \
				fi ;; \
			esac; \
			cp -a "$$f" "$(PLAN_STAGING)/update/$$bn"; \
		done; \
	fi
	@touch "$(PLAN_STAGING)/.nojekyll"

	@# --- Split files >95 MB ---
	@echo "=== plan: split large files ==="
	@SPLIT=0; \
	while IFS= read -r -d '' bigfile; do \
		rel="$${bigfile#$(PLAN_STAGING)/}"; \
		sz=$$(( $$(stat -c%s "$$bigfile") / 1024 / 1024 )); \
		echo "  Splitting $$rel ($${sz} MB)"; \
		orig_sha=$$(sha256sum "$$bigfile" | cut -d' ' -f1); \
		orig_size=$$(stat -c%s "$$bigfile"); \
		orig_name=$$(basename "$$bigfile"); \
		split --bytes=$(CHUNK_SIZE) --numeric-suffixes=0 --suffix-length=2 \
			"$$bigfile" "$${bigfile}.part"; \
		rm -f "$$bigfile"; \
		parts=""; \
		for p in "$${bigfile}".part*; do \
			pn=$$(basename "$$p"); \
			ps=$$(sha256sum "$$p" | cut -d' ' -f1); \
			pz=$$(stat -c%s "$$p"); \
			[ -n "$$parts" ] && parts="$$parts,"; \
			parts="$${parts}{\"file\":\"$$pn\",\"sha256\":\"$$ps\",\"size\":$$pz}"; \
		done; \
		printf '{\n  "originalFile": "%s",\n  "originalSha256": "%s",\n  "originalSize": %s,\n  "parts": [%s]\n}\n' \
			"$$orig_name" "$$orig_sha" "$$orig_size" "$$parts" \
			> "$${bigfile}.parts.json"; \
		echo "  → $$(ls "$${bigfile}".part* | wc -l) parts"; \
		SPLIT=$$((SPLIT+1)); \
	done < <(find "$(PLAN_STAGING)" -type f -size +$(MAX_FILE_SIZE)c -print0); \
	[ "$$SPLIT" -eq 0 ] && echo "  Nothing to split"

	@# --- Compute tree fingerprint + write marker ---
	@echo "=== plan: write marker ==="
	@TREE_SHA=$$(cd "$(PLAN_STAGING)" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1); \
	 MAIN_HEAD=$$(git rev-parse HEAD); \
	 APPS_COUNT=$$(python3 -c "import json; print(len(json.load(open('$(PLAN_STAGING)/apps/index.json')).get('apps', [])))" 2>/dev/null || echo "?"); \
	 printf '{\n  "schema": "melusina-publish-plan-v1",\n  "plan_time": "%s",\n  "repo_root": "%s",\n  "main_head": "%s",\n  "staging_dir": "%s",\n  "staging_tree_sha": "%s",\n  "apps_count": %s\n}\n' \
	   "$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	   "$(CURDIR)" \
	   "$$MAIN_HEAD" \
	   "$(PLAN_STAGING)" \
	   "$$TREE_SHA" \
	   "$$APPS_COUNT" \
	   > "$(PLAN_MARKER)"
	@cat "$(PLAN_MARKER)"
	@echo ""
	@echo "  plan ready. Inspect $(PLAN_STAGING) before running 'make apply'."
	@echo "  Force-push will not happen until 'make apply' is invoked."

# --- apply: read marker, validate, force-push --------------------------------
# Refuses to run if:
#   - $(PLAN_MARKER) is missing (no plan was run)
#   - main HEAD has moved since plan
#   - staging tree fingerprint has changed (someone touched $(PLAN_STAGING))
# Cleans up $(PLAN_DIR) on success so the next call requires a fresh plan.
apply:
	@echo "ERROR: legacy flat-catalog apply is retired; use the catalog-keyed default-bazaar-release.sh"
	exit 2

# The retired writer body is deliberately absent: a dormant force-publish
# implementation would remain a source-level bypass behind one removable guard.
apply-locked:
	@echo "ERROR: legacy apply-locked is retired; direct catalog force-push is forbidden"
	exit 2

# --- deploy: backwards-compat alias for plan + apply -------------------------
# Pre-v0.4 callers run `make build && make deploy`. Keep that working by
# chaining the new verbs.
deploy:
	@echo "ERROR: legacy deploy is retired; no direct publish/gh-pages writer remains"
	exit 2

# --- publish: legacy flat-catalog deployment only ----------------------------
# This target is retained solely for exact 1.0.3 rollback/catalog maintenance.
# It cannot publish an app and never invokes the two-phase store API. App
# publication has exactly one entry point: the catalog-keyed
# `scripts/default-bazaar-release.sh` release driver.
publish:
	@echo "ERROR: legacy flat-catalog publish is retired; use the catalog-keyed default-bazaar-release.sh"
	exit 2

# --- submit-build: compile the sealed-v3 submit client -----------------------
# NB: under .ONESHELL a `cd` would persist into the test line, so build with an
# absolute -o and check the absolute path (no cd).
submit-build:
	@echo "=== Building submit client ($(SUBMIT_BIN)) ==="
	go build -C $(SIDECAR_DIR) -o "$(CURDIR)/$(SUBMIT_BIN)" ./cmd/submit
	@test -x "$(CURDIR)/$(SUBMIT_BIN)" || { echo "submit build failed — no $(SUBMIT_BIN)"; exit 1; }

# --- publish-app: retired caller-selected entry point ------------------------
# A Golden-MVP package must start with catalog appId -> source_path ->
# source_commit.  The old SRC/KEYS/CATALOG_PATH route cannot establish that
# provenance, so fail closed rather than allowing old automation to stage an
# otherwise plausible but ungoverned artifact.
publish-app:
	@echo "ERROR: caller-selected publish-app is disabled during the Golden MVP freeze"
	@echo "Use: MEL_RELEASE_SOURCE_ROOT=/absolute/clean/source-root scripts/default-bazaar-release.sh publish --app <catalog-appId|slug> --version <version>"
	@exit 2

# --- sync: refresh submodules + rebuild dist-publish (no plan/apply) ---------
# Cheap "pick up whatever publish branches have moved upstream" target.
# Without --deploy it just rebuilds the catalog locally; add MELUSINA_PUBLISH_AUTHORITATIVE=1
# and DEPLOY=1 to also force-push gh-pages.
sync:
	bash scripts/sync-catalog.sh \
	  $(if $(APP),--app "$(APP)") \
	  $(if $(NO_BUILD),--no-build) \
	  $(if $(DEPLOY),--deploy)

# --- bump-version: bump a single app's version --------------------------------
#   make bump-version SRC=/absolute/path/to/app-source BUMP=minor
bump-version:
	@test -n "$(SRC)" || { echo "ERROR: SRC=<app source dir> required"; exit 2; }
	bash scripts/version-bump.sh "$(SRC)" $(or $(BUMP),patch) $(if $(DRY_RUN),--dry-run)

# --- icon-qc: standalone catalog icon scan -----------------------------------
icon-qc:
	bash scripts/icon-qc.sh

dev:
	@npm install --silent 2>/dev/null
	npx vite

clean:
	rm -rf dist dist-publish .staging-tmp
