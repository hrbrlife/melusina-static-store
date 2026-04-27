# Makefile — Build and deploy the Melusina App Bazaar
#
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
MAX_FILE_SIZE  := $$((95 * 1024 * 1024))
CHUNK_SIZE     := 90M

.PHONY: publish build clean dev refresh deploy preflight doctor publish-check \
        plan apply

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
				git -C "$$sm_path" checkout FETCH_HEAD 2>/dev/null; \
				echo "  ✓ $$sm_name: $$old → $$new"; \
				UPDATED=$$((UPDATED+1)); \
			else \
				echo "  ✓ $$sm_name: up to date ($$old)"; \
			fi; \
		else \
			echo "  ⚠ $$sm_name: fetch failed, using $$old"; \
			FAILED=$$((FAILED+1)); \
		fi; \
	done < <(git config --file .gitmodules --get-regexp 'submodule\..*\.path' | awk '{print $$2}'); \
	git add packages/ 2>/dev/null || true; \
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
	@test -f "$(PLAN_MARKER)" || { \
	  echo "✗ apply aborted: no plan marker at $(PLAN_MARKER)"; \
	  echo "  Run 'make plan' first."; \
	  exit 1; \
	}
	@if [ "$${MELUSINA_PUBLISH_AUTHORITATIVE:-}" != "1" ]; then \
	  echo "✗ apply aborted: MELUSINA_PUBLISH_AUTHORITATIVE is not set (defensive re-check)."; \
	  exit 1; \
	fi
	@PLANNED_HEAD=$$(python3 -c "import json; print(json.load(open('$(PLAN_MARKER)'))['main_head'])"); \
	 CURRENT_HEAD=$$(git rev-parse HEAD); \
	 if [ "$$PLANNED_HEAD" != "$$CURRENT_HEAD" ]; then \
	   echo "✗ apply aborted: main HEAD moved since plan."; \
	   echo "  planned: $$PLANNED_HEAD"; \
	   echo "  current: $$CURRENT_HEAD"; \
	   echo "  Re-run 'make plan' to refresh the marker."; \
	   exit 1; \
	 fi
	@PLANNED_SHA=$$(python3 -c "import json; print(json.load(open('$(PLAN_MARKER)'))['staging_tree_sha'])"); \
	 CURRENT_SHA=$$(cd "$(PLAN_STAGING)" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1); \
	 if [ "$$PLANNED_SHA" != "$$CURRENT_SHA" ]; then \
	   echo "✗ apply aborted: staging tree fingerprint drift."; \
	   echo "  planned: $$PLANNED_SHA"; \
	   echo "  current: $$CURRENT_SHA"; \
	   echo "  Someone (or something) touched $(PLAN_STAGING). Re-run 'make plan'."; \
	   exit 1; \
	 fi
	@echo "  plan/apply consistency: OK (HEAD + staging tree match)"

	@# --- Commit main (only catalog inputs generated by this workflow) ---
	@echo "=== apply: commit main ==="
	git add packages/ src/apps.json package.json package-lock.json e2e/fixtures/expected_apps.ts 2>/dev/null || true
	git diff --cached --quiet || git commit -m "Store build $$(date +%Y-%m-%d)" --quiet
	@# Pull --rebase to integrate any remote changes before pushing
	git pull --rebase $(REMOTE) $(MAIN_BRANCH) 2>/dev/null || true
	git push $(REMOTE) $(MAIN_BRANCH) || { echo "⚠ main push failed — continuing to deploy publish branch"; }

	@# --- Orphan commit directly to publish ---
	@echo "=== apply: orphan commit to $(PUBLISH_BRANCH) ==="
	TINDEX=$$(mktemp -u /tmp/store-index.XXXXXX)
	export GIT_INDEX_FILE="$$TINDEX"
	GIT_DIR="$(CURDIR)/.git" GIT_WORK_TREE="$(PLAN_STAGING)" git add -A
	TREE=$$(GIT_DIR="$(CURDIR)/.git" git write-tree)
	COMMIT=$$(echo "Store publish $$(date +%Y-%m-%d\ %H:%M)" | GIT_DIR="$(CURDIR)/.git" git commit-tree "$$TREE")
	GIT_DIR="$(CURDIR)/.git" git update-ref refs/heads/$(PUBLISH_BRANCH) "$$COMMIT"
	rm -f "$$TINDEX"
	unset GIT_INDEX_FILE

	@# --- Tag the previous publish tip as publish-prev (cheap revert) ---
	@echo "=== apply: tag previous publish as publish-prev ==="
	@PREV=$$(git rev-parse $(REMOTE)/$(PUBLISH_BRANCH) 2>/dev/null || echo ""); \
	if [ -n "$$PREV" ]; then \
		git tag -f publish-prev "$$PREV" >/dev/null 2>&1; \
		git push -f $(REMOTE) refs/tags/publish-prev 2>/dev/null && \
			echo "  publish-prev → $$PREV (cheap revert: git push -f $(REMOTE) publish-prev:$(PUBLISH_BRANCH))" || \
			echo "  ⚠ publish-prev tag push failed (non-fatal; tag exists locally)"; \
	else \
		echo "  no previous $(REMOTE)/$(PUBLISH_BRANCH) — first publish, no rollback tag"; \
	fi
	git push $(REMOTE) $(PUBLISH_BRANCH) --force

	@# --- Cleanup: marker is consumed; require fresh plan next time ---
	@rm -rf "$(PLAN_DIR)"
	@echo "=== apply: done (plan dir cleaned up) ==="

# --- deploy: backwards-compat alias for plan + apply -------------------------
# Pre-v0.4 callers run `make build && make deploy`. Keep that working by
# chaining the new verbs.
deploy:
	@$(MAKE) plan
	@$(MAKE) apply

# --- publish: all-in-one (refresh + build + plan + apply) --------------------
publish:
	@echo "╔══════════════════════════════════════════════╗"
	@echo "║   Full publish: refresh → build → plan → apply"
	@echo "╚══════════════════════════════════════════════╝"
	@echo ""
	$(MAKE) refresh
	@echo ""
	bash build-store.sh --no-refresh
	@test -d "$(OUTPUT_DIR)" || { echo "Build failed — no $(OUTPUT_DIR)/"; exit 1; }
	@echo ""
	$(MAKE) plan
	@echo ""
	$(MAKE) apply

dev:
	@npm install --silent 2>/dev/null
	npx vite

clean:
	rm -rf dist dist-publish .staging-tmp
