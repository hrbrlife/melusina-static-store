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

.PHONY: publish build clean dev refresh deploy preflight

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

# --- deploy: push existing dist-publish/ to publish branch --------------------
deploy: preflight
	@# Hard authoritative-builder gate (POSTMORTEM follow-up #1). This checkout
	@# is one of two static_store mirrors on this host with non-overlapping app
	@# sets; either could trigger the 2026-04-25 catalog-shrink regression on
	@# an accidental publish. The canonical builder must declare itself.
	@if [ "$$MELUSINA_PUBLISH_AUTHORITATIVE" != "1" ]; then \
		echo ""; \
		echo "✗ deploy aborted: MELUSINA_PUBLISH_AUTHORITATIVE is not set."; \
		echo "  This static_store checkout is a development mirror by default."; \
		echo "  See docs/M1_CCASH_CONFIG_PUBLISH_PATH.md and POSTMORTEM.md follow-up #1."; \
		echo "  To deploy from this host, set MELUSINA_PUBLISH_AUTHORITATIVE=1 explicitly."; \
		echo ""; \
		exit 1; \
	fi
	@test -d "$(OUTPUT_DIR)" || { echo "No $(OUTPUT_DIR)/ — run 'make build' first"; exit 1; }
	@test -d .git || { echo "Not a git repo"; exit 1; }
	@test "$$(git branch --show-current)" = "$(MAIN_BRANCH)" \
		|| { echo "Must be on $(MAIN_BRANCH)"; exit 1; }

	@# --- Stage to temp dir ---
	@echo "=== Staging ==="
	STMP=$$(mktemp -d /tmp/store-publish.XXXXXX)
	trap 'rm -rf "$$STMP"' EXIT
	cp -a $(OUTPUT_DIR)/. "$$STMP/"
	@if [ -d update ]; then \
		echo "  Merging update/ (repo root → staging, without overwriting build output)"; \
		mkdir -p "$$STMP/update"; \
		for f in update/*; do \
			bn=$$(basename "$$f"); \
			[ -e "$$STMP/update/$$bn" ] && continue; \
			case "$$bn" in *.tar.xz) \
				if ls "$$STMP/update/$${bn}".part* >/dev/null 2>&1; then \
					echo "    Skipping $$bn (pre-split parts exist)"; \
					continue; \
				fi ;; \
			esac; \
			cp -a "$$f" "$$STMP/update/$$bn"; \
		done; \
	fi
	touch "$$STMP/.nojekyll"

	@# --- Split files >95 MB ---
	@echo "=== Split large files ==="
	@SPLIT=0; \
	while IFS= read -r -d '' bigfile; do \
		rel="$${bigfile#$$STMP/}"; \
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
	done < <(find "$$STMP" -type f -size +$(MAX_FILE_SIZE)c -print0); \
	[ "$$SPLIT" -eq 0 ] && echo "  Nothing to split"

	@# --- Commit main (only catalog inputs generated by this workflow) ---
	@echo "=== Commit main ==="
	git add packages/ src/apps.json package.json package-lock.json e2e/fixtures/expected_apps.ts 2>/dev/null || true
	git diff --cached --quiet || git commit -m "Store build $$(date +%Y-%m-%d)" --quiet
	@# Pull --rebase to integrate any remote changes before pushing
	git pull --rebase $(REMOTE) $(MAIN_BRANCH) 2>/dev/null || true
	git push $(REMOTE) $(MAIN_BRANCH) || { echo "⚠ main push failed — continuing to deploy publish branch"; }

	@# --- Deploy: orphan commit directly to publish ---
	@echo "=== Deploy to publish ==="
	TINDEX=$$(mktemp -u /tmp/store-index.XXXXXX)
	export GIT_INDEX_FILE="$$TINDEX"
	GIT_DIR="$(CURDIR)/.git" GIT_WORK_TREE="$$STMP" git add -A
	TREE=$$(GIT_DIR="$(CURDIR)/.git" git write-tree)
	COMMIT=$$(echo "Store publish $$(date +%Y-%m-%d\ %H:%M)" | GIT_DIR="$(CURDIR)/.git" git commit-tree "$$TREE")
	GIT_DIR="$(CURDIR)/.git" git update-ref refs/heads/$(PUBLISH_BRANCH) "$$COMMIT"
	rm -f "$$TINDEX"
	unset GIT_INDEX_FILE
	@# --- Tag the previous publish tip as publish-prev (cheap revert per POSTMORTEM follow-up #5) ---
	@echo "=== Tag previous publish as publish-prev ==="
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
	rm -rf "$$STMP"
	@echo "=== Done ==="

# --- publish: all-in-one (refresh + build + deploy) --------------------------
publish:
	@echo "╔════════════════════════════════════════╗"
	@echo "║   Full publish: refresh → build → deploy"
	@echo "╚════════════════════════════════════════╝"
	@echo ""
	$(MAKE) refresh
	@echo ""
	bash build-store.sh --no-refresh
	@test -d "$(OUTPUT_DIR)" || { echo "Build failed — no $(OUTPUT_DIR)/"; exit 1; }
	@echo ""
	$(MAKE) deploy

dev:
	@npm install --silent 2>/dev/null
	npx vite

clean:
	rm -rf dist dist-publish .staging-tmp
