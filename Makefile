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

.PHONY: publish build clean dev refresh deploy

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

# --- deploy: push existing dist-publish/ to publish branch --------------------
deploy:
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

	@# --- Commit main (submodule pointers, build artifacts) ---
	@echo "=== Commit main ==="
	git add -A
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
