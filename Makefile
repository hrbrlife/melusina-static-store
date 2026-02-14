# Melusina Static Store — Build & Deploy
#
# Usage:
#   make publish           Full build (npm + vite + aggregate) and deploy
#   make publish-aggregate Skip vite, re-aggregate submodules + deploy
#   make publish-deploy    Deploy current dist-publish/ only (no rebuild)
#   make build             Full build without deploying
#   make build-aggregate   Aggregate-only build without deploying
#   make submodules        Pull latest from each submodule's publish branch
#   make validate          Dry-run metadata validation
#   make clean             Remove build artifacts
#
SHELL       := /bin/bash
.ONESHELL:
.SHELLFLAGS := -euo pipefail -c

# ── Config ────────────────────────────────────────────────────────────────────
REMOTE         := origin
MAIN_BRANCH    := main
PUBLISH_BRANCH := publish
OUTPUT_DIR     := dist-publish
MAX_FILE_SIZE  := $$((95 * 1024 * 1024))
CHUNK_SIZE     := 90M
STORE_URL      := https://hrbrlife.github.io/melusina-static-store/

# ── Colors ────────────────────────────────────────────────────────────────────
_C := \033[0;36m
_G := \033[0;32m
_Y := \033[1;33m
_R := \033[0;31m
_B := \033[1m
_0 := \033[0m

info  = @printf "$(_C)[INFO]$(_0)  %s\n" $(1)
ok    = @printf "$(_G)[ OK ]$(_0)  %s\n" $(1)
warn  = @printf "$(_Y)[WARN]$(_0)  %s\n" $(1)
fail  = @printf "$(_R)[FAIL]$(_0)  %s\n" $(1)
step  = @printf "\n$(_B)=== %s ===$(_0)\n" $(1)

# ── Phony targets ─────────────────────────────────────────────────────────────
.PHONY: publish publish-aggregate publish-deploy \
        build build-aggregate validate submodules \
        clean help preflight \
        _push-main _stage _split _deploy _summary

.DEFAULT_GOAL := help

# ══════════════════════════════════════════════════════════════════════════════
# Top-level targets
# ══════════════════════════════════════════════════════════════════════════════

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-20s\033[0m %s\n", $$1, $$2}'

publish: preflight submodules build _push-main _stage _split _deploy _summary ## Full build + deploy
publish-aggregate: preflight submodules build-aggregate _push-main _stage _split _deploy _summary ## Aggregate + deploy
publish-deploy: preflight _push-main _stage _split _deploy _summary ## Deploy existing dist-publish/

build: preflight submodules ## Full build (vite + aggregate), no deploy
	$(call step,"Build (full)")
	bash build-store.sh
	@if ! git diff --quiet -- src/apps.json 2>/dev/null; then \
		git add src/apps.json; \
		git commit -m "Update src/apps.json from build" --quiet || true; \
	fi
	$(call ok,"Build complete")

build-aggregate: preflight submodules ## Aggregate-only build, no deploy
	$(call step,"Build (aggregate)")
	bash build-store.sh --aggregate
	@if ! git diff --quiet -- src/apps.json 2>/dev/null; then \
		git add src/apps.json; \
		git commit -m "Update src/apps.json from build" --quiet || true; \
	fi
	$(call ok,"Build complete")

validate: ## Validate metadata only (dry-run)
	bash build-store.sh --dry-run

clean: ## Remove build artifacts
	rm -rf dist/ $(OUTPUT_DIR)/ .staging-tmp/
	$(call ok,"Clean")

# ══════════════════════════════════════════════════════════════════════════════
# Internal targets
# ══════════════════════════════════════════════════════════════════════════════

preflight:
	$(call step,"Preflight")
	@test -d .git || { printf "$(_R)[FAIL]$(_0)  Not a git repository\n"; exit 1; }
	@git diff --quiet && git diff --cached --quiet \
		|| { printf "$(_R)[FAIL]$(_0)  Working tree dirty. Commit or stash first.\n"; exit 1; }
	@test "$$(git branch --show-current)" = "$(MAIN_BRANCH)" \
		|| { printf "$(_R)[FAIL]$(_0)  Must be on '$(MAIN_BRANCH)' (on '$$(git branch --show-current)')\n"; exit 1; }
	@command -v python3 >/dev/null || { printf "$(_R)[FAIL]$(_0)  python3 required\n"; exit 1; }
	@command -v split   >/dev/null || { printf "$(_R)[FAIL]$(_0)  split (coreutils) required\n"; exit 1; }
	$(call ok,"Preflight passed")

submodules: ## Pull latest from each submodule publish branch
	$(call step,"Update submodules")
	@git submodule update --init --recursive 2>/dev/null || true
	@UPDATED=0; \
	for sub in $$(git submodule --quiet foreach --recursive 'echo $$sm_path'); do \
		track=$$(git config -f .gitmodules "submodule.$${sub}.branch" 2>/dev/null || echo "publish"); \
		printf "$(_C)[INFO]$(_0)  Updating $$sub → $$track\n"; \
		pushd "$$sub" >/dev/null; \
		git fetch origin "$$track" --quiet 2>/dev/null; \
		old=$$(git rev-parse HEAD); \
		git checkout "origin/$$track" --quiet 2>/dev/null || git checkout FETCH_HEAD --quiet; \
		new=$$(git rev-parse HEAD); \
		if [ "$$old" != "$$new" ]; then \
			printf "$(_G)[ OK ]$(_0)  $$sub: $${old:0:7} → $${new:0:7}\n"; \
			UPDATED=$$((UPDATED+1)); \
		else \
			printf "$(_C)[INFO]$(_0)  $$sub already at $${old:0:7}\n"; \
		fi; \
		popd >/dev/null; \
	done; \
	if [ "$$UPDATED" -gt 0 ]; then \
		printf "$(_C)[INFO]$(_0)  $$UPDATED submodule(s) updated\n"; \
		git add packages/; \
		git commit -m "Update submodules to latest publish-branch commits" --quiet || true; \
	else \
		printf "$(_C)[INFO]$(_0)  All submodules up to date\n"; \
	fi

_push-main:
	$(call step,"Push main")
	@git add -A; \
	if ! git diff --cached --quiet; then \
		git commit -m "Store build $$(date +%Y-%m-%d)" --quiet; \
	fi
	git push $(REMOTE) $(MAIN_BRANCH) 2>&1 | tail -3
	$(call ok,"Main pushed")

# Stage dist-publish/ + update/ into a temp dir (while LFS files are real on main)
_stage:
	$(call step,"Stage for publish")
	@test -d "$(OUTPUT_DIR)" || { printf "$(_R)[FAIL]$(_0)  No $(OUTPUT_DIR)/. Run 'make build' first.\n"; exit 1; }
	@rm -rf .staging-tmp && mkdir -p .staging-tmp
	cp -a $(OUTPUT_DIR)/. .staging-tmp/
	@if [ -d update ]; then \
		printf "$(_C)[INFO]$(_0)  Staging update/ (LFS-resolved from main)\n"; \
		mkdir -p .staging-tmp/update; \
		cp -a update/. .staging-tmp/update/; \
	fi
	$(call ok,"Staged to .staging-tmp/")

# Split any file over 95 MB into 90 MB chunks + parts manifest
_split:
	$(call step,"Split large files (>95 MB)")
	@SPLIT=0; \
	while IFS= read -r -d '' bigfile; do \
		rel="$${bigfile#.staging-tmp/}"; \
		sz=$$(( $$(stat -c%s "$$bigfile") / 1024 / 1024 )); \
		printf "$(_C)[INFO]$(_0)  Splitting $$rel ($${sz} MB)…\n"; \
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
		nparts=$$(ls "$${bigfile}".part* 2>/dev/null | wc -l); \
		printf "$(_G)[ OK ]$(_0)  $$rel → $$nparts parts + manifest\n"; \
		mdir=$$(dirname "$$bigfile"); \
		if [ -f "$$mdir/manifest.json" ] && echo "$$orig_name" | grep -q '^sandstorm-.*\.tar\.xz$$'; then \
			printf "$(_C)[INFO]$(_0)  Patching manifest.json with parts info\n"; \
			python3 -c " \
import json, os; \
mf='$$mdir/manifest.json'; pf='$${bigfile}.parts.json'; \
m=json.load(open(mf)); p=json.load(open(pf)); \
m['split']=True; m['partsManifest']=os.path.basename(pf); m['parts']=p['parts']; \
json.dump(m,open(mf,'w'),indent=2)"; \
		fi; \
		SPLIT=$$((SPLIT+1)); \
	done < <(find .staging-tmp -type f -size +$(MAX_FILE_SIZE)c -print0); \
	if [ "$$SPLIT" -eq 0 ]; then \
		printf "$(_C)[INFO]$(_0)  No files exceed the limit\n"; \
	fi

# Switch to publish, replace contents, verify sizes, commit, force-push, return
_deploy:
	$(call step,"Deploy to publish")
	@ORIG_BRANCH=$$(git branch --show-current); \
	_cleanup() { \
		cur=$$(git branch --show-current 2>/dev/null || true); \
		[ "$$cur" != "$$ORIG_BRANCH" ] && git checkout "$$ORIG_BRANCH" --quiet 2>/dev/null || true; \
	}; \
	trap '_cleanup; rm -rf .staging-tmp' EXIT; \
	\
	printf "$(_C)[INFO]$(_0)  Switching to $(PUBLISH_BRANCH)\n"; \
	git checkout $(PUBLISH_BRANCH) 2>/dev/null; \
	\
	find . -maxdepth 1 -not -name '.git' -not -name '.' -exec rm -rf {} + 2>/dev/null || true; \
	cp -a .staging-tmp/. .; \
	touch .nojekyll; \
	rm -f .gitattributes; \
	\
	OVERSIZED=0; \
	while IFS= read -r -d '' f; do \
		fsz=$$(stat -c%s "$$f"); \
		if [ "$$fsz" -gt $(MAX_FILE_SIZE) ]; then \
			printf "$(_R)[FAIL]$(_0)  $$(basename $$f) still $$(( fsz / 1024 / 1024 )) MB\n"; \
			OVERSIZED=$$((OVERSIZED+1)); \
		fi; \
	done < <(find . -not -path './.git/*' -type f -print0); \
	if [ "$$OVERSIZED" -gt 0 ]; then \
		printf "$(_R)[FAIL]$(_0)  $$OVERSIZED file(s) exceed limit!\n"; \
		_cleanup; exit 1; \
	fi; \
	printf "$(_G)[ OK ]$(_0)  All files under 95 MB\n"; \
	\
	git add -A; \
	CHANGED=$$(git diff --cached --stat 2>/dev/null | tail -1); \
	if [ -z "$$CHANGED" ] || echo "$$CHANGED" | grep -q '0 files changed'; then \
		printf "$(_C)[INFO]$(_0)  No changes to publish\n"; \
	else \
		printf "$(_C)[INFO]$(_0)  $$CHANGED\n"; \
		git commit -m "Store publish $$(date +%Y-%m-%d\ %H:%M)" --quiet; \
		printf "$(_C)[INFO]$(_0)  Pushing $(PUBLISH_BRANCH) (force)…\n"; \
		git push $(REMOTE) $(PUBLISH_BRANCH) --force 2>&1 | tail -5; \
		printf "$(_G)[ OK ]$(_0)  Publish branch deployed\n"; \
	fi; \
	\
	printf "$(_C)[INFO]$(_0)  Switching back to $(MAIN_BRANCH)\n"; \
	git checkout $(MAIN_BRANCH) --quiet 2>/dev/null; \
	rm -rf .staging-tmp

_summary:
	@printf "\n$(_B)=== Done ===$(_0)\n\n"
	@printf "$(_G)[ OK ]$(_0)  main    → $(REMOTE)/$(MAIN_BRANCH)\n"
	@printf "$(_G)[ OK ]$(_0)  publish → $(REMOTE)/$(PUBLISH_BRANCH)\n\n"
	@printf "$(_C)[INFO]$(_0)  $(STORE_URL)\n\n"
