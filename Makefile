# Makefile — Build and deploy the Melusina App Bazaar
#
#   make publish   Build store, push to publish branch (fast orphan deploy)
#   make build     Build only (no deploy)
#   make clean     Remove build artifacts
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

.PHONY: publish build clean dev

build:
	@echo "=== Building store ==="
	bash build-store.sh
	@test -d "$(OUTPUT_DIR)" || { echo "Build failed — no $(OUTPUT_DIR)/"; exit 1; }
	@echo "=== Build complete ==="

dev:
	@npm install --silent 2>/dev/null
	npx vite

publish: build
	@# --- Preflight ---
	@test -d .git || { echo "Not a git repo"; exit 1; }
	@test "$$(git branch --show-current)" = "$(MAIN_BRANCH)" \
		|| { echo "Must be on $(MAIN_BRANCH)"; exit 1; }

	@# --- Stage to temp dir ---
	@echo "=== Staging ==="
	STMP=$$(mktemp -d /tmp/store-publish.XXXXXX)
	trap 'rm -rf "$$STMP"' EXIT
	cp -a $(OUTPUT_DIR)/. "$$STMP/"
	@if [ -d update ]; then \
		echo "  Copying update/"; \
		mkdir -p "$$STMP/update"; \
		cp -a update/. "$$STMP/update/"; \
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

	@# --- Commit main (submodule updates, build artifacts) ---
	@echo "=== Commit main ==="
	git add -A
	git diff --cached --quiet || git commit -m "Store build $$(date +%Y-%m-%d)" --quiet
	git push $(REMOTE) $(MAIN_BRANCH) || true

	@# --- Deploy: orphan commit directly to publish (no checkout, no re-upload) ---
	@echo "=== Deploy to publish ==="
	@# Create a new git index from the staging directory
	TINDEX=$$(mktemp -u /tmp/store-index.XXXXXX)
	export GIT_INDEX_FILE="$$TINDEX"
	@# Add all staged files to a temporary index
	GIT_DIR="$(CURDIR)/.git" GIT_WORK_TREE="$$STMP" git add -A
	@# Create a tree object from the index
	TREE=$$(GIT_DIR="$(CURDIR)/.git" git write-tree)
	@# Create an orphan commit (no parent)
	COMMIT=$$(echo "Store publish $$(date +%Y-%m-%d\ %H:%M)" | GIT_DIR="$(CURDIR)/.git" git commit-tree "$$TREE")
	@# Update the publish branch ref to point at this commit
	GIT_DIR="$(CURDIR)/.git" git update-ref refs/heads/$(PUBLISH_BRANCH) "$$COMMIT"
	rm -f "$$TINDEX"
	unset GIT_INDEX_FILE
	@# Push — only new/changed objects get uploaded
	git push $(REMOTE) $(PUBLISH_BRANCH) --force
	rm -rf "$$STMP"
	@echo "=== Done ==="

clean:
	rm -rf dist dist-publish .staging-tmp
