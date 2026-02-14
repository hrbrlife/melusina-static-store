# Makefile — Deploy dist-publish/ to the publish branch
#
#   make publish   Stage dist-publish/ + update/, split files >95MB, push to publish branch
#   make clean     Remove staging artifacts
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

.PHONY: publish clean

publish:
	@# --- Preflight ---
	@test -d .git || { echo "Not a git repo"; exit 1; }
	@test "$$(git branch --show-current)" = "$(MAIN_BRANCH)" \
		|| { echo "Must be on $(MAIN_BRANCH)"; exit 1; }
	@test -d "$(OUTPUT_DIR)" || { echo "No $(OUTPUT_DIR)/ — run build-store.sh first"; exit 1; }

	@# --- Stage to temp dir OUTSIDE the repo (survives branch switch) ---
	@echo "=== Staging ==="
	STMP=$$(mktemp -d /tmp/store-publish.XXXXXX)
	trap 'rm -rf "$$STMP"' EXIT
	cp -a $(OUTPUT_DIR)/. "$$STMP/"
	@if [ -d update ]; then \
		echo "  Copying update/ (LFS-resolved)"; \
		mkdir -p "$$STMP/update"; \
		cp -a update/. "$$STMP/update/"; \
	fi

	@# --- Commit and push main ---
	@echo "=== Push main ==="
	git add -A
	git diff --cached --quiet || git commit -m "Store build $$(date +%Y-%m-%d)" --quiet
	git push $(REMOTE) $(MAIN_BRANCH) 2>&1 | tail -3

	@# --- Split files >95 MB into 90 MB chunks ---
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
		mdir=$$(dirname "$$bigfile"); \
		if [ -f "$$mdir/manifest.json" ] && echo "$$orig_name" | grep -q '^sandstorm-.*\.tar\.xz$$'; then \
			python3 -c " \
import json, os; \
m=json.load(open('$$mdir/manifest.json')); p=json.load(open('$${bigfile}.parts.json')); \
m['split']=True; m['partsManifest']=os.path.basename('$${bigfile}.parts.json'); m['parts']=p['parts']; \
json.dump(m,open('$$mdir/manifest.json','w'),indent=2)"; \
		fi; \
		SPLIT=$$((SPLIT+1)); \
	done < <(find "$$STMP" -type f -size +$(MAX_FILE_SIZE)c -print0); \
	[ "$$SPLIT" -eq 0 ] && echo "  Nothing to split"

	@# --- Deploy to publish branch ---
	@echo "=== Deploy to publish ==="
	git checkout $(PUBLISH_BRANCH) 2>/dev/null
	find . -maxdepth 1 -not -name '.git' -not -name '.' -exec rm -rf {} + 2>/dev/null || true
	cp -a "$$STMP"/. .
	touch .nojekyll
	rm -f .gitattributes
	@# Verify nothing is oversized
	@OVER=0; \
	while IFS= read -r -d '' f; do \
		[ "$$(stat -c%s "$$f")" -gt $(MAX_FILE_SIZE) ] && { echo "FAIL: $$f too large"; OVER=$$((OVER+1)); }; \
	done < <(find . -not -path './.git/*' -type f -print0); \
	[ "$$OVER" -gt 0 ] && { git checkout $(MAIN_BRANCH) --quiet; exit 1; }
	git add -A
	git diff --cached --quiet \
		&& echo "  No changes" \
		|| { git commit -m "Store publish $$(date +%Y-%m-%d\ %H:%M)" --quiet; \
		     git push $(REMOTE) $(PUBLISH_BRANCH) --force 2>&1 | tail -5; }
	git checkout $(MAIN_BRANCH) --quiet 2>/dev/null
	rm -rf "$$STMP"
	@echo "=== Done ==="

clean:
	@echo "Nothing to clean (staging uses /tmp/)"
