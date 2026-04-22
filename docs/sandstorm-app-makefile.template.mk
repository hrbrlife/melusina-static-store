# ============================================================================
# Sandstorm/Melusina app Makefile — canonical template
# ============================================================================
#
# Universal discipline (see docs/sandstorm-app-makefile.md):
#
#   - Every spk invocation runs under a freshly verified /opt/app bind-mount.
#     Stale mounts from prior-app builds are the #1 cause of silently-wrong
#     SPKs.  We unmount first, mount, verify the mount, then hand off to spk.
#   - Each target does exactly one thing named by the target.
#   - `make publish` pushes to THIS app's `publish` branch only.  It does
#     NOT call `spk publish` (external app-market).
#   - `make pack` runs `spk verify` before returning success.
#   - `make publish` is idempotent — skips the push if origin already has
#     a matching packageId.
#
# To use in a new app:
#   1. Copy this file to the app repo root as `Makefile`.
#   2. Fill in the three vars in the "Per-app configuration" block.
#   3. Write the `build-source` target body (app-specific; Go/Node/etc.).
#   4. Commit the Makefile + docs pointer to `main` and `develop`.
# ============================================================================

# ---- Per-app configuration -------------------------------------------------
# The slug is the directory name on the publish branch (e.g. `doc-bureau`).
APP_SLUG        := REPLACE_ME_SLUG
# The GPG key id used to sign metadata.json.asc.
GPG_KEY         := REPLACE_ME_GPG_KEY_LONG_ID
# The app.spk output path (inside this repo).  Usually $(APP_DIR)/app.spk.
SPK_OUT         := $(CURDIR)/app.spk

# ---- Fixed infrastructure (do not change per-app) --------------------------
APP_DIR         := $(CURDIR)
MOUNT           := /opt/app
LOCK            := /tmp/melusina-spk-mount.lock
PKGDEF          := sandstorm-pkgdef.capnp
METADATA        := metadata.json
METADATA_ASC    := metadata.json.asc

.PHONY: build build-source dev pack verify publish clean help \
        _mount _unmount _check-mount _publish-push

help:
	@echo "Targets:"
	@echo "  make build      — compile source (app-specific; no spk, no mount)"
	@echo "  make dev        — bind-mount + spk dev (no build)"
	@echo "  make pack       — bind-mount + spk pack + spk verify (no build)"
	@echo "  make verify     — spk verify + gpg --verify metadata.asc"
	@echo "  make publish    — make pack + push artefacts to this repo's publish branch"
	@echo "  make clean      — unmount + rm app.spk"

# --- Mount discipline -------------------------------------------------------
# Every spk-touching target depends on _check-mount.  _check-mount depends on
# _mount, which depends on _unmount.  Ordering is enforced by prerequisites.

_unmount:
	@# Unconditionally unmount.  mountpoint -q returns 0 iff MOUNT is a
	@# mountpoint; otherwise no-op.  Uses flock to serialise parallel makes.
	@flock $(LOCK) -c '\
	  if mountpoint -q $(MOUNT); then \
	    echo "  [mount] unbinding stale $(MOUNT)"; \
	    sudo umount $(MOUNT); \
	  fi'

_mount: _unmount
	@flock $(LOCK) -c '\
	  sudo mkdir -p $(MOUNT); \
	  sudo mount --bind $(APP_DIR) $(MOUNT); \
	  echo "  [mount] bound $(APP_DIR) -> $(MOUNT)"'

_check-mount: _mount
	@# Assert /opt/app really is this app's tree, not a stale bind or a
	@# different app that raced ahead.  Inode comparison of the pkgdef is
	@# the cheapest O(1) proof.
	@test -f $(MOUNT)/$(PKGDEF) || { \
	  echo "FATAL: $(MOUNT)/$(PKGDEF) not visible after mount — bind failed."; \
	  exit 1; }
	@if [ "$$(stat -c%i $(APP_DIR)/$(PKGDEF))" != \
	       "$$(stat -c%i $(MOUNT)/$(PKGDEF))" ]; then \
	  echo "FATAL: /opt/app points at a DIFFERENT tree than $(APP_DIR)."; \
	  echo "       $(APP_DIR)/$(PKGDEF)  inode=$$(stat -c%i $(APP_DIR)/$(PKGDEF))"; \
	  echo "       $(MOUNT)/$(PKGDEF)    inode=$$(stat -c%i $(MOUNT)/$(PKGDEF))"; \
	  exit 1; \
	fi
	@echo "  [mount] verified $(MOUNT) == $(APP_DIR)"

# --- build ------------------------------------------------------------------
# Source compilation only.  Overridden per-app in `build-source`.  This
# target MUST NOT call spk or mount.
build: build-source
	@echo "  [build] done"

build-source:
	@# PER-APP STUB — override with your language's build step.
	@# Examples:
	@#   build-source: ; go build -o bin/server ./cmd/server
	@#   build-source: ; npm ci && npm run build
	@#   build-source: ; true     # static app with no build step
	@echo "  [build-source] placeholder — override this target per-app"

# --- dev --------------------------------------------------------------------
# Bind-mount + spk dev.  NO build.  Assumes prior `make build`.
# Trap cleans up the bind on Ctrl-C.
dev: _check-mount
	@trap 'echo; $(MAKE) _unmount' INT TERM EXIT; \
	 spk dev

# --- pack -------------------------------------------------------------------
# Bind-mount + spk pack + spk verify.  NO build.  Always unmounts on exit.
pack: _check-mount
	@trap '$(MAKE) _unmount' EXIT; \
	 echo "  [pack] writing $(SPK_OUT)"; \
	 spk pack "$(SPK_OUT)"; \
	 $(MAKE) _do-verify

# --- verify -----------------------------------------------------------------
# Standalone SPK + signature verification.  Safe to call anytime.
verify:
	@$(MAKE) _do-verify

_do-verify:
	@test -f "$(SPK_OUT)" || { echo "FATAL: $(SPK_OUT) not found; run make pack first"; exit 1; }
	@echo "  [verify] spk verify $(SPK_OUT)"
	@spk verify "$(SPK_OUT)" > /tmp/spk-verify.$$$$ 2>&1 || { \
	  cat /tmp/spk-verify.$$$$; rm -f /tmp/spk-verify.$$$$; exit 1; }
	@# Assert appId + packageId match metadata.json
	@spk_app=$$(spk verify "$(SPK_OUT)" 2>/dev/null | grep -oE '"appId": "[^"]*"' | head -1 | cut -d'"' -f4); \
	 spk_pkg=$$(spk verify "$(SPK_OUT)" 2>/dev/null | grep -oE '"packageId": "[^"]*"' | head -1 | cut -d'"' -f4); \
	 meta_app=$$(python3 -c "import json; print(json.load(open('$(APP_SLUG)/$(METADATA)'))['appId'])" 2>/dev/null); \
	 meta_pkg=$$(python3 -c "import json; print(json.load(open('$(APP_SLUG)/$(METADATA)'))['packageId'])" 2>/dev/null); \
	 if [ -n "$$meta_app" ] && [ "$$spk_app" != "$$meta_app" ]; then \
	   echo "FATAL: SPK appId ($$spk_app) != metadata.json appId ($$meta_app)"; exit 1; \
	 fi; \
	 if [ -n "$$meta_pkg" ] && [ "$$spk_pkg" != "$$meta_pkg" ]; then \
	   echo "FATAL: SPK packageId ($$spk_pkg) != metadata.json packageId ($$meta_pkg)"; exit 1; \
	 fi
	@# GPG signature check on metadata.json.asc (only when publish branch has one)
	@if [ -f "$(APP_SLUG)/$(METADATA_ASC)" ]; then \
	   echo "  [verify] gpg --verify $(APP_SLUG)/$(METADATA_ASC)"; \
	   gpg --verify "$(APP_SLUG)/$(METADATA_ASC)" "$(APP_SLUG)/$(METADATA)" 2>&1 | grep -q "Good signature" || { \
	     echo "FATAL: metadata.json.asc does not verify"; exit 1; }; \
	 fi
	@echo "  [verify] OK"

# --- publish ----------------------------------------------------------------
# make pack → verify → git push to this repo's publish branch.
# NEVER invokes `spk publish` (that's external app-market).
publish: pack
	@$(MAKE) _publish-push

_publish-push:
	@# Stage a worktree for the publish branch; lay down the standard
	@# artefact set; sign metadata; commit; push.  Idempotent: skip if
	@# origin/publish already carries the same packageId.
	@spk_pkg=$$(spk verify "$(SPK_OUT)" 2>/dev/null | grep -oE '"packageId": "[^"]*"' | head -1 | cut -d'"' -f4); \
	 echo "  [publish] packageId=$$spk_pkg"; \
	 wt=$$(mktemp -d); \
	 git fetch origin publish --depth=1 2>/dev/null || true; \
	 git worktree add -B publish "$$wt" origin/publish 2>/dev/null || \
	   git worktree add --detach "$$wt" && (cd "$$wt" && git checkout --orphan publish && git rm -rf . 2>/dev/null || true); \
	 # Check idempotency \
	 existing_pkg=$$(python3 -c "import json,os; p='$$wt/$(APP_SLUG)/$(METADATA)'; print(json.load(open(p))['packageId'] if os.path.exists(p) else '')" 2>/dev/null); \
	 if [ "$$spk_pkg" = "$$existing_pkg" ]; then \
	   echo "  [publish] packageId unchanged on origin/publish — skipping push"; \
	   git worktree remove --force "$$wt"; \
	   exit 0; \
	 fi; \
	 mkdir -p "$$wt/$(APP_SLUG)"; \
	 cp "$(SPK_OUT)" "$$wt/$(APP_SLUG)/app.spk"; \
	 cp "$(APP_DIR)/$(METADATA)" "$$wt/$(APP_SLUG)/" 2>/dev/null || true; \
	 [ -f "$(APP_DIR)/icon.png" ] && cp "$(APP_DIR)/icon.png" "$$wt/$(APP_SLUG)/"; \
	 [ -f "$(APP_DIR)/icon.svg" ] && cp "$(APP_DIR)/icon.svg" "$$wt/$(APP_SLUG)/"; \
	 [ -f "$(APP_DIR)/description.md" ] && cp "$(APP_DIR)/description.md" "$$wt/$(APP_SLUG)/"; \
	 [ -d "$(APP_DIR)/screenshots" ] && cp -r "$(APP_DIR)/screenshots" "$$wt/$(APP_SLUG)/"; \
	 rm -f "$$wt/$(APP_SLUG)/$(METADATA_ASC)"; \
	 gpg --batch --yes -u "$(GPG_KEY)" --detach-sign --armor \
	     --output "$$wt/$(APP_SLUG)/$(METADATA_ASC)" "$$wt/$(APP_SLUG)/$(METADATA)"; \
	 (cd "$$wt" && \
	   git add -A && \
	   git commit -m "Publish $(APP_SLUG) (pkg=$${spk_pkg:0:12})" && \
	   git push origin HEAD:publish); \
	 git worktree remove --force "$$wt"; \
	 echo "  [publish] pushed $(APP_SLUG) pkg=$$spk_pkg to origin publish"

# --- clean ------------------------------------------------------------------
clean:
	@$(MAKE) _unmount
	rm -f "$(SPK_OUT)"
	@echo "  [clean] removed $(SPK_OUT); /opt/app unmounted"
