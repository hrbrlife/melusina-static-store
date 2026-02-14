# Melusina Static Store

Static app store for Melusina (Sandstorm fork). Hosted on GitHub Pages from the `publish` branch.

**Live store**: https://hrbrlife.github.io/melusina-static-store/

---

## Publish the store

```
make publish
```

That's it. One command. It does everything:

1. Pulls latest from all app submodules (their `publish` branches)
2. Runs `build-store.sh` (scans metadata, builds Vite frontend, assembles `dist-publish/`)
3. Copies the Sandstorm binary update (`update/sandstorm-0.tar.xz`) into the output
4. Splits any files over 95MB into 90MB chunks (GitHub Pages limit)
5. Commits and pushes `main`
6. Deploys everything to the `publish` branch
7. Switches back to `main`

You must be on the `main` branch. Nothing else required.

---

## Publish an individual app

Every app repo has the same standardized Makefile. From any app repo:

```bash
# Build and test locally
make build && make dev

# Pack a release (auto-bumps version, signs PGP, creates .spk, verifies)
make pack

# Pack + push to the app's publish branch
make publish
```

Then come back here and run `make publish` to deploy the store.

### Full workflow (app change → live store)

```bash
# 1. In the app repo — make your changes, then:
make publish

# 2. In this repo (static_store):
make publish
```

Done. The store picks up the new version automatically.

---

## App repos

Each app is a git submodule under `packages/hrbrlife/`, tracking the `publish` branch:

| App | Repo | Slug |
|-----|------|------|
| BLOOM Identity | [hrbrlife/BLOOM_FINAL](https://github.com/hrbrlife/BLOOM_FINAL) | `bloom-identity` |
| Bureau (CheeseSpread) | [hrbrlife/CHEESESPREAD](https://github.com/hrbrlife/CHEESESPREAD) | `bureau` |
| Instasys Mail | [hrbrlife/INSTASYS_MAIL](https://github.com/hrbrlife/INSTASYS_MAIL) | `instasys-mail` |
| BotMother | [hrbrlife/MELUSINA_BOTMOTHER](https://github.com/hrbrlife/MELUSINA_BOTMOTHER) | `botmother` |
| MiniGit | [hrbrlife/MiniGit](https://github.com/hrbrlife/MiniGit) | `minigit` |
| Shell Tester | [hrbrlife/shell_tester](https://github.com/hrbrlife/shell_tester) | `shell-tester` |

Each app's `publish` branch contains: `{slug}/app.spk`, `{slug}/metadata.json`, `{slug}/icon.svg`, `author.pgp.pub`, `README.md`.

---

## Adding a new app

1. Create the app repo with the standardized Makefile (copy `mk/sandstorm.mk` from any existing app)
2. Run `make publish` in the app repo to create its `publish` branch
3. Add the submodule here:
   ```bash
   git submodule add -b publish https://github.com/hrbrlife/NEW_APP.git packages/hrbrlife/NEW_APP
   ```
4. Run `make publish` here

---

## Sandstorm binary update

The file `update/sandstorm-0.tar.xz` is the Sandstorm binary itself. It gets deployed to `publish` alongside the store. Do not regenerate or modify it unless you're shipping a new Sandstorm build.

---

## Repo structure

```
static_store/
├── Makefile              # make publish — does everything
├── build-store.sh        # Scans submodules, builds Vite frontend, assembles dist-publish/
├── src/
│   ├── main.jsx          # Store frontend (React)
│   └── apps.json         # Generated app index (do not edit — built by build-store.sh)
├── packages/hrbrlife/    # App submodules (publish branches)
│   ├── BLOOM_FINAL/
│   ├── CHEESESPREAD/
│   ├── INSTASYS_MAIL/
│   ├── MELUSINA_BOTMOTHER/
│   ├── MiniGit/
│   └── shell_tester/
├── update/
│   └── sandstorm-0.tar.xz   # Sandstorm binary (do not touch)
├── verifier/
│   └── index.html        # SPK verification page
└── dist-publish/         # Build output (deployed to publish branch)
```

## Branches

- **`main`** — Source code, submodule refs, Sandstorm binary (LFS). Push here for development.
- **`publish`** — GitHub Pages deployment. Raw files only, no LFS. Never edit directly — `make publish` manages it.