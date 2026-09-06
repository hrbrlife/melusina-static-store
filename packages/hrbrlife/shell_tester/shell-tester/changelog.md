# Shell Tester changelog

## 0.1.12

- Fixes the native WebSession asset boundary: the grain now explicitly serves
  the embedded `style.css` and `app.js` assets with their correct MIME types.
  An uncached launch therefore retains the readable tabbed UI and can run the
  passive test controls. The route allow-list rejects arbitrary paths.

## 0.1.11

- Adds Solana-wallet and Ethereum-wallet registration plus single-credential
  and all-credential revocation paths to the E2E test surface. This retains the
  forward release controls from the v13 candidate while restoring coverage that
  existed only on the retained admin-auth feature line.

## 0.1.9

- Provenance repair. The live Store served 0.1.8 / appVersion 11, but that
  content existed only on the unmerged branch
  `codex/shell-tester-store-release-20260729`; `main` was three versions behind
  at 0.1.4 / appVersion 8 and its `sandstorm-pkgdef.capnp` disagreed with
  `metadata.json` (0.1.5 / appVersion 8). The branch is now landed on `main`,
  the two halves state one version, and the cohort moves forward of live.
- Fixes the package's own build inputs, which were unbuildable from a clean
  checkout:
  - `.gitmodules` gains the `shared/grain-crypto-journal` mapping. `main` had
    committed the gitlink without it, so `git submodule update --init` aborted
    with "no submodule mapping found" and never initialised `spkmodule`
    either — the Makefile's `include spkmodule/mk/core.mk` could not resolve.
  - `go.mod` points the `grain-crypto-journal` replacement at the in-repo
    submodule (`./shared/grain-crypto-journal`) instead of `../shared/...`, a
    sibling clone outside the repository that does not exist on any host. A
    clean checkout now builds without a mutable workstation dependency.
  - The `shared/grain-crypto-journal` gitlink is re-pinned to
    `4fbc192e8d0b99c1c122b9f8f61f8af7f892b100`, the keybox revision `main.go`
    actually compiles against. The branch's recorded pin
    (`4fbc19280f7c75f4e5d31bbb0f2da0d18cb364d8`) is not a real object in that
    repository — `git fetch` of it is refused with "not our ref".
  - `sandstorm-files.list` includes the `shell-tester` binary, which the
    packaged image previously omitted.
  - `third_party/sandstorm/capnp/grain/grain.capnp.go` imports the real
    lowercase `capnp/powerbox` package again; a terminology sweep had
    capitalised the import path.
- Packaging moves to spkmodule v0.7.0, so candidate bytes are produced by the
  governed `pack-local` lane with `SOURCE_DATE_EPOCH` clamped to the commit
  time — two packs of one commit are byte-identical.
- Catalog hygiene: `metadata.json` gains a non-empty canonical description and
  a `marketingVersion` in the cohort. No screenshot claims, no legacy
  top-level field spellings, canonical title-case categories.
