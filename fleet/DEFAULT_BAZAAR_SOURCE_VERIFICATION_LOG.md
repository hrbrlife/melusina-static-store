# Default Bazaar source verification log

This log records independent, clean-source checks for `source-pinned` entries
in the default Bazaar catalog. It is deliberately narrower than a release
approval: a passing source record does **not** prove package bytes, governed
publication, served catalog state, tenant pins, or fresh-install behavior.

## BotMother — source-level proof

- Immutable app ID:
  `xjdtxcy392qtrf317pyutxt2h5m022h291juzj1fs7023qsck3j0`
- Canonical source:
  `https://github.com/hrbrlife/melusina_botmother`
- Exact source commit:
  `899cddba7d379813a37c391226f75b069895736d`
- Recovery evidence: on 2026-08-19 the commit was the advertised tip of
  `fix/prelaunch-rendering-20260817`; an independent shallow recursive clone
  checked out that exact commit with all three declared submodules initialized
  at their gitlinks and no tracked or untracked changes.
- Release-input evidence: `metadata.json` and `RUNTIME-CONTRACT.json` are
  tracked regular files; their app IDs match the immutable catalog identity;
  the source runtime contract has the governed v1 schema and retains the
  required `PENDING_BUILD` fields for version, SPK digest, and app hash.
- Verification gates passed from that clean clone:
  - `bash tests/test-launcher.sh`
  - `go test -count=1 -tags=melusina ./templates/...`
  - `go test -count=1 -race ./pkg/...`
  - `go vet -tags=melusina ./...`
  - `git diff --check` and clean recursive Git status.

### Deliberate hold

The verified source metadata is version `1.3.5`; the catalog's `live_version`
remains `1.3.4`. This record proves a forward source candidate, not that it is
already published. It remains held until the complete 33-app source cohort,
deterministic package proof, governed release receipt, served pointer/catalog
evidence, and fresh-install runtime checks all agree.
