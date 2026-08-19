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

## Additional source-level proofs

On 2026-08-19, each source below was independently shallow-cloned from its
advertised canonical branch with recursive submodules. Each clone reached the
catalog pin, remained clean before and after its checks, contained tracked
`metadata.json` and `RUNTIME-CONTRACT.json`, and passed the same source
contract semantic check used for BotMother above.

| App | Immutable app ID | Commit and advertised ref | Metadata version | Catalog `live_version` | Source gates passed |
| --- | --- | --- | --- | --- | --- |
| ccash Domain Template | `hck466e5ath1p4k4z1hhmd75ujjhs6z4pexe3d230hsrzzs2dg2h` | `f21c77615fe3bd2b3ce7c8a1d889000fe75b4f3a` on `fix/prelaunch-domain-template-v109-greenfield` | `0.5.87` (versionNumber 109) | `0.5.85` | `make check-greenfield check-release-metadata vet test check-fmt`; clean recursive status and `git diff --check` |
| DueProcess | `47der88w353m8ne2j009yj7yzh9dhhmgqfy8an66qt0za1cj0ax0` | `a4f27e9737529c360782458d1ab9ed3563e7544b` on `main` | `0.1.74` (versionNumber 78) | `0.1.74` | app-ID and boundary tripwires; `make vet test`; clean recursive status and `git diff --check` |
| Teleport | `ar4the0nec9myt6k4h5qw7x4fgwnyg8r8nf42t84jygst97c7e3h` | `a943d5a5fb491d5029b67ac157b92379d94e0a60` on `main` | `1.3.4` (versionNumber 10) | `1.3.4` | `make vet test` (full race suite); clean recursive status and `git diff --check` |
| MiniGit | `pe3k6wapfczy7797n8xxu3qsn40sd1k4mvfmqv8kz2200dqavv50` | `610c44614a8b499d1e80795a97daca66a9912f77` on `main` | `0.2.14` (versionNumber 20) | `0.2.14` | `make vet test`; clean recursive status and `git diff --check` |

The domain-template row, like BotMother, is a verified forward source
candidate rather than a publication claim: metadata is `0.5.87` while the
catalog records live `0.5.85`. Every row above remains held pending the full
33-app source cohort, deterministic package/release proof, served state, and
fresh-install verification.
