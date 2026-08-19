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
| GoldKey | `quckdm544ydg12dmx8jt7t6vgnmy2trtt8jnsjv3afxvcfas4hvh` | `a46106ded2aab2c7b50465cd561f176de25b4947` on `master` | `0.3.4` (versionNumber 7) | `0.3.4` | pinned toolchain check; `make vet test`; clean recursive status and `git diff --check` |
| Fineract Setup | `7htu16dens78fcfkc7u498sx33n0gsm25r0q8r5tqx0k7c5yft9h` | `d8ccf4e49b314e535ebc4d6762d6d6e2bd6c8c7f` on `main` | `0.2.19` (versionNumber 19) | `0.2.18` | release-cohort and source-portability checks with mutation controls; grain and sidecar vet/test/race suites; clean recursive status and `git diff --check` |
| MerMail | `wfy0c4706yw6rp70t4a4pse8c2spm0d4hdasya6vkc4fdhhyw86h` | `55e276e3a5aef4e0f5605c191759c5fdce781fdc` on `main` | `0.5.5` (versionNumber 20) | `0.5.5` | tracked release-input validation; both Pearl test suites; both module vet checks; clean recursive status and `git diff --check` |
| NamedCoin | `8kea8reanvm5cw7awrxj8udguh5hf3yfcns01fmq7vq42ps2hvuh` | `f82c217f643bdfc217ba8b3ba91a4cbbf521ba55` on `main` | `0.1.35` (versionNumber 37) | `0.1.35` | `GOWORK=off go vet ./...` and uncached `go test ./...`; clean recursive status and `git diff --check` |

The domain-template and Fineract Setup rows, like BotMother, are verified
forward source candidates rather than publication claims: their metadata is
ahead of the catalog's recorded live version. Every row above remains held
pending the full 33-app source cohort, deterministic package/release proof,
served state, and fresh-install verification.

## NamedCoin Admin — portable-gate repair awaiting publication

The source at catalog commit
`0dda2a0a89335e12ad86c70792585bc3006445d5` was independently cloned from
the advertised `main` tip with its submodule pinned and clean. Its metadata
and runtime-contract app ID match the catalog; metadata is `0.1.42`
(versionNumber 45), matching the catalog's live version. Its `GOWORK=off`
vet/test suite, app-ID check, encoder check, envelope check, and ordinal check
all pass when the ordinal checker receives the actual repository root.

The checked-in `make check-capnp-ordinal` target instead named an unrelated
workstation path, so it could not reliably validate this source. A one-line,
repository-relative fix was tested through `GOWORK=off make check-drift` and
committed locally as `38cdf76202719776abcf5781877c5b3d72833b6e`. As of
2026-08-19 that corrective commit is not advertised by the canonical origin.
No catalog pin was changed: the source owner must publish that fix or a
reviewed successor, after which the clean-clone proof must be repeated before
this app can join a release cohort.

## Cyberteller — recovered source pin, egress-policy gate unresolved

The canonical source at catalog commit
`8cd83ed9a9a28aab633ccdf466cd89fdcbd7beb7` was independently shallow-cloned
from the advertised `main` tip with its declared submodule initialized and a
clean recursive Git status. Its metadata and runtime-contract app ID match the
catalog identity; metadata is `0.1.93`, matching the catalog's live version.
`GOWORK=off go vet ./...`, `GOWORK=off make test`, and the app-ID and Cap'n
Proto ordinal checks passed from that clean clone.

It is **not** source-gate ready. The raw, source-owned
`go run ./cmd/check-e2e-envelope-coverage/` gate exits nonzero with 15
uncovered outbound HTTP call sites. They span the capability bridge,
DueProcess case and risk-rule clients, the optional price feed, the sanctions
sidecar client, webhook delivery, and Chainwatch's upstream RPC pool. The
finding does not assert that every one is unsigned: for example, the webhook
paths wrap their bodies with the existing signer, but that operation is not
recognized by the policy checker. It does prove that the checked-in policy
gate cannot yet establish the required coverage.

The checked-in `make check-e2e-envelope` target currently masks this failure
with `|| true`, which means `make check-drift` is not a release gate for this
source. No local waiver, source-pin change, or package claim was made here.
The source owner must make each path independently auditable: retain or add
real peer-verifiable signing where the receiver supports it; use a narrow,
reviewed policy reason only for proven capability or public-read paths; teach
the checker about the existing signed webhook wrapper; then remove the mask
and publish a commit whose clean-clone gate passes. Repeat the full source
proof only after that remotely recoverable successor exists.

## InstaCo — client toolchain pin repair awaiting publication

The source at catalog commit
`5d9347ce837ec423013bc17bd17ff3a60b7f39eb` was independently shallow-cloned
from the advertised `main` tip with both declared submodules initialized and a
clean recursive Git status. Its metadata and runtime-contract app ID match the
catalog; metadata is `0.1.8` (versionNumber 15), matching the catalog's live
version. Its frozen-lockfile client install, typecheck, Vite build, Go vet,
ordinary Go tests, and race suite all passed.

The source did not declare an exact `packageManager` in
`client/package.json`. A lockfile fixes dependency resolutions but does not
identify the pnpm implementation that materializes the client build inputs,
so that source is not sufficient for deterministic candidate construction.
A local repair commit,
`58216f58ade895d9842682f0c1f61f05a71fdf65`, pins `pnpm@9.15.5` and adds a
release-candidate regression test tying that pin to the existing pnpm v9
lockfile. The full client and Go gate suite passed again from that repaired,
clean recursive checkout.

As of 2026-08-19 the canonical origin advertises only the catalog base
commit, not the repair. No catalog pin was changed. The source owner must
publish that repair or a reviewed successor, determine the appropriate
forward release version if the resulting package bytes differ, and repeat the
clean-clone proof before InstaCo can join a release cohort.
