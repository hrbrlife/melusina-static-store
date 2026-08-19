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
already published. It remains held until the complete 32-app source cohort,
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
| DueProcess | `47der88w353m8ne2j009yj7yzh9dhhmgqfy8an66qt0za1cj0ax0` | `aff5cc7ce2b793eee34f97e10d27d00bec441941` on `dev-publish` | `0.1.74` (versionNumber 78) | `0.1.74` | fresh filtered recursive clone; `GOWORK=off go test ./pkg/station`; `GOWORK=off go vet ./...`; `make check-drift`; clean recursive status and `git diff --check` |
| Teleport | `ar4the0nec9myt6k4h5qw7x4fgwnyg8r8nf42t84jygst97c7e3h` | `a943d5a5fb491d5029b67ac157b92379d94e0a60` on `main` | `1.3.4` (versionNumber 10) | `1.3.4` | `make vet test` (full race suite); clean recursive status and `git diff --check` |
| MiniGit | `pe3k6wapfczy7797n8xxu3qsn40sd1k4mvfmqv8kz2200dqavv50` | `610c44614a8b499d1e80795a97daca66a9912f77` on `main` | `0.2.14` (versionNumber 20) | `0.2.14` | `make vet test`; clean recursive status and `git diff --check` |
| GoldKey | `quckdm544ydg12dmx8jt7t6vgnmy2trtt8jnsjv3afxvcfas4hvh` | `4cdde8588370bfb9ae7b4a7d736d623b8ab0536b` on `dev-publish` | `0.3.4` (versionNumber 7) | `0.3.4` | fresh recursive clone; pinned-toolchain `make ci`; clean recursive status and `git diff --check` |
| Fineract Setup | `7htu16dens78fcfkc7u498sx33n0gsm25r0q8r5tqx0k7c5yft9h` | `d8ccf4e49b314e535ebc4d6762d6d6e2bd6c8c7f` on `main` | `0.2.19` (versionNumber 19) | `0.2.18` | release-cohort and source-portability checks with mutation controls; grain and sidecar vet/test/race suites; clean recursive status and `git diff --check` |
| MerMail | `wfy0c4706yw6rp70t4a4pse8c2spm0d4hdasya6vkc4fdhhyw86h` | `55e276e3a5aef4e0f5605c191759c5fdce781fdc` on `main` | `0.5.5` (versionNumber 20) | `0.5.5` | tracked release-input validation; both Pearl test suites; both module vet checks; clean recursive status and `git diff --check` |
| NamedCoin | `8kea8reanvm5cw7awrxj8udguh5hf3yfcns01fmq7vq42ps2hvuh` | `f82c217f643bdfc217ba8b3ba91a4cbbf521ba55` on `main` | `0.1.35` (versionNumber 37) | `0.1.35` | `GOWORK=off go vet ./...` and uncached `go test ./...`; clean recursive status and `git diff --check` |

The domain-template and Fineract Setup rows, like BotMother, are verified
forward source candidates rather than publication claims: their metadata is
ahead of the catalog's recorded live version. Every row above remains held
pending the full 32-app source cohort, deterministic package/release proof,
served state, and fresh-install verification.

## 2026-08-19 `dev-publish` source transition

The source candidates recorded in the recovery queue have been published on
their canonical origins' `dev-publish` branches, and DueProcess now points at
its tested forward RPC-compatibility commit
`aff5cc7ce2b793eee34f97e10d27d00bec441941`. This is a source-recovery event,
not a release claim: it makes the exact commits remotely recoverable, but does
not supersede the fresh-clone, source-gate, deterministic-package, catalog,
tenant, or fresh-install requirements documented here.

In particular, later references in this log to an unadvertised local candidate
describe the historical pre-transition state. The recovery queue is the
current ledger for the published `dev-publish` refs and the remaining
clean-clone validation work.

CrateLink's current non-archival v15 origin tip
`95d27ba095eae4589f290b2e3857d6ad92174ddb` was then published as
`dev-publish`, recursively clean-cloned, and passed `make vet test`. Its
missing older local-only candidate remains evidence only; the source-pinned
catalog entry selects the verified current remote tip instead.

MiniGit's sole timestamp-newer remote head,
`0e9adc2abc87d229a04f5166beec633ecc3df644` on `publish`, was independently
rejected as source input: it is a divergent release-artifact archive that
removes the buildable application tree. The exact `dev-publish` tip
`610c44614a8b499d1e80795a97daca66a9912f77` is therefore the newest valid
source; a fresh recursive clone passed `make vet test` on 2026-08-19.

GoldKey's current `dev-publish` tip
`4cdde8588370bfb9ae7b4a7d736d623b8ab0536b` is a direct forward descendant of
the prior production source. A fresh recursive clone hydrated both declared
submodules and passed the pinned-toolchain `make ci`. The production v0.3.4
and separate DEV v0.1.3/version-4 identities retain their distinct metadata,
runtime contracts, and package targets while sharing this one verified source.

## Shell–DueProcess autonomous-create versioning

On 2026-08-19, the shell ordinal gate exposed that a prior respondent-share
change had altered `AutonomousGrainCreator.createGrain @0` after the committed
baseline. The repair preserves the original no-share method at `@0` and
appends `createGrainWithShare @1`; an older shell therefore rejects a requested
share rather than creating an unshared grain silently.

- Shell candidate `5663e3838486292d9c4f6984714a459545083518` restores the
  frozen `@0` signature, implements the share-aware `@1` method, and adds a
  source ratchet for both shapes. Its Cap'n Proto compile, respondent-share
  ratchet, six shell invariant ratchets, and ordinal gate passed; the ordinal
  gate reports the new `@1` method as additive and safe.
- DueProcess source `aff5cc7ce2b793eee34f97e10d27d00bec441941` calls `@0`
  with its original one-pointer request when no share is wanted, and calls
  `@1` only for a non-negative respondent role. Its focused wire tests prove
  ordinary creation works against an `@0`-only fake shell and a share request
  fails closed against that same fake. It is now published on `dev-publish`;
  a fresh recursive clone repeated the Station test, whole-tree vet, and
  drift check before the catalog pin advanced.
- Initial bare-repository probes rejected both candidates as local-only.
  DueProcess has since completed its remote-source and clean-clone proof;
  the shell candidate still requires its own independent publication and
  integration proof.

The Fineract Setup QA copy of DueProcess was byte-identical to the previously
pinned source for these files. It must consume this published ref (or a
validated successor) before the cross-component clean-cohort proof. The shell
still needs a published, independently verified counterpart before package,
runtime-contract, and fresh-install integration testing can clear the shared
blocker. The complete default Bazaar remains held.

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

## Sheets Bureau — source repairs and Python lock still awaiting publication

The source at catalog commit
`965766d662771323f770eb9e956f1e8b03bea7a0` was independently shallow-cloned
from the advertised `main` tip with a clean Git status. Its metadata and
runtime-contract app ID match the catalog; metadata is `2.1.4`
(versionNumber 26), matching the catalog's live version. The production npm
audit reports zero runtime vulnerabilities (`npm audit --omit=dev`), and the
repaired source passed 202 Python unit tests, 35 Python integration tests, a
locked frontend build, and the Grainlinkd Go vet, ordinary-test, and race
suites.

The catalog-base source was not source-gate ready. Grainlinkd's PowerBox JSON
request and response fields were unexported, so JSON could neither receive nor
return a capability sturdyref; its frontend test target also suppressed a
missing test command. Three local, clean commits repair those issues and make
test-manager shutdown explicit:

- `4093318e27210a69b60c0a477eab0ba5980b566f` exports the PowerBox wire fields
  while preserving their `sturdyref` JSON name and adds round-trip coverage.
- `27fe9a6668bf0005a1714e46aa6428bb1bf34c26` replaces unlocked npm install and
  suppressed frontend testing with a fail-closed `npm ci` plus production
  build, with a release-recipe regression guard.
- `0c9401219c7713af5e6e382d4bc39737192af58e` tears down test WebSocket
  managers through their existing cancellation path, removing orphan-task
  warnings from the passing suite.

This repair chain is not advertised by the canonical origin; no catalog pin or
package claim was changed. It also cannot yet become a reproducible release
candidate: the greenfield Sheets build installs eight Python requirements by
version only, with zero hashes, no lockfile, and no `pip --require-hashes`
control. The source owner must publish the reviewed repairs (or a successor),
add a complete hash-locked Python dependency set enforced by the greenfield
build, determine the appropriate forward release version if package bytes
differ, and then repeat the clean-clone proof before Sheets Bureau can join a
release cohort.

## Doc Bureau — source repair awaiting publication and Python-input hold

The source at catalog commit
`ea232d48cc837bdc65b1886ab41ca5109e6c8a69` was independently shallow-cloned
from the advertised `main` tip with its declared submodule initialized and a
clean Git status. Its metadata and runtime-contract app ID match the catalog
identity; metadata is `2.0.32` (versionNumber 27), matching the catalog's
`live_version`. Production dependency audits report zero runtime
vulnerabilities for the root client, Document backend, and Document client
(`npm audit --omit=dev`).

The repaired clean checkout passed all of the following:

- `make release-inputs test-release-inputs`, including mutations that reject
  floating frontend installs and an unisolated Document build output;
- `make test`: 204 Python unit tests, 23 integration tests, the locked root
  frontend build, and the locked Document client build into a disposable
  output directory;
- `make build-source`, including the built-rich-frontend verification and
  Grainlinkd binary build; and
- `GOWORK=off go vet ./...`, uncached Go tests, and the Go race suite in
  `grain/go/grainlinkd`.

The catalog-base source was not source-gate ready: its Document client helper
used a floating `npm install`, while the top-level test target suppressed a
missing frontend command. Invoking the Document helper also made Vite empty
the tracked frontend directory, deleting separately managed shared assets
until a later full build restored them. Local commit
`e1d0627671ebe4d191d8057eb64172aab9ce4a1d` changes every checked build path
to `npm ci`, makes the test build the Document frontend in an explicit
temporary output directory, verifies that output, and adds fail-closed source
and mutation controls for that routing. The full source gate passed again
after the repair and left no generated tracked-file changes.

This repair is not advertised by the canonical origin: on 2026-08-19 remote
`main` remains the catalog-base commit and no remote head contains
`e1d0627671ebe4d191d8057eb64172aab9ce4a1d`. No catalog pin or package claim
was changed. It is also not yet a deterministic release candidate: under
`grains/document`, the tracked Python requirements file has seven
version-only entries, zero hashes, no Python lockfile, and no checked-in
hash-enforcement control for a greenfield install. The source owner must
publish the reviewed repair (or successor), either prove that this input is
not a release dependency or add a complete enforced hash lock, determine any
needed forward version, and repeat the clean-clone proof before Doc Bureau can
join a release cohort.

## Jinn v9 — current generic-peer source proof

The canonical `dev-publish` tip
`08daf329d602bccc0d539c4ee7710e52b370fe99` was independently cloned with its
declared submodules and remained clean before and after verification. It
declares Jinn metadata `0.0.9` (versionNumber 9), ahead of the current catalog
listing `0.0.6`.

The fresh source passed Jinn's focused integration checks for generic peer
discovery/dispatch and the matching GrainContext binding, plus `make build`.
Those checks establish source-level compatibility with a universal,
permission-scoped provider: a user-initiated peer is discoverable and
claimable, declared read-only tools dispatch, Paint native `canvas.*` reads
are admitted, and mutation tools such as `canvas.save` are excluded. A clean
status and `git diff --check` completed after the proof.

This source pin does not claim that a real shell picker, tenant capability
grant, governed package release, or newly installed runtime has passed. Those
remain cohort-level launch gates.

## Bureau Paint v21 — current peer-provider source proof

The canonical `dev-publish` tip
`c5347931c2ae9ab3579c8eb869edec5a0f7b44ea` was independently filtered-cloned
with its declared `spkmodule` gitlink hydrated at the recorded revision. It
declares Paint metadata `2.0.28` (versionNumber 21), matching the current
catalog version while still being the current valid source tip.

The clean source passed `make release-inputs mutation-test test` (including
234 Python tests), `go test -count=1 ./internal/capabilities ./internal/service`
under `grain/go/grainlinkd`, `git diff --check`, and clean recursive status.
The native tests cover GrainContext descriptor recognition, the scoped
read-only provider, and persistent grant restoration needed by Jinn's generic
peer flow.

This source pin does not claim a governed package, public catalog update, or
fresh tenant installation. Those remain held until the full source cohort and
release evidence are complete.
