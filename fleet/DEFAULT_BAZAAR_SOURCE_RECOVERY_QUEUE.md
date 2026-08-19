# Default Bazaar source recovery queue

This is the current, evidence-backed recovery queue for the complete default
Bazaar catalog at `https://bazaar.melusina-os.org`. It is not a release
approval and must not be used to promote a local checkout.

## Snapshot

- Catalog snapshot: 33 declared live app identities.
- Source-pinned: 18.
- Unreconciled: 15.
  - 14 are marked `source-clean-clone-pending`.
  - 1 is marked `source-policy-unreconciled`.

## 2026-08-19 remote `dev-publish` transition

The recovery result below records the state before this controlled source
transition. The following reviewed candidate commits have now been published
to their canonical origin's `dev-publish` branch. This makes the source
objects remotely recoverable; it does **not** by itself change a catalog pin,
approve a package, or authorize a Bazaar release. Each still requires a fresh
clean-clone provenance check, its declared source gates, deterministic package
proof, and the complete-cohort gate before it can leave its current hold.

| App | `dev-publish` commit |
| --- | --- |
| Welcome | `7a50e8b123fd7d107b4df1ba9c9db567a7862753` |
| Popaye | `75e48c66a691cb2379d32d0599f2cc895b63a7b6` |
| Cyberteller Config | `15e64ee261cd2b2ede14e5ce109611bfbf3d277e` |
| AI Lagoon | `dc4b842a7953eb3721d4a99edf0faa29d7c36853` |
| TeleScreen | `fe6707e0a95409a28b2af5c148d38fc434151847` |
| InstaDAO | `a5a434ae3d36b32d415435df060f7349525dd087` |
| Jinn | `08daf329d602bccc0d539c4ee7710e52b370fe99` |
| Bureau Paint | `c5347931c2ae9ab3579c8eb869edec5a0f7b44ea` |
| Bureau Calendar | `0e1be5ff0782f8a3999d5b5dc6f0cbbf5c600cbc` |
| Bureau Contacts | `039d7ea6f977a3fc02e6d96545de0c3d5850db88` |
| CanBoard | `2164058d5ad3cd275ec24d9498786a257e1efb2a` |
| clientspace | `cdd1ac07f9c2e93b5b1c06805619e903f990bb35` |
| Creeper | `d9a282fb50711038f7f456e8d107064f888742ae` |
| GoldKey DEV | `4cdde8588370bfb9ae7b4a7d736d623b8ab0536b` |
| Melusina Dashboard | `f2ff99faed09a9596cfebfa50670671ab6ff1e42` |
| OpenSanctions | `3fb91a0cd37fe40a3d1341c8a0d9ac5851004ee6` |
| Shell Tester | `9852aee2278e59e1411737bbb008c51d809d980a` |
| Vintage | `bf88344c05ae70d2b791858f1a0a3e506d4e3740` |

DueProcess also advanced its `dev-publish` branch from the catalog base to
`aff5cc7ce2b793eee34f97e10d27d00bec441941`, the tested forward fix for the
versioned autonomous-create RPC. A fresh filtered recursive clone hydrated
every declared gitlink at its exact revision and passed Station tests,
whole-tree vet, and `make check-drift`; it is now a source-pinned catalog
input. The separate shell integration and the complete cohort remain held.

CrateLink now has `dev-publish` at
`95d27ba095eae4589f290b2e3857d6ad92174ddb`, the current non-archival v15
origin tip. A fresh recursive clone of that exact ref passed `make vet test`
on 2026-08-19, so it is a source-pinned input. Its older recorded
`09ffb91596ace2bfc164117401632584f270f702` candidate remains absent from the
origin and from every available source object; it is not source authority and
must not be reconstructed or backfilled from an older Store release.

On 2026-08-19, every canonical origin below was readable with the release
workstation's non-interactive Git configuration. For every named candidate in
the current table, a fresh temporary bare repository ran:

```sh
GIT_TERMINAL_PROMPT=0 git fetch --dry-run --no-tags <canonical-origin> <candidate-commit>
```

Those pre-transition probes explain the original holds; they are not current
source availability results. Each listed candidate was subsequently published
directly and non-destructively to its canonical `dev-publish` branch. The
current question is therefore whether an independent clean clone of the exact
current tip passes its source gates, not whether a historical object can be
fetched. A release pin is created only after that proof; a remotely readable
candidate remains held as `source-clean-clone-pending` until then.

### Focused recovery re-probe

The launch-critical TeleScreen v19 candidate remains
`source-clean-clone-pending`. Jinn v9 and Bureau Paint v21 now have the
independent fresh-source evidence recorded below; their package, governed
release, and installed-runtime gates remain held.

### Source-level Jinn–Paint compatibility

The current Jinn v9 and Bureau Paint v21 `dev-publish` tips are compatible at
the source-contract level. Both carry the same GrainContext schema file ID and
universal interface ID. A fresh filtered Jinn clone passed its focused generic
peer discovery/dispatch and GrainContext tests plus a production build. A
fresh filtered Paint clone passed release-input and mutation controls, 234
Python tests, and its native capabilities/service tests. The tests establish
that a generic peer can be discovered and claimed through the browser-driven
PowerBox route; declared read-only tools dispatch; Paint's native `canvas.*`
reads are admitted; and `canvas.save` is excluded. Paint's tests also prove
descriptor recognition, its native scoped provider, and persistent grant
restoration. Jinn's bootstrap captures the Sandstorm API and supplies it to
the resolver used by this user-initiated claim path.

This is deliberately only source-level evidence. It does not prove a real
shell picker interaction, a tenant capability grant, a governed release, or a
fresh installed runtime. Those checks remain required after the complete
source cohort and reproducible package proof are complete.

## Required recovery action

For each `source-clean-clone-pending` entry, an independent verifier must
clone the declared canonical `dev-publish` tip, verify the candidate commit,
clean recursive worktree, metadata, runtime contract, source gates, package
output, and release hashes before the catalog may change its state to
`source-pinned`. If the source has moved forward, the verifier selects the
newest valid forward tip instead of backfilling an older release.

| App | Current reconciliation state | Candidate commit | Recovery result | Safe next action |
| --- | --- | --- | --- | --- |
| Welcome | `source-clean-clone-pending` | `7a50e8b123fd7d107b4df1ba9c9db567a7862753` | Current `dev-publish` tip; clean proof has not run | Run fresh-clone source gates against this exact tip. |
| Popaye | `source-clean-clone-pending` | `75e48c66a691cb2379d32d0599f2cc895b63a7b6` | Current `dev-publish` tip; clean proof has not run | Run fresh-clone source gates against this exact tip. |
| Cyberteller Config | `source-clean-clone-pending` | `15e64ee261cd2b2ede14e5ce109611bfbf3d277e` | Current `dev-publish` tip; clean proof has not run | Run fresh-clone source gates against this exact tip. |
| AI Lagoon | `source-policy-unreconciled` | `dc4b842a7953eb3721d4a99edf0faa29d7c36853` | Current `dev-publish` candidate; source policy unresolved | Resolve policy, then run fresh-clone source gates. |
| TeleScreen | `source-clean-clone-pending` | `fe6707e0a95409a28b2af5c148d38fc434151847` | Current `dev-publish` tip; clean proof has not run | Run fresh-clone source gates against this exact tip. |
| InstaDAO | `source-clean-clone-pending` | `a5a434ae3d36b32d415435df060f7349525dd087` | Current `dev-publish` tip; clean proof has not run | Run fresh-clone source gates against this exact tip. |
| Jinn | `source-pinned` | `08daf329d602bccc0d539c4ee7710e52b370fe99` | Fresh filtered clone passed focused generic-peer/GrainContext tests and production build. | Continue package, governed-release, and installed-runtime proof. |
| CrateLink | `source-pinned` | `95d27ba095eae4589f290b2e3857d6ad92174ddb` | Fresh recursive clone at the exact `dev-publish` tip passed `make vet test` on 2026-08-19. | Preserve the absent historical candidate as non-authoritative evidence; continue through the held complete-cohort/package proof. |
| Bureau Paint | `source-pinned` | `c5347931c2ae9ab3579c8eb869edec5a0f7b44ea` | Fresh filtered clone passed release controls, 234 Python tests, native capability/service tests, and clean checks. | Continue package, governed-release, and installed-runtime proof. |
| Bureau Calendar | `source-clean-clone-pending` | `0e1be5ff0782f8a3999d5b5dc6f0cbbf5c600cbc` | Current `dev-publish` tip; clean proof has not run | Run fresh-clone source gates against this exact tip. |
| Bureau Contacts | `source-clean-clone-pending` | `039d7ea6f977a3fc02e6d96545de0c3d5850db88` | Current `dev-publish` tip; clean proof has not run | Run fresh-clone source gates against this exact tip. |
| CanBoard | `source-clean-clone-pending` | `2164058d5ad3cd275ec24d9498786a257e1efb2a` | Current `dev-publish` tip; clean proof has not run | Run fresh-clone source gates against this exact tip. |
| clientspace | `source-clean-clone-pending` | `cdd1ac07f9c2e93b5b1c06805619e903f990bb35` | Current `dev-publish` tip; clean proof has not run | Run fresh-clone source gates against this exact tip. |
| Creeper | `source-clean-clone-pending` | `d9a282fb50711038f7f456e8d107064f888742ae` | Current `dev-publish` tip; clean proof has not run | Run fresh-clone source gates against this exact tip. |
| GoldKey Dev | `source-pinned` | `4cdde8588370bfb9ae7b4a7d736d623b8ab0536b` | Fresh recursive clone at the exact shared `dev-publish` tip passed the pinned-toolchain build, vet, and full test suite on 2026-08-19. | Keep production and DEV package identities separate through deterministic package and release proof. |
| Dashboard | `source-clean-clone-pending` | `f2ff99faed09a9596cfebfa50670671ab6ff1e42` | Current `dev-publish` tip; clean proof has not run | Run fresh-clone source gates against this exact tip. |
| OpenSanctions | `source-clean-clone-pending` | `3fb91a0cd37fe40a3d1341c8a0d9ac5851004ee6` | Current `dev-publish` tip; clean proof has not run | Run fresh-clone source gates against this exact tip. |
| Shell Tester | `source-clean-clone-pending` | `9852aee2278e59e1411737bbb008c51d809d980a` | Current `dev-publish` tip; clean proof has not run | Run fresh-clone source gates against this exact tip. |
| Vintage | `source-clean-clone-pending` | `bf88344c05ae70d2b791858f1a0a3e506d4e3740` | Current `dev-publish` tip; clean proof has not run | Run fresh-clone source gates against this exact tip. |

## Release gate

The `audit-cohort` provider command remains expected to return `incomplete`
until all 33 catalog entries are source-pinned and a clean source root proves
their origins, commits, metadata, and runtime contracts. This queue is the
release blocker record for that gate.
