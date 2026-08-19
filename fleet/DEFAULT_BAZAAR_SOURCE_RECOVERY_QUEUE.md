# Default Bazaar source recovery queue

This is the current, evidence-backed recovery queue for the complete default
Bazaar catalog at `https://bazaar.melusina-os.org`. It is not a release
approval and must not be used to promote a local checkout.

## Snapshot

- Catalog snapshot: 33 declared live app identities.
- Source-pinned: 14.
- Unreconciled: 19.
  - 18 are marked `source-commit-not-remotely-recoverable`.
  - 1 is marked `source-policy-unreconciled`.

On 2026-08-19, every canonical origin below was readable with the release
workstation's non-interactive Git configuration. For every named candidate in
the current table, a fresh temporary bare repository ran:

```sh
GIT_TERMINAL_PROMPT=0 git fetch --dry-run --no-tags <canonical-origin> <candidate-commit>
```

All 19 named candidates failed the probe with the remote rejecting the object
as `not our ref`; none was the target of an advertised head or tag. None
therefore has the clean-source proof required to become a release pin in this
audit. This does not claim that an object never existed; the source owner must
make it recoverable from the canonical origin and the normal
clean-clone/advertised-ancestry check must then pass. An entry without a
current named candidate cannot be made reproducible until its owner identifies
one.

### Focused recovery re-probe

The complete current re-probe includes the launch-critical TeleScreen, Jinn,
and Bureau Paint candidates. TeleScreen's v19 candidate is recorded in the
table below; it remains held with the same source-owner publication
requirement as Jinn and Paint.

### Source-level Jinn–Paint compatibility

The reviewed local Jinn v9 and Bureau Paint v21 candidates are compatible at
the source-contract level. Both carry the same GrainContext schema file ID and
universal interface ID. Jinn's focused tests prove that a generic peer is
visible and claimable through the browser-driven PowerBox route, that its
declared read-only tool can be discovered and dispatched, and that Paint's
native `canvas.*` reads are admitted while `canvas.save` is excluded. Paint's
focused GrainContext tests prove descriptor recognition, its native scoped
provider, and persistent grant restoration. Jinn's bootstrap captures the
Sandstorm API and supplies it to the resolver used by this user-initiated
claim path.

This is deliberately only source-level evidence. It does not prove a real
shell picker interaction, a tenant capability grant, a governed release, or a
fresh installed runtime. Those checks remain blocked by the two unrecoverable
source commits and must follow their owner publication and clean-clone review.

## Required recovery action

For each entry, the canonical source owner must do one of the following:

1. Publish the reviewed candidate on the declared canonical origin, reachable
   from an immutable tag or a maintained branch; or
2. Publish a reviewed successor and explicitly replace the candidate evidence.

After publication, a clean-clone review must verify the exact source commit,
clean recursive worktree, metadata, runtime contract, package output, and
release hashes before the catalog may change its state to `source-pinned`.
No local-only commit is a substitute for that proof.

| App | Current reconciliation state | Candidate commit | Recovery result | Safe next action |
| --- | --- | --- | --- | --- |
| Welcome | `source-commit-not-remotely-recoverable` | `7a50e8b123fd7d107b4df1ba9c9db567a7862753` | Not fetchable | Owner publishes the reviewed Welcome candidate or a validated successor. |
| Popaye | `source-commit-not-remotely-recoverable` | `75e48c66a691cb2379d32d0599f2cc895b63a7b6` | Not fetchable | Owner publishes the reviewed Popaye candidate or a validated successor. |
| Cyberteller Config | `source-commit-not-remotely-recoverable` | `15e64ee261cd2b2ede14e5ce109611bfbf3d277e` | Not fetchable | Owner publishes the reviewed Config candidate or a validated successor. |
| AI Lagoon | `source-policy-unreconciled` | `dc4b842a7953eb3721d4a99edf0faa29d7c36853` | Not fetchable | Owner first resolves the source policy, then publishes the chosen reviewed revision. |
| TeleScreen | `source-commit-not-remotely-recoverable` | `fe6707e0a95409a28b2af5c148d38fc434151847` | Fresh bare-repository recovery probe rejected; no advertised head or tag | Owner publishes the reviewed v19 candidate or a validated successor. |
| InstaDAO | `source-commit-not-remotely-recoverable` | `a5a434ae3d36b32d415435df060f7349525dd087` | Not fetchable | Owner publishes the reviewed InstaDAO candidate or a validated successor. |
| Jinn | `source-commit-not-remotely-recoverable` | `08daf329d602bccc0d539c4ee7710e52b370fe99` | Local clean candidate; not advertised by the canonical origin on 2026-08-19 | Owner publishes this reviewed v9 candidate or a validated successor, then clean-clone/pin verification may resume. |
| CrateLink | `source-commit-not-remotely-recoverable` | `09ffb91596ace2bfc164117401632584f270f702` | Not fetchable | Owner publishes the reviewed CrateLink candidate or a validated successor. |
| Bureau Paint | `source-commit-not-remotely-recoverable` | `c5347931c2ae9ab3579c8eb869edec5a0f7b44ea` | Not fetchable | Owner publishes the reviewed Paint candidate or a validated successor. |
| Bureau Calendar | `source-commit-not-remotely-recoverable` | `0e1be5ff0782f8a3999d5b5dc6f0cbbf5c600cbc` | Not fetchable | Owner publishes the reviewed Calendar candidate or a validated successor. |
| Bureau Contacts | `source-commit-not-remotely-recoverable` | `039d7ea6f977a3fc02e6d96545de0c3d5850db88` | Not fetchable | Owner publishes the reviewed Contacts candidate or a validated successor. |
| CanBoard | `source-commit-not-remotely-recoverable` | `2164058d5ad3cd275ec24d9498786a257e1efb2a` | Not fetchable | Owner publishes the reviewed CanBoard candidate or a validated successor. |
| clientspace | `source-commit-not-remotely-recoverable` | `cdd1ac07f9c2e93b5b1c06805619e903f990bb35` | Not fetchable | Owner publishes the reviewed clientspace candidate or a validated successor. |
| Creeper | `source-commit-not-remotely-recoverable` | `d9a282fb50711038f7f456e8d107064f888742ae` | Not fetchable | Owner publishes the reviewed Creeper candidate or a validated successor. |
| GoldKey Dev | `source-commit-not-remotely-recoverable` | `4cdde8588370bfb9ae7b4a7d736d623b8ab0536b` | Not fetchable | Owner publishes the reviewed GoldKey Dev candidate or a validated successor. |
| Dashboard | `source-commit-not-remotely-recoverable` | `f2ff99faed09a9596cfebfa50670671ab6ff1e42` | Not fetchable | Owner publishes the reviewed Dashboard candidate or a validated successor. |
| OpenSanctions | `source-commit-not-remotely-recoverable` | `3fb91a0cd37fe40a3e1341c8a0d9ac5851004ee6` | Not fetchable | Owner publishes the reviewed OpenSanctions candidate or a validated successor. |
| Shell Tester | `source-commit-not-remotely-recoverable` | `9852aee2278e59e1411737bbb008c51d809d980a` | Not fetchable | Owner publishes the reviewed Shell Tester candidate or a validated successor. |
| Vintage | `source-commit-not-remotely-recoverable` | `bf88344c05ae70d2b791858f1a0a3e506d4e3740` | Not fetchable | Owner publishes the reviewed Vintage candidate or a validated successor. |

## Release gate

The `audit-cohort` provider command remains expected to return `incomplete`
until all 33 catalog entries are source-pinned and a clean source root proves
their origins, commits, metadata, and runtime contracts. This queue is the
release blocker record for that gate.
