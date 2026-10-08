# First original Bazaar source preparation

This is the closed initial-onboarding policy for the first original Bazaar
Control identity `zukk3pav049f7wr4a12x76ytpgmsyt3136sz1hev4zy8g33f1310`.
It permits only the existing original `main` at
`161b99160c5f47dcdacb8b68b57bced0d6b88c95`, tree
`7723513927f32814e19954417020f8d3ea35768c`, and the two independently reproduced,
original-key SPK packs whose SHA is
`1228db1458c0f3e2955031b257a2347708687f310fd421e9da40cdcea73a2f34`.

The preparation checks the actual canonical public repository's advertised
heads and the exact local Git object. It reads the selected committed object,
not dirty or untracked workspace changes. It neither creates a branch nor
labels `main` as `dev-publish`. General `mel-release` selection gates remain
unchanged. Other identities, versions, source commits, repositories and package
bytes cannot use this initial policy.

Run `prepare-first-bazaar --source ORIGINAL_BAZAAR_REPOSITORY --spk
PROTECTED_ORIGINAL_FIRST_SPK --out NEW_PRIVATE_DIRECTORY`. The command writes
the minimal original author tree `app/{app.spk,metadata.json}`, its canonical
AppHash, a release-bound declarative runtime contract, and a public preparation
record. The metadata includes the exact initial source admission, so the
original Core ReleaseEntry approval binds the selected source as part of
AppHash. The runtime contract promises only disconnected first-grain startup
and actual durable command-key export. It claims no completed publication
workflow, tenant proof or authenticated Store Link.

This preparation has no signing key access, Store write, proposal creation or
installation. The original author must prepare its exact payload, the original
Store must privately stage and sign the candidate receipt, and original Core
3-of-4 must approve and execute the ReleaseEntry. Only then may the original
Store publish its signed catalog pointer and the owner install through Store.
There is no authenticated historical baseline before that first publication.
After it completes, the exact original main commit becomes the initial
authenticated baseline. The first grain must create its own command identity;
this tool cannot supply one or pre-enroll a PublisherGrant.
