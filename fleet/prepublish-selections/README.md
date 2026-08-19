# Per-app source-selection receipts

Each release-ready default-Bazaar app has one JSON receipt named
`<appId>.json` in this directory. The provider accepts two explicit paths:

- `direct-dev`: `dev-publish` is the selected source and its declared reviewed
  baseline (normally `main`, but explicitly recorded for established
  repositories during branch migration) is either the same commit, its stable
  reviewed ancestor, or an explicitly recorded historical baseline after a ref
  rewrite. Use this normal fast path when there is no relevant divergent work; do not create a no-op
  `feat1-prepublish` branch merely to make the two refs equal. A rewritten
  baseline requires `"mainBaselineRelation": "historical-divergent"` in the
  receipt; the provider independently checks the relationship at packaging.
- `feat1-prepublish`: relevant divergent work was integrated and tested first;
  `feat1-prepublish` and `dev-publish` then point to the same selected commit.

```json
{
  "schema": "melusina-source-selection-v1",
  "appId": "immutable-app-id",
  "sourceRepository": "https://github.com/hrbrlife/repository",
  "sourceCommit": "40-lowercase-hex-commit",
  "selectionMethod": "direct-dev",
  "baselineBranch": "main",
  "baselineRelation": "ancestor",
  "internalControls": {
    "status": "passed",
    "checks": ["clean clone", "relevant tests", "package consistency"]
  },
  "reviewedRefs": [
    {"ref": "refs/heads/dev-publish", "commit": "40-lowercase-hex-commit", "outcome": "selected"},
    {"ref": "refs/heads/main", "commit": "40-lowercase-hex-commit", "outcome": "baseline"}
  ]
}
```

`reviewedRefs` must include every current remote head and label it `selected`,
`baseline`, `retained`, `archive`, `hold`, or `not-app-relevant`. The provider
compares that snapshot with the remote immediately before packaging.
