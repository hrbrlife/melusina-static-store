# Bureau Sheets: canonical rich release source

The governed default-Bazaar catalog entry `bureau-rich-office/sheets-bureau` is the only
selection path for the Bureau Sheets identity
`fz7r56h1kr79g4v65cgxf7dv85ymt3ysas2em90739ry3vczt8t0`.

- Canonical source repository: `hrbrlife/CHEESESPREAD`.
- Required rich-source ancestry: `71b015c168a4ee4a06cc2b3b828bc1f01b4c1563`
  on `origin/main` (the retained Jspreadsheet/jsuites office line).
- Pinned governed release source: `e7b6b044b44712c481177a5a0ef63ec93ba82e3f`,
  the direct canonical `dev-publish` forward cut for Bureau Sheets `2.1.6` /
  appVersion `28`. It retains the Jspreadsheet/jsuites frontend and runtime,
  makes the full payload reproducible without checkout paths, bytecode caches,
  or stale wheel console-script RECORD metadata, and verifies the completed
  SPK against the canonical rich editor payload before a candidate exists.
  The package retains its embedded rich screenshot; public catalog screenshot
  URLs remain empty until the governed Store transport can serve their bytes.
- Required app cohort: `2.1.6`, appVersion `28`, and root
  `RUNTIME-CONTRACT.json` with only `PENDING_BUILD` artifact fields.
- Immutable catalog slot: `packages/hrbrlife/melusina-bureau-sheets-app/sheets-bureau`.

The release must retain the rich formula bar, multi-sheet Jspreadsheet/jsuites
surface, XLSX/CSV import/export, snapshots, and two-session WebSocket
collaboration. The source tests content-address the rich assets and reject a
minimal replacement.

## Historical lines

`fix/bureau-shared-restore-republish` and its preservation ref both point to
the older `ad0062ac` ancestor. They remain as signed historical evidence; they
are not release selectors. The sparse Sheets v25 candidate lineage (including
its old candidate artifacts) is explicitly prohibited from this family. No
direct source publish target, branch push, or legacy catalog path may release
this app; only the governed provider using the family slot above may do so.
