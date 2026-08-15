# Sheets Bureau: canonical rich release source

The governed release family `bureau-rich-office/sheets-bureau` is the only
selection path for the Sheets Bureau identity
`fz7r56h1kr79g4v65cgxf7dv85ymt3ysas2em90739ry3vczt8t0`.

- Canonical source repository: `hrbrlife/CHEESESPREAD`.
- Required rich-source ancestry: `71b015c168a4ee4a06cc2b3b828bc1f01b4c1563`
  on `origin/main` (the retained Jspreadsheet/jsuites office line).
- Pinned governed release source: `86b9466996e7c7a09f949905795e700c4ab24dab`,
  a direct descendant that removes the obsolete direct-release instruction,
  packages the retained Jspreadsheet/jsuites frontend with the runtime, and
  makes that full payload reproducible without checkout paths or bytecode
  caches. Its package verifier also unpacks the completed SPK and compares the
  rich editor payload against the canonical source before a candidate exists.
- Required app cohort: `2.1.4`, appVersion `26`, and root
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
