# Release notes

## 0.3.1 — 2026-05-24

PSP-polish Pass-2 (audit `PSP_UX_AUDIT_2026_05_24.md` §C P0-1/2/3):

- PowerBox picker copy rewritten from grain/capnp developer language
  into PSP/MSB operator language. All three modes (full-catalog access,
  per-domain access, station template) now read as policy decisions a
  compliance officer can reason about, not capability tokens a Sandstorm
  developer must decode.
- PowerBox picker now renders the bound version + first-8 of the
  content digest on every station-profile card and in the
  domain-section header, so an operator can match against an approved
  change-management record before committing.
- `StationSummary` JSON wire shape (`GET /api/domain/<slug>`) gains
  `icon`, `version`, `digest` fields (omitempty — pre-V1.1 consumers
  unaffected). Wire compatibility tests in `api_domain_detail_test.go`
  preserved.
- README documents that DueProcess / popaye / cyberteller / Welcome
  pearl require a launched Template Authority grain in the Sandstorm
  instance before their bind flows can succeed (no DTG ⇒ PowerBox
  returns "No token received from PowerBox" and the user is forced
  into a blank-builder fallback).

## 0.1.0 — 2026-04-23

Initial release. Ported as a standalone package from the AITX Procedures
monorepo, where it lived as the `template` grain type of `bloom-process`.
Ships with embedded ccash, openclaw, and telescreen domain packs and the
admin UI for managing them.
