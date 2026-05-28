# 0.0.4-icon-hires (2026-05-06)

- HiDPI pearl + appGrid icons. Switched pkgdef icons block from
  embedded SVG (~430 bytes) to 128/256-px PNG embeds so the Melusina
  shell apps grid stops rasterising the SVG at the wrong size.

# 0.0.1

- **Imperative #22 — TeleScreen Hub**: greenfield reset to a new app
  with new appId minted via `spk keygen`. The two-pearl TeleScreen
  v0.1.1 (sidecar + core) collapses into a single Hub pearl that
  supervises the Python sidecar internally on localhost:8001 and
  serves the Go pearl on the Sandstorm port. Foreign Sandstorm apps
  can claim a `ScreeningService` capability via Grapple to consume
  Hub screening as a service.
- Outbound `ScreeningService` capnp interface
  (`@0xc0d0e0f000111213`): typed `screenPerson` / `screenEntity` /
  `screenSearch` / `getResult` / `listHistory`. Per-claim isolation
  enforced — a consumer cannot read another consumer's screening
  results.
- AiLagoon-only LLM: direct OpenAI / Anthropic / Ollama / OpenRouter
  SDK imports are CI-banned. `AILAGOON_BASE_URL` is required at
  runtime; calls without it fail loud.
- pkgdef collapse: `sidecarCommand` + `coreCommand` actions retired.
  Single `hubCommand` action declared. CI tripwire enforces the
  post-collapse shape.

Old appId `w1wq63jy7jtuwhxmf0y36w8egmpyej0vn8x8zqtrrfurtne23xq0`
(TeleScreen v0.1.1) retires in `static_store/src/apps.json` when
this SPK publishes. The Telescreen Sidecar Configurator (App 1) is
shipped as a separate SPK from
`/home/user/Desktop/Melusina/sidecar/telescreen-companion-app/`.

# 0.1.1

- Add `tier=regular` + `domains=["*"]` to `metadata.json` so the
  Melusina per-audience catalog matrix (Seven idx-1048 /
  dist-publish/{domain}/{audience}/apps/index.json) includes
  TeleScreen in `shared/regular/apps/index.json`.
- Native-capnp Go core pearl landed (not yet the production
  wire — pkgdef `coreCommand` still execs Python). Binary is
  staged alongside at `/opt/telescreen/grain` for pre-flip
  smoke. Full architecture: `pearl/README.md`. Flip commit
  mapped in `docs/H-flip.md`.

# 0.1.0

- Package TeleScreen as a Sandstorm SPK using `sandstorm-http-bridge`.
- Run the sidecar on port 8001 inside Sandstorm.
- Stage the Python virtualenv and source tree for `spk dev` and `spk pack`.
- Remove Docker/systemd from the primary development loop.
- Declare the three-pearl composition explicitly: `telescreen.spk` ships
  Sidecar + Core actions; the Setup pearl ships separately as
  `telescreen-companion.spk` (built from the Melusina scaffold),
  mirroring the way `Fineract-sidecar` ships `Fineract-setup.spk`.
- Retire the legacy Bootstrap SPA at `src/telescreen/web/`; the sidecar
  is REST/JSON only (no HTML surface) and the core pearl owns all UI.
