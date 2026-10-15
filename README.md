# Melusina Static Store

**Role:** signed Store releases and rendered app install/update. This is a source contract, not an installed-state claim. The current job brief and live readiness board set the milestone; exact signed installed readbacks and the rendered Store UI establish what is live.

Apps install and update only through a reviewed signed Store release and the real Store UI. A source/SPK hash, app identity, approval and licence scope bind the listing. A catalog, generation, pointer or served-byte edit cannot manufacture approval or repair drift. After an update, read back the app pin and grain version, use the app page's rendered **Upgrade Pearls** control, confirm existing pearls match the current app index, then launch a fresh grain at the new version.

| Joint | Contract |
|---|---|
| Consumes | Reviewed source/SPK hash, app identity, approval and licensee scope. |
| Emits | Signed listing/generation, app pin, upgraded pearls and fresh launch. |
| Visible to operator | Store UI app page and update status. |
| Next owner | Shell admits packages; each app proves its installed screen; DeployOps operates. |

Build and test on farm 3 with labelled synthetic fixtures. `make test` is a source check, not an installed-state claim. Prove a positive rendered update and a named rejected stale or unauthorized release on the built path; after install compare the exact artifact, signer, pin, old-pearl upgrade and fresh launch. Push only the assigned `refs/velocity/<JOB>/<repo>` ref for coordinator review. DeployOps alone performs estate, chain, Store and browser actions.

Hard lines from agentchat `CLAUDE.md`: real signatures, authorization and launch control; Store-only app install/update, real UI administration, governed Shell/contract updates, no direct state edit or production-reachable fallback. Owner gates govern funds, production keys, authority and spend.
