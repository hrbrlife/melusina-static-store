# store-estate-standalone-20260922: current D1 estate and updates entry

**Role:** Signed Store releases and rendered install/update. This is the current first-drop/in-flight contract, not an installed-state claim. The coordinator's N-1438–N-1442 plan and live board set the sequence; exact source, signed installed readback and observed screen decide what is live. Earlier detailed prose is preserved on `refs/archive/docs-greenfield-20261012` at `1bba27dd3babbf3ef69b4c0cff491061ad0282aa`.

| Joint | Contract |
|---|---|
| Consumes | Reviewed source/SPK hash, app identity, approval and licensee scope. |
| Emits | Signed listing/generation, app pin, Upgrade Pearls and fresh launch. |
| Visible to user/operator | Store UI app page and update status. |
| Next owner | Shell admits package; each app proves its installed screen; DeployOps operates. |

Build and test on farm 3. Money runs on public Solana devnet; Currencycloud demo, Orca devnet and own wallets are the test provider set. Read sibling `PROGRESS.md` before a shared interface change and record it in the job's `JOINTS.md`. Run a positive and named failing mutation on the built path, then compare the installed artifact, signed actor, result ID, exact amount/source age and UI state. Push only `refs/velocity/<JOB>/store-estate-standalone-20260922` and confirm remote SHA. One independent wave review precedes coordinator landing; DeployOps alone performs live estate, chain, Store and browser actions.

Hard lines from agentchat `CLAUDE.md`: real signatures, authorization and launch control; Store-only app install/update, real UI administration, governed Shell/contract updates, no direct state edit or production-reachable fallback. Owner gates apply to faucets, domains, spend, real funds, production keys and upgrade authority.
