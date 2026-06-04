# MINION BRIEF — ceremony-remaining-5
<!-- Captain fills every <ANGLE> placeholder. The minion is non-interactive
     (claude -p): the brief MUST be complete and self-contained. Any ambiguity
     becomes a wrong guess. Be concrete: exact file paths, function names, env
     var names, FINALE2E scenario numbers. -->

## Identity
You are a DeepSeek-v4-pro minion on the Melusina PSP fleet.
- Working dir: `/home/user/Desktop/static_store`
- Fleet chat: `http://127.0.0.1:8767`  (NEVER message 8766 — that is the live crew)
- Your report goes to: `/home/user/Desktop/agentchat/fleet/work/ceremony-remaining-5/report.md`
- Read first: `/home/user/Desktop/agentchat/MELUSINA_FLEET_PLAN.md` (the goal),
  `/home/user/Desktop/agentchat/CLAUDE.md` (Hard Truths).

## The task (what + why)
Run pearl-app-ceremony.sh SERIALLY for 5 apps that currently have offline RELEASE.json stubs.
This advances the §1 journey by placing real on-chain ReleaseEntry PDAs for: (1) cca-sh-config
(sc11, money-path), (2) welcome-pearl (sc18, money-path), (3) cca-sh-domain-template-v2 (sc16,
money-path), (4) creeper (sc34 sidecar), and (5) namedcoin-pearl (backlog #4). Run money-path
apps first. COPY_TO_CATALOG=1 is the default so RELEASE.json is updated in-place.
Do NOT commit — leave all RELEASE.json changes uncommitted for the captain to audit.

## Scope — files in play
Script: `scripts/pearl-app-ceremony.sh` (read it to understand the flow)
Catalog dirs (read + write RELEASE.json only):
- `packages/hrbrlife/melusina_ccashconfig_app/cca-sh-config/RELEASE.json`
- `packages/hrbrlife/welcome-pearl/welcome-pearl/RELEASE.json`
- `packages/hrbrlife/ccash_domain_template_v2/cca-sh-domain-template-v2/RELEASE.json`
- `packages/hrbrlife/melusina-app-creeper/creeper/RELEASE.json`
- `packages/hrbrlife/namedcoin-pearl/namedcoin-pearl/RELEASE.json`

## LIFECYCLE — do every step, in order. Do not skip.
1. Read `scripts/pearl-app-ceremony.sh` to understand the env vars and flow.
2. Run App 1 (cca-sh-config): execute ceremony, verify PASS, check RELEASE.json updated.
3. Run App 2 (welcome-pearl): execute ceremony, verify PASS, check RELEASE.json updated.
4. Run App 3 (cca-sh-domain-template-v2): execute ceremony, verify PASS, check RELEASE.json updated.
5. Run App 4 (creeper): execute ceremony, verify PASS, check RELEASE.json updated.
6. Run App 5 (namedcoin-pearl): execute ceremony, verify PASS, check RELEASE.json updated.
7. Write report, announce DONE, /leave.

## Apps (in priority order — money-path first)

| # | APP_SLUG | APP_CATALOG_PATH | versionNumber | packageId |
|---|----------|-----------------|---------------|-----------|
| 1 | cca-sh-config | packages/hrbrlife/melusina_ccashconfig_app/cca-sh-config | 22 | 97f79a1356b169dbe7a41eb79c9fe095 |
| 2 | welcome-pearl | packages/hrbrlife/welcome-pearl/welcome-pearl | 7 | 40f5a4873fc10723cb8375ca25251dd8 |
| 3 | cca-sh-domain-template-v2 | packages/hrbrlife/ccash_domain_template_v2/cca-sh-domain-template-v2 | 29 | d6778e50e4b7bbd68df45bed6a6b44fb |
| 4 | creeper | packages/hrbrlife/melusina-app-creeper/creeper | 5 | 400c686e69447c9c1e2830d1a68a4f49 |
| 5 | namedcoin-pearl | packages/hrbrlife/namedcoin-pearl/namedcoin-pearl | 1 | 24f5913f50261338a995559b59fb4349 |

## How to run (from /home/user/Desktop/static_store root)

```bash
cd /home/user/Desktop/static_store

# App 1: cca-sh-config (money-path sc11)
APP_SLUG=cca-sh-config \
APP_CATALOG_PATH=packages/hrbrlife/melusina_ccashconfig_app/cca-sh-config \
COPY_TO_CATALOG=1 \
bash scripts/pearl-app-ceremony.sh

# App 2: welcome-pearl (money-path sc18)
APP_SLUG=welcome-pearl \
APP_CATALOG_PATH=packages/hrbrlife/welcome-pearl/welcome-pearl \
COPY_TO_CATALOG=1 \
bash scripts/pearl-app-ceremony.sh

# App 3: cca-sh-domain-template-v2 (money-path sc16)
APP_SLUG=cca-sh-domain-template-v2 \
APP_CATALOG_PATH=packages/hrbrlife/ccash_domain_template_v2/cca-sh-domain-template-v2 \
COPY_TO_CATALOG=1 \
bash scripts/pearl-app-ceremony.sh

# App 4: creeper (sc34)
APP_SLUG=creeper \
APP_CATALOG_PATH=packages/hrbrlife/melusina-app-creeper/creeper \
COPY_TO_CATALOG=1 \
bash scripts/pearl-app-ceremony.sh

# App 5: namedcoin-pearl (backlog #4)
APP_SLUG=namedcoin-pearl \
APP_CATALOG_PATH=packages/hrbrlife/namedcoin-pearl/namedcoin-pearl \
COPY_TO_CATALOG=1 \
bash scripts/pearl-app-ceremony.sh
```

## Keypairs (defaults — no override needed)
- Author: `/home/user/.config/solana/id.json`
- Publisher: `/home/user/Desktop/Melusina/test-wallets/core-app-team/publisher.json`
- Reviewer1: `/home/user/Desktop/Melusina/test-wallets/core-app-team/reviewer-1.json`
- Reviewer2: `/home/user/Desktop/Melusina/test-wallets/core-app-team/reviewer-2.json`
- Squads config: `/home/user/Desktop/melusina-attestdeployer-tool/config/core-app-team-Squads.json`

## Definition of Done (per app)
- [ ] Script exits 0
- [ ] `verify-release` PASS line printed
- [ ] RELEASE.json in catalog path has real releaseEntryPda (NOT starting with "offline-")
- [ ] RELEASE.json appHash matches SPK hash (verify-release confirms this)
- [ ] result.json shows `approvedStatus: "Executed"` and a `vaultTransactionExecute` sig
- [ ] NOT committed (leave for captain)

## report.md (write this on completion)
```
# ceremony-remaining-5 report
## Per-app results
| App | Version | appHash (first 16 chars) | releaseEntryPda | transactionIndex | execute sig | verify |
|-----|---------|--------------------------|-----------------|-----------------|-------------|--------|
| cca-sh-config | ... | ... | ... | ... | ... | PASS/FAIL |
| welcome-pearl | ... | ... | ... | ... | ... | PASS/FAIL |
| cca-sh-domain-template-v2 | ... | ... | ... | ... | ... | PASS/FAIL |
| creeper | ... | ... | ... | ... | ... | PASS/FAIL |
| namedcoin-pearl | ... | ... | ... | ... | ... | PASS/FAIL |

## DoD checklist (per app): [X] / [ ]
## Next expected transactionIndex: ...
## Failures: none / <exact error if any>
```

## Announce DONE (fleet chat)
```bash
PID=$(curl -sS -X POST http://127.0.0.1:8767/join -H 'Content-Type: application/json' \
  -d '{"type":"ai","name":"ceremony-remaining-5","directory":"/home/user/Desktop/static_store","modeltype":"deepseek-v4-pro","lanes":["ops"]}' \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['participant_id'])")
python3 - "$PID" <<'PY'
import json,sys,urllib.request
pid=sys.argv[1]
b=json.dumps({"participant_id":pid,"to":["e967b8f7999c4fc0a34326d4e8939076"],"lanes":["ops","storekeeper"],
  "idem_key":"ceremony-remaining-5-done","text":"ceremony-remaining-5 DONE. report: fleet/work/ceremony-remaining-5/report.md"}).encode()
urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8767/msg",b,{"Content-Type":"application/json"}),timeout=8)
PY
curl -sS -X POST http://127.0.0.1:8767/leave -H 'Content-Type: application/json' -d "{\"participant_id\":\"$PID\"}"
```

## Hard rules (non-negotiable)
- SERIAL — never run two ceremonies at the same time (Squads transactionIndex conflict)
- If a ceremony fails: stop, document in report.md, do NOT run remaining apps
- Do NOT commit — leave RELEASE.json changes for captain
- No Agent-tool sub-agents (you are already a spawned agent)
- No kill/pkill of any process
- `idem_key` on every `/msg`. Never message port 8766
