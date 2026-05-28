Retrofit complete — all 21 apps on the spkmodule pattern.    
                                                                             
  Final state                                                                                                                                            
                                                                                                                                                         
  ┌─────────────────────────────────────┬───────┬────────────────────────────────────────────────────────────────────────────────────────────────────┐   
  │              Category               │ Count │                                                Apps                                                │   
  ├─────────────────────────────────────┼───────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤ 
  │ Shared component                    │     1 │ melusina-spkmodule-component — the doctrine lives here                                             │   
  ├─────────────────────────────────────┼───────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ APP_BUILD_STYLE := noop (Coming     │     8 │ bureau-notes, bureau-cal, bureau-contacts, canboard, consilium, cratelink, ccash-client,           │   
  │ Soon stubs, already thin)           │       │ ccash-org-member                                                                                   │   
  ├─────────────────────────────────────┼───────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤   
  │ APP_BUILD_STYLE := custom (legacy   │    13 │ clientspace, openclaw-melusina, instaco-app, namedcoin-app, 4× bureau (doc/sheets/paint/diagram),  │   
  │ retrofitted)                        │       │ MiniGit, AITX-Procedures, INSTASYS_MAIL, MELUSINA_BOTMOTHER, ccash_go_htmx                         │   
  ├─────────────────────────────────────┼───────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤ 
  │ Direct-tracked in static_store (no  │     2 │ AiLagoon, cyberteller — not applicable                                                             │   
  │ submodule repo)                     │       │                                                                                                    │   
  └─────────────────────────────────────┴───────┴────────────────────────────────────────────────────────────────────────────────────────────────────┘ 
                                                                                                                                                         
  What each retrofit preserved                                                                                                                         
                                                                                                                                                       
  For the 13 legacy apps, the retrofit:                                                                                                                  
  - Kept the custom build: recipe verbatim, renamed to build-source:
  - Kept app-specific helper targets (tidy, test, vet, fmt, capnp, ui, deps, setup, envir, etc.)                                                         
  - Stripped the spkmodule-owned targets (dev, pack, verify, publish, clean, help)                                                                     
  - Migrated version-bump + PGP-regen blocks from the old pack: target into .spkmodule-hooks/pre-pack (MiniGit, INSTASYS_MAIL, MELUSINA_BOTMOTHER, the 4 
  bureau apps got hooks)                                                                                                                                 
  - Backed up the true pre-retrofit Makefile as Makefile.legacy for reference                                                                            
                                                                                                                                                         
  Each app's Makefile is now                                                                                                                             
                                                                                                                                                         
  # -------- Per-app configuration --------                                                                                                              
  APP_SLUG        := <slug>                                                                                                                              
  GPG_KEY         := 0F6D67C10A4B88123DFE8603CE589F15B50846E1                                                                                            
  APP_BUILD_STYLE := custom       # or noop for Coming Soon stubs                                                                                        
                                                                                                                                                         
  # -------- Discipline (shared via submodule) --------                                                                                                  
  include spkmodule/mk/core.mk                                                                                                                           
                                                                                                                                                         
  # ================================================================                                                                                     
  # Preserved legacy build + helpers (build-source + tidy/test/vet/…)                                                                                  
  # ================================================================                                                                                     
  ...                                                                                                                                                  
                                                                                                                                                         
  Parser lessons captured in the script                                                                                                                  
                                                                                                                                                       
  .build-tmp/retrofit_app.py now handles:                                                                                                                
  - Multi-line shell recipes with \ continuations (the thing that broke the first pass)                                                                
  - Quoted multi-line strings embedded in Make recipes (Python heredocs in python3 -c "..." blocks — the ccash bug)                                      
  - Proper Makefile.legacy recovery from git history when a prior partial retrofit clobbered the backup            
  - Idempotent commit (skip-if-no-change) so re-running is safe                                                                                          
                                                                                                                                                         
  Published state                                                                                                                                        
                                                                                                                                                         
  - 13 × main branches pushed                                                                                                                            
  - Each has spkmodule/ submodule pinned at af880c7 (initial component commit)                                                                         
  - Each carries Makefile (thin) + Makefile.legacy (true original) + possibly .spkmodule-hooks/pre-pack                                                  
  - Where develop existed, it was fast-forwarded to main and pushed                                                                                      
  - Sanity tested via make -n help on a sample of 5 reps — all parse clean, single include, expected output                                              
                                                                                                                                                         
  What to run when you want to verify a per-app flow                                                                                                     
                                                                                                                                                         
  git clone --recurse-submodules -j4 git@github.com:hrbrlife/<app>.git                                                                                   
  cd <app>                                                                                                                                               
  make help    # lists targets served by spkmodule                                                                                                     
  make build   # invokes the preserved build-source recipe                                                                                               
                                                                                                                                                         
  The canonical end-to-end (build → dev → test → pack → publish) now uses the same mount/verify/sign discipline regardless of which app you're in.       
  Upgrade flow for the entire fleet when the component evolves: cd <app>/spkmodule && git pull origin main && cd .. && git commit spkmodule && git push —
   one line per repo.                                                                                                                                    
                                                                                                                                                       
✻ Baked for 49m 19s · 1 shell still running                                                                                                            
                                                                             
※ recap: Goal was to greenfield the Melusina static-store bazaar and standardize every per-app build pipeline. All 21 apps are now live at               
  `hrbrlife.github.io/melusina-static-store/`, and every submodule-backed app uses the shared `melusina-spkmodule-component`. Next: you choose what to   
  tackle — bump submodule pointers in static_store, or move on.                                                                                          
                                                                                                                                                         
❯ what other melusina components as such should we have to standardize operations or how can we expand the current one from a devops perspective?        
                                                                                                                                                         
● A good question — the answer sorts into two axes: deepen the current spkmodule (cheap, no coordination cost) vs spin up new focused components         
  (heavier, but unlocks orthogonal concerns). Here's how I'd stage it.                                                                                 
                                                                                                                                                         
  Meta-principle for when something becomes a component
                                                                                                                                                         
  Three tests before you extract code into melusina-X-component:                                                                                         
                                                                                                                                                       
  1. Repeated-today test. Is the pattern already living in ≥2 app repos, copy-pasted?                                                                    
  2. Enforceable-invariant test. Does extraction let you enforce a policy one place instead of auditing N repos?                                       
  3. Consumer-interface test. Can you name the 3–5 knobs the consumer passes in? If per-app customisation is an endless list, it probably shouldn't be a 
  shared component (you'd just push complexity onto callers).                                                                                            
                                                                                                                                                         
  Spkmodule passes all three (build/dev/pack/publish were copy-pasted, /opt/app mount safety is an enforceable invariant, and APP_SLUG / GPG_KEY /       
  APP_BUILD_STYLE / hooks / PUBLISH_EXTRAS are a tight interface). That's the bar.                                                                     
                                                                                                                                                         
  Deepen the current spkmodule (no new repos)                                                                                                          
                                                                                                                                                       
  Things that naturally belong to "Sandstorm-app build/pack/publish discipline":                                                                         
  
  ┌────────────────────────────────┬─────────────────────────────────────────────────────────────────────────────────────────────────┬──────────────┐    
  │            Addition            │                                          What it adds                                           │  Rough size  │  
  ├────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────┼──────────────┤    
  │ mk/build-rust.mk,              │ More build backends                                                                             │ ~30 lines    │  
  │ build-python.mk                │                                                                                                 │ each         │  
  ├────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────┼──────────────┤    
  │ bin/stage-publish                                │ Dry-run what make publish would push; diff vs origin/publish before the         │ 80 lines   │    
  │                                                  │ force-push                                                                      │ bash       │    
  ├──────────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────┼────────────┤    
  │ bin/diff-publish                                 │ Show what changed between last publish and staged                               │ similar    │  
  ├──────────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────┼────────────┤    
  │ bin/bump-version                                 │ Semver bump + pkgdef appVersion sync (currently 7 apps each roll their own in   │ 60 lines   │  
  │                                                  │ hooks)                                                                          │ bash       │    
  ├──────────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────┼────────────┤  
  │ bin/validate-metadata                            │ JSON-schema check against schema/metadata.schema.json                           │ 30 lines   │    
  │                                                  │                                                                                 │ python     │  
  ├──────────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────┼────────────┤    
  │ schema/metadata.schema.json                      │ Single source of truth for the bazaar entry shape                               │            │  
  ├──────────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────┼────────────┤    
  │ schema/pkgdef-sanity.sh                          │ pkgdef lint (required fields, no actions = [], etc.)                            │ 50 lines   │  
  ├──────────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────┼────────────┤    
  │ ci/workflow.yml                                  │ Drop-in GitHub Actions: workflow_call with lint → test → pack → verify,         │ 80 lines   │  
  │                                                  │ pluggable into any app's .github/workflows/app.yml in 3 lines                   │ YAML       │  
  ├──────────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────┼────────────┤
  │ templates/README.md, templates/metadata.json,    │ Scaffolder when spinning a new app                                              │            │
  │ templates/description.md                         │                                                                                 │            │    
  ├──────────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────┼────────────┤
  │ docs/runbook-release.md                          │ Canonical release runbook (what humans do)                                      │            │    
  ├──────────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────┼────────────┤    
  │ docs/runbook-incident.md                         │ "App is broken on pbay — what do I do"                                          │            │  
  └──────────────────────────────────────────────────┴─────────────────────────────────────────────────────────────────────────────────┴────────────┘    
                                                                                                                                                       
  This is where most of the near-term win is. No new repos, no coordination, apps pick up improvements via a single submodule bump.                      
                                                                                                                                                       
  Spin up as separate components (tier 1 — do now)                                                                                                       
                                                                                                                                                       
  These concerns are not build-discipline; they're their own thing.                                                                                      
                                                                                                                                                       
  melusina-icon-pipeline-component                                                                                                                       
                                                                                                                                                       
  Problem: today each app has an icons/ dir with 25 variant files, plus the taxonomy rules live in a markdown file in static_store, plus                 
  recolor/gen-variant scripts live in .build-tmp/. Every icon update is manual copy-paste across 25 sizes.                                             
                                                                                                                                                         
  Interface:                                                                                                                                           
  ./icons.config.json   # {category: "office", source: "icons/source.png"}                                                                             
  make -f melusina-icons/render.mk render    # regenerates all 25 variants                                                                               
  make -f melusina-icons/render.mk recolor   # applies taxonomy bg/accent                                                                                
                                                                                                                                                         
  What it would own:                                                                                                                                     
  - ICON_TAXONOMY.md (single source of truth; currently in static_store)                                                                                 
  - Raster pipeline: PNG → all 12 sizes + apple-touch + favicon + manifest + html-head                                                                   
  - Vector pipeline: SVG → same                                                                                                                        
  - Category-colored recolor rules                                                                                                                       
  - Diff-against-shipped check ("your icon.svg differs from the shipped hash; republish")                                                              
                                                                                                                                                         
  Cost: ~1 day. Extracts directly from existing scripts.                                                                                                 
                                                                                                                                                         
  melusina-grain-runtime-component                                                                                                                       
                                                                                                                                                         
  Problem: I hand-bundled sandstorm-http-bridge + a custom Go staticserve into 8 SPKs. Every Coming Soon / static-grain reimplements the same runtime.   
                                                                                                                                                       
  Interface:                                                                                                                                             
  APP_BUILD_STYLE := grain-runtime                                                                                                                     
  GRAIN_STATIC_DIR := www                                                                                                                              
  include spkmodule/mk/core.mk                                                                                                                           
  
  What it would own:                                                                                                                                     
  - The 38MB sandstorm-http-bridge binary (vendored + version-pinned)                                                                                  
  - The Go staticserve source + prebuilt binary                                                                                                          
  - A Sandstorm pkgdef fragment (sub-capnp) the app can import instead of writing by hand                                                              
  - files.list fragment covering the bridge + runtime                                                                                                    
  - Upgrade path when sandstorm-http-bridge version bumps                                                                                                
                                                                                                                                                         
  Cost: ~1 day. Mostly packaging what already works.                                                                                                     
                                                                                                                                                         
  melusina-metadata-schema-component                                                                                                                     
                                                                                                                                                         
  Problem: we keep reconciling metadata drift (the SPK truth vs catalog JSON mismatch, version/license fixing) because no schema is enforced at write    
  time.                                                                                                                                                
                                                                                                                                                         
  Interface: one JSON-schema file + a validator binary. The spkmodule's spk-verify-strict delegates to it.                                               
                                                                                                                                                       
  What it would own:                                                                                                                                     
  - metadata.schema.json — canonical                                                                                                                   
  - Examples for each isOpenSource × license combination                                                                                                 
  - A validator (node or python) that caller scripts invoke                                                                                            
                                                                                                                                                         
  Cost: half a day. High value — eliminates a whole class of reconciliation work.                                                                        
                                                                                                                                                         
  Spin up as separate components (tier 2 — do when pain hits)                                                                                            
                                                                                                                                                         
  melusina-grain-sdk                                                                                                                                     
                                                                                                                                                       
  MELUSINA_BOTMOTHER already has a substantial Go framework for building grains (capnp schemas, HTMX wire helpers, pearl lifecycle hooks). It's currently
   bundled in that one app. Extract → every Go-based grain depends on it instead of inlining copies. Sizable undertaking — probably a couple of weeks to
  tease out cleanly.                                                                                                                                     
                                                                                                                                                       
  melusina-auth-component                                                                                                                              

  Every app re-implements "Solana key lifecycle + session + role". ccash, ClientSpace, AITX-Procedures all do this differently today. Extract the shared 
  layer — but only after you've run the pattern in production across 2–3 apps so you know what the shared API actually needs to be.
                                                                                                                                                         
  melusina-ui-shell-component                                                                                                                          
                                                                                                                                                       
  The cyberpunk design tokens (T.cyan, T.magenta, Orbitron/JetBrains Mono/Inter, scan-lines, glow effects) are currently baked into src/main.jsx. Any    
  per-app web UI will want the same tokens. Extract as a React component library OR (simpler) a CSS-in-JS tokens file that apps import. Value grows as
  more apps ship UIs.                                                                                                                                    
                                                                                                                                                       
  melusina-e2e-harness-component                                                                                                                         
  
  I just wrote playwright tests for the static store. Every app under pbay would want similar: "does the install flow from bazaar → pbay → grain actually
   work?" Shared fixtures for: Sandstorm shell login, grain creation, pearl URL resolution. Deferred until you have ≥2 apps with real grains (so the   
  abstractions reflect reality, not aspirations).                                                                                                        
                                                                                                                                                       
  melusina-license-component                                                                                                                             
  
  Already referenced in the catalog (every metadata.json license field points at github.com/hrbrlife/melusina-license-component/blob/main/LICENSE.md). It
   exists as a concept but I haven't inspected the repo. If the reality is "it's the license text + some boilerplate," it's fine as-is; promote to a   
  proper submodule only if apps start needing it at build time (e.g. for LICENSE file generation).                                                       
                                                                                                                                                       
  Tier 3 — polish, rarely urgent                                                                                                                         
  
  - melusina-observability-component — structured logging + metric emission. Not urgent because Sandstorm grains are usually observed via Melusina's own 
  admin panel, not external collectors.                                                                                                                
  - melusina-lint-component — shared .golangci.yml, .eslintrc, editorconfig, pre-commit hooks. Nice to have; low value until inconsistent style starts   
  hurting.                                                                                                                                               
  - melusina-docs-component — README / CONTRIBUTING / SECURITY templates + docsite generator. Nice-to-have.                                            
  - melusina-keyring-component — GPG keys + Sandstorm signing keys + canonical keyring layout. Probably better as a private docs/keyring.md in spkmodule 
  than a repo (secrets don't want submodules pointing at them).                                                                                          
                                                                                                                                                         
  How these relate (dependency graph)                                                                                                                    
                                                                                                                                                       
                      melusina-metadata-schema                                                                                                         
                                ▲                                                                                                                        
                                │
                      melusina-spkmodule ◄─── apps                                                                                                       
                        ▲         ▲                                                                                                                    
                        │         │                                                                                                                      
                        │         └─── melusina-ci (workflow_call)
                        │                                                                                                                                
          melusina-grain-runtime ◄─── Coming Soon apps                                                                                                 
                        ▲                                                                                                                                
                        │                                                                                                                                
                melusina-grain-sdk ◄─── Go-based grains                                                                                                
                                            │                                                                                                            
                                            └── melusina-auth                                                                                          
                                            └── melusina-ui-shell                                                                                        
  
  Keep the arrows shallow. spkmodule shouldn't depend on grain-runtime — you can ship a grain without the runtime if it brings its own. grain-runtime    
  shouldn't depend on grain-sdk — you can ship a minimal static-HTML grain without the Go framework. Each layer should be independently useful.        
                                                                                                                                                         
  My concrete recommendation for the next cut                                                                                                            
                                                                                                                                                       
  Pick one tier-1 component and ship it this week to prove the pattern scales:                                                                           
                                                                                                                                                       
  melusina-icon-pipeline-component is the sweet spot:                                                                                                    
  - Everything needed already exists in .build-tmp/*.py scripts                                                                                        
  - Clear per-app interface (one JSON config + one make target)                                                                                          
  - High ongoing ROI (icon changes happen often; right now they're painful)                                                                            
  - Low coordination cost (icons are leaf artefacts; no grain runtime changes)                                                                           
                                                                                                                                                         
  If you want, I can extract it now — clone the pattern from melusina-spkmodule-component, move gen_pwa_variants.py + recolor_icons.py + ICON_TAXONOMY.md
   into it, and inject into the 8 new-app repos (which currently have icons baked in at SPK-build time, not driven by a component).                      
                                                                                                                                                         
  The second-best extraction is melusina-grain-runtime-component — it would let us deprecate the hand-built Coming Soon grain from rebuild_grains.py and 
  all 8 new apps would consume a versioned runtime instead of each shipping their own 9MB bundle.                                                      
                                                                                                                                                         
  Beyond that, I'd defer. Tier 2+ needs real pain signal before you guess wrong about the shared API shape. 