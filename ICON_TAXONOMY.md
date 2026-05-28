# Melusina App Icon Color Taxonomy

Every Melusina app icon uses one of eight category tiles. The **background hex** is the full-tile fill; the **accent hex** is used for strokes, glyph highlights, and the single-color thumbnail rendering. The category is the rule of record — new apps must pick one before shipping.

## Categories

| # | Category | Background | Accent | Intent |
|---|---|---|---|---|
| 1 | 💚 Finance / Calculation | `#BDEBCD` | `#35A56A` | money, ledgers, calculation |
| 2 | 🟡 Crypto / Chain | `#F5D47A` | `#B88616` | on-chain, payments-rail, custody |
| 3 | 🔵 Identity / Compliance | `#A6C8F5` | `#355FA5` | KYC, legal entities, sanctions, trust |
| 4 | 🟣 AI / Assistants | `#D4A6F5` | `#6E35A5` | cognition, model routing, agents |
| 5 | 💗 Communications / Bots | `#F5A6C8` | `#A5355F` | messaging, mail, chat, workflows |
| 6 | ⚪ Office / Docs | `#C8D0D8` | `#556170` | documents, diagrams, paint, paper |
| 7 | 🟠 Infrastructure / Admin-ops | `#F5C8A6` | `#A56135` | sidecars, desktops, deployment |
| 8 | 🔷 Developer Tools | `#A6E6F5` | `#167B99` | dev utilities, code, test harnesses |

## App → Category Assignments

| App | Category | Bg | Accent |
|---|---|---|---|
| AiLagoon | AI | `#D4A6F5` | `#6E35A5` |
| BLOOM Identity | Identity | `#A6C8F5` | `#355FA5` |
| BotMother | Communications | `#F5A6C8` | `#A5355F` |
| Bureau (generic) | Office | `#C8D0D8` | `#556170` |
| CashSurge | Finance | `#BDEBCD` | `#35A56A` |
| ccash | Finance | `#BDEBCD` | `#35A56A` |
| ClientSpace | Identity | `#A6C8F5` | `#355FA5` |
| Consilium | Office | `#C8D0D8` | `#556170` |
| CrateLink | Infrastructure | `#F5C8A6` | `#A56135` |
| cyberteller | Crypto | `#F5D47A` | `#B88616` |
| Diagram Bureau | Office | `#C8D0D8` | `#556170` |
| Doc Bureau | Office | `#C8D0D8` | `#556170` |
| DueProcess | Identity | `#A6C8F5` | `#355FA5` |
| Fineract Setup | Finance | `#BDEBCD` | `#35A56A` |
| InstaCo.app | Identity | `#A6C8F5` | `#355FA5` |
| Melusina OpenClaw | AI | `#D4A6F5` | `#6E35A5` |
| MerMail | Communications | `#F5A6C8` | `#A5355F` |
| MerMail Station | Communications | `#F5A6C8` | `#A5355F` |
| MiniGit | Developer | `#A6E6F5` | `#167B99` |
| NamedCoin | Crypto | `#F5D47A` | `#B88616` |
| Paint Bureau | Office | `#C8D0D8` | `#556170` |
| Shell Tester | Developer | `#A6E6F5` | `#167B99` |
| Sheets Bureau | Finance | `#BDEBCD` | `#35A56A` |
| TeleScreen | Identity | `#A6C8F5` | `#355FA5` |
| Telescreen Configuration | Infrastructure | `#F5C8A6` | `#A56135` |
| Teleport | Communications | `#F5A6C8` | `#A5355F` |
| Vintage | Infrastructure | `#F5C8A6` | `#A56135` |

## How to apply

Icons live in two places:
- `icons_split/<AppName>.svg` — single 404×404 tile, single `<rect fill="...">` background
- `app_icons/<AppName>/{appGrid,grain,market,marketBig}.svg` — per-Sandstorm-slot variants

The background `<rect fill="…">` is the taxonomy bg hex. When recoloring, only that one rect changes; foreground glyph art is untouched.

To recolor any icon in the split set, run `./recolor_icons.py` at the repo root. It reads this file as the rule of record.

## Adding a new app

1. Pick a category (pick one, not two — `AiLagoon` straddles AI/Dev but is AI for taxonomy purposes).
2. Add a row to the app assignments table above.
3. Drop a monochrome SVG glyph into `icons_split/<Name>.svg`. Use a plain `<rect x="0" y="0" width="512" height="512" fill="<<BG>>" />` backdrop, accent-hex strokes.
4. Run `./recolor_icons.py --generate-variants` to mint the `app_icons/<Name>/` set.
5. Drop the result into the app's source repo's `icons/` + publish branch icon.svg.

## Rationale

The original icon set shared one background (`#A6E6F5` cyan) across every app, which flattened the catalog at thumbnail size. Categorizing by dominant use-case and reserving one hue per category lets users scan the grid visually even before reading titles. Pastel harmony across categories keeps the set feeling like one family.
