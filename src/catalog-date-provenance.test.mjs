// Bazaar dates are release facts, not source metadata. The sidecar must derive
// updatedAt from the signed release, and the rendered public UI must use only
// that field when it says an app was updated or promoted.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SRC = dirname(fileURLToPath(import.meta.url));
const ROOT = join(SRC, "..");

test("the sidecar replaces metadata updatedAt with signedAtUnix", () => {
  const catalog = readFileSync(join(ROOT, "sidecar", "melusina-store-sidecar", "catalog.go"), "utf8");
  assert.ok(catalog.includes('delete(row, "updatedAt")'),
    "catalog must discard metadata updatedAt before projecting the signed release");
  assert.match(catalog, /attest\["signedAtUnix"\][\s\S]*row\["updatedAt"\] = signedAt \* 1000/,
    "catalog must derive updatedAt from RELEASE.json signedAtUnix");
});

test("the public card and detail UI render only signed promotion timestamps", () => {
  const main = readFileSync(join(SRC, "main.jsx"), "utf8");
  assert.ok(main.includes("const signedPromotionAt = (app) => app?.updatedAt ?? null;"),
    "UI must expose an explicit signed-promotion timestamp helper");
  assert.ok(main.includes('"LAST PROMOTED", fmtDate(signedPromotionAt(app))'),
    "details must label the signed date as a promotion, not deployment metadata");
  assert.ok(main.includes("timeAgo(signedPromotionAt(app))"),
    "cards must use signed promotion time for their updated label");
  assert.ok(!main.includes("app.createdAt") && !main.includes("app?.createdAt"),
    "public UI must not render stale createdAt source metadata as an app update date");
});

const BUILT_UI = process.env.BAZAAR_UI_TEST_DIR;

test("the generated governed bundle contains no createdAt fossil", { skip: !BUILT_UI }, () => {
  const assets = join(BUILT_UI, "assets");
  assert.ok(existsSync(assets), `generated UI assets missing: ${assets}`);
  for (const file of readdirSync(assets).filter((name) => name.endsWith(".js"))) {
    const bundle = readFileSync(join(assets, file), "utf8");
    assert.ok(!bundle.includes("createdAt"),
      `governed UI bundle ${file} still renders source-createdAt as a date`);
  }
});
