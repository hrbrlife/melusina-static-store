// The Bazaar card-icon map is a signed-package projection, never a second
// catalog. These offline gates protect the generated lock before Vite can copy
// any icon into the governed sidecar shell.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SRC = dirname(fileURLToPath(import.meta.url));
const ROOT = join(SRC, "..");
const APP_ID = /^[a-z0-9]{52}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const ICONLESS_IDS = [
  "gcm92hhzx20xgtfakp0kpdywmav49m2p9wnq75rv35fez680j9k0", // InstaDAO
  "msgn23jkp96yrup53t1yv71ens7kpda7yw10p8aepdzg7rhqssdh", // OpenSanctions
  "p0wjp099ry06x0shap6ts270x55tn24pa5pt5029qdyhpqkaztv0", // Bureau Calendar
  "pm1afskzvf2vfasvxhwktk0u0sq7um0942psrdzdhf7w463n92eh", // Creeper
  "trymnqgywrmc3pskv6160e7h2gjscm9kentjkeah6pnvyeqeq0kh", // Bureau Contacts
  "vau6r6xst3mg96npt6zf0wkc1hzycrtzprd2su7z38myaudam3kh", // Jinn
];
const CONFIG_APP_ID = "6gdgveudrer5a61hp8qkmxcn89wyce5uq1mg92ud40ugr2uj7mz0";

const sha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const lock = JSON.parse(readFileSync(join(ROOT, "app-icons.lock.json"), "utf8"));

function assertedSource(source, appId) {
  for (const field of ["appHash", "packageId", "packageSha256", "releaseEntryPda", "releaseHash"]) {
    assert.equal(typeof source[field], "string", `${appId}: signed source.${field} is required`);
  }
  assert.match(source.appHash, SHA256, `${appId}: malformed signed appHash`);
  assert.match(source.packageId, /^[0-9a-f]{32}$/, `${appId}: malformed packageId`);
  assert.match(source.packageSha256, SHA256, `${appId}: malformed package SHA-256`);
  assert.match(source.releaseHash, SHA256, `${appId}: malformed signed releaseHash`);
  assert.ok(source.releaseEntryPda.length > 20, `${appId}: signed releaseEntryPda is required`);
}

test("the icon lock is an exact 30-app signed-package projection", () => {
  assert.equal(lock.schema, "melusina-bazaar-app-icons-v1");
  assert.match(lock.catalogSha256, SHA256, "lock must bind the exact served catalog input");
  assert.ok(Array.isArray(lock.assets));
  assert.ok(Array.isArray(lock.iconless));
  assert.equal(lock.assets.length + lock.iconless.length, 30,
    "catalog growth requires a deliberate signed-icon lock regeneration");

  const ids = new Set();
  for (const asset of lock.assets) {
    assert.deepEqual(Object.keys(asset).sort(), ["appId", "assetSha256", "path", "source"]);
    assert.match(asset.appId, APP_ID);
    assert.ok(!ids.has(asset.appId), `duplicate appId ${asset.appId}`);
    ids.add(asset.appId);
    assert.match(asset.assetSha256, SHA256);
    assert.match(asset.path, new RegExp(`^icons/apps/${asset.appId}\\.(?:png|svg)$`));
    const icon = join(ROOT, "public", asset.path);
    assert.ok(existsSync(icon), `${asset.appId}: committed icon asset is missing`);
    assert.equal(sha256(icon), asset.assetSha256, `${asset.appId}: icon bytes do not match lock`);
    assertedSource(asset.source, asset.appId);
    const expectedSourceFields = [
      "appHash", "format", "packageId", "packageSha256", "quality",
      "releaseEntryPda", "releaseHash", "slot", "variant",
      ...(asset.source.format === "png" ? ["height", "width"] : []),
    ].sort();
    assert.deepEqual(Object.keys(asset.source).sort(), expectedSourceFields,
      `${asset.appId}: lock source must carry only signed provenance and icon selection`);
    assert.ok(["appGrid", "market"].includes(asset.source.slot), `${asset.appId}: unapproved icon slot`);
    assert.ok(["png", "svg"].includes(asset.source.format), `${asset.appId}: unsupported icon format`);
  }

  for (const iconless of lock.iconless) {
    assert.deepEqual(Object.keys(iconless).sort(), ["appId", "source"]);
    assert.match(iconless.appId, APP_ID);
    assert.ok(!ids.has(iconless.appId), `duplicate appId ${iconless.appId}`);
    ids.add(iconless.appId);
    assertedSource(iconless.source, iconless.appId);
    assert.deepEqual(Object.keys(iconless.source).sort(), [
      "appHash", "checkedSlots", "packageId", "packageSha256", "releaseEntryPda", "releaseHash",
    ], `${iconless.appId}: iconless lock source must carry only signed provenance and checked slots`);
    assert.deepEqual(iconless.source.checkedSlots, ["appGrid", "market", "grain"],
      `${iconless.appId}: iconless fallback must be proven across all signed slots`);
  }
  assert.deepEqual([...lock.iconless.map((entry) => entry.appId)].sort(), [...ICONLESS_IDS].sort(),
    "only packages with all signed icon slots absent may use the Bazaar mark");
});

test("Config alone uses the signed 128px market fallback", () => {
  const config = lock.assets.find((entry) => entry.appId === CONFIG_APP_ID);
  assert.ok(config, "ccash Config must have an explicit signed market fallback");
  assert.deepEqual(
    {
      slot: config.source.slot,
      format: config.source.format,
      variant: config.source.variant,
      width: config.source.width,
      height: config.source.height,
      quality: config.source.quality,
    },
    { slot: "market", format: "png", variant: "dpi2x", width: 128, height: 128, quality: "legacy-low-res" },
  );
});

test("the generated map contains only asset paths and explicit iconless IDs", () => {
  const map = readFileSync(join(SRC, "app-icon-map.js"), "utf8");
  const paths = [...map.matchAll(/^  "([a-z0-9]{52})": "\/(icons\/apps\/[^\"]+)"/gm)];
  const pathById = new Map(paths.map((match) => [match[1], match[2]]));
  assert.equal(pathById.size, lock.assets.length, "map coverage differs from signed assets");
  for (const asset of lock.assets) {
    assert.equal(pathById.get(asset.appId), asset.path, `${asset.appId}: map points away from locked asset`);
  }
  const iconlessBlock = map.match(/ICONLESS_APP_IDS = Object\.freeze\(new Set\(\[([\s\S]*?)\]\)\);/);
  assert.ok(iconlessBlock, "generated map omits explicit iconless set");
  const iconless = [...iconlessBlock[1].matchAll(/"([a-z0-9]{52})"/g)].map((match) => match[1]);
  assert.deepEqual(iconless.sort(), ICONLESS_IDS.slice().sort());
  for (const forbidden of ["packageId", "version", "imageId", "packageUrl", "screenshots", "createdAt", "updatedAt"]) {
    assert.ok(!map.includes(forbidden), `presentation map must not carry catalog field ${forbidden}`);
  }
});

test("the card UI never derives a tile from mutable catalog text", () => {
  const main = readFileSync(join(SRC, "main.jsx"), "utf8");
  assert.ok(main.includes('from "./app-icon-map.js"'), "card UI must use the generated signed icon map");
  assert.ok(main.includes("BAZAAR_MARK_ICON_PATH"), "card UI must retain the Bazaar-mark fallback");
  assert.ok(main.includes("isExplicitlyIconless(appId)"), "card UI must distinguish proven iconless packages");
  assert.ok(main.includes("appIconPath(appId)"), "card UI must use an appId-keyed signed icon path");
  assert.ok(!main.includes("imageId"), "card UI must not consult mutable catalog image IDs");
  assert.ok(!main.includes("const letter"), "card UI must not resurrect letter-tile fallback");
});
