// One catalog, one source.
//
// The store used to embed a copy of the catalog in the bundle (src/apps.json) and
// paint it before the network answered. Measured on the deployed bundle 2026-08-14:
// that baked copy carried 30 apps, 11 of which were no longer published at all, and
// 18 of the 20 that did survive carried a stale packageId — so an INSTALL clicked
// during the flash aimed at a package the catalog no longer serves.
//
// These tests fail BY NAME if the second catalog comes back, in the file, in the
// generator, or in the built bundle.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const SRC = dirname(fileURLToPath(import.meta.url));
const ROOT = join(SRC, "..");

// Fields that decide WHAT gets installed. None of them may be baked into the bundle.
const CATALOG_FIELDS = [
  "packageId", "version", "versionNumber", "marketingVersion",
  "sha256", "attest", "imageId", "screenshots", "createdAt", "updatedAt",
];

test("baked second catalog src/apps.json is absent", () => {
  assert.equal(
    existsSync(join(SRC, "apps.json")), false,
    "BAKED SECOND CATALOG PRESENT: src/apps.json is back. The served /apps/index.json " +
    "is the only catalog; a baked copy rots between store builds and hands the grid " +
    "stale install targets."
  );
});

test("no store-local app profile map remains", () => {
  assert.equal(
    existsSync(join(SRC, "capabilities.json")), false,
    "SECOND APP PRESENTATION AUTHORITY: src/capabilities.json is back. " +
    "Capabilities must come from the signed, served catalog row with the app release."
  );
});

test("the app never seeds its catalog from a bundled import", () => {
  const main = readFileSync(join(SRC, "main.jsx"), "utf8");
  assert.ok(
    !/import\s+\w+\s+from\s+["']\.\/apps\.json["']/.test(main),
    "BAKED CATALOG IMPORTED: src/main.jsx imports ./apps.json again."
  );
  assert.ok(
    !/import\s+\w+\s+from\s+["']\.\/capabilities\.json["']/.test(main),
    "STORE-LOCAL CAPABILITY MAP IMPORTED: src/main.jsx imports ./capabilities.json again."
  );
  // positive control — the live fetch path and its explicit states still exist
  assert.ok(main.includes("/apps/index.json"), "live catalog fetch path is missing");
  assert.ok(main.includes('setCatalogState("ready")'), "catalog ready state is missing");
  assert.ok(main.includes('setCatalogState("error")'), "catalog error state is missing");
  assert.ok(
    main.includes('useState("loading")'),
    "catalog must start in an explicit loading state, not with stand-in rows"
  );
});

test("the store generator refuses to rebuild a baked catalog", () => {
  const build = readFileSync(join(ROOT, "build-store.sh"), "utf8");
  assert.ok(
    !/with open\('src\/apps\.json', 'w'\)/.test(build),
    "GENERATOR WRITES A BAKED CATALOG: build-store.sh recreates src/apps.json."
  );
  assert.ok(
    build.includes("the baked second catalog is back"),
    "build-store.sh must refuse when src/apps.json reappears (positive control)"
  );
});

test("the governed sidecar bundle embeds no catalog rows", { skip: !existsSync(join(ROOT, "sidecar", "melusina-store-sidecar", "ui")) }, () => {
  const assets = join(ROOT, "sidecar", "melusina-store-sidecar", "ui", "assets");
  if (!existsSync(assets)) return;
  for (const f of readdirSync(assets).filter((f) => f.endsWith(".js"))) {
    const js = readFileSync(join(assets, f), "utf8");
    // Vite inlines imported JSON as an object literal, so keys appear unquoted.
    const hits = (js.match(/[,{]packageId:/g) || []).length;
    assert.equal(
      hits, 0,
      `BAKED CATALOG IN BUNDLE: ${f} embeds ${hits} packageId field(s). The bundle must ` +
      `carry no install targets; they come from the served catalog at runtime.`
    );
  }
});
