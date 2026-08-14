// The service worker's never-cache guards must actually fire.
//
// sw.js built NO_CACHE_PREFIXES from `BASE`, which was '/melusina-static-store/'
// — the retired GitHub Pages sub-path. The store is served at the ORIGIN ROOT by
// the melusina-store-sidecar, so every one of those prefixes matched nothing and
// the guards for packages/, apps/index.json, update/ and signatures/ were inert:
// a guard that cannot fire is not a guard. These tests fail BY NAME if it returns.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const HERE = dirname(fileURLToPath(import.meta.url));
const ORIGIN = "https://bazaar.melusina-os.org";

// Evaluate sw.js with a stubbed worker global so its listeners are inert.
function loadSW() {
  const src = readFileSync(join(HERE, "sw.js"), "utf8");
  const ctx = {
    self: { addEventListener() {}, location: { origin: ORIGIN }, skipWaiting() {}, clients: { claim() {} } },
    caches: { open: async () => ({}), keys: async () => [], match: async () => undefined, delete: async () => {} },
    fetch: async () => ({}), URL, console,
  };
  vm.createContext(ctx);
  vm.runInContext(src + "\n;globalThis.__t = { isNoCache, isCacheable, BASE, NO_CACHE_PREFIXES };", ctx);
  return ctx.__t;
}

const sw = loadSW();
const u = (p) => new URL(p, ORIGIN);

test("the store is treated as root-served, not as a gh-pages sub-path", () => {
  assert.equal(
    sw.BASE, "/",
    `SERVICE WORKER KEYED TO THE RETIRED GH-PAGES SUB-PATH: BASE is ${JSON.stringify(sw.BASE)}. ` +
    `The sidecar serves this store at the origin root, so every NO_CACHE_PREFIXES entry built ` +
    `from BASE matches nothing and every never-cache guard is inert.`
  );
});

for (const p of ["/packages/91d7f7c1f0b21b54b24fa89cd8386d40", "/apps/index.json",
                 "/update/manifest.json", "/signatures/pe3k6w/metadata.json"]) {
  test(`never-cache guard fires for ${p}`, () => {
    assert.equal(
      sw.isNoCache(u(p)), true,
      `GUARD INERT: isNoCache("${p}") is false, so this path is eligible for caching. ` +
      `A stale SPK or catalog served from cache is exactly what this list exists to prevent.`
    );
  });
}

test("hashed assets are still cacheable (positive control)", () => {
  assert.equal(sw.isCacheable(u("/assets/index-DDlYX80K.js")), true,
    "hashed bundle assets must remain cacheable — otherwise this fix broke offline boot");
  assert.equal(sw.isCacheable(u("/icons/melulogo.svg")), true, "icons must remain cacheable");
});

test("a never-cache path is never also cacheable", () => {
  for (const p of ["/packages/abc", "/apps/index.json", "/update/manifest.json"]) {
    assert.equal(sw.isCacheable(u(p)), false, `${p} must not match a cacheable pattern`);
  }
});
