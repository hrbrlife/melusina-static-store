const CACHE_NAME = 'melusina-market-v3';
const BASE = '/melusina-static_store/';

/* Precache only the shell files needed to boot the app offline.
 * Hashed bundle chunks (assets/*) are cached on-demand via the fetch handler.
 */
const PRECACHE_URLS = [
  BASE,
  BASE + 'index.html',
  BASE + 'icons/melulogo.svg',
  BASE + 'icons/melulogo-192.png',
  BASE + 'icons/melulogo-512.png',
  BASE + 'manifest.json',
];

/* Paths we must NEVER cache: SPKs (large, hash-addressed, change on re-publish),
 * GitHub release assets, Sandstorm binary update bundles, and the live app
 * catalog. A stale cache here would serve wrong/expired packages.
 */
const NO_CACHE_PREFIXES = [
  BASE + 'packages/',
  BASE + 'releases/',
  BASE + 'update/',
  BASE + 'apps/index.json',
  BASE + 'signatures/',
];

/* Caching is only applied to these asset categories (hashed, safe to cache) */
const CACHEABLE_PATTERNS = [
  /\/assets\/.*\.(js|css|woff2?)$/i,
  /\/images\/.*\.(svg|png|jpg|jpeg|gif|webp)$/i,
  /\/icons\/.*\.(svg|png|ico)$/i,
  /\/screenshots\/.*\.(png|jpg|jpeg|gif|webp)$/i,
];

function isNoCache(url) {
  return NO_CACHE_PREFIXES.some((p) => url.pathname.startsWith(p));
}

function isCacheable(url) {
  return CACHEABLE_PATTERNS.some((re) => re.test(url.pathname));
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // Never intercept SPK downloads, release bundles, or the live catalog.
  if (isNoCache(url)) return;

  // Navigation: network-first, shell fallback.
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response && response.status === 200) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
          }
          return response;
        })
        .catch(() => caches.match(request).then((r) => r || caches.match(BASE + 'index.html')))
    );
    return;
  }

  // Assets: cache-first for hashed bundle files, network-only for everything else.
  if (isCacheable(url)) {
    event.respondWith(
      caches.match(request).then((cached) => {
        if (cached) return cached;
        return fetch(request).then((response) => {
          if (response && response.status === 200) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
          }
          return response;
        });
      })
    );
    return;
  }

  // Default: network-only (no caching).
});
