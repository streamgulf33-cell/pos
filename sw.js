/**
 * PharmaDesk Service Worker
 * -------------------------
 * Purpose: guarantee the app itself loads offline once it's been opened
 * at least once, even when hosted online (Vercel, Netlify, etc). This is
 * separate from — and doesn't replace — the app's IndexedDB data layer,
 * which was already fully offline-capable. This just makes sure the app
 * shell (the HTML/CSS/JS) is available with zero network too.
 *
 * Strategy: cache-first for the app shell, so it's instant and reliable
 * offline; falls back to network for anything not cached, and updates
 * the cache in the background when online.
 */
const CACHE_NAME = 'pharmadesk-shell-v1';
const APP_SHELL = [
  './',
  './index.html',
  './manifest.json',
  './icon-192.png',
  './icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  // Only handle same-origin GET requests for the app shell.
  // Sync API calls to your backend always go straight to the network —
  // we never want to accidentally serve stale sync data from cache.
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) return;

  event.respondWith(
    caches.match(event.request).then((cached) => {
      const networkFetch = fetch(event.request)
        .then((response) => {
          if (response && response.status === 200) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => cached); // offline: fall back to whatever's cached

      // Cache-first: instant load offline; refreshes cache quietly in the background.
      return cached || networkFetch;
    })
  );
});
