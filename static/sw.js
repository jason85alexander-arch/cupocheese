/* Cup O' Cheese service worker: caches static assets + an offline page only.
   Pages are network-first and never stored; audio, avatars, and POSTs pass straight through. */
const VERSION = "coc-v2";
const STATIC_CACHE = VERSION + "-static";
const PRECACHE = [
  "/offline",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
  "/static/icons/apple-touch-icon.png",
  "/static/icons/favicon-32.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(STATIC_CACHE).then((c) => c.addAll(PRECACHE)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => !k.startsWith(VERSION)).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;                 // POSTs (posts, reactions, uploads) untouched
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  if (req.mode === "navigate") {
    // Network-first for HTML; never cache authenticated pages. Offline -> fallback page.
    event.respondWith(fetch(req).catch(() => caches.match("/offline")));
    return;
  }

  if (url.pathname.startsWith("/static/")) {
    // Cache-first for static assets.
    event.respondWith(
      caches.match(req).then((hit) => hit || fetch(req).then((res) => {
        if (res.ok) { const copy = res.clone(); caches.open(STATIC_CACHE).then((c) => c.put(req, copy)); }
        return res;
      }))
    );
  }
  // Everything else (/clip/, /avatar/, JSON) goes to the network as normal.
});
