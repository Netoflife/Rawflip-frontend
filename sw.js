const CACHE = "rf-v2";

const PRECACHE = [
  "/",
  "/manifest.json",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
  "/icons/icon-128.png",
  "/icons/icon-96.png",
  "/icons/icon-72.png"
];

// Install event
self.addEventListener("install", e => {
  e.waitUntil(
    caches.open(CACHE).then(cache =>
      Promise.allSettled(
        PRECACHE.map(url =>
          cache.add(url).catch(() => {})
        )
      )
    ).then(() => self.skipWaiting())
  );
});

// Activate event
self.addEventListener("activate", e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(k => k !== CACHE).map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

// Fetch event
self.addEventListener("fetch", e => {
  if (!e.request.url.startsWith("http")) return;

  const url = e.request.url;

  if (url.includes("/api/") || url.includes("socket.io")) return;

  if (e.request.method !== "GET") return;

  e.respondWith(
    fetch(e.request)
      .then(res => {
        if (res.ok) {
          caches.open(CACHE).then(cache =>
            cache.put(e.request, res.clone())
          );
        }
        return res;
      })
      .catch(() =>
        caches.match(e.request).then(cached =>
          cached || new Response("Offline", { status: 503 })
        )
      )
  );
});
