/* ═══════════════════════════════════════════════════════════
   RawFlip Service Worker  — sw.js
   • Offline shell caching (app shell strategy)
   • Push notification display
   • Notification click → open / focus app
   • Background sync ready
   • Auto-cleanup of old caches on activate
═══════════════════════════════════════════════════════════ */

const CACHE_NAME    = 'rawflip-v1';
const OFFLINE_URL   = '/';

// Files to pre-cache on install (app shell)
const PRECACHE = [
  '/',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
];

/* ── Install ─────────────────────────────────────────────── */
self.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return cache.addAll(PRECACHE);
    }).then(function() {
      // Activate immediately — don't wait for old SW to die
      return self.skipWaiting();
    })
  );
});

/* ── Activate ────────────────────────────────────────────── */
self.addEventListener('activate', function(event) {
  event.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys
          .filter(function(key) { return key !== CACHE_NAME; })
          .map(function(key) {
            console.log('[SW] deleting old cache:', key);
            return caches.delete(key);
          })
      );
    }).then(function() {
      // Take control of all open tabs immediately
      return self.clients.claim();
    })
  );
});

/* ── Fetch — Network-first, fallback to cache ────────────── */
self.addEventListener('fetch', function(event) {
  var req = event.request;

  // Only handle GET requests — skip POST/PUT etc. (API calls)
  if (req.method !== 'GET') return;

  // Skip cross-origin requests (Cloudinary, Google Fonts, Socket.io CDN, etc.)
  if (!req.url.startsWith(self.location.origin)) return;

  // Skip API calls — always go to network
  if (req.url.includes('/api/')) return;

  event.respondWith(
    fetch(req)
      .then(function(response) {
        // Cache successful responses for the app shell
        if (response && response.status === 200) {
          var clone = response.clone();
          caches.open(CACHE_NAME).then(function(cache) {
            cache.put(req, clone);
          });
        }
        return response;
      })
      .catch(function() {
        // Network failed — try cache
        return caches.match(req).then(function(cached) {
          if (cached) return cached;
          // Last resort for navigation requests — serve the app shell
          if (req.mode === 'navigate') {
            return caches.match(OFFLINE_URL);
          }
          return new Response('Offline', { status: 503, statusText: 'Service Unavailable' });
        });
      })
  );
});

/* ── Push Notifications ──────────────────────────────────── */
self.addEventListener('push', function(event) {
  var data = {};
  if (event.data) {
    try {
      data = event.data.json();
    } catch(e) {
      data = { title: 'RawFlip', body: event.data.text(), url: '/' };
    }
  }

  var title   = data.title || 'RawFlip';
  var body    = data.body  || 'You have a new notification.';
  var url     = data.url   || '/';
  var icon    = '/icons/icon-192.png';
  var badge   = '/icons/icon-64.png';

  var options = {
    body:    body,
    icon:    icon,
    badge:   badge,
    vibrate: [100, 50, 100],
    data:    { url: url },
    actions: [
      { action: 'open',    title: 'Open App' },
      { action: 'dismiss', title: 'Dismiss'  }
    ],
    tag:            'rawflip-notification',
    renotify:       true,
    requireInteraction: false,
  };

  event.waitUntil(
    self.registration.showNotification(title, options)
  );
});

/* ── Notification Click ──────────────────────────────────── */
self.addEventListener('notificationclick', function(event) {
  event.notification.close();

  if (event.action === 'dismiss') return;

  var targetUrl = (event.notification.data && event.notification.data.url)
    ? event.notification.data.url
    : '/';

  // Make the URL absolute
  if (!targetUrl.startsWith('http')) {
    targetUrl = self.location.origin + targetUrl;
  }

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clientList) {
      // If app is already open, focus it and navigate
      for (var i = 0; i < clientList.length; i++) {
        var client = clientList[i];
        if (client.url.startsWith(self.location.origin) && 'focus' in client) {
          client.focus();
          if ('navigate' in client) {
            client.navigate(targetUrl);
          }
          return;
        }
      }
      // App is not open — open a new window
      if (clients.openWindow) {
        return clients.openWindow(targetUrl);
      }
    })
  );
});

/* ── Push Subscription Change ────────────────────────────── */
// Fires if the browser rotates push credentials automatically
self.addEventListener('pushsubscriptionchange', function(event) {
  event.waitUntil(
    self.registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: event.oldSubscription
        ? event.oldSubscription.options.applicationServerKey
        : null
    }).then(function(newSub) {
      // Send new subscription to server
      return fetch(self.location.origin + '/api/push-subscription', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          endpoint: newSub.endpoint,
          keys: {
            p256dh: newSub.toJSON().keys.p256dh,
            auth:   newSub.toJSON().keys.auth,
          }
        })
      });
    }).catch(function(e) {
      console.error('[SW] pushsubscriptionchange failed:', e);
    })
  );
});

/* ── Message from main thread ────────────────────────────── */
self.addEventListener('message', function(event) {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

console.log('[SW] RawFlip service worker loaded ✓');
