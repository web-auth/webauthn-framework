'use strict';

// Cache-first service worker for the offline-only PRF page. We only cache the
// static assets that the offline experience needs; API calls under /api/* are
// pass-through, but offline.html doesn't make any.
const CACHE = 'prf-offline-v1';
const ASSETS = ['/', '/offline.html', '/sw.js'];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting()),
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches
            .keys()
            .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
            .then(() => self.clients.claim()),
    );
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    // Never cache API calls — they belong to the online demo only.
    if (url.pathname.startsWith('/api/')) {
        return;
    }
    event.respondWith(
        caches.match(event.request).then((hit) => hit || fetch(event.request)),
    );
});
