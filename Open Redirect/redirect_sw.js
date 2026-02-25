/**
 * Open Redirect Test - Service Worker (sw.js)
 * Test vectors: fetch event intercept + redirect Response, clients.navigate()
 *
 * Register this service worker on a page, then requests through it can be
 * redirected to external URLs.
 */

// TEST VECTOR 1: Intercept fetch and return a redirect Response
self.addEventListener('fetch', function(event) {
  const url = new URL(event.request.url);

  // If request contains a ?redirect= param, issue a redirect
  const redirectTarget = url.searchParams.get('redirect');
  if (redirectTarget) {
    event.respondWith(
      // OPEN REDIRECT: return a 302 response pointing to user-controlled URL
      new Response(null, {
        status: 302,
        headers: {
          'Location': redirectTarget
        }
      })
    );
    return;
  }

  // Normal passthrough
  event.respondWith(fetch(event.request));
});

// TEST VECTOR 2: clients.navigate() — navigate a controlled client to external URL
self.addEventListener('message', function(event) {
  if (event.data && event.data.type === 'REDIRECT') {
    const target = event.data.url || 'https://example.com';
    // OPEN REDIRECT: navigate client window to external URL
    self.clients.matchAll({ type: 'window' }).then(clients => {
      clients.forEach(client => client.navigate(target));
    });
  }
});

// TEST VECTOR 3: postMessage back to page with redirect instruction
self.addEventListener('notificationclick', function(event) {
  const target = event.notification.data && event.notification.data.url
    ? event.notification.data.url
    : 'https://example.com';
  // OPEN REDIRECT: open window to URL from notification data
  event.waitUntil(
    self.clients.openWindow(target)
  );
});
