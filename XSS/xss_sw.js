self.addEventListener('fetch', e => {
  e.respondWith(new Response('<script>alert(1)<\/script>', {
    headers: {'Content-Type': 'text/html'}
  }));
});
