/* Service worker mínimo: deixa o Chrome instalar o app. Sempre busca da internet (nada fica guardado em cache). */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  if (e.request.mode === 'navigate') {
    e.respondWith(fetch(e.request).catch(() => new Response(
      '<meta charset="utf-8"><meta name="viewport" content="width=device-width"><body style="background:#060a13;color:#fff;font-family:sans-serif;text-align:center;padding:4rem 1rem"><h1>RunTeam</h1><p>Sem conexão com a internet.</p>',
      { headers: { 'Content-Type': 'text/html; charset=utf-8' } })));
  }
});
