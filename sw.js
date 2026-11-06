// Decrypts the library's media after the gate is unlocked. Files on the server are <name>.enc (12-byte IV + AES-GCM).
const TYPES = {mp4: 'video/mp4', jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png'};
let KEY = null; const CACHE = new Map(), ORDER = [];
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('message', e => { if (e.data === 'key') KEY = null; });
function getKey() {
  if (KEY) return Promise.resolve(KEY);
  return new Promise((res, rej) => { const r = indexedDB.open('wfel', 1); r.onupgradeneeded = () => r.result.createObjectStore('k'); r.onerror = rej;
    r.onsuccess = () => { const q = r.result.transaction('k').objectStore('k').get('media'); q.onerror = rej; q.onsuccess = () => { KEY = q.result || null; KEY ? res(KEY) : rej(new Error('locked')); }; }; });
}
function plain(url) {
  if (CACHE.has(url)) return CACHE.get(url);
  const p = (async () => {
    const r = await fetch(url + '.enc', {cache: 'force-cache'}); if (!r.ok) throw new Error('missing ' + r.status);
    const buf = new Uint8Array(await r.arrayBuffer()), key = await getKey();
    return new Uint8Array(await crypto.subtle.decrypt({name: 'AES-GCM', iv: buf.slice(0, 12)}, key, buf.slice(12)));
  })();
  CACHE.set(url, p); ORDER.push(url); while (ORDER.length > 40) CACHE.delete(ORDER.shift());
  p.catch(() => CACHE.delete(url));
  return p;
}
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (u.origin !== location.origin || e.request.method !== 'GET') return;
  const m = u.pathname.match(/\/refs\/.+\.(mp4|jpe?g|png)$/i); if (!m) return;
  e.respondWith((async () => {
    try {
      const data = await plain(u.origin + u.pathname), type = TYPES[m[1].toLowerCase()], n = data.length;
      const range = e.request.headers.get('range'), mm = range && /bytes=(\d*)-(\d*)/.exec(range);
      if (mm) {
        let a = mm[1] === '' ? Math.max(0, n - (+mm[2] || 0)) : +mm[1], b = mm[1] !== '' && mm[2] !== '' ? Math.min(+mm[2], n - 1) : n - 1;
        return new Response(data.slice(a, b + 1), {status: 206, headers: {'Content-Type': type, 'Content-Range': `bytes ${a}-${b}/${n}`, 'Content-Length': String(b - a + 1), 'Accept-Ranges': 'bytes'}});
      }
      return new Response(data, {headers: {'Content-Type': type, 'Content-Length': String(n), 'Accept-Ranges': 'bytes'}});
    } catch (err) { return new Response('locked', {status: 403}); }
  })());
});
