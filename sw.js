/* TimeTable PWA Service Worker */
const CACHE_NAME = 'timetable-pwa-v1';
const APP_SHELL = ['./'];
self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL)).catch(()=>{}));
  self.skipWaiting();
});
self.addEventListener('activate', event => {
  event.waitUntil((async()=>{const keys=await caches.keys();await Promise.all(keys.filter(k=>k!==CACHE_NAME).map(k=>caches.delete(k)));await self.clients.claim();})());
});
self.addEventListener('fetch', event => {
  const req=event.request;
  if(req.method!=='GET' || new URL(req.url).origin!==self.location.origin) return;
  event.respondWith((async()=>{
    try { const network=await fetch(req); if(network.ok && req.destination!=='document'){const cache=await caches.open(CACHE_NAME);cache.put(req,network.clone());} return network; }
    catch { const cached=await caches.match(req); if(cached) return cached; if(req.mode==='navigate') return (await caches.match('./')) || Response.error(); throw new Error('offline'); }
  })());
});
self.addEventListener('push', event => {
  let payload={title:'時間割のお知らせ',body:'明日の予定があります。',url:'./',sound:true};
  try { if(event.data) payload={...payload,...event.data.json()}; } catch { if(event.data) payload.body=event.data.text(); }
  const options={body:payload.body,icon:payload.icon||'./icon-192.png',badge:payload.badge||'./icon-192.png',tag:payload.tag||'timetable-daily',renotify:false,data:{url:payload.url||'./'},silent:payload.sound===false};
  event.waitUntil(self.registration.showNotification(payload.title||'時間割のお知らせ',options));
});
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const target=new URL(event.notification.data?.url||'./',self.location.origin).href;
  event.waitUntil((async()=>{const wins=await clients.matchAll({type:'window',includeUncontrolled:true});for(const win of wins){if(new URL(win.url).origin===self.location.origin){await win.focus();if('navigate' in win) await win.navigate(target);return;}}await clients.openWindow(target);})());
});
