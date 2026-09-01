const CACHE='forced-self-care-v7';
const ASSETS=['./','index.html','manifest.webmanifest','icon.png'];
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(ASSETS))));
self.addEventListener('activate',event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>key!==CACHE).map(key=>caches.delete(key))))));
self.addEventListener('fetch',event=>{if(event.request.method==='GET')event.respondWith(fetch(event.request).catch(()=>caches.match(event.request)))});
self.addEventListener('push',event=>{let data={title:'Forced Self Care',body:'Medication reminder',tag:'reminder',url:'./'};try{data={...data,...event.data.json()}}catch{}event.waitUntil(self.registration.showNotification(data.title,{body:data.body,icon:'icon.png',badge:'icon.png',tag:data.tag,data:{url:data.url},vibrate:[300,150,300],requireInteraction:true}))});
self.addEventListener('notificationclick',event=>{event.notification.close();event.waitUntil(clients.matchAll({type:'window',includeUncontrolled:true}).then(list=>{for(const client of list){if('focus' in client)return client.focus()}return clients.openWindow(event.notification.data?.url||'./')}))});
