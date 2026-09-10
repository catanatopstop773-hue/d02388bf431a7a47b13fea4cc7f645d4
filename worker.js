import { connect } from "cloudflare:sockets";

const te = new TextEncoder();
const td = new TextDecoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/") {
      return Response.redirect(`${url.origin}/panel`, 302);
    }

    if (url.pathname === "/panel") {
      if (!(await isAdmin(request, env))) return loginPage();
      return html(panelPage());
    }

    if (url.pathname === "/api/login" && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      if (!env.ADMIN_PASSWORD || body.password !== env.ADMIN_PASSWORD) {
        return json({ ok:false, error:"Неверный пароль" }, 401);
      }
      return json({ ok:true }, 200, {
        "Set-Cookie": `admin=${await adminHash(env)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800`
      });
    }

    if (url.pathname === "/api/logout" && request.method === "POST") {
      return json({ok:true}, 200, {
        "Set-Cookie":"admin=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
      });
    }

    if (url.pathname.startsWith("/api/")) {
      if (!(await isAdmin(request, env))) return json({error:"Unauthorized"}, 401);

      if (url.pathname === "/api/info") {
        return json({
          subscription: `${url.origin}/sub/${env.SUB_TOKEN || "SET_SUB_TOKEN"}`,
          origin: url.origin
        });
      }

      if (url.pathname === "/api/servers" && request.method === "GET") {
        return json({servers: await listServers(env)});
      }

      if (url.pathname === "/api/servers" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const count = Math.min(Math.max(Number(body.count || 1), 1), 500);
        const base = String(body.baseName || "CF").trim().slice(0, 40) || "CF";
        const created = [];

        for (let i=0;i<count;i++) {
          const id = crypto.randomUUID().replaceAll("-","").slice(0,16);
          const s = {
            id,
            uuid: crypto.randomUUID(),
            name: count === 1 ? base : `${base}-${i+1}`,
            path: `/ws/${id}`,
            enabled: true,
            createdAt: new Date().toISOString()
          };
          await env.SERVERS.put(`server:${id}`, JSON.stringify(s));
          created.push(s);
        }

        return json({ok:true, created});
      }

      if (url.pathname === "/api/server" && request.method === "PATCH") {
        const body = await request.json().catch(() => ({}));
        const key = `server:${body.id || ""}`;
        const s = await env.SERVERS.get(key, "json");
        if (!s) return json({error:"Не найден"}, 404);
        if (body.enabled !== undefined) s.enabled = !!body.enabled;
        if (body.name !== undefined) s.name = String(body.name).slice(0,60);
        await env.SERVERS.put(key, JSON.stringify(s));
        return json({ok:true, server:s});
      }

      if (url.pathname === "/api/server" && request.method === "DELETE") {
        const body = await request.json().catch(() => ({}));
        await env.SERVERS.delete(`server:${body.id || ""}`);
        return json({ok:true});
      }

      if (url.pathname === "/api/clear" && request.method === "POST") {
        const list = await env.SERVERS.list({prefix:"server:"});
        await Promise.all(list.keys.map(k => env.SERVERS.delete(k.name)));
        return json({ok:true});
      }
    }

    if (url.pathname.startsWith("/sub/")) {
      const token = decodeURIComponent(url.pathname.slice(5));
      if (!env.SUB_TOKEN || token !== env.SUB_TOKEN) {
        return new Response("Not found", {status:404});
      }

      const servers = (await listServers(env)).filter(s => s.enabled);
      const lines = servers.map(s => makeVless(url, s)).join("\n");
      const b64 = toBase64(te.encode(lines));

      return new Response(b64, {
        headers: {
          "content-type":"text/plain; charset=utf-8",
          "cache-control":"no-store",
          "profile-title":"base64:Happ Cloudflare"
        }
      });
    }

    if (url.pathname.startsWith("/ws/")) {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        return new Response("WebSocket required", {status:426});
      }

      const id = url.pathname.split("/").pop();
      const server = await env.SERVERS.get(`server:${id}`, "json");
      if (!server || server.enabled === false) {
        return new Response("Not found", {status:404});
      }

      return handleVless(request, server);
    }

    return new Response("Not found", {status:404});
  }
};

async function handleVless(request, cfg) {
  const pair = new WebSocketPair();
  const client = pair[0], ws = pair[1];
  ws.accept();

  let socket = null, writer = null, initialized = false, closed = false;

  const safeClose = () => {
    if (closed) return;
    closed = true;
    try { writer?.releaseLock(); } catch {}
    try { socket?.close(); } catch {}
    try { ws.close(); } catch {}
  };

  ws.addEventListener("message", async ev => {
    try {
      const chunk = toU8(ev.data);

      if (!initialized) {
        const p = parseVless(chunk);
        if (!p.ok || p.uuid.toLowerCase() !== cfg.uuid.toLowerCase() || p.command !== 1) {
          ws.close(1008, "Unauthorized/unsupported");
          return;
        }

        socket = connect({hostname:p.address, port:p.port});
        writer = socket.writable.getWriter();
        initialized = true;

        ws.send(new Uint8Array([p.version, 0]));

        if (p.payload.length) await writer.write(p.payload);
        pipeBack(socket, ws, safeClose);
        return;
      }

      await writer.write(chunk);
    } catch {
      safeClose();
    }
  });

  ws.addEventListener("close", safeClose);
  ws.addEventListener("error", safeClose);

  return new Response(null, {status:101, webSocket:client});
}

async function pipeBack(socket, ws, close) {
  try {
    const reader = socket.readable.getReader();
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      if (value?.byteLength && ws.readyState === 1) ws.send(value);
    }
    reader.releaseLock();
  } catch {}
  close();
}

function parseVless(data) {
  try {
    if (data.length < 24) return {ok:false};
    let i=0;
    const version=data[i++];
    const uuid=bytesUuid(data.slice(i,i+16)); i+=16;
    const optLen=data[i++]; i+=optLen;
    const command=data[i++];
    const port=(data[i++]<<8)|data[i++];
    const type=data[i++];
    let address="";

    if(type===1){
      address=Array.from(data.slice(i,i+4)).join(".");
      i+=4;
    } else if(type===2){
      const n=data[i++];
      address=td.decode(data.slice(i,i+n));
      i+=n;
    } else if(type===3){
      const parts=[];
      for(let x=0;x<8;x++){
        parts.push(((data[i+x*2]<<8)|data[i+x*2+1]).toString(16));
      }
      address=parts.join(":");
      i+=16;
    } else {
      return {ok:false};
    }

    return {ok:true,version,uuid,command,port,address,payload:data.slice(i)};
  } catch {
    return {ok:false};
  }
}

async function listServers(env) {
  const out=[];
  let cursor;
  do {
    const page=await env.SERVERS.list({prefix:"server:",cursor});
    for(const k of page.keys){
      const s=await env.SERVERS.get(k.name,"json");
      if(s) out.push(s);
    }
    cursor=page.list_complete?undefined:page.cursor;
  } while(cursor);
  out.sort((a,b)=>String(b.createdAt).localeCompare(String(a.createdAt)));
  return out;
}

function makeVless(url,s){
  const host=url.hostname;
  const q=new URLSearchParams({
    encryption:"none",
    security:"tls",
    type:"ws",
    host,
    path:s.path,
    sni:host
  });
  return `vless://${s.uuid}@${host}:443?${q.toString()}#${encodeURIComponent(s.name)}`;
}

function bytesUuid(b){
  const h=[...b].map(x=>x.toString(16).padStart(2,"0")).join("");
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
function toU8(v){
  if(v instanceof ArrayBuffer)return new Uint8Array(v);
  if(ArrayBuffer.isView(v))return new Uint8Array(v.buffer,v.byteOffset,v.byteLength);
  return te.encode(String(v));
}
function toBase64(bytes){
  let s="";
  for(let i=0;i<bytes.length;i+=0x8000)s+=String.fromCharCode(...bytes.subarray(i,i+0x8000));
  return btoa(s);
}
function json(o,status=200,headers={}){
  return new Response(JSON.stringify(o),{
    status,
    headers:{"content-type":"application/json; charset=utf-8",...headers}
  });
}
function html(body){
  return new Response(body,{
    headers:{
      "content-type":"text/html; charset=utf-8",
      "cache-control":"no-store",
      "x-frame-options":"DENY"
    }
  });
}
async function adminHash(env){
  const h=await crypto.subtle.digest("SHA-256",te.encode("admin:"+(env.ADMIN_PASSWORD||"")));
  return [...new Uint8Array(h)].map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function isAdmin(req,env){
  const m=(req.headers.get("Cookie")||"").match(/(?:^|;\s*)admin=([^;]+)/);
  return !!m && m[1]===await adminHash(env);
}

const CSS=`:root{color-scheme:dark;font-family:system-ui;background:#080b12;color:#eef2ff}*{box-sizing:border-box}body{margin:0;background:#080b12}main{max-width:980px;margin:auto;padding:22px 14px 60px}.card{background:#111827;border:1px solid #253047;border-radius:18px;padding:18px;margin:14px 0}h1{margin:0}h2{margin:0 0 12px}.row,.top,.server,.actions{display:flex;gap:10px;align-items:center}.top,.server{justify-content:space-between}input{width:100%;background:#090e18;border:1px solid #303d57;color:white;border-radius:11px;padding:12px}button{border:0;border-radius:11px;padding:11px 14px;background:#5878ff;color:white;font-weight:700}.ghost{background:#273248}.danger{background:#a73546}.server{border-top:1px solid #273248;padding:13px 0}.meta{display:grid;gap:4px;min-width:0}.meta code{font-size:11px;color:#9ba7bb;overflow-wrap:anywhere}.badge{padding:4px 8px;border-radius:99px;background:#273248}.login{max-width:420px;margin:12vh auto}small,p{color:#98a4b8}@media(max-width:700px){.row,.server{flex-direction:column;align-items:stretch}.actions{display:grid;grid-template-columns:1fr 1fr 1fr}}`;

function loginPage(){
  return html(`<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><style>${CSS}</style><main class=login><section class=card><h1>☁ Happ Cloud Panel</h1><p>Введите пароль администратора</p><input id=p type=password autofocus><button style="width:100%;margin-top:10px" onclick="go()">Войти</button><p id=e></p></section></main><script>async function go(){let r=await fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:p.value})});if(r.ok)location='/panel';else e.textContent='Неверный пароль'};p.onkeydown=x=>x.key==='Enter'&&go()</script>`);
}

function panelPage(){
  return `<!doctype html><html lang=ru><meta name=viewport content="width=device-width,initial-scale=1"><title>Happ Cloud Panel</title><style>${CSS}</style><body><main>
  <div class=top><div><h1>☁ Happ Cloud Panel</h1><p>Cloudflare Worker · VLESS/WSS</p></div><button class=ghost onclick=logout()>Выйти</button></div>

  <section class=card>
    <h2>Подписка Happ</h2>
    <div class=row><input id=sub readonly><button onclick="copy(sub.value)">Копировать</button></div>
  </section>

  <section class=card>
    <h2>Создать профили</h2>
    <div class=row>
      <input id=base value="CF" placeholder="Имя">
      <input id=count type=number min=1 max=500 value=10>
      <button onclick=createMany()>Создать</button>
    </div>
    <small>До 500 профилей за раз. У каждого свой UUID и WebSocket path. Порт — 443.</small>
  </section>

  <section class=card>
    <div class=top><h2>Профили <span id=n class=badge>0</span></h2><button class=danger onclick=clearAll()>Удалить все</button></div>
    <div id=list></div>
  </section>
  </main>

  <script>
  const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  async function api(u,o){let r=await fetch(u,o);if(r.status===401){location='/';throw 0}let j=await r.json();if(!r.ok)throw Error(j.error||'Ошибка');return j}
  async function load(){
    let i=await api('/api/info');sub.value=i.subscription;
    let j=await api('/api/servers');n.textContent=j.servers.length;
    list.innerHTML=j.servers.map(s=>`<div class=server><div class=meta><b>${esc(s.name)}</b><code>${s.uuid}</code><code>${s.path}</code></div><div class=actions><button class=ghost onclick="link('${s.id}')">VLESS</button><button class=ghost onclick="toggle('${s.id}',${!s.enabled})">${s.enabled?'Выкл':'Вкл'}</button><button class=danger onclick="del('${s.id}')">Удалить</button></div></div>`).join('')||'<p>Пока пусто</p>'
  }
  async function createMany(){await api('/api/servers',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({baseName:base.value,count:Number(count.value)})});load()}
  async function link(id){let j=await api('/api/servers');let s=j.servers.find(x=>x.id===id),h=location.hostname,q=new URLSearchParams({encryption:'none',security:'tls',type:'ws',host:h,path:s.path,sni:h});copy('vless://'+s.uuid+'@'+h+':443?'+q+'#'+encodeURIComponent(s.name))}
  async function toggle(id,en){await api('/api/server',{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({id,enabled:en})});load()}
  async function del(id){await api('/api/server',{method:'DELETE',headers:{'content-type':'application/json'},body:JSON.stringify({id})});load()}
  async function clearAll(){if(confirm('Удалить все профили?')){await api('/api/clear',{method:'POST'});load()}}
  async function copy(t){await navigator.clipboard.writeText(t);alert('Скопировано')}
  async function logout(){await fetch('/api/logout',{method:'POST'});location='/'}
  load()
  </script></body></html>`;
}
