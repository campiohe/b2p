// Usage: node test.mjs ws://127.0.0.1:8787   (or wss://<worker>.workers.dev)
// Exercises: healthz, pairing, binary forwarding (600 KiB), text/ack
// forwarding, ping auto-response, peer-left, 409 on duplicate role.
const base = process.argv[2];
if (!base) throw new Error("usage: node test.mjs <ws-base-url>");
const httpBase = base.replace(/^ws/, "http");
const room = "testroom" + Math.floor(Math.random() * 1e9);

const url = (r) => `${base}/v1/room/${room}?role=${r}`;
// Messages are queued from the moment the socket opens — a frame that lands
// before the test awaits it must not be dropped.
const open = (r) =>
  new Promise((res, rej) => {
    const ws = new WebSocket(url(r));
    ws.binaryType = "arraybuffer";
    ws.queue = [];
    ws.waiters = [];
    ws.onmessage = (e) => {
      const w = ws.waiters.shift();
      if (w) w(e.data);
      else ws.queue.push(e.data);
    };
    ws.onopen = () => res(ws);
    ws.onerror = () => rej(new Error(`connect failed for ${r}`));
  });
const next = (ws, what, ms = 5000) =>
  new Promise((res, rej) => {
    if (ws.queue.length) return res(ws.queue.shift());
    const t = setTimeout(() => rej(new Error(`timeout: ${what}`)), ms);
    ws.waiters.push((d) => { clearTimeout(t); res(d); });
  });
const assert = (ok, what) => { if (!ok) throw new Error(`FAIL: ${what}`); console.log(`ok: ${what}`); };

const health = await fetch(`${httpBase}/healthz`);
assert(health.status === 200 && (await health.text()) === "ok", "healthz");

const recv = await open("recv");
const send = await open("send");
assert((await next(recv, "peer-joined@recv")) === '{"t":"peer-joined"}', "peer-joined at recv");
assert((await next(send, "peer-joined@send")) === '{"t":"peer-joined"}', "peer-joined at send");

const dup = new WebSocket(url("send"));
await new Promise((res) => { dup.onerror = res; dup.onclose = res; });
assert(dup.readyState !== WebSocket.OPEN, "duplicate role refused");

const payload = new Uint8Array(600 * 1024).map((_, i) => i % 251);
send.send(payload);
const got = new Uint8Array(await next(recv, "binary forward", 15000));
assert(got.length === payload.length && got.every((b, i) => b === payload[i]), "600 KiB forwarded byte-identical");

recv.send('{"t":"ack","n":614400}');
assert((await next(send, "ack forward")) === '{"t":"ack","n":614400}', "ack forwarded to sender");

send.send('{"t":"ping"}');
assert((await next(send, "pong")) === '{"t":"pong"}', "ping auto-response");

send.close();
assert((await next(recv, "peer-left")) === '{"t":"peer-left"}', "peer-left at recv");
recv.close();
console.log("ALL OK");
