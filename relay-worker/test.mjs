// Usage: node test.mjs ws://127.0.0.1:8787   (or wss://<worker>.workers.dev)
// Exercises: healthz, pairing, binary forwarding (600 KiB), text/ack
// forwarding, ping auto-response, duplicate-role takeover (no spurious
// peer-left), peer-left on real departure.
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

const payload = new Uint8Array(600 * 1024).map((_, i) => i % 251);
send.send(payload);
const got = new Uint8Array(await next(recv, "binary forward", 15000));
assert(got.length === payload.length && got.every((b, i) => b === payload[i]), "600 KiB forwarded byte-identical");

recv.send('{"t":"ack","n":614400}');
assert((await next(send, "ack forward")) === '{"t":"ack","n":614400}', "ack forwarded to sender");

send.send('{"t":"ping"}');
assert((await next(send, "pong")) === '{"t":"pong"}', "ping auto-response");

// Takeover: a second join in the same role replaces the first — the old
// socket is closed, the peer keeps its pairing (no spurious peer-left) and
// hears a fresh peer-joined.
const oldClosed = new Promise((res) => { send.onclose = res; });
const send2 = await open("send");
await oldClosed;
assert(true, "old sender closed on takeover");
assert((await next(send2, "peer-joined@send2")) === '{"t":"peer-joined"}', "peer-joined at send2");
assert((await next(recv, "peer-joined again")) === '{"t":"peer-joined"}', "recv re-paired, no spurious peer-left");

send2.close();
assert((await next(recv, "peer-left")) === '{"t":"peer-left"}', "peer-left at recv");
recv.close();
console.log("ALL OK");
