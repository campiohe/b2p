// b2p relay: a Durable Object per room pairs one `send` and one `recv`
// WebSocket and forwards messages verbatim. It sees only ciphertext.
// Hibernation API: a waiting receiver holds no duration; the ping/pong
// auto-response answers keepalives without waking the object.

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") return new Response("ok");
    const m = url.pathname.match(/^\/v1\/room\/([A-Za-z0-9]{1,64})$/);
    if (!m) return new Response("not found", { status: 404 });
    if (env.RELAY_TOKEN) {
      const auth = request.headers.get("Authorization") || "";
      if (auth !== `Bearer ${env.RELAY_TOKEN}`)
        return new Response("unauthorized", { status: 401 });
    }
    return env.ROOM.get(env.ROOM.idFromName(m[1])).fetch(request);
  },
};

const EXPIRE_UNPAIRED_MS = 30 * 60 * 1000;

export class Room {
  constructor(ctx) {
    this.ctx = ctx;
    this.ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair('{"t":"ping"}', '{"t":"pong"}'),
    );
  }

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket")
      return new Response("expected websocket", { status: 426 });
    const role = new URL(request.url).searchParams.get("role");
    if (role !== "send" && role !== "recv")
      return new Response("bad role", { status: 400 });
    // Takeover: a new join replaces any existing socket in the same role.
    // The Cloudflare edge can hold a silently-dead socket for minutes; a
    // reconnecting peer must not be locked out behind its own stale self.
    for (const old of this.ctx.getWebSockets(role)) {
      old.close(1012, "replaced by a new connection");
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server, [role]);

    const other = this.peerOf(role);
    if (other) {
      server.send(JSON.stringify({ t: "peer-joined" }));
      other.send(JSON.stringify({ t: "peer-joined" }));
      await this.ctx.storage.deleteAlarm();
    } else {
      await this.ctx.storage.setAlarm(Date.now() + EXPIRE_UNPAIRED_MS);
    }
    return new Response(null, { status: 101, webSocket: client });
  }

  peerOf(role) {
    const list = this.ctx.getWebSockets(role === "send" ? "recv" : "send");
    return list.length ? list[0] : null;
  }

  async webSocketMessage(ws, message) {
    const peer = this.peerOf(this.ctx.getTags(ws)[0]);
    if (peer) peer.send(message);
  }

  async webSocketClose(ws) {
    await this.departed(ws);
  }

  async webSocketError(ws) {
    await this.departed(ws);
  }

  async departed(ws) {
    const role = this.ctx.getTags(ws)[0];
    // A replaced socket (takeover) must not send peer-left: its replacement
    // is already paired with the peer.
    if (this.ctx.getWebSockets(role).some((s) => s !== ws)) return;
    const peer = this.peerOf(role);
    if (peer) {
      peer.send(JSON.stringify({ t: "peer-left" }));
      // The survivor is alone again — re-arm the expiry so an abandoned
      // socket can't squat the room forever.
      await this.ctx.storage.setAlarm(Date.now() + EXPIRE_UNPAIRED_MS);
    }
  }

  async alarm() {
    for (const ws of this.ctx.getWebSockets()) ws.close(1013, "room expired");
  }
}
