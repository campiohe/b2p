# b2p v2 — Design Specification

*Encrypted peer-to-peer transfer that survives hostile networks — free, zero-account, zero-config.*

Status: **Draft for discussion** · Supersedes the v1 tunnel-only transport · Companion to the corporate-network bug report.

---

## 0. Why v2

v1 is *"encrypted file transfer over plain HTTPS uploads"*: the **receiver** opens a Cloudflare quick tunnel (`*.trycloudflare.com`), prints a code (`https://<host>.trycloudflare.com#<secret>`), and the **sender** fetches `/v1/manifest` over that URL and uploads. Content is end-to-end encrypted with the fragment secret. The UX is excellent — one command each side, no account, no config.

The fatal weakness is the transport. `*.trycloudflare.com` is categorized as an anonymizer/tunnel service and blocked by default on most enterprise networks; the tunnel is a single point of failure; and v1's HTTPS client uses a bundled trust store, so it breaks the moment a network runs TLS inspection. The result is total failure with a misleading *"check the code and their tunnel"* error.

**v2 keeps the v1 UX and threat model but replaces the single tunnel with a negotiated, degrading stack of transports, none of which depends on one blockable domain.**

### Design goals

- **Zero bureaucracy.** Sending a file must require no account, no signup, no API key, no config file. This is v1's best property; v2 must not regress it.
- **Free.** No paid infrastructure on the default path. Self-hosting is optional, never required.
- **Robust across NAT / firewall / proxy.** Home, mobile, café, and inspected corporate networks.
- **Open and adaptive, not one-size-fits-all.** Transports and rendezvous are *pluggable modes* (Appendix A), so b2p fits many network contexts — LAN, open internet, NAT'd, self-hosted, offline. Trust the OS certificate store so inspecting proxies pass b2p rather than break it.
- **End-to-end encrypted always.** No rendezvous, relay, or proxy ever sees plaintext or the session key.
- **Fail loud and specific.** Every failure names the layer (DNS / TLS / signaling / transport) and suggests a next step.

---

## 1. Evidence: what a hostile network actually permits

Measured on a real network that DNS-blocks `trycloudflare.com` (Cisco Umbrella) **and** runs a TLS-inspection proxy (`BTG Pactual-RootCA`), with outbound port-53 to public resolvers also blocked. This is the design's proving ground.

| Capability | Result | Implication for v2 |
| --- | --- | --- |
| **UDP egress + STUN** (Google `19302`, Cloudflare `3478`) | ✅ binding responses returned | **WebRTC is viable** — primary internet transport |
| `ntfy.sh` | ✅ HTTP 200 (via proxy) | **Default signaling/rendezvous** — free, no account |
| `0x0.st`, `paste.rs` | ✅ 200 | Blob dead-drop candidates (no account) |
| GitHub / GitLab / Codeberg | ✅ 200/301 | Always-allowed category; relay/gist option (needs token) |
| `storage.googleapis.com`, `s3.amazonaws.com` | ✅ reachable (uninspected) | Pre-signed-URL fallback (needs creds) |
| `trycloudflare.com`, `ngrok`, `bore.pub` | ❌ DNS-blocked / reset | v1's transport — unusable, do not depend on it |
| `discord.com`, `api.telegram.org` | ❌ TLS reset | Social APIs blocked — not a reliable transport |
| `pastebin.com`, `bashupload.com` | ❌ DNS timeout | Blocked |
| HTTPS to allowed hosts | mostly re-signed by `BTG Pactual-RootCA` | **Must use OS trust store** |

Two conclusions drive the architecture:

1. **The network permits standard connectivity (UDP, STUN, mainstream HTTPS) — it blocks *tunnels*.** So the winning move is to use standard connectivity (WebRTC) plus a rendezvous on a permitted, non-tunnel domain, not to build another tunnel.
2. **Nearly all HTTPS is MITM'd but passes once you trust the corporate root.** Cooperating with the proxy (system trust store) is both the correct fix and sufficient.

---

## 2. Architecture

```
   b2p receive                                        b2p send <code>
        │                                                    │
        │   1. PAKE handshake over RENDEZVOUS (ntfy default) │
        └──────────────► derive session key + peer info ◄────┘
                              (low-entropy code → strong key, SPAKE2)
        │                                                    │
        │   2. Exchange transport candidates via rendezvous  │
        │                                                    │
        ▼                    3. Connect (first that wins)    ▼
   ┌───────────────────────────────────────────────────────────┐
   │  T0  LAN direct (mDNS discovery, same-subnet TCP/QUIC)      │
   │  T1  WebRTC data channel  (STUN → TURN fallback)           │  ◄── primary on this network
   │  T2  HTTPS relay          (self-hostable; store-&-forward) │
   │  T3  (none) → diagnose + fail with a specific message      │
   └───────────────────────────────────────────────────────────┘
        │                                                    │
        └──────── 4. Encrypted stream (XChaCha20-Poly1305) ──┘
```

Three decoupled layers:

- **Rendezvous / signaling** — a tiny, pluggable channel used only to run the PAKE and exchange transport candidates. Default: `ntfy.sh` (reachable, free, no account). Self-hostable. Carries only ciphertext and public handshake values.
- **Transport** — the ordered, auto-negotiated data path (T0–T3 above). Each peer advertises what it can offer; the first mutually-workable transport wins.
- **Crypto** — a PAKE turns the short human code into a strong shared key; the payload is streamed with an AEAD. Independent of which rendezvous/transport is chosen.

---

## 3. The code and the cryptography

### 3.1 Code format

Keep v1's ergonomics, drop the domain dependence. Two supported spellings:

- **Human code** (wormhole-style): `4-tunnel-mosaic` — a channel number plus two words from a fixed wordlist. Great for reading aloud.
- **URL-style** (v1 compatible): `b2p://<rendezvous-id>#<pake-secret>` — the secret stays in the fragment so it is never sent to any server.

Both encode the same two things: a **rendezvous id** (which topic/mailbox to meet on) and a **PAKE secret** (the low-entropy password).

### 3.2 PAKE (why, and which)

A short code is low-entropy, so it must never be usable for an offline dictionary attack by whoever runs the rendezvous. Use **SPAKE2** (as magic-wormhole does) — a balanced PAKE: both sides prove knowledge of the code and derive a strong shared key, and a passive or active rendezvous operator learns nothing usable. This is what lets the rendezvous be an untrusted public service like `ntfy.sh`.

- Derive `rendezvous_topic = HKDF(code_prefix)` and run SPAKE2 with the full code.
- Output a 256-bit session key. Single-use: the code expires on first successful handshake or after a timeout.

### 3.3 Payload encryption

- Stream with **XChaCha20-Poly1305** (libsodium `secretstream`), 64 KiB chunks, per-chunk authentication, final-chunk marker to prevent truncation.
- Per-file nonce/subkey via HKDF from the session key.
- Manifest (filenames, sizes, mode) encrypted with the same key and sent as the first framed message.

---

## 4. Transports in detail

### T0 — LAN direct (opportunistic, fastest)

If both peers are on the same network, skip the internet entirely.

- Receiver advertises `_b2p._tcp` over mDNS/DNS-SD with its LAN address and a rendezvous-derived instance id.
- Sender that finds a matching instance connects directly (TCP or QUIC), then runs the PAKE over that socket.
- Extends v1's existing `--direct` flag to the **sender** side, and makes it automatic when discovery succeeds.

### T1 — WebRTC data channel (primary internet path)

The workhorse, and confirmed viable on the proving-ground network.

- Each peer gathers ICE candidates: host, server-reflexive (via **STUN**), and relayed (via **TURN**) if needed.
- SDP offer/answer and ICE candidates are exchanged over the rendezvous channel (small, encrypted).
- Data flows over an SCTP data channel inside DTLS — already E2E-encrypted at the transport layer, with b2p's AEAD as a second, key-independent layer.
- **STUN:** default to public no-account servers (Google `stun.l.google.com:19302`, Cloudflare `stun.cloudflare.com:3478`) — both reachable here.
- **TURN fallback:** needed when both peers are behind symmetric NAT (common on corporate networks) or when UDP is blocked. Options, in preference order:
  1. **Self-hosted `coturn`** (single command; the "own your infra" path).
  2. A TURN provider with ephemeral credentials (Cloudflare Calls / Open Relay) — this is the one spot that may need an account, so it is **fallback-only**, never the default, and only engaged when STUN-only fails.
  3. **TURN-over-TLS on 443** — doubles as the escape hatch for networks that block UDP outright (not this one, but many).
- Rust implementation: `webrtc` crate or `str0m` (sans-I/O, easier to embed in a CLI).

### T2 — HTTPS relay (store-and-forward fallback)

When live P2P can't form (both symmetric NAT and no TURN, or one peer is offline), fall back to a relay that both peers *can* reach over ordinary HTTPS.

- **Protocol:** sender PUTs E2E-encrypted, chunked blocks to `relay/<rendezvous-id>/<seq>`; receiver GETs and streams them. The relay sees only ciphertext and an opaque id; it cannot read content or derive the key (PAKE).
- **Self-hostable single binary** is the reference relay — deploy on any VPS/domain the org permits. On an inspected network this works *cooperatively*: the proxy inspects the TLS, sees ciphertext, and passes it; nothing is disguised.
- **Store-and-forward** enables async transfer (receiver offline): blocks persist until fetched or TTL expires. Deliberately **no default public dead-drop** ships — a hosted anonymous blob store is the one design element that invites abuse, so it is opt-in and self-hosted only (§11).
- Public paste hosts (`0x0.st`, `paste.rs`) are supported as a *manual, small-payload* escape hatch, not an automatic default.

### T3 — No transport

If T0–T2 all fail, do **not** print "check the code." Run the doctor (§6) and report exactly which layer failed and what to try (e.g., *"UDP and TURN unavailable and no relay configured; run `b2p relay` on a reachable host, or connect both peers to the same network and retry"*).

### Rendezvous / signaling providers

- **Default: `ntfy.sh`.** POST signaling frames to `ntfy.sh/<topic>`, subscribe via the SSE/JSON stream. Free, no account, reachable through the proxy here. Only encrypted/PAKE values transit it.
- **Pluggable + self-hostable:** `ntfy` is self-hostable; the interface is a 3-method trait (`publish`, `subscribe`, `close`) so alternative providers (a self-hosted relay's own signaling endpoint, a chosen paste host) drop in.
- No dependency on any single blockable domain: if the default rendezvous is unreachable, b2p tries the next configured provider and says so.

---

## 5. Transport negotiation

Deterministic, with per-stage budgets so it degrades quickly instead of hanging:

1. Both peers complete the PAKE over rendezvous → session key established.
2. Each advertises an ordered capability set: `[LAN?, WebRTC(stun,turn?), relay?]`.
3. Attempt in order, in parallel where cheap:
   - LAN discovery: ~1.5 s window.
   - WebRTC ICE: gather + connectivity checks, ~8 s; STUN first, escalate to TURN if no candidate pair forms.
   - Relay: only if a relay URL is known (configured or advertised by receiver).
4. First transport to reach "connected + authenticated" wins; others are cancelled.
5. On total failure, emit a structured diagnosis (§6), never a generic message.

---

## 6. Diagnostics: `b2p doctor`

Automates the investigation that currently takes a human 20 minutes. Run automatically on failure, or manually anytime. Checks and sample verdicts:

- **DNS:** resolve the rendezvous/relay host; compare against expected ranges. *"Host resolves to 146.112.61.106 (a Cisco Umbrella block IP) — this network is DNS-filtering it."*
- **TLS interception:** read the peer cert issuer. *"Certificates are re-signed by `BTG Pactual-RootCA` — this network runs TLS inspection. b2p is using the OS trust store, so this is fine."* (Or, if the store lacks it: *"…add its CA or pass `--cafile`."*)
- **UDP / STUN:** send a STUN binding request. *"UDP egress OK, STUN reachable — WebRTC should work."* vs *"No STUN response — UDP likely blocked; will need TURN-over-443 or a relay."*
- **Rendezvous:** can we publish/subscribe on the default provider? Name the fallback if not.
- **Verdict line:** the single recommended transport, or the single blocking reason.

---

## 7. Trust & TLS (P0 correctness fix)

- Load roots via **`rustls-native-certs`** (the OS store) instead of a bundled root set. Honor `SSL_CERT_FILE`/`SSL_CERT_DIR` and add an explicit `--cafile`.
- Effect: b2p works *with* corporate TLS inspection (the proxy's root is already trusted system-wide) instead of failing with `invalid peer certificate: UnknownIssuer`. This alone unbreaks every HTTPS path on inspected networks.
- Payload confidentiality does not depend on the transport TLS: it is E2E-encrypted regardless, so an inspecting proxy sees only ciphertext.

---

## 8. CLI & UX

```
b2p receive [--out DIR] [--direct] [--relay URL] [--rendezvous URL] [--yes]
    → prints:  code: 4-tunnel-mosaic      (and a b2p:// URL)
    → "Waiting for sender…"  with live transport/negotiation status

b2p send <code> [PATHS…] [--text TEXT] [--relay URL] [--rendezvous URL]
    → negotiates transport, shows the chosen path, streams with a progress bar

b2p doctor [<code|host>]      → network capability report + recommended transport
b2p relay  [--listen ADDR]    → run the self-hostable relay/signaling binary
```

- **Resume:** chunked + content-addressed so an interrupted transfer restarts from the last acked block (large-file robustness).
- **Progress & transparency:** always show which transport won (`via WebRTC (STUN)`, `via relay (self-hosted)`, `via LAN`) so behavior is legible.
- **Backwards compatibility:** accept v1 `https://…trycloudflare.com#…` codes when that transport happens to be reachable, but it is now just one option, not the architecture.

---

## 9. Security model

**End-to-end confidentiality & integrity** via PAKE-derived key + AEAD stream. Holds regardless of transport.

What each party can observe:

| Party | Sees | Cannot see |
| --- | --- | --- |
| Rendezvous (ntfy) | an opaque topic id, timing, PAKE public values, encrypted SDP | code, session key, file content, filenames |
| TURN / relay | ciphertext blocks, an opaque id, size/timing | key, plaintext, filenames |
| TLS-inspecting proxy | that a transfer occurs, endpoints, byte volume | payload (E2E-encrypted under the proxy's view) |
| Network passive observer | endpoints, volume | payload |

- **Code security:** SPAKE2 makes the low-entropy code safe against an untrusted rendezvous; codes are single-use and time-boxed; an active MITM on signaling that guesses wrong is detected at key confirmation and the transfer aborts.
- **Metadata:** b2p does not hide that a transfer is happening or to/from where — that is deliberate (§11). It hides *content*.

---

## 10. Phasing / migration

| Phase | Scope | Value |
| --- | --- | --- |
| **P0** | OS trust store + `b2p doctor` + layered error messages | Unbreaks inspected networks; stops misleading errors. Ship first. |
| **P1** | Rendezvous abstraction (ntfy default) + **WebRTC transport (STUN)** + PAKE code | Real P2P that works on this network without any tunnel. |
| **P2** | Self-hostable relay/signaling binary + TURN fallback (self-host + TLS-443) | Works when P2P can't form or UDP is blocked. |
| **P3** | LAN/mDNS auto-direct, store-and-forward (self-host), resume | Speed, async, large-file robustness. |

P0 is independently shippable and fixes the reported bug immediately; each later phase adds a transport without changing the code format or crypto.

---

## 11. Scope: modes, contexts, and what b2p core ships

v2 is **open and multi-mode by design** (Appendix A): transports and rendezvous are plugins, so b2p adapts to many contexts — a LAN, the open internet, a NAT'd home link, self-hosted infrastructure, or fully offline. No single principle like *"always cooperate with the network"* is imposed on every mode, because the right behavior genuinely differs by context and different deployments run on very different networks.

What the **core project** maintains is scoped, though — this bounds what the core *binary* ships and supports, not what the open architecture permits:

- **Ships in core:** transports that use *permitted connectivity* (WebRTC/STUN/TURN, LAN, mainstream HTTPS) or *the operator's own infrastructure* (self-hosted relay/rendezvous/TURN, cloud/git backends under the user's own credentials) — always E2E-encrypted, and trusting the OS trust store so inspecting proxies pass b2p rather than break it.
- **Not maintained in core, but open to plugins:** transports whose function depends on traffic obfuscation/mimicry, domain fronting, SNI spoofing, or blocklist-evasion domain cycling. These are not rejected on principle — the open Transport/Rendezvous interfaces (Appendix A) let anyone add them as out-of-tree plugins. The core *binary* simply doesn't ship or maintain them, to keep its threat and abuse profile predictable.
- **Honest DNS resolution ships:** resolving a tunnel host over DoH against a *truthful* public resolver when the local resolver is lying (e.g. sinkholing `*.trycloudflare.com` to a block page) is honest, not evasion — you ask a correct resolver by name, spoofing no one. It ships on the `--tunnel` path (the default WebRTC transport never resolves a tunnel host, so DoH does not apply there).

---

## Appendix A — Transport & rendezvous modes (the open catalog)

v2 core is transport-agnostic: a **mode** is a plugin behind two small interfaces. This is what makes v2 *open* — new modes for new network contexts drop in without touching the core, so the same binary suits a LAN, the open internet, a self-hosted deployment, or an offline exchange.

```rust
// Rendezvous: run the PAKE + exchange transport candidates. Carries only ciphertext / public values.
trait Rendezvous {
    async fn publish(&self, topic: &str, frame: &[u8]);
    async fn subscribe(&self, topic: &str) -> Stream<Vec<u8>>;
}

// Transport: move the encrypted payload once peers have met.
trait Transport {
    async fn offer(&self) -> Candidate;              // receiver side
    async fn connect(&self, c: Candidate) -> Conn;   // sender side
    fn kind(&self) -> Kind;
}
```

Each peer advertises the modes it supports; negotiation (§5) picks the first that works for both. The modes below were surfaced by probing the inspected test network — but **"Tested here" reflects only that one network**. Other test machines on other networks will permit and block different things; keeping modes pluggable is exactly how b2p covers that spread instead of betting on one transport.

| Mode | Best context | Mechanism | Tested here | Needs |
| --- | --- | --- | --- | --- |
| **LAN direct** | two machines on one network | mDNS/DNS-SD discovery → TCP/QUIC | standard (not re-probed) | nothing |
| **WebRTC / STUN** | general internet, behind NAT | ICE + DTLS data channel | ✅ STUN round-trip (Google + Cloudflare) | nothing |
| **WebRTC / TURN** | symmetric NAT, or UDP blocked | TURN relay (UDP 3478 / TLS 443) | partial — STUN worked; TURN-over-443 not run | TURN (self-host coturn, or provider) |
| **Self-hosted relay** | teams, full control, off public infra | HTTPS PUT/GET store-and-forward | ✅ HTTPS relay class reachable | a host you run |
| **ntfy rendezvous** *(default)* | zero-config signaling | pub/sub over HTTP | ✅ publish + read round-trip verified | nothing |
| **Paste dead-drop** | tiny manual transfers | HTTP PUT to `0x0.st` / `paste.rs` | reachable (GET 200) | nothing |
| **Cloud-storage dead-drop** | async, large files, existing account | pre-signed S3 / GCS / R2 URL | ✅ endpoints reachable | cloud creds |
| **Git-host dead-drop** | developers | Gist / repo via API | ✅ reachable | a token |
| **Offline / sneakernet** | air-gapped, maximum privacy | QR-code / copy-paste SDP — no rendezvous server at all | n/a (no network) | nothing |

### Validated live on the inspected network

- **UDP egress + STUN** — binding responses from `stun.l.google.com:19302` and `stun.cloudflare.com:3478` (32-byte replies) → WebRTC is viable here.
- **ntfy rendezvous round-trip** — `POST ntfy.sh/<topic>` (HTTP 200) then `GET …/json?poll=1` returned the exact published frame (msg id `wMjR0qFr7AmV`) → the default signaling path works end-to-end *through* the `BTG Pactual` inspection proxy.
- **HTTPS relay / dead-drop class** — `ntfy.sh`, `0x0.st`, `paste.rs`, GitHub/GitLab/Codeberg, GCS/S3 reachable; tunnels (`trycloudflare` / `ngrok` / `bore`) and social APIs (`discord` / `telegram`) blocked.

### Recommended default stack (zero bureaucracy)

`b2p receive` advertises **LAN + WebRTC(STUN) + ntfy-rendezvous**; TURN and relay engage only if negotiation fails. No account, no config, and it works on every network probed so far *that permits standard connectivity*. For locked-down or self-owned contexts, point `--relay` / `--rendezvous` / `--turn` at your own host and b2p uses that mode instead.

