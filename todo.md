# b2p — TODO / backlog

Follow-ups for the relay-only b2p. History: v0.4.0 shipped the always-relay
transport (`docs/superpowers/specs/2026-07-23-b2p-v2-p2b-relay-design.md`);
the pre-relay WebRTC (`--p2p`) and Cloudflare-tunnel (`--tunnel`) stacks were
**removed** after the relay was field-confirmed — they failed on the networks
that matter (CGNAT/symmetric NAT/UDP-blocked), which is why the relay exists.
Their history lives in git and in `docs/superpowers/specs/`.

## Relay transport

- [ ] **Receiver-side progress bar / status lines** (receive_relay passes
      `progress: None` today).
- [ ] **Text snippets print as `Done: <text>` on stderr** — print the snippet
      itself to stdout (pipe-friendly), like the old tunnel path did.
- [ ] **Custom-domain recipe** for networks that category-block
      `*.workers.dev` (attach a domain to the Worker; doc + doctor hint).
- [ ] **HTTP CONNECT proxy support** for corporate proxies that require
      explicit proxy configuration (doctor at least names the failure today).
- [ ] **Store-and-forward via R2 / self-hosted relay** — receiver can be
      offline; rooms currently require both peers live.
- [ ] **LAN / mDNS auto-direct** — advertise `_b2p._tcp` and connect directly
      when both peers share a subnet; would be a second transport and would
      reopen the negotiation question deferred from v2.

## relay serve

- [ ] Built-in ACME/Let's Encrypt certs — only with real demand (Caddy
      covers it).
- [ ] Metrics endpoint / rate limiting — only with real demand.
- [ ] Standalone protocol document if third-party relay implementations
      appear.
- [ ] Prompt reaping of a send-parked connection: a task blocked in
      `sink.send().await` on a backpressured (half-open) socket doesn't
      observe the graceful-shutdown signal or its slot removal until the OS
      TCP write finally errors (possibly minutes), pinning its semaphore
      permit + bounded queue. Memory is already bounded (the DoS fix holds);
      this is a liveness nicety — wrap the outbound send in a timeout if a
      public relay ever needs prompt shutdown of wedged clients.

## Receive flow

- [ ] **`Kind::Tar` (folder) clobber check** in the accept flow — only a
      `Kind::File` destination is checked before overwrite; a folder transfer
      can overwrite files under `--out` without prompting, and `--yes`
      bypasses it entirely.
- [ ] **Blocking stdin in the accept prompt** runs on a runtime worker — on a
      1-core box it can stall the WebSocket keepalives. Use
      `spawn_blocking` / `block_in_place`.

## Internals

- [ ] **`Store` per-chunk persistence write-amplification** — at 16 KiB
      frames, `state.json` is rewritten every chunk (O(n²) writes). Resume
      depends on the staged chunks, but the state file could be batched
      (e.g. every N chunks / on drop) without losing much resume granularity.
- [ ] **Orphaned `.b2p-partial` staging cleanup** for abandoned transfers.

## Housekeeping

- [ ] Consider a `--code-expiry` / `--timeout` flag for the receiver's
      24 h wait window.
