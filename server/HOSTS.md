# Hosts

A server's member logic is a core with no I/O (`core/`): `openGroup(loaded, io)` is one
membership in one group, and everything outside it goes through the `Io` its host hands
it (`core/io.ts`):

| `Io`                         | what for                                                       |
| ---------------------------- | -------------------------------------------------------------- |
| `publish(e)`                 | a sealed member message, or an answer to a site, on the group's relays |
| `listen(relays)`             | a site's or a new device's own relays, for this group           |
| `publishOut(relays, e)`, `query(relays, filter)` | one-off: an undo to your write relays; the archive, copies of what's deleted |
| `push(url)`                  | wake a device through ntfy                                      |
| `now()`, `trustedNow()`      | this machine's clock (timeouts), the network's (the future)     |
| `save.state/archive/entry/saved` | keep state.json, archive.json, history.jsonl, saved.jsonl   |
| `note(text)`                 | a log line                                                      |

The host calls `onEvent(e)` with each event addressed to the group's member key or signer
key, `start()` once, and `tick()` every 10 s (pings, forgetting old answers, the archive
every 15 min). Rounds wait with `setTimeout` inside the core; that's all it needs of its
runtime besides WebCrypto, and `node:crypto` for NIP-04's AES-CBC (`nodejs_compat` on
Workers, or `@noble/ciphers`, which nostr-tools already brings).

Taking on a new group is `core/enroll.ts`: `enroll_key` hands out a member key derived
from the host key, and `enroll { how, … }` runs one of `enrollers` — `dealt` today, which
checks the share against the group's share points; DKG goes beside it under its own `how`.

## Node (`server.ts`, today)

One process, any number of groups: one relay pool, one subscription per relay naming
every group's member and signer keys (and the host key), each event routed by its `p`
tag. Files per group as before (`files.ts`), `--root` for a host key and `groups/`.

## A Cloudflare Worker (designed, not built)

The shape §9.1 of the spec describes: the server *is* a relay for its users' member
traffic. Devices and the other servers add its `wss://` address to the group's relays;
it needs no outbound connections, so its Durable Object can hibernate between messages.

- **Inbound WebSocket, NIP-01.** A Durable Object accepts relay connections (hibernation
  API). An `EVENT` of kind 28001 p-tagged to a key it serves goes to that group's
  `onEvent`; a `REQ` for events p-tagged to someone else is how a phone or the other
  server hears this one. `publish(e)` hands the event to every open socket whose
  subscription matches (and nothing is stored: member traffic is ephemeral). One DO per
  host to start; one per group behind a router when it needs to scale.
- **No NIP-46 signer key, no dialing out.** A public server MUST NOT hold the signer key
  (§9.2), so groups enrolled here have none (`signer` is optional; the core then serves
  no sites) and `listen()` is a no-op. `publishOut`/`query` open a short outbound
  WebSocket inside the request, or are left to the phone.
- **Shares in Workers KV, never in the DO.** A SQLite-backed Durable Object keeps a
  30-day point-in-time history of everything it stored (`~/bothy/docs/key-management.md`
  §2.1): an overwritten or deleted share would still be recoverable, which defeats
  refresh and removal. So the Worker's `save.state(S)` splits the state: the secret part
  (`self.sk`, `self.share`/`self.shares`, `pairing`) goes to KV under `share:<group id>`,
  written only when it changes and deleted for real when it goes; the rest (sites,
  tickets, changes, archive, history — nothing that signs) can live in the DO's SQLite.
  KV is eventually consistent across locations, but a group's DO is in one place and
  keeps the share in memory once read; an enrollment's write is read back where it was
  made.
- **Timers.** `tick()` from a DO alarm. Pings every 10 s would keep it awake: before this
  host, the core should move to on-demand liveness (§9.4: ping a partner just before a
  round, count any message as a ping), which helps the Node host too.
- **Time.** `Date.now()` in a Worker only moves between I/O, which is fine for timeouts;
  `trustedNow()` can be `Date.now()` (Cloudflare's clock), so no `clock.ts` fetches.
- **The FROST WebAssembly.** Workers can't compile WebAssembly from bytes at run time;
  the module has to be uploaded with the Worker. `sign.ts` loads `frost-wasm/` through
  `createRequire` (wasm-bindgen's `nodejs` target, which reads the file); the Worker gets
  a second build from the same `frost/` crate with `--target web` (or `bundler`),
  imported as a module, behind a two-line loader so the rest of `sign.ts` is shared.
  Both builds are committed, and CI rebuilds them and fails on any difference:
  a pinned toolchain (`rust-toolchain.toml`), `cargo build --locked --release --target
  wasm32-unknown-unknown --features wasm`, `wasm-bindgen` at the version in `Cargo.lock`,
  `--remap-path-prefix` so the paths are the same on any machine, then
  `git diff --exit-code server/frost-wasm worker/frost-wasm`. That way what runs is
  what the source says, and nobody has to trust a binary in the repository.

### Standalone, or a switchable module inside bothy

Standalone, it's its own Worker with a DO binding and a KV namespace binding
(`COSIGN_SHARES`).

Inside bothy it's a module the relay's DO calls for kind 28001 events p-tagged to a key
the module serves, off unless the operator adds the KV binding. bothy deliberately has
no KV binding (a clean deploy asks for nothing but a name), so the module costs a bothy
that doesn't want it nothing, and one that does must opt in by adding the namespace;
without it the module refuses to enroll, rather than fall back to DO storage. bothy's
own rule still applies: a host that holds a user's backup blob must not also hold their
share (key-management.md §2.2), so an enrollment from a user whose blob it stores is
refused.
