# Reading and writing messages faster

*A proposal, not part of COSIGN.md. Written 2026-10-25 after a messaging app (Keychat) was
slow and awkward against Marble.*

## The problem

A signer that holds the whole key decrypts a message locally, in microseconds. Cosign's key
is split: a shared secret with another person is worked out from this device's points and a
server's, so **every new correspondent costs a round trip to a server over relays**
(`ecdh_req`/`ecdh_res`, COSIGN.md §5.6). Signing has the same shape, but a person signs now
and then, while a messaging app decrypts a whole conversation list at once — dozens of
round trips where Amber does dozens of local computations.

The shared secret is kept for ten minutes in memory, so repeats are free and a cold start is
not. Opening an app with forty conversations is forty round trips, however fast each one is.

## What would actually help, and what wouldn't

**Batching helps only where we know several correspondents at once.** NIP-55's content
provider is asked for one decryption at a time by the app, and nothing in NIP-55 lets an app
ask for several. So batching does nothing for Keychat as it stands. It *would* help:

- Marble's own screens, when it reads a conversation list of its own;
- a NIP-46 site that asks repeatedly, where the phone can see the pattern;
- restoring on a new phone, where every conversation is cold at once.

**What helps a NIP-55 messaging app is the cache**, and that is a trade-off for the user to
make, not a protocol change — see the last section.

## Asking for several at once

The wire, as it is today:

    device → server   {type: "ecdh_req", id, peerX, participants, grant}
    server → device   {type: "ecdh_res", id, ok: true, points: [...], point}

With several, the device sends `peers` **as well as** `peerX`:

    device → server   {type: "ecdh_req", id, peerX, peers: [x1, x2, …], participants, grant}
    server → device   {type: "ecdh_res", id, ok: true, points: [...], point,
                       many: [{peerX: x1, points: [...]}, {peerX: x2, points: [...]}, …]}

`peerX` stays what it is now and is the first of `peers`, so **an older server answers it and
ignores the rest**: the device gets one correspondent's partial and asks again for the others,
exactly as today. A newer server answers `many` as well. No version negotiation, no discovery,
and nothing breaks either way.

### The server

- Same gate, per request, unchanged: a live device only, never the paper or a removed member,
  the shares taking part must make the threshold, and the app's grant must be live (§5.6).
- `peers`: at most 50 keys, each a valid x-only key, duplicates dropped. Anything beyond the
  cap is left out of `many` rather than refused, and the device asks for the rest.
- An answer stays inside one member message (a partial is 66 characters; 50 of them with their
  keys is about 7 KB, well under the 64 KB NIP-44 limit and the 24 KB part size).
- Nothing is logged about who the correspondents are, as now.

### The app

- `sharedX(peer)` becomes the single-peer face of `sharedXs(peers)`, which asks once and fills
  the cache for all of them. The existing nip44/nip04 calls are unchanged.
- A `warm(peers)` call for the places that know a list up front.
- One answer that doesn't verify doesn't spoil the rest: each correspondent's partial is
  checked on its own.

## The cache, which is the real lever for a messaging app

Today the shared secret lives ten minutes in memory and is gone when the signer process stops.
Keeping it longer, or on disk, would make a messaging app feel normal — and would weaken what
the servers are for. A stored shared secret lets whoever holds the phone's storage read that
correspondent's messages without any server taking part, so the "a server sees every
decryption" property (§5.6, §12) would hold only until the first one.

That is the user's decision, not ours to take quietly. Written down here so it is made on
purpose:

- **Ten minutes, in memory** (today): every cold start pays a round trip per correspondent.
- **Longer in memory** (an hour, say): no new exposure beyond the signer process's lifetime,
  helps an app used through the day.
- **On disk, encrypted with the device's key**: a messaging app feels local; a stolen unlocked
  phone reads old conversations without the servers, and reporting the device lost no longer
  stops that for correspondents whose secret was cached.

## Order

1. The cache decision, since it is what a messaging app actually feels, and it needs the user.
2. `peers` on the wire: small, backwards compatible, and it helps restoring and our own screens.
3. NIP-55's `permissions` extra at connect, so an app that asks up front isn't prompted per
   type (Amber does this; Keychat sends it).
