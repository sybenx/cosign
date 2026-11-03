# Keykin module: Doors and grants

Draft 19 · 2026-11-03 · module of [Keykin Core](../core.md) draft 14.13 · not built

Sites and apps reach a Keykin account through the doors they already use: NIP-07 (browser extension),
NIP-55 (Android), NIP-46 (remote signer) and the QRST signer-ticket. **Sites change nothing.** This module
says how a member device answers each door, what a site is allowed to do (its **grant**), how grants are
kept, synced and revoked, and how a borrowed computer signs in without holding any piece. The core wins
any disagreement, and nothing here may weaken it.

The bar is the core's: an nsec in a password manager. Signing in must be as quick as pasting an nsec into
a site, and routine signing must stay silent.

## 1. Grants

A **grant** is a site's permission to use the account. It lives on the user's devices, never on a Keykin
server (a watching server sees only public keys, §3.3).

```jsonc
{ "id": "<16 random bytes>",
  "v": <integer, raised by the maker at every change>,
  "site": "<origin, or Android package name + signing-certificate SHA-256, or NIP-46 client pubkey>",
  "says": "<the name the site gave itself, shown as 'says it is …'>",
  "door": "nip07" | "nip55" | "nip46",
  "connection": "<browser profile or app install; for nip46 the client pubkey, so the same as site>",
  "relays": ["<NIP-46 relays, nip46 only>"],
  "signer": "<the per-site NIP-46 signer public key, nip46 only>",
  "scopes": ["sign-in", "post", "lists", "dms", "private-data", "wallet"],
  "borrowed": false,
  "helper": false,
  "made": <unix>, "expiry": "unused-90d" | <unix> | null,
  "by": "<member key of the device that made it: its home>",
  "by_sig": "<BIP-340 by that member key over SHA-256('keykin-grant/1' ‖ g ‖ JCS(entry without by_sig))>" }
```

A grant is named by `(by, id)`. The signer **secret** key is never in an entry: it stays on its home (§3.3).

**Scopes.** A site gets only what it was granted, and asks again for more. The device decides which scope
a request needs by looking at what it is.

| Scope | Lets the site | Asked |
|---|---|---|
| `sign-in` | `get_public_key`; relay auth (kind 22242); NIP-98 (`GET`, `POST`; `PUT`, `PATCH` under `post`) and Blossom (`upload`, `list`, `get`, `media`) tokens for the site's **own host**; for any other host, once per host: "Let *site* sign in to *nostr.build* as you?". A Blossom `upload`, `media` or `get` token bound to one blob by an `x` tag is silent, `server` tag or not; a `list` token, or one with no `x` tag, counts as another host | at connect |
| `post` | ordinary events: notes, reactions, reposts, zap requests, deletions (judged by Device policy), articles, app data (kind 30078) except the `keykin-` prefix; **encrypting** to the account's own key; NIP-98 `PUT`/`PATCH` tokens for the site's own host; Blossom `t=delete` and NIP-98 `DELETE` tokens, a Confirm card or declined (Device policy §2) | at connect (default on) |
| `lists` | the profile (0); follows, mutes and other lists (3, 10000, and the other list and set kinds Device policy §2 lists exactly); relay lists (10002, 10050); and decrypting the private items of those lists | the first time it tries |
| `dms` | NIP-04/NIP-44 encrypt and decrypt **with other people's keys**, NIP-59 unwrap, the person's own sent NIP-17 copies (below), and NIP-55 `decrypt_zap_event` | the first time: "Let *site* read and send your messages?" |
| `wallet` | NIP-60/61 wallet events (17375, 37375, 7375, 7376, 7374), payment targets (10019), and decrypting them | the first time: "Let *site* use your ecash wallet?" |
| `private-data` | any other **decrypt** of something encrypted to the account's own key (notes, private app data) | the first time: "Let *site* read your private notes and app data?" |

- **Which scope a decrypt needs.** The device parses the peer key as a 32-byte x-coordinate and compares
  bytes to tell a decrypt-to-self from a message.
  - For a decrypt-to-self it **decodes** the payload (refusing non-canonical base64) and matches the
    decoded bytes against the account's own events. An event counts as evidence only if its ciphertext
    was **encrypted for the same grant, or the member app, that signed it** (encrypt records are part of
    the signed metadata, Device policy §1). So no site, alone or with a second site, can plant a copy.
    At import and at join, the device records every list ciphertext it fetches as the member app's. With
    no metadata to hand, a list kind's ciphertext that matches no wallet or private-data event needs
    `lists`.
  - **Whatever the evidence, a release under `lists` checks the plaintext first**: the device decrypts
    locally and releases it only if it is a tag array whose tag names are all ones that list kind's spec
    allows (for example `p`, `e`, `a`, `t`, `r`, `word`, `emoji`, `group`, `relay`), with no `privkey`,
    `mint`, `proofs`, `direction`, `amount` or other wallet fields. Anything else needs the scope it looks like, or
    `private-data`.
  - If the bytes match events of several kinds, **the most private one wins** (`private-data`, then
    `wallet`, then `lists`). Bytes it can't match need `private-data` (live finding #10).
  - **NIP-17 sent copies and notes to self.** Bytes it can't match are decrypted locally. Under `dms` the
    plaintext is released only if it parses as a rumor with `pubkey == g` and kind 14, 15, 7 or 5;
    otherwise it needs `private-data`. A matched kind 4 or 14 to self is `dms`. Wallet and list plaintexts
    are tag arrays, never rumors.
- **Deletions under `post`** may name any ordinary event of the account; Device policy judges them,
  silently only for the site's own events.
- **Decrypts in bulk.** Site decrypts arriving within about 50 ms go in one `ecdh` request with many
  points (core §5.5); the site's own decrypts always go first, and a prefetch batch yields to them; above
  about 30 a minute (per device, a reference that keeps the account under core §9.3's figure) it batches
  more and waits, so a client decrypting junk one by one can't use up the account's
  message budget. On a site's first NIP-59 unwrap under `dms`, the device fetches the account's kind
  1059 wraps from its 10050 relays and sends all their ephemeral keys in a few large `ecdh` batches; NIP-04
  peers seen in kind 4 events likewise: at most 2,000 keys per site connection per 10 minutes, from the
  last 90 days, newest first, so spam wraps can't use up the account's message budget. This cap is for the
  prefetch only; the site's own decrypt requests are answered first and aren't counted in it. A conversation key MAY be cached **in memory only**, for at most 10
  minutes, and is never written to storage. Later decrypts answer locally.
- **Permissions at connect.** A client's decrypt `perms` grant nothing at connect; each scope is asked the
  first time it is needed.
- Destructive events are judged by the Device policy module, whatever the scopes.
- Relay auth, NIP-98 and Blossom tokens a site gets signed are never accepted as authority by any Keykin
  endpoint.

**Expiry.** By default a grant never expires while it is used, and expires after 90 days unused.

- The home records `last_used` and republishes it at most once a day, only when the day changes.
- The person may pick a fixed 30, 60 or 90 days, or never.
- An expired grant stays listed, grey, below the active ones, on its home only. Signing in again from that
  site asks the connect question again and makes a **new** entry (and, for NIP-46, a new signer key).

**Listing and signing out.** Grants are grouped by site, with each connection listed inside it ("Chrome
on *Work PC*", "*Laptop* extension", "*Phone*") and when it was last used. The person can sign out one
connection, the whole site everywhere, or **every site at once**; before that last one, the device fetches
every maker's newest grant event, and also sends each home, the helper included, a **wildcard tombstone**
`{home, all: true, before: <unix>}` that ends every grant whose `made` is before then (after a takeover,
`made` is the original's), any not yet published included. Only the home applies it; other devices use it
for listing. The wildcard is also published in the ending device's event.

## 2. Keeping and syncing grants

- **One event per device.** Each device publishes its grants as a kind 30078 event, signed by the account,
  with `d = "keykin-grants:" ‖ hex(first 16 bytes of HMAC-SHA256(HKDF-SHA256(base data key,
  "keykin-grants-d/1"), member key))`, so relays can't link the event to a member key. It carries a
  `["state", <state hash>]` tag naming the state whose data key encrypts it. Its content is
  XChaCha20-Poly1305 under `HKDF-SHA256(salt = empty, ikm = dk(S), info = "keykin-grants/1", L = 32)` for
  the **current** state (re-encrypted after each redeal), with associated data `g ‖ d ‖ state hash`, as
  `base64(24-byte nonce ‖ ciphertext)`. Expired entries are pruned from it, and once a part's encrypted, base64-encoded content
  would pass 24 KB (under strfry's and most relays' 32–64 KB limits) it is split into `d ‖ ":1"`, `":2"`, …, each part its own encrypted chunk of the
  JCS-encoded set, all with the same `created_at` and a `["parts", n]` tag; the parts count as one
  event, newest only when every part is present. Inside, `maker_sig` is the maker's member-key signature over `"keykin-grant-set/1"
  ‖ g ‖ d ‖ created_at ‖ SHA-256(JCS({entries, tombstones, ended, union}))`. The maker publishes at `created_at = max(now,
  last + 1)`.
- **The counted relays** are the account's **live recorded relays**: the epoch record's relays plus the
  current seat holders' relays, leaving out a relay that has failed **10 tries over at least 7 days, each
  made while other counted relays answered** (so a device's own downtime never drops a relay), and one
  that refused with `blocked:` or `restricted:`, or still answered reads with `CLOSED` after the device's
  NIP-42 sign-in (the device signs the relay's challenge with the account, as any client does), on three
  tries spread over a day; a dropped relay is retried weekly and counts again once it answers, and the
  device fetches from it before writing to it again. A size refusal makes the device split into smaller
  parts instead. A relay that accepts writes but never serves reads doesn't count, and one that refuses writes but answers
  reads counts only for fetches. An answer to a fetch is an `EOSE`, never a `CLOSED` or a
  `NOTICE`. When the set changes, each device republishes its own grant event to a majority of the new
  set; it also re-sends its own event weekly, since an `OK` is not a promise to keep it.
- **Publishing.** A home stores a change to its grants before it publishes it. A publish counts once **more
  than half of the counted relays** accept every part (an `OK`); it retries with back-off until then. It
  also writes to its NIP-65 write relays, which don't count.
- **A member whose storage can be restored adopts its own newest event**: every member whose grant store
  could come back from a backup, a system image, a reverted virtual machine or a copied profile. That is
  every browser extension and every desktop app; it is not an iPhone or iPad app keeping grants in
  app-group files excluded from backup, or an Android app keeping them in `noBackupFilesDir`, in either
  case encrypted under a key that never leaves the device.
  - At start, at each 5-minute inbox fetch and before each publish or takeover, it first catches up the
    change set (core §3.2, skipping a server that takes more than 2 seconds), then fetches its own newest
    grant event. A fetch is good once **more than half of the counted relays, and more than half of the
    part of its last publish's set that is still counted**, answer (the current set alone when fewer than
    three of the last set remain, or the device has never published), so any good fetch and any counted
    publish share a relay. Re-sending an unchanged event needs no fetch.
    A newer own event from any relay is adopted at once; one it can't decrypt or that misses a part is
    ignored once the fetch is otherwise good, and the device publishes above it. A device records each
    event (its parts and date) before sending any part, so a publish cut short never leaves it stuck. A
    re-send is a publish and moves the last publish's set. If no server answers the catch-up within 2
    seconds, the device fetches anyway and repeats the catch-up at its next 5-minute fetch. At start it
    also reads the other devices' ended ids, and republishes when its union grows.
  - Until the first good fetch it waits up to 3 seconds, then answers `get_public_key` and grants made since
    its last publish, gives other requests `try-later:`, retries every 10 seconds, and shows one quiet line
    if relays can't be reached. It never publishes after a failed fetch.
  - **With fewer than three counted relays** a majority can't survive one relay down. There the device still
    fetches from every reachable relay before it publishes, never publishes a set that drops an id in the
    union or an entry it has seen ended, and otherwise answers from its own state. The person's relays change only with server seats
    (core §6.7.2).
  - It merges ended ids and tombstones from **any** of its own events, whatever their date. It takes an
    event's entries over **only if it is newer than its own last publish**, and then drops only entries
    **made before** that event that are missing from it; for each entry the higher `v` wins (ties as
    below). A restart of the background worker within 5 minutes of a good fetch, measured by a clock that survives
    only in memory, doesn't count as a start.
- **Grants are stored like shares** (core §7.3): grants, ended lists and signer keys are excluded from
  restorable backups, so restoring a device from a backup brings back no grant. An extension keeps them in
  its local storage, never in browser sync storage. (A copied browser profile is a copy of a member, as
  core §10 says, which the check above handles.)
- **A grant that left its maker's event never comes back.** Each device's grant event keeps a compact
  **ended list** of `{id, until}`: the 16-byte ids of its grants that were **ended** (signed out, revoked
  or ended by a removal; an expiry needs no entry, since a restored copy sees it expired too), and for
  helper grants the signer key's hash, matched against a helper entry's signer key; `until` is the grant's
  fixed expiry plus 30 days, or one year after it ended for an "unused" or a never-expiring grant. Every device also keeps the **union** of all
  makers' ended lists, reading the others' grant events at each 5-minute fetch (with `since` a day before the last read), and **carries the union in
  its own event** too, so relays hold each ended id in several devices' events. Union entries are `{by, id,
  until}`, kept only while `by` is a member and up to `until`, and `maker_sig` covers the union too; the welcome's and
  handover's `grants` field carries it, and a home merges the ids of **its own** grants it learns into its
  own list before it publishes. An
  id is dropped after its `until`. Any entry whose id is in the union is a resurrection: ignored everywhere. No tombstone needs re-sending
  to devices: a maker drops it at its next read of the union. The helper reads no union, so a helper grant
  that reappears in a `helper_report` is sent its tombstone again. (A handover keeps the ids, so moved grants are no
  resurrection.)
- **Tombstones** are kept until the maker's newest event no longer has the entry, and at least 30 days;
  for helper grants, until the helper's report no longer lists them. Each device also applies, for its own
  grants, any tombstone it finds in other devices' events. A home answers `revoked:` for 30 days for a
  NIP-46 grant it dropped (so its signer key tells the site); NIP-07 and NIP-55 sites, and second-browser
  origins (which make a fresh key on the next sign-in), can sign in again at once. For equal `v`, the
  narrower scopes win (the scope set that is a subset of the other's), and otherwise the later event's
  copy.
- No tombstone is sent to the helper because of a device's removal; the helper ends those grants itself
  (Helper module §2), so kept ones survive.
- **Only each device's newest event counts.** For each maker, a device uses only the newest event (highest
  `created_at`) whose `maker_sig` verifies for the member whose `d` it is, so no other member can hide or
  bring back a device's entries. An entry missing from it is gone, and a device keeps the highest `v` seen
  per `(by, id)` and refuses lower ones. A home never re-adds an entry it ended, whatever relays say. The
  grant set is the union across makers.
- **Every entry is signed by its maker** (`by_sig`). A device accepts an entry only if:
  - the event is account-signed and decrypts under the data key of the state it names;
  - `by` is a current device in its own view;
  - `by_sig` verifies, and `by` is the maker whose event it came from.
- **When a device is removed, every grant it made is revoked** by every device, because a thief's device
  could plant grants while it was a member. The person sees the list, with what to do for each NIP-46
  site homed there: "Grants made by *Laptop* were signed out. Sign out of *Coracle* on that site too, then
  sign in again."
  - The one exception is a `self` remove (core §4.6) or a handover: the extension first fetches its inbox
    and applies every tombstone; then the machine's app takes the grants over (its signer keys over
    native messaging, §3.3), re-signs them under its own key with `"was": [by, id]` naming the old entry
    (the one way a grant is made without a human act), and sends its `watch_set`. A tombstone for the old
    name also ends the new entry, and old-name tombstones are kept and mapped through `was` after the
    takeover, so a grant ended during it stays ended. Device policy follows `was` for its metadata. Other devices show no sign-out screen for it.
- **Ends made by another device** are tombstones `(by, id)`, published in the ending device's event and
  **also sent as deliveries** (core §7.1) with an `ask` push: one delivery per home per action, carrying
  every tombstone of that action for that home, so the home drops the entries at once. For a helper-homed
  grant, the tombstone names the grant by its **signer public key**, which both the entry and the helper's
  report carry.
- **Only a human act** makes a new grant (live finding #15): a scanned code, a pasted link, or an explicit
  "Allow *app*" on the device the app is on. For NIP-55, the same app (same package and certificate) can
  be allowed again on that phone.
- **Before answering any site request**, on any door, a device must have fetched its inbox, or had any
  answered exchange with a server (a co-sign, an `ecdh`), within the last 30 seconds (reference), and a
  real inbox fetch within the last 5 minutes, skipping a server that takes more than 2 seconds. A tombstone
  delivery's `ask` push makes it fetch at once. If no server answers, it answers only requests that need no
  round. So "Sign out everywhere" and End take effect within seconds where the push arrives, and within 5
  minutes everywhere.
- **New devices.** This module adds a `grants` field (every current entry, tombstone and the union of ended
  ids) to the welcome
  and the handover (core §4.2, §4.6; core §11.1 ignores unknown fields). A new device that got none reads
  the grant events from relays, checks them as above, and answers for no grant until it has.
- **A grant applies only on its connection.** A NIP-07 grant for an origin in Chrome on the laptop
  doesn't let the same origin sign silently in another browser, profile or machine. Synced copies are for
  listing and signing out.
- The `keykin-` app-data prefix is guarded: a device never signs, on a site's request, a kind 30078 with
  a `d` starting with `keykin-`, or a kind 5 that targets one by `e` or `a`; nor any key-family kind
  (1244–1247, Key families module), or a kind 5 aimed at one or at any kind 1040 the account authored.

## 3. The doors

### 3.1 NIP-07 (browser extension)

The extension is the machine's member, or relays to the desktop app that is (core §4.6). A site calls
`window.nostr`. The first call from an origin in this browser profile shows the connect prompt, with the
scopes. Later calls are silent within the grant.

### 3.2 NIP-55 (Android)

The member app is the signer. Each calling app is a grant by package name **and** signing-certificate
digest. Android apps on the phone share the one member (core §4.6).

### 3.3 NIP-46 (remote signer)

- **Per-site signer keys.** For each NIP-46 site, the device that connected it (its **home**) makes a fresh
  signer key: a mailbox address, not the account key, that can sign nothing.
  - **The signer secret key never leaves its home**, whatever the scopes, except to the same machine's
    app over native messaging in a handover or a `self` remove (core §4.6). Only the home answers. So a
    removed or stolen other device can never read a site's requests or replies, or answer in the home's
    place.
  - It never goes to any server, `own` or not, and is kept like a share: encrypted at rest, excluded from
    iCloud and restorable backups (core §7.3).
  - After a grant ends, its home keeps the signer key for 30 days, inactive, only to answer every request
    with `revoked:`, so the site stops sending.
  - If the home is removed, its grants end (§2), and the site signs in again from another device.
  - A grant's home may be the account's **helper** instead of a device (Helper module §2): the helper mints
    the link, holds the signer key and answers, only for posting kinds; its entries carry `by` = the
    device that asked (marked `helper`), and devices also see its grants in its
    reports and deliver their tombstones to it.
- **Connecting:**
  - A `bunker://` link minted on a device, naming only relays that answered in the last minute. Its
    secret binds to the first client key that uses it and expires after 10 minutes if unused. That same
    client key may `connect` again with it, for example after a reload. Any other key is refused, and the
    device offers to mint a new link (command-line tools such as `nak` make a new key each run).
  - A `nostrconnect://` code the device scans. The device returns the code's secret in its `connect`
    reply, as clients check it.
  - The QRST signer-ticket (§3.4).
  - A client's `perms` are mapped to scopes and asked in one question. Connecting shows a quiet
    "Connected to *site*".
  - **"Is this your computer?"** (§4) is asked at the first `connect` of a NIP-46 grant whose link or code
    left the device (scanned, pasted from elsewhere, or a QRST ticket). It isn't asked for a same-device
    hand-off (§3.5) or for a helper's link (Helper module §2); for the second-browser pairing it is asked
    once, at pairing (§3.6).
- **Answering.** The home answers. It coordinates the signing round itself (core §5.1), refuses requests
  from any client key other than the grant's, accepts NIP-44 and NIP-04 encrypted requests, and answers
  `switch_relays`.
  - A **Confirm** event (Device policy) shows the card on the home; the result follows when the person
    answers. A single deletion's 10-second wait simply delays the answer.
  - A **Held** event is answered at once with `held: approve on your phone`. If the person approves, the
    home publishes the signed event itself, to the grant's relays and the account's own.
  - There is no `auth_url`. A link from whoever answers first could be phishing.
- **When the home is asleep: watching.** A server the person opts in for **watching** (core §2) holds, for
  each watched grant, the signer pubkey, the client pubkey, the relays and the home's member key. The home
  sends them with `watch_set {grants: [ … ]}` (class `ask`), a live request the server answers only from a
  current device, about grants whose home is that device; each `watch_set` replaces that home's whole set,
  an empty one stops it, and a home's set is dropped when the home is removed. While a minted `bunker://`
  link or QRST ticket is live (up to 10 minutes), its entry has `client: null`, and the server forwards
  only the first kind 24133 to that signer key, until the home names the bound client. The server then:
  - forwards to the home's inbox only kind 24133 events whose signature verifies, from the grant's client
    key, addressed to its signer key, with `created_at` within 2 minutes, each event id once, sealed to
    the home as the item `{type: "nip46", event}` (core §8.2);
  - skips the push if it sees a reply from the signer key, whose signature verifies, on the relays within
    3 seconds;
  - sends **one push per burst**: no new push while an earlier one for that signer key is unanswered and
    under about 20 seconds old, and at most 60 pushes per signer key per hour. The inbox holds the rest.

  Each wake **drains every pending item** for that signer key, then stays subscribed on the grant's relays
  and answers new requests until its time runs out.

  Watching uses **one** server per account, the person's choice (by default the first server), and moves
  with that seat when the server is replaced: the home sends `watch_set` to the new holder. Without a
  watching server, a NIP-46 site is answered only while its home is awake.
- **On a phone** (iPhone and Android), the app offers watching once at the first NIP-46 connect: "Let your server wake this phone when a site asks? It will
  see when sites ask, not what they ask."
- **Methods.** `connect`, `get_public_key`, `sign_event`, `nip04_*`, `nip44_*` (subject to scopes),
  `ping`, `switch_relays`, and `get_relays` where a client still calls it. A `logout` (where a client
  sends it) ends the grant. Errors start with a stable code: `not-connected:`, `revoked:`, `declined:`,
  `held:`, `try-later:`, `unsupported:`. **Sending** a NIP-57 private zap needs a secret derived from the
  private key itself, which a threshold key can't make, so it gets `unsupported:`.
- **Clients that assume the signer key is the user's key** don't work, and are told so by
  `get_public_key`'s answer being different from the signer key.

### 3.4 The QRST signer-ticket

The site shows a QRST code for the `signer-ticket` profile (`{pubkey, signer, relays, t, expires}`). A
member device scans it, shows the site as "says it is *name*", the person taps **Connect** (choosing
scopes), and the site redeems the ticket as a NIP-46 `connect` secret. QRST check level `none` is allowed
for a camera scan or a verified App Link; `compare` for a pasted link, the `qrst:` handoff or a custom
scheme. A member app MUST work with no bounce host reachable.

*Guidance for sites, not rules:* skip your own "Sign in as …?" only when you handed the code to one
specific app by a verified `https` App Link. In people's words, say "Sign in with your phone" and
"sign-in app", never "signer", "key", "relay" or "Nostr".

### 3.5 The same-device door on iPhone

iOS has no NIP-55. Apps on the same iPhone reach the member by NIP-46 to the member itself (`bunker://`
handed over by link), or by a link hand-off to the member app and back. The Safari extension shares the
app's member through the app's keychain group and signs directly (core §4.6).

### 3.6 A second browser on the same machine

With no desktop app, a second browser's extension holds no pieces (core §4.6). It is a NIP-07 provider
that is itself a NIP-46 client of the machine's member.

- **Pairing, once.** The person pastes a `bunker://` link from the member into the second extension. That
  makes a **pairing** grant, with no scopes of its own, whose client key is the extension's pairing key.
- **Per origin.** The first call from an origin sends a `connect` over the pairing channel, naming the
  origin and a fresh client key for it. The member asks "Allow *origin*?", which is the human act, and
  makes an ordinary NIP-46 grant for that client key. So each site has its own grant, scopes, history and
  Undo, exactly as on the member. Per-origin connects are accepted only this way.
- "Is this your computer?" is asked once, at pairing; the per-origin grants under it inherit the answer.
  Ending the pairing ends every grant under it.

## 4. Borrowed computers

At the first connect (§3.3), the device asks once: **"Is this your computer?"** If not:

- The grant is marked `borrowed`, with `sign-in` and `post` only unless the person adds more, and
  `expiry` 24 hours from now.
- No piece is ever copied, and its signer key stays on the phone (§3.3), so the phone answers every
  request.
- It ends at its expiry, or when the person taps End on the phone, or on a `logout`. It never relies on
  the site signing out, because many clients keep their client key.
- The phone keeps an **End** button visible on its home screen while a borrowed session is live.

## 5. Appendix: iPhone push (guidance, not normative)

- Handling a watched request without a visible notification needs Apple's notification filtering
  entitlement; without it, the collapse id keeps one notification per site.

- Servers send Web Push to the app maker's gateway (core §8.3), which turns it into APNs:
  - `sign` and `ask` at APNs priority 10, with `mutable-content: 1` and a generic alert ("Keykin"), which
    the notification service extension rewrites, because the gateway can't read the site name;
  - a short `apns-expiration` matching the request's lifetime class;
  - for watched NIP-46 requests, a collapse id the server derives from the signer key, so one site's
    requests show as one notification.
- The notification service extension has about 25 seconds and 24 MB:
  - it fetches the request from the server's inbox over HTTPS;
  - it judges the event by Device policy;
  - it either coordinates the round, publishes the NIP-46 reply itself and shows "Signed a note for
    *site* · Delete", or shows "Approve on your phone" and opens the app;
  - `ping` and other requests that need no person leave no visible notification where the platform
    allows, and are grouped per site where it doesn't.
- It keeps no nonce state in shared storage. Grants and signer keys live in app-group files marked
  excluded from backup.

## 6. Limits, said plainly

- **A Blossom token bound to one blob** may be silent for any host the site names; it uploads only that
  blob, as the person.
- **Grant changes reach a home within 5 minutes**, or up to 10 for a decrypt answered from a cached
  conversation key.
- **A helper signs no upload tokens** (Helper module §1): sites the helper answers upload media with their
  own hosts' sign-in, not the account's.
- **A device that can't reach a majority of the counted relays** answers only its newest grants and
  `get_public_key`, publishes nothing until it can, and says so; with fewer than three counted relays it
  answers from its own state.
- **A device restored from an old copy**, while most of the account's relays are unreachable, may answer a
  site it had signed out of, until it next reaches most of its relays or is reported. This is at the bar: a
  site given a pasted nsec can never be signed out at all (Q9).
- **A NIP-46 site is answered only by its home.** If that device sleeps and no server watches, the site
  waits. A watching server sees when sites talk to the account, though not what they say.
- **A stolen home** receives what its NIP-46 sites still send (requests, and the text of messages the
  person types there) until each site is signed out on the site itself. It can't answer them, because its
  rounds are refused once it is reported.
- **The grant events' `d`** comes from the base data key, which never rotates, so a removed device can
  link every member's grant event and its timing for ever.
- **A second browser's sites work only while the first browser** (the member, with no desktop app) is
  running.
- **Site names are self-claimed.** A site can relay another site's code. The device shows "says it is"
  and the person decides.
- **Scopes are only as good as the person's yes.**
- **The grant events reveal**, from their number and timing, roughly how many devices have grants and
  when they change.

## Changes

- **Draft 19**, from its eighteenth red team (0 critical, 0 high), its medium and lows:
  - an unreadable newer own event is ignored once a fetch is otherwise good, and events are recorded
    before any part is sent (M1);
  - re-sends move the set, other devices' ended ids read at start, write-refusing relays count only for
    fetches, the worker-restart clock kept in memory, catch-up repeated at the next fetch (lows).
- **Draft 18**, from its seventeenth red team (0 critical, 1 high):
  - the last publish's set counts only relays still counted, and falls back to the current set, so a device
    that slept through a relay change isn't stuck for good (H1).

  The mediums and lows:
  - ended ids merged from any own event, and dropped relays fetched from before being written again (M1);
  - who signs in with NIP-42, write-only relays, 24 KB parts, unreadable events, catch-up with no server
    (lows).
- **Draft 17** (and Q9: the restored-copy case stated as a limit at the bar), from its sixteenth red team (0 critical, 1 high):
  - a relay drops out only after failed tries made while other relays answered, so a device's own downtime
    never drops one (H1; draft 12's rule restored).

  The mediums and lows:
  - a fetch needs a majority of both the current set and its last publish's set (M1);
  - relays still `CLOSED` after NIP-42 sign-in dropped (M2);
  - own events re-sent weekly (M3);
  - catch-up skips a slow server (M4);
  - the `maker_sig` encoding with the union, `since` a day back, unreadable newer events, the device-bound
    key for the phone exemption, the "never drops ended ids" rule, smaller parts on size refusals (lows).
- **Draft 16**, from its fifteenth red team (0 critical, 1 high):
  - a relay silent for 7 days stops counting, the counted relays are the epoch record's plus the current
    seat holders', and devices republish when the set changes (H1).

  The mediums and lows:
  - the fewer-than-three rule made exact, with no advice to add a relay (M1);
  - re-sends kept for helper grants (M2);
  - only ended grants are listed, not expiries; reads use `since` (M3);
  - `{by, id, until}` union entries under `maker_sig`, always fetching, refusals retried weekly and size
    refusals counted, `EOSE` as the answer, a newer own event adopted at once, `get_public_key` exempt,
    catching up changes first, the exemption by where the store lives (lows).
- **Draft 15**, from its fourteenth red team (0 critical, 2 high):
  - every desktop app runs the start check, since a system image restores its storage (H1);
  - publishes and fetches both count more than half of all recorded relays, so they always share one; an
    account with fewer than three relays answers from local state and suggests a third (H2, M1).

  The mediums and lows:
  - union ids kept only while their maker is a member and up to `until`, under the maker's signature (M2);
  - `until` for never-expiring grants, relays dropped only after refusals spread over a day, devices that
    never published, re-sends dropped as redundant (lows).
- **Draft 14**, from its thirteenth red team (0 critical, 1 high):
  - desktop apps whose storage can be restored run the check too, and every device carries the union of
    ended ids in its own event, read every 5 minutes (H1).

  The mediums and lows:
  - a fallback fetch answers but never allows a publish; permanent refusals defined (M1);
  - re-sends wait for a newer event from the maker (M2);
  - `until` for "unused" expiries, the union in the `grants` field, fewer than three relays, helper entries
    matched by signer key (lows).
- **Draft 13**, from its twelfth red team (0 critical, 1 high):
  - a fetch that finds no majority in the last set counts against it plus the account's recorded relays at
    once, so one relay outage doesn't stall a restart (H1).

  The mediums and lows:
  - publishing counts only the recorded relays, drops refusing relays, and backs off (M1);
  - the resurrection test uses the union, and homes merge only their own ids (M2);
  - only a browser extension runs the start check; phone and desktop apps keep grants with their shares
    and skip it, so NIP-55 needs no exception (M3);
  - `{id, until}` with 30 days' slack, extension local storage only, re-sends paused while unacknowledged,
    one-relay accounts (lows).
- **Draft 12**, from its eleventh red team (0 critical, 2 high):
  - grants are stored like shares, excluded from backups; every device keeps the union of ended ids,
    carried in welcomes and merged before publishing (H1);
  - a publish counts only when two relays and more than half accept it, with a fallback to the account's
    relays (H2).

  The mediums and lows:
  - relays drop out by failed tries, not by the clock (M1);
  - NIP-55 answered at once, and process restarts (M2);
  - ended ids dropped at their grant's expiry (M3);
  - helper signer keys in ended lists (M4);
  - weekly re-sends after a week (M5);
  - `maker_sig` covers the ended list, the other-host rule for `PUT`/`PATCH`, wording (lows).
- **Draft 11**, from its tenth red team (0 critical, 2 high):
  - ended ids kept in each device's own grant event and in welcomes, and a good fetch counted against the
    relays that accepted the last publish (H1);
  - silent relays drop out of the count, with a quiet line (H2).

  The mediums and lows:
  - a handover keeps ended ids, so moved grants aren't resurrections (M1);
  - no removal tombstones to the helper (M2);
  - batched re-sends (M3);
  - a 3-second wait before `try-later:`, and worker restarts (M4);
  - second-browser origins sign in again with a fresh key (M5);
  - the tie rule, and wording (lows).
- **Draft 10**, from its ninth red team (0 critical, 1 high):
  - a dropped grant's name is remembered while its maker is a member, any reappearance is ignored and
    answered with a tombstone, devices apply others' tombstones for their own grants, and a good fetch
    needs more than half the account's relays (H1, L5).

  The mediums and lows:
  - re-sends at most once a day per grant (M1);
  - removal tombstones skip kept helper grants (M2);
  - no wildcard slack (M3);
  - `revoked:` only for NIP-46 (M4);
  - a site's own decrypts first (M5);
  - one tie rule, the wait before the first good fetch, the unreachable-relays limit, a `helper` field, the
    wildcard applied only by the home (lows).
- **Draft 9**, from its eighth red team (0 critical, 1 high):
  - a home fetches from and publishes to at least two relays, answers only new grants until a good fetch,
    never publishes after a failed one, and any device re-sends a tombstone when an ended grant reappears
    (H1).

  The mediums and lows:
  - helper grants named by their signer key (M1);
  - one decrypt request in flight per server, slowed above 30 a minute (M2);
  - kept helper sites regranted before the remove (M3, Helper draft 7);
  - no 5-second start wait, ties by narrower scopes, wildcard slack and publishing, helper tombstones kept
    while reported, `revoked:` for dropped grants (lows).
- **Draft 8**, from its seventh red team (0 critical, 1 high):
  - a home adopts its relay event only if newer than its own last publish, and drops only entries made
    before it (H1, M3).

  The mediums and lows:
  - tombstones re-sent when an ended helper grant reappears in a report (M1);
  - helper grants ended by the helper's own ids, and a wildcard by `made` (M2);
  - the unwrap cap is for the prefetch only (M4);
  - one tombstone-retention rule, ties on `v`, nothing answered before the first adopt, two limits (lows).
- **Draft 7**, from its sixth red team (0 critical, 2 high):
  - every home adopts its own newest relay event at start, every 5 minutes, before publishing and before a
    takeover (H1);
  - Blossom tokens bound to one blob are silent (H2).

  The mediums and lows:
  - old-name tombstones kept through a takeover (M1);
  - the borrowed question at pairing, not at the helper's links (M2);
  - allowed tag names for `lists` (M3);
  - a wildcard tombstone for "sign out every site" (M4);
  - unwrap batches per connection, only the account's wraps (M5);
  - the helper's upload limit stated (M6);
  - timing wording, 48 KB parts, Device policy and `was` (lows).
- **Draft 6**, from its fifth red team (0 critical, 2 high):
  - a release under `lists` checks the plaintext is a list, never wallet or key material (H1);
  - a takeover applies tombstones first, and re-signed entries carry `was` (H2).

  The mediums and lows:
  - Blossom tokens without a server tag are asked each time;
  - the borrowed question once at pairing;
  - split events count as one, and "sign out every site" fetches every maker first;
  - a real inbox fetch at least every 5 minutes;
  - a restored home never publishes older grants;
  - unwrap batches bounded.
- **Draft 5**, from its fourth red team (0 critical, 3 high):
  - NIP-98 and Blossom tokens silent for the site's own host, asked once per other host (H1);
  - the second browser pairs once, and per-origin grants go through the pairing (H2);
  - watched wakes drain everything pending, one push per burst, watching offered on every phone (H3).

  The mediums and lows:
  - signer keys move only to the same machine's app, in a handover or `self` remove (M1, L10);
  - evidence only for ciphertexts encrypted for the grant that signed the list, and imported lists count
    as the member app's (M2);
  - inbox-wide unwrap batches (M3);
  - fresh links watched before their first connect (M4);
  - one tombstone delivery per home per action (M5);
  - no borrowed question for same-device hand-offs (M6);
  - `maker_sig` on grant events, highest `v` kept, ended entries never re-added (M7);
  - the XChaCha20 encoding, the current state, `watch_set` checks, NIP-17 kinds, notes to self, perms,
    the 30-second rule, `created_at` ordering, event splitting, token types, and two limits (lows).
- **Draft 4**, from its third red team (1 critical, 4 high):
  - signer secret keys never leave their home, whatever the scopes (C1, H1, M2);
  - a list is evidence for a ciphertext only if the site didn't write it (H2);
  - decoded bytes are matched, and non-canonical base64 refused (H3);
  - one client key per origin in a second browser (H4).

  The mediums and lows:
  - only each maker's newest event counts (M1);
  - an inbox fetched within 30 seconds before any site request, and pushed tombstones (M3);
  - batched decrypts, conversation keys in memory only (M4);
  - NIP-17 sent copies under `dms` (M5);
  - XChaCha20-Poly1305 content with no size limit, expired entries pruned (M6);
  - the removal screen and a stated limit for a stolen home (M7);
  - NIP-98 and Blossom tokens scoped (M8);
  - grants named by `(by, id)` (L1);
  - core 13.9 wording on published events (L2);
  - a `grants` field in the welcome (L3);
  - `watch_set` replaced per home, verified events, sealed items (L4);
  - the borrowed question at every first connect (L5);
  - private zaps (L6);
  - a daily `last_used` (L7);
  - a new link for command-line clients (L8);
  - a `self` remove keeps the grants (L9);
  - reactivation makes a new entry and key (L10).

- **Draft 3**, from its second red team (0 critical, 4 high): most-private scope matching, versioned
  entries, `watch_set`, home-only private signer keys, and its mediums and lows.

- Draft 2, from its red team (1 critical, 4 high): signed entries and revoked grants of removed devices,
  one event per device with tombstones, opt-in watching servers (core §2), scopes split out, grants bound
  to connections, and the rest (D1 to D24).
