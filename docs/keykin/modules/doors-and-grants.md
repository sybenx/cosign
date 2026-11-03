# Keykin module: Doors and grants

Draft 4 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.10 · not built

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
  "made": <unix>, "expiry": "unused-90d" | <unix> | null,
  "by": "<member key of the device that made it: its home>",
  "by_sig": "<BIP-340 by that member key over SHA-256('keykin-grant/1' ‖ g ‖ JCS(entry without by_sig))>" }
```

A grant is named by `(by, id)`. The signer **secret** key is never in an entry: it stays on its home (§3.3).

**Scopes.** A site gets only what it was granted, and asks again for more. The device decides which scope
a request needs by looking at what it is.

| Scope | Lets the site | Asked |
|---|---|---|
| `sign-in` | `get_public_key`; relay auth (kind 22242); NIP-98 auth for a URL on the calling origin (NIP-07) or any URL (other doors) with `GET`/`POST`; Blossom upload and list auth (24242) | at connect |
| `post` | ordinary events: notes, reactions, reposts, zap requests, deletions (judged by Device policy), articles, app data (kind 30078) except the `keykin-` prefix; **encrypting** to the account's own key; Blossom `t=delete` and NIP-98 `DELETE`/`PUT` tokens, judged as deletions | at connect (default on) |
| `lists` | the profile (0); follows, mutes and other lists (3, 10000–10030 except 10019, 30000–30030); relay lists (10002, 10050); and decrypting the private items of those lists | the first time it tries |
| `dms` | NIP-04/NIP-44 encrypt and decrypt **with other people's keys**, NIP-59 unwrap, the person's own sent NIP-17 copies (below), and NIP-55 `decrypt_zap_event` | the first time: "Let *site* read and send your messages?" |
| `wallet` | NIP-60/61 wallet events (17375, 37375, 7375, 7376, 7374), payment targets (10019), and decrypting them | the first time: "Let *site* use your ecash wallet?" |
| `private-data` | any other **decrypt** of something encrypted to the account's own key (notes, private app data) | the first time: "Let *site* read your private notes and app data?" |

- **Which scope a decrypt needs.** The device parses the peer key as a 32-byte x-coordinate and compares
  bytes to tell a decrypt-to-self from a message.
  - For a decrypt-to-self it **decodes** the payload (refusing non-canonical base64) and matches the
    decoded bytes against the account's own events. An event counts as evidence only if the device made
    that ciphertext itself, or its metadata (Device policy §1) records it as signed for **another** site
    or the member app. So a site can't plant a copy in one of its own lists.
  - If the bytes match events of several kinds, **the most private one wins** (`private-data`, then
    `wallet`, then `lists`). Bytes it can't match need `private-data` (live finding #10).
  - **NIP-17 sent copies.** The device decrypts a decrypt-to-self locally. Under `dms` it releases the
    plaintext only if it parses as a NIP-17 rumor: an unsigned event with `pubkey == g` and a DM kind (14,
    15, or a reaction or deletion of one). Wallet and list plaintexts are tag arrays, never rumors, so they
    still need their own scopes.
- **Deletions under `post`** may name any ordinary event of the account; Device policy judges them,
  silently only for the site's own events.
- **Decrypts in bulk.** Site decrypts arriving within about 50 ms go in one `ecdh` request with many
  points (core §5.5). A conversation key MAY be cached **in memory only**, for at most 10 minutes, and is
  never written to storage.
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
connection, the whole site everywhere, or **every site at once**.

## 2. Keeping and syncing grants

- **One event per device.** Each device publishes its grants as a kind 30078 event, signed by the account,
  with `d = "keykin-grants:" ‖ hex(first 16 bytes of HMAC-SHA256(HKDF-SHA256(base data key,
  "keykin-grants-d/1"), member key))`, so relays can't link the event to a member key. It carries a
  `["state", <state hash>]` tag naming the state whose data key encrypts it. Its content is
  XChaCha20-Poly1305 under `HKDF-SHA256(ikm = dk(S), info = "keykin-grants/1")`, with a random nonce, so it
  has no NIP-44 size limit. Expired entries are pruned from it.
- **Only each device's newest event counts.** For each maker, a device uses only the newest event (highest
  `created_at` that verifies). An entry missing from it is gone, so a stale relay copy can't bring one
  back. The grant set is the union across makers.
- **Every entry is signed by its maker** (`by_sig`). A device accepts an entry only if:
  - the event is account-signed and decrypts under the data key of the state it names;
  - `by` is a current device in its own view;
  - `by_sig` verifies, and `by` is the maker whose event it came from.
- **When a device is removed, every grant it made is revoked** by every device, because a thief's device
  could plant grants while it was a member. The person sees the list, with what to do for each NIP-46
  site homed there: "Grants made by *Laptop* were signed out. Sign out of *Coracle* on that site too, then
  sign in again."
  - The one exception is a `self` remove (core §4.6): the app that takes over re-signs the extension's
    grants under its own key before the remove, so the browser's sites stay signed in.
- **Ends made by another device** are tombstones `(by, id)`, published in the ending device's event and
  **also sent to every device as deliveries** (core §7.1) with an `ask` push, so the home drops the entry
  at once. A tombstone is dropped once the maker's newest event no longer has the entry.
- **Only a human act** makes a new grant (live finding #15): a scanned code, a pasted link, or an explicit
  "Allow *app*" on the device the app is on. For NIP-55, the same app (same package and certificate) can
  be allowed again on that phone.
- **Before answering any site request**, on any door, a device must have fetched its inbox within the
  last 30 seconds (reference), skipping a server that takes more than 2 seconds. So "Sign out everywhere"
  and End take effect within seconds everywhere.
- **New devices.** This module adds a `grants` field (every current entry and tombstone) to the welcome
  and the handover (core §4.2, §4.6; core §11.1 ignores unknown fields). A new device that got none reads
  the grant events from relays, checks them as above, and answers for no grant until it has.
- **A grant applies only on its connection.** A NIP-07 grant for an origin in Chrome on the laptop
  doesn't let the same origin sign silently in another browser, profile or machine. Synced copies are for
  listing and signing out.
- The `keykin-` app-data prefix is guarded: a device never signs, on a site's request, a kind 30078 with
  a `d` starting with `keykin-`, or a kind 5 that targets one by `e` or `a`.

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
  - **The signer secret key never leaves its home**, whatever the scopes. Only the home answers. So a
    removed or stolen other device can never read a site's requests or replies, or answer in the home's
    place.
  - It never goes to any server, `own` or not, and is kept like a share: encrypted at rest, excluded from
    iCloud and restorable backups (core §7.3).
  - After a grant ends, its home keeps the signer key for 30 days, inactive, only to answer every request
    with `revoked:`, so the site stops sending.
  - If the home is removed, its grants end (§2), and the site signs in again from another device.
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
  - **"Is this your computer?"** (§4) is asked at the first `connect` of every NIP-46 grant, scanned or
    pasted.
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
  sends them with `watch_set {grants: [ … ]}`, a live request the server answers; each `watch_set`
  replaces that home's whole set, an empty one stops it, and a home's set is dropped when the home is
  removed. The server then:
  - forwards to the home's inbox only kind 24133 events whose signature verifies, from the grant's client
    key, addressed to its signer key, with `created_at` within 2 minutes, each event id once, sealed to
    the home as the item `{type: "nip46", event}` (core §8.2);
  - skips the push if it sees the signer key's reply on the relays within 3 seconds;
  - sends at most 30 pushes per signer key per hour.

  Watching uses **one** server per account, the person's choice (by default the first server), and moves
  with that seat when the server is replaced: the home sends `watch_set` to the new holder. Without a
  watching server, a NIP-46 site is answered only while its home is awake.
- **On iPhone**, where NIP-46 is how other apps and borrowed computers reach the member, the app offers
  watching once at the first NIP-46 connect: "Let your server wake this phone when a site asks? It will
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
that is itself a NIP-46 client of the machine's member, with **one client key per origin**. The first call
from an origin asks the person on the member, which makes an ordinary NIP-46 grant for that origin's
client key. So each site has its own grant, scopes, history and Undo, exactly as on the member.

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

- **A NIP-46 site is answered only by its home.** If that device sleeps and no server watches, the site
  waits. A watching server sees when sites talk to the account, though not what they say.
- **A stolen home** receives what its NIP-46 sites still send (requests, and the text of messages the
  person types there) until each site is signed out on the site itself. It can't answer them, because its
  rounds are refused once it is reported.
- **Site names are self-claimed.** A site can relay another site's code. The device shows "says it is"
  and the person decides.
- **Scopes are only as good as the person's yes.**
- **The grant events reveal**, from their number and timing, roughly how many devices have grants and
  when they change.

## Changes

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
