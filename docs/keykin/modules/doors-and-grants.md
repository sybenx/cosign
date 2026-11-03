# Keykin module: Doors and grants

Draft 3 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.5 · not built

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
  "scopes": ["sign-in", "post", "lists", "dms", "private-data", "wallet"],
  "borrowed": false,
  "made": <unix>, "expiry": "unused-90d" | <unix> | null,
  "by": "<member key of the device that made it: its home>",
  "by_sig": "<BIP-340 by that member key over SHA-256('keykin-grant/1' ‖ g ‖ JCS(entry without by_sig))>",
  "signer_key": "<per-site NIP-46 signer secret key, nip46 only, and only in synced copies when §3.3 allows>" }
```

**Scopes.** A site gets only what it was granted, and asks again for more. The device decides which scope
a request needs by looking at what it is.

| Scope | Lets the site | Asked |
|---|---|---|
| `sign-in` | `get_public_key`; relay auth (kind 22242), NIP-98 HTTP auth and Blossom auth (24242) | at connect |
| `post` | ordinary events: notes, reactions, reposts, zap requests, deletions of its own events, articles, app data (kind 30078) except the `keykin-` prefix; and **encrypting** to the account's own key | at connect (default on) |
| `lists` | the profile (0); follows, mutes and other lists (3, 10000–10030 except 10019, 30000–30030); relay lists (10002, 10050); and decrypting the private items of those lists | the first time it tries |
| `dms` | NIP-04/NIP-44 encrypt and decrypt **with other people's keys**, and NIP-59 unwrap | the first time: "Let *site* read and send your messages?" |
| `wallet` | NIP-60/61 wallet events (17375, 37375, 7375, 7376, 7374), payment targets (10019), and decrypting them | the first time: "Let *site* use your ecash wallet?" |
| `private-data` | any other **decrypt** of something encrypted to the account's own key (notes, private app data) | the first time: "Let *site* read your private notes and app data?" |

- **Which scope a decrypt needs.** The device parses the peer key as a 32-byte x-coordinate and compares
  bytes, never strings, to tell a decrypt-to-self from a message. For a decrypt-to-self it matches the
  ciphertext against the account's own events in its history. If the same ciphertext appears in events of
  several kinds, **the most private one wins** (`private-data`, then `wallet`, then `lists`). A ciphertext
  it can't match needs `private-data` (live finding #10).
- **Its own events**, for deletions under `post`, are those the device's history metadata records as
  signed for this site (Device policy §1).
- Destructive events are judged by the Device policy module, whatever the scopes.
- Relay auth, NIP-98 and Blossom tokens a site gets signed are never accepted as authority by any Keykin
  endpoint.

**Expiry.** By default a grant never expires while it is used, and expires after 90 days unused.

- Each device records `last_used` for the connections it answered for, and publishes it with its grants
  (§2). A grant is unused only when no device has used it for the period.
- The person may pick a fixed 30, 60 or 90 days, or never.
- An expired grant stays listed, grey, below the active ones, for a year. Signing in again from that site
  asks the connect question again and reactivates the same entry, with a higher `v`.

**Listing and signing out.** Grants are grouped by site, with each connection listed inside it ("Chrome
on *Work PC*", "*Laptop* extension", "*Phone*") and when it was last used. The person can sign out one
connection, the whole site everywhere, or **every site at once**.

## 2. Keeping and syncing grants

- **One event per device.** Each device publishes its grants as a kind 30078 event, signed by the account,
  with `d = "keykin-grants:" ‖ hex(first 16 bytes of HMAC-SHA256(HKDF-SHA256(base data key,
  "keykin-grants-d/1"), member key))`, so relays can't link the event to a member key. It carries a
  `["state", <state hash>]` tag naming the state whose data key encrypts it, and is encrypted with NIP-44
  v2 under the conversation key `HKDF-SHA256(ikm = dk(S), info = "keykin-grants/1")`. Every device reads
  all of them and takes the **union across relays and devices**.
- **Every entry is signed by the device that made it** (`by_sig`). A device accepts an entry only if:
  - the event is account-signed and decrypts under the data key of the state it names;
  - `by` is a current device in its own view;
  - `by_sig` verifies.

  For one grant id, the entry with the **highest `v` from that `by`** wins. Entries for the same id from a
  different `by` are ignored. Narrowing a grant is a new `v` by its home; any other device narrows or ends
  it only by a tombstone.
- **When a device is removed, every grant it made is revoked** by every device, because a thief's device
  could plant grants while it was a member. The person sees the list ("Grants made by *Laptop* were
  signed out").
- **A revoke always wins.** Revocations are **tombstones by grant id**, and each destroyed signer key also
  leaves a tombstone of its public key's hash.
  - Tombstones are published with the grants, and **also sent to every device as deliveries** (core
    §7.1). A device fetches its inbox before answering any NIP-46 request, so "Sign out everywhere" and
    End take effect at once.
  - A grant whose id or signer key is tombstoned never comes back by sync.
  - **Only a human act** makes a new grant (live finding #15): a scanned code, a pasted link, or an
    explicit "Allow *app*" on the device the app is on. That new grant has a new id. For NIP-55, the
    same app (same package and certificate) can be allowed again on that phone.
  - A tombstone is dropped a year after the grant it ends stopped appearing in every device's event.
- **New devices** receive the full grant set and tombstones in their welcome (core §4.2 step 4: a
  handover's "site grants" and the welcome's deliveries). A new device that got none reads the grant
  events from relays, checks them as above, and answers for no grant until it has.
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
  - **A grant with any decrypt scope** (`lists`, `dms`, `wallet`, `private-data`), or a borrowed one,
    keeps its signer key **on its home device only**. Only the home answers it, so a removed or stolen
    other device can never read its requests or replies. If the home is removed, the grant is revoked
    (§2), and the site signs in again.
  - A grant with only `sign-in` and `post` may sync its signer key to the account's other devices inside
    its entry, so another device can answer while the home sleeps.
  - Signer keys never go to any server, `own` or not, and are kept like shares: encrypted at rest,
    excluded from iCloud and restorable backups (core §7.3).
  - After a grant is revoked, its home keeps the signer key for 30 days, inactive, only to answer every
    request with `revoked:`, so the site stops sending.
- **Connecting:**
  - A `bunker://` link minted on a device, naming only relays that answered in the last minute. Its
    secret binds to the first client key that uses it and expires after 10 minutes if unused. That same
    client key may `connect` again with it, for example after a reload. Any other key is refused.
  - A `nostrconnect://` code the device scans. The device returns the code's secret in its `connect`
    reply, as clients check it.
  - The QRST signer-ticket (§3.4).
  - A client's `perms` are mapped to scopes and asked in one question. Connecting shows a quiet
    "Connected to *site*".
- **Answering.** Of the devices holding the signer key, the one that answered last answers first; any
  other answers only if it has seen no reply on the relays within 3 seconds. The answering device
  coordinates the signing round itself (core §5.1). It refuses requests from any client key other than
  the grant's. It accepts NIP-44 and NIP-04 encrypted requests, and answers `switch_relays`.
  - A **Confirm** event (Device policy) shows the card on the answering device; the result follows when
    the person answers. A single deletion's 10-second wait simply delays the answer.
  - A **Held** event is answered at once with `held: approve on your phone`. If the person approves, the
    device publishes the signed event itself, to the grant's relays and the account's own.
  - There is no `auth_url`. A link from whoever answers first could be phishing.
- **When no device is awake: watching.** A server the person opts in for **watching** (core §2) holds,
  for each watched grant, the signer pubkey, the client pubkey, the relays and the home device's member
  key. The home sends it these with `watch_set {grants: [ … ]}` (and an empty list to stop), as a
  delivery from a current device. The server then:
  - forwards to the home device's inbox only kind 24133 events from the grant's client key, addressed to
    its signer key, with `created_at` within 2 minutes, each event id once, as an inbox item
    `{type: "nip46", event}`;
  - skips the push if it sees the signer key's reply on the relays within 3 seconds;
  - sends at most 30 pushes per signer key per hour.

  Watching uses **one** server per account, the person's choice (by default the first server), and moves
  with that seat when the server is replaced: the device sends `watch_set` to the new holder. Without a
  watching server, a NIP-46 site is answered only while a device holding its signer key is awake.
- **On iPhone**, where NIP-46 is how other apps and borrowed computers reach the member, the app offers
  watching once at the first NIP-46 connect: "Let your server wake this phone when a site asks? It will
  see when sites ask, not what they ask."
- **Methods.** `connect`, `get_public_key`, `sign_event`, `nip04_*`, `nip44_*` (subject to scopes),
  `ping`, `switch_relays`, and `get_relays` where a client still calls it. A `logout` (where a client
  sends it) revokes the grant. Errors start with a stable code: `not-connected:`, `revoked:`,
  `declined:`, `held:`, `unsupported:`.
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
that is itself a NIP-46 client of the machine's member: the person connects it once by a `bunker://` link
from the member, as one grant whose connection is that extension's client key. The extension then asks
its own per-origin connect question and passes requests on within that grant's scopes.

## 4. Borrowed computers

When the person scans a site's code, the device asks once: **"Is this your computer?"** If not:

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

- **Without a watching server** (opt-in), a NIP-46 site is answered only while a device holding its signer
  key is awake. A watching server sees when sites talk to the account, though not what they say.
- **A synced signer key** (a `post`-only grant) sits on every device. A stolen device can read that site's
  requests, which are notes it is asked to sign, until the device is reported.
- **Site names are self-claimed.** A site can relay another site's code. The device shows "says it is"
  and the person decides.
- **Scopes are only as good as the person's yes.**
- **The grant events reveal**, from their number and timing, roughly how many devices have grants and
  when they change.
- **A private-scope NIP-46 site answers only from its home.** If that device sleeps and no server
  watches, the site waits.

## Changes

- **Draft 3**, from its second red team (0 critical, 4 high):
  - the most private matching category wins, and an unmatched ciphertext needs `private-data` (D-H1);
  - entries are versioned by their maker; narrowing by others only by tombstone (D-H2);
  - `watch_set`, `relays` in the entry, and an inbox format for watched requests (D-H3);
  - signer keys of grants with any decrypt scope stay on the home device, so a removed device can't read
    them, and other removals no longer sign sites out (D-H4, D-M11).

  The mediums and lows:
  - revoked signer keys answer `revoked:` for 30 days (D-M1);
  - watching forwards only fresh events from the grant's client, with a push budget (D-M2);
  - tombstones are deliveries (D-M3);
  - borrowed signer keys stay on the phone, with `expiry` (D-M4);
  - a keyed `d` (D-M5);
  - byte comparison of keys (D-M6);
  - encrypting to self needs only `post` (D-M7);
  - 10019 under `wallet` (D-M8);
  - `bunker` secrets expire, and a quiet connect notice (D-M9);
  - no `auth_url`; Held answers `held:` and the device publishes (D-M10, D-L7);
  - one watching server, fewer iPhone notifications (D-M12);
  - watching offered once on iPhone, kept across replacements (D-M13);
  - the second-browser door (D-M14);
  - the last answerer answers first, and `last_used` is shared (D-M15);
  - NIP-46 interop details (D-L1);
  - grants in the welcome (D-L2);
  - fewer fields (D-L3);
  - pruning (D-L4);
  - own events, Blossom and 7374 (D-L5);
  - the iPhone appendix (D-L6);
  - the state tag (D-L8).

- Draft 2, from its red team (1 critical, 4 high): signed entries and revoked grants of removed devices,
  one event per device with tombstones, opt-in watching servers (core §2), scopes split out, grants bound
  to connections, and the rest (D1 to D24).
