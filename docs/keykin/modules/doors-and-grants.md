# Keykin module: Doors and grants

Draft 1 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.1 · not built

Sites and apps reach a Keykin account through the doors they already use: NIP-07 (browser extension),
NIP-55 (Android), NIP-46 (remote signer) and the QRST signer-ticket. **Sites change nothing.** This module
says how a member device answers each door, what a site is allowed to do (its **grant**), how grants are
kept, synced and revoked, and how a borrowed computer signs in without holding any piece. The core wins
any disagreement, and nothing here may weaken it.

The bar is the core's: an nsec in a password manager. Signing in must be as quick as pasting an nsec
into a site, and routine signing must stay silent.

## 1. Grants

A **grant** is a site's permission to use the account. It lives on the user's devices, never on a
server.

```jsonc
{ "site": "<origin, or Android package name, or NIP-46 client key>",
  "door": "nip07" | "nip55" | "nip46",
  "client": "<NIP-46 client pubkey, when door is nip46>",
  "scopes": ["sign-in", "post", "lists", "dms", "private-data"],
  "made": <unix>, "last_used": <unix>,
  "expiry": "unused-90d" | <unix> | null,
  "by": "<member key of the device that made it>",
  "signer_key": "<per-site NIP-46 signer key, nip46 only>" }
```

**Scopes.** A site gets only what it was granted, and asks again for more.

| Scope | Lets the site | Asked |
|---|---|---|
| `sign-in` | `get_public_key`, and sign kind 22242 (relay auth) and NIP-98 HTTP auth | at connect |
| `post` | sign ordinary events (notes, reactions, reposts, zap requests, app data of its own `d` prefix) | at connect (default on) |
| `lists` | sign follows, mutes, bookmarks, relay lists, the profile | the first time it tries |
| `dms` | NIP-04/NIP-44 encrypt and decrypt **with other people's keys**, and NIP-59 unwrap | the first time it tries: "Let *site* read and send your messages?" |
| `private-data` | decrypt and encrypt **to the account's own key** (notes, app data) | the first time it tries: "Let *site* read your private notes and app data?" |

- Destructive events (Device policy module) are always held, whatever the scopes.
- Decrypting to the account's own key is **not** "reading your DMs". It needs its own scope (live finding
  #10).
- App data (kind 30078) a site writes is under its own `d` prefix. Overwriting another site's prefix needs
  `lists`. The `keykin-` prefix is reserved: a device never signs a kind 30078 whose `d` starts with
  `keykin-` on a site's request.

**Expiry.** By default a grant never expires while it is used and expires after 90 days unused. The person
may pick a fixed 30, 60 or 90 days, or never. An expired grant stays listed, grey, below the active ones
("Expired · last used *date*"); signing in again from that site reactivates the same entry.

**Listing.** Grants are grouped by site, whichever door they came through. Inside, each connection is
listed by where it lives ("Chrome on *Work PC*", "*Laptop* extension", "*Phone*") with when it was last
used. The person can sign out one connection, or the whole site everywhere, and **Sign out of all sites**
revokes every grant at once.

## 2. Keeping and syncing grants

- Each device keeps its grants as a **to-self encrypted event**: kind 30078, `d = "keykin-grants"`,
  encrypted under a key derived from the data key (`HKDF(dk(S), "keykin-grants/1")`), signed by the
  account. It is published to the account's relays so the user's other devices see it.
- Devices merge grant sets entry by entry. **A revoke always wins** over a grant for the same site and
  client: a revoked entry is a tombstone with the time it was revoked.
- **Only a human act clears a tombstone** (live finding #15): a scanned code, a pasted link, or an
  explicit "Allow *app*" on the device the app is on. A grant arriving by sync never clears one.
  - For NIP-46 every reconnect is a new client key, so it is a new grant anyway.
  - For a NIP-55 app (stable package name) the person can say yes again on that phone.
- A device MUST accept grant events only when they are signed by the account and decrypt under the data
  key, so a server or a stranger can't inject one. A removed device stops getting new data-key seeds
  (core §4.5), so it can't read grants made after its removal.

## 3. The doors

### 3.1 NIP-07 (browser extension)

The extension is the machine's member, or relays to the desktop app that is (core §4.6). A site calls
`window.nostr`. The first call from an origin shows the connect prompt, with the scopes. Later calls are
silent within the grant. `nip04`/`nip44` calls check `dms` or `private-data` by whether the peer is the
account's own key.

### 3.2 NIP-55 (Android)

The member app is the signer. Each calling app is a grant by package name. Android apps on the phone share
the one member (core §4.6).

### 3.3 NIP-46 (remote signer)

- **Per-site signer keys.** For each NIP-46 site, the device that connected it makes a fresh **signer
  key**: a mailbox address, not the account key. It can sign nothing.
  - The key is synced to the account's other devices inside the grant event (§2), and so to `own`
    servers the user runs.
  - It is **never** sent to any other server. A public server never holds a NIP-46 signer key, never sees
    a NIP-46 request, and never coordinates.
  - A device MUST accept a signer key only from a grant event signed by the account (§2), never from a
    single member's message, so a server can't install a signing door through the user's phone.
- **Connecting.**
  - A `bunker://` link minted on a device. It names only relays that answered in the last minute, so one
    dead relay can't hang the client. It carries a one-time secret.
  - A `nostrconnect://` code the device scans.
  - The QRST signer-ticket (§3.4).
- **Answering.** Whichever holder of the signer key is awake answers. It coordinates the signing round
  itself (core §5.1) with a server or another device.
  - A held event gets an immediate `auth_url` answer pointing at the device ("Approve on your phone"),
    so the client doesn't time out silently. When the person approves or declines, the result follows.
  - A client is answered twice, a few seconds apart, and moved onto relays that answer (`switch_relays`).
- **When no device is awake.** A server the user runs (`own`) may receive the request, push a device
  (core §8), and wait up to 60 seconds. A public server is never involved.

### 3.4 The QRST signer-ticket

The site shows a QRST code for the `signer-ticket` profile (`{pubkey, signer, relays, t, expires}`). A
member device scans it, the person taps **Connect** (choosing scopes), and the site redeems the ticket as a
NIP-46 `connect` secret. QRST check level `none` is allowed for a camera scan or a verified App Link;
`compare` for a pasted link, the `qrst:` handoff or a custom scheme.

- **No host needed.** A member app MUST work with no bounce host reachable: every parameter is in the
  code.
- **Same-device shortcut.** A site MAY skip its own "Sign in as …?" only when it handed the code to one
  specific app by a verified `https` App Link. Through `qrst:` or a custom scheme, the site asks first.
- **Words people see.** "Sign in with your phone", "sign-in app", never "signer", "key", "relay" or
  "Nostr".

### 3.5 The same-device door on iPhone

iOS has no NIP-55. Apps on the same iPhone reach the member by NIP-46 to the member itself (`bunker://`
handed over by link) or by a link hand-off to the member app and back. The Safari extension shares the
app's member through the app's keychain group and signs directly, in the extension's own short background
time (core §4.6).

## 4. Borrowed computers

On a computer that isn't the person's own (a library, a friend's laptop):

- The site signs in by NIP-46 with a code scanned on the person's phone, as in §3.3–3.4.
- **No piece is ever copied.** The phone coordinates every signature.
- The session's grant is marked **borrowed**: `post` and `sign-in` only, no `lists`, `dms` or
  `private-data` unless the person adds them. It ends when the site signs out, when the person taps End
  on the phone, or after **24 hours**, whichever comes first.

## 5. Interop rules for NIP-46

These come from the 2026-10-26 audit of nak and nostr-tools:

- Every standard method answers: `connect`, `get_public_key`, `sign_event`, `nip04_*`, `nip44_*` (subject
  to scopes), `ping`, `get_relays`, `logout`.
- Errors carry a stable code first, then words: `not-connected: …`, `revoked: …`, `declined: …`,
  `unsupported: …`.
- A single deletion's 10-second Undo hold (Device policy module) answers with `auth_url` at once, so
  clients don't read it as a timeout.

## 6. Appendix: iPhone push (guidance, not normative)

- Servers send Web Push to the app maker's gateway (core §8.3), which turns it into APNs:
  - `sign` and `ask` at APNs priority 10, `sign` as a passive notification, `ask` as time-sensitive;
  - a short `apns-expiration` matching the request's lifetime class, and the wait id or request id as
    `apns-collapse-id`.
- The notification service extension has about 25 seconds and 24 MB:
  - it fetches the request over HTTPS when the server offers it, else over relays;
  - it judges the event by Device policy;
  - it either co-signs and shows "Signed a note for *site* · Undo", or shows "Approve on your phone" and
    opens the app.
- It keeps no nonce state in shared storage. Site grants live in the app group, so the extension and the
  Safari extension can enforce them.

## 7. Limits, said plainly

- **A NIP-46 site is answered only while a device holding its signer key (or an `own` server) is
  awake.** With only a sleeping iPhone it waits for a push, and may time out.
- **A synced signer key** sits on every device of the account. A stolen device can read a NIP-46 site's
  requests until the grant is revoked.
- **Scopes are only as good as the person's yes.** A site that asks for `dms` and gets it can read
  messages.

## Changes

- Draft 1.
