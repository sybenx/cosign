# Keykin module: Doors and grants

Draft 2 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.3 · not built

Sites and apps reach a Keykin account through the doors they already use: NIP-07 (browser extension),
NIP-55 (Android), NIP-46 (remote signer) and the QRST signer-ticket. **Sites change nothing.** This module
says how a member device answers each door, what a site is allowed to do (its **grant**), how grants are
kept, synced and revoked, and how a borrowed computer signs in without holding any piece. The core wins
any disagreement, and nothing here may weaken it.

The bar is the core's: an nsec in a password manager. Signing in must be as quick as pasting an nsec into
a site, and routine signing must stay silent.

## 1. Grants

A **grant** is a site's permission to use the account. It lives on the user's devices, never on a server.

```jsonc
{ "id": "<16 random bytes>",
  "site": "<origin, or Android package name + signing-certificate SHA-256, or NIP-46 client key>",
  "says": "<the name the site gave itself, shown as 'says it is …'>",
  "door": "nip07" | "nip55" | "nip46",
  "connection": "<the browser profile, app install or NIP-46 client key this grant is bound to>",
  "client": "<NIP-46 client pubkey, nip46 only>",
  "scopes": ["sign-in", "post", "lists", "dms", "private-data", "wallet"],
  "borrowed": false,
  "made": <unix>, "expiry": "unused-90d" | <unix> | null,
  "by": "<member key of the device that made it>",
  "by_sig": "<BIP-340 by that member key over SHA-256('keykin-grant/1' ‖ g ‖ JCS(entry without by_sig))>",
  "signer_key": "<per-site NIP-46 signer secret key, nip46 only>" }
```

**Scopes.** A site gets only what it was granted, and asks again for more. The device decides which scope
a request needs by looking at what it is.

| Scope | Lets the site | Asked |
|---|---|---|
| `sign-in` | `get_public_key`; relay auth (kind 22242) and NIP-98 HTTP auth | at connect |
| `post` | ordinary events: notes, reactions, reposts, zap requests, deletions of its own events, articles, app data (kind 30078) except the `keykin-` prefix | at connect (default on) |
| `lists` | the profile (0); follows, mutes and other lists (3, 10000–10030, 30000–30009); relay lists (10002, 10050); payment-target lists (10019); and decrypting the private items of those lists | the first time it tries |
| `dms` | NIP-04/NIP-44 encrypt and decrypt **with other people's keys**, and NIP-59 unwrap | the first time: "Let *site* read and send your messages?" |
| `wallet` | NIP-60/61 wallet events (17375, 37375, 7375, 7376) and decrypting them | the first time: "Let *site* use your ecash wallet?" |
| `private-data` | any other decrypt or encrypt **to the account's own key** (notes, private app data) | the first time: "Let *site* read your private notes and app data?" |

- To tell decrypt-to-self requests apart, the device matches the ciphertext against the account's own
  events in its history. Private list items count as `lists`, wallet content as `wallet`, and anything
  else to self as `private-data` (live finding #10).
- Destructive events are judged by the Device policy module, whatever the scopes.
- Relay auth and NIP-98 tokens a site gets signed are never accepted as authority by any Keykin endpoint.

**Expiry.** By default a grant never expires while it is used, and expires after 90 days unused.

- Each device records `last_used` for its own connections only, locally. Expiry is judged per connection.
- The person may pick a fixed 30, 60 or 90 days, or never.
- An expired grant stays listed, grey, below the active ones. Signing in again from that site asks the
  connect question again and reactivates the same entry.

**Listing and signing out.** Grants are grouped by site, with each connection listed inside it ("Chrome
on *Work PC*", "*Laptop* extension", "*Phone*") and when it was last used. The person can sign out one
connection, the whole site everywhere, or **every site at once**.

## 2. Keeping and syncing grants

- **One event per device.** Each device publishes its grants as a kind 30078 event with
  `d = "keykin-grants:" ‖ hex(SHA-256(member key))`, signed by the account, encrypted with NIP-44 v2 under
  the conversation key `HKDF-SHA256(ikm = dk(S), info = "keykin-grants/1")`. Every device reads all of
  them and takes the **union across relays and devices**.
- **Every entry is signed by the device that made it** (`by_sig`). A device accepts an entry only if:
  - the event is account-signed and decrypts under the data key;
  - `by` was a current device when its event was published;
  - `by_sig` verifies.

  A thief's own device could still plant a grant while it is a member. So **when a device is removed,
  every grant it made is revoked** by every device, and the person sees the list ("Grants made by
  *Laptop* were signed out").
- **A revoke always wins.** Revocations are **tombstones by grant id**, kept for ever (a few bytes
  each), and each destroyed signer key also leaves a permanent tombstone of its public key's hash.
  - A grant whose id or signer key is tombstoned never comes back by sync.
  - **Only a human act** makes a new grant (live finding #15): a scanned code, a pasted link, or an
    explicit "Allow *app*" on the device the app is on. That new grant has a new id. For NIP-55, the
    same app (same package and certificate) can be allowed again on that phone.
- **Conflicts:** for the same grant id, the narrower scopes and the earlier expiry win.
- **New devices** receive the full grant set and tombstones in their welcome (core §4.2), and never rely
  on whatever relays return.
- **Removal ends private access.** On any device removal, every NIP-46 grant with `dms`, `wallet` or
  `private-data` is revoked and its signer key destroyed, because the removed device kept a copy of the
  signer key. Such sites sign in again. Grants with only `sign-in`, `post` and `lists` keep working.
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

- **Per-site signer keys.** For each NIP-46 site, the device that connected it makes a fresh signer key:
  a mailbox address, not the account key, that can sign nothing.
  - It is synced to the account's other devices only inside a grant entry (§2).
  - It never goes to any server, `own` or not.
  - Signer keys are kept like shares: encrypted at rest, excluded from iCloud and restorable backups
    (core §7.3).
- **Connecting:**
  - A `bunker://` link minted on a device, naming only relays that answered in the last minute. Its
    secret binds to the first client key that uses it. That same client key may `connect` again with it,
    for example after a reload. Any other key is refused.
  - A `nostrconnect://` code the device scans.
  - The QRST signer-ticket (§3.4).
- **Answering.** The device that made the grant (its **home**) answers. Another device holding the signer
  key answers only if it has seen no reply on the relays within 3 seconds, so two devices rarely both
  answer. The answering device coordinates the signing round itself (core §5.1). It refuses requests from
  any client key other than the grant's.
  - A Confirm or Held event (Device policy) gets an immediate `auth_url` answer pointing at an approval
    page on the device ("Approve on your phone"); the result follows when the person answers.
  - A single deletion's 10-second wait gets no `auth_url`; the answer simply arrives after 10 seconds.
- **When no device is awake.** A server the person has opted in for **watching** (core §2) sees the
  request, keeps it in the home device's inbox and pushes it, and the device answers when it wakes. Without
  a watching server, a NIP-46 site is answered only while a device holding its signer key is awake.
- **Methods.** `connect`, `get_public_key`, `sign_event`, `nip04_*`, `nip44_*` (subject to scopes),
  `ping`, and `get_relays` where a client still calls it. A `logout` (where a client sends it) revokes the
  grant. Errors start with a stable code: `not-connected:`, `revoked:`, `declined:`, `unsupported:`.

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

## 4. Borrowed computers

When the person scans a site's code, the device asks once: **"Is this your computer?"** If not:

- The grant is marked `borrowed`, with `sign-in` and `post` only unless the person adds more.
- No piece is ever copied. The phone coordinates every signature.
- It ends after **24 hours**, or when the person taps End on the phone, or on a `logout`. It never relies
  on the site signing out, because many clients keep their client key.
- The phone keeps an **End** button visible on its home screen while a borrowed session is live.

## 5. Appendix: iPhone push (guidance, not normative)

- Servers send Web Push to the app maker's gateway (core §8.3), which turns it into APNs:
  - `sign` and `ask` at APNs priority 10, with `mutable-content: 1` and real alert text ("Signing for
    *site*…");
  - a short `apns-expiration` matching the request's lifetime class;
  - the request or wait id as `apns-collapse-id`.
- The notification service extension has about 25 seconds and 24 MB:
  - it fetches the request from the server's inbox over HTTPS;
  - it judges the event by Device policy;
  - it either coordinates the round and shows "Signed a note for *site* · Delete", or shows "Approve on
    your phone" and opens the app.
- It keeps no nonce state in shared storage. Grants and signer keys live in the app group, excluded from
  backups.

## 6. Limits, said plainly

- **Without a watching server** (opt-in), a NIP-46 site is answered only while a device holding its signer
  key is awake. A watching server sees when sites talk to the account, though not what they say.
- **A synced signer key** sits on every device. A stolen device can read that site's requests until the
  device is reported. Reporting it revokes the private-scope NIP-46 grants (§2); a `post`-only site's
  requests stay readable to it until the person signs that site out too.
- **Site names are self-claimed.** A site can relay another site's code. The device shows "says it is"
  and the person decides.
- **Scopes are only as good as the person's yes.**
- **The grant events reveal**, from their number and timing, roughly how many devices have grants and
  when they change.

## Changes

- Draft 2, from its red team (1 critical, 4 high):
  - entries signed by their maker, and a removed device's grants revoked (D1);
  - private NIP-46 grants revoked on any removal (D2);
  - one event per device, union, tombstones by id, grants in the welcome (D3);
  - opt-in watching servers in core §2 (D4);
  - `own` servers get no grants (D5, core text);
  - `lists` and `wallet` split out of `private-data` (D6);
  - a full scope map (D7);
  - grants bound to their connection (D8);
  - grant ids (D9);
  - borrowed sessions marked at scan (D10);
  - no `auth_url` for the 10-second wait (D11);
  - one answering device (D12);
  - reusable `bunker` secrets per client (D13);
  - the kind 5 guard (D14);
  - local `last_used` (D15);
  - NIP-55 certificates (D16);
  - encryption spelled out (D17);
  - NIP-46 interop (D18);
  - iPhone push (D19);
  - "says it is" (D20);
  - auth tokens never authority (D21);
  - privacy (D22);
  - site guidance labelled (D23);
  - backups (D24).
