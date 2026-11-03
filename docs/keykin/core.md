# Keykin Core

Draft 8.4 · 2026-11-02 · `draft` `optional` · not built

Keykin keeps one Nostr key for life without any single device, server or company holding it.
The key is split with FROST into weighted shares: each of the user's devices holds 3, each server
1, a paper backup 2, and signing takes 4. So the device you're using plus any one server signs, two
of your devices sign, and all the servers together never can.

This document is the **core**: the smallest set of rules two independent implementations need to
work together and keep the account safe. "Refresh now", the one ceremony meant to change the
account's structure, is in [`refresh.md`](refresh.md), which is **parked** (§12): until it is
reworked, an account keeps the servers, helper and paper it was created with (§10). Everything a person sees, and every other optional
feature, lives in a module (§12). Sites change nothing: they keep using NIP-07, NIP-46, NIP-55 and
the QRST signer-ticket, which the Doors module covers.

**The bar.** An nsec kept in a password manager. Every rule here must beat it on security *and* on
how it feels to use; a rule that costs a person effort without beating it does not belong. So
nothing here puts a face or fingerprint in front of everyday or background signing, or opening the
stored shares.

**How to read it.** MUST, SHOULD and MAY apply to wire behaviour and to what a member stores. The
only exceptions are the few **security displays** in §1.1. Everything else a person sees is up to
the app. "Reference" numbers are defaults an implementation may change without breaking anyone.

Keykin is the new working name of Cosign. Cosign 0.12 (built, described in `../COSIGN.md`) is the
prototype this replaces; §11 says how existing accounts move over. Old `cosign` names stay readable
for ever.

**How it got this shape.** Seven independent red teams kept finding serious problems in the same
places, and the user cut them (decision log, 2026-11-02; reasoning in `simplification.md`):

- the core never re-deals shares;
- every account change needs a biometric lock, a second device with a typed code, or the paper;
- everyday changes (add a device, report one lost, paper recovery) are independent signed approvals,
  safe in any order;
- structural changes (servers, a helper, the paper) happen only in "Refresh now", with everyone
  online;
- there is no in-place move from Cosign 0.12: an account moves by importing its nsec (§11.2).

---

## 1. Terms

- **Group key** `g`: the account's Nostr key (x-only, BIP-340). Its private half never exists whole
  anywhere (§6.6).
- **Ciphersuite**: `FROST-secp256k1-SHA256-TR-v1`, as implemented by the Zcash Foundation's
  `frost-secp256k1-tr` 2.x: RFC 9591's FROST(secp256k1, SHA-256) with the BIP-340 challenge as H2,
  the group key and shares brought to even y at key generation (`into_even_y`), and each signer's
  nonce negated when the group commitment `R` has odd y. Plain RFC 9591 does not interoperate with
  this, and neither does Cosign 0.12's hand-rolled `server/frost.ts` (§11.2).
- **Share**: one FROST share `s_i = f(i)` at a unique index `i ≥ 1`, worth one point. `f` has degree
  3; threshold `t = 4`.
- **Epoch**: one polynomial `f`. An account starts in epoch 1 at creation; only "Refresh now" moves
  it to a new epoch, re-dealing every share (`refresh.md`). Between refreshes nothing re-deals.
- **Member**: anything holding shares. It has a **member key** (secp256k1) that seals and
  authenticates its messages. Member kinds:

  | Kind | Shares | What it is | Joins |
  |---|---|---|---|
  | `device` | 3 | An app on hardware the user owns: phone, tablet, desktop app, browser extension. | any time (§4) or at a refresh |
  | `helper` | 3 | A family or friend's always-on box, only on the user's opt-in. | only at a refresh |
  | `server` | 1 | An always-on service: public, a friend's, or the user's own. | at creation or a refresh |
  | `backup` | 2 | The paper backup key. Nothing online holds its shares. | at creation or a refresh |

- **Device-class**: `device` and `helper`. Only these coordinate everyday signing.
- **Epoch record**: the signed list of members at the start of an epoch, with the polynomial
  commitment (§3.1). Made only at creation and by "Refresh now".
- **Change**: a signed, self-contained account change made between refreshes: adding a device,
  removing a device or helper, or re-registering a device's lock (§3.2). Changes can be applied in
  any order.
- **Membership**: the epoch record plus every valid change of that epoch.
- **Lock**: a P-256 key in secure hardware that signs only after a fresh **biometric** match and stops
  working when the enrolled faces or fingerprints change (§6.1). A passcode never counts.
- **Approval**: what an account change needs: a lock, two devices with a typed code, a device with
  the paper, or a paper recovery (§6.2).
- **Wait**: a delay, 3 days by default (`W`), that servers apply on their own clocks to exactly two
  things: a paper recovery (§6.5) and a held mass deletion (§5.8).
- **Release key**: a random 32-byte key held by devices and servers, never by helpers or backups,
  that wraps the backup's shares a second time (§7.2). It changes only at a refresh.
- **Data key**: a random 32-byte key held whole by devices only, for reading the account's own
  private data. It can read, never sign, and changes only at a refresh (§4.5).
- **Request**: any member message that asks for an answer. Each has an `id` (16 random bytes, hex)
  and a lifetime class (§5.6).

### 1.1 Security displays

These are the only things this document requires an app to show, because the protocol's safety
depends on a person seeing them:

1. the 6-digit join check, shown on the new device and **typed** by the person on the inviting
   device before a join goes ahead (§4.1);
2. the account a device joined, when it joined from a join code (§4.2);
3. a refused epoch record or change, with the member it came from (§3.4);
4. that an update is needed, when a device meets a version it does not know (§11.1);
5. a two-device approval: the first device shows a 6-digit code and the person **types** it on the
   second device; for adding a device, the code is the join check shown on the new device, typed on
   the second device (§6.2);
6. the paper: before a device forgets the backup secret, the person shows the paper is readable by
   scanning it back or re-entering it (§4.3).

`refresh.md` (parked) adds its own: when a refresh has finished, that the person must now destroy the
old paper.

## 2. Who does what

**Devices do the work.** A device coordinates its own signing rounds, judges what is destructive,
asks the person, keeps the account's history and does Undo. When it can, it does anything a server
would.

**Servers do the minimum.** Per account, a server MUST keep only:

1. its share for the current epoch (and, during a refresh, the pending and the previous one,
   `refresh.md`);
2. the current epoch record and the set of changes of this epoch (§3);
3. the current release key and the backup material (§7.2);
4. running waits (recoveries and holds) with their notices, and recovery sessions (§6);
5. push addresses and notice channels (§8.1), and the inbox, including deliveries kept until
   acknowledged (§7.1);
6. answered request ids until each expires (§5.6), and its own counters for §5.8.

A server MUST NOT keep signed events, list versions, site grants or logs of what it signed. It
co-signs, checks approvals, enforces the two waits and the stateless destructive rule (§5.8), sends
wake-up pushes, and helps with repair. That is all.

| | device | helper | server | backup |
|---|---|---|---|---|
| Coordinate everyday signing | yes | yes | only if `own` (§3.1), and only by asking a device | only in a recovery session (§6.5) |
| Co-sign for others | yes | yes | yes | no |
| Get decryption answers (§5.5) | yes | no | no | no |
| Approve an account change (§6.2) | with its lock, with a second device, or with the paper | **no** | no | with a device, or in a recovery |
| Cancel a wait | with its lock, or with a second device | **no** | no | no (the holder withdraws its own) |
| Hold the release key | yes | no | yes | after release only |
| Hold the data key | yes | no | no | no |

## 3. Membership

### 3.1 The epoch record

A **kind 30242** event signed by the group key (4 points, so no single member can make one), with
tags `["d","keykin"]`, `["v","1"]` and `["epoch","<number>"]`. Its content is JSON:

```jsonc
{
  "v": 1,
  "g": "<x-only group key, hex>",
  "epoch": { "n": 3, "id": "<16 random bytes, hex>" },
  "prev": "<event id of the previous epoch record, or null at creation>",
  "t": 4,
  "commitment": ["<C0>", "<C1>", "<C2>", "<C3>"],   // 33-byte compressed points, hex, even-y form
  "role": "master",            // or "child" (§6.6); set at creation only
  "origin": "dkg",             // or "import"; set at creation only
  "relays": ["wss://…", "wss://…", "wss://…"],
  "members": [
    { "key": "<member key>", "kind": "device", "shares": [1, 2, 3],
      "lock": { "pub": "<65-byte P-256 point, hex>", "rp": "<32-byte rpIdHash, hex>" } },
    { "key": "<member key>", "kind": "server", "shares": [4],
      "host": "<host key>", "operator": "<operator pubkey>", "own": false,
      "https": "https://…", "vapid": "<65-byte P-256 point, hex>" },
    { "key": "<backup key>", "kind": "backup", "shares": [5, 6] }
  ],
  "removed": [ "<every member key ever removed from this account>" ],
  "backup": "<SHA-256 of the backup material's inner layer, §7.2>",
  "refresh": { /* the refresh's approval and every staying member's confirmation, refresh.md */ }
}
```

- `commitment` is the Feldman commitment to this epoch's `f`: `C_k = a_k·G`, with `C0` the group
  point, which never changes. The point of share `i` is always **derived**, `P_i = Σ C_k·i^k`, and
  never taken from a message.
- `lock` is absent for a member without one. `own` marks a server the user runs; it counts as one of
  the user's devices for privacy, nothing else.
- `removed` only grows, across epochs. A key in it is never a member again, in this epoch or any
  later one.
- **Unknown member kinds** are kept, and a device shows them. For the invariants, an unknown kind's
  shares count towards I2 as if it were a server, and as neither device nor server in I5. A member
  that meets an unknown kind MUST NOT take part in a refresh until it is updated, but signs everything
  else.

The epoch record and the changes are passed only between members, inside sealed messages (§9).
Members MUST NOT publish them to relays: they name the account's servers and devices.

### 3.2 Changes

A change is a **kind 24302** event signed by the group key, with tags `["v","1"]` and
`["epoch","<epoch id>"]`. Its content is JSON:

```jsonc
{ "v": 1, "g": "<group key>", "epoch": "<epoch id>",
  "change": { "add": { "key": "<member key>", "kind": "device", "lock": { … } | null, "salt": 0 } },
            // or { "remove": "<member key>" }
            // or { "lock": { "member": "<device key>", "replaces": "<old lock pub, or null>", "new": { "pub": "…", "rp": "…" } } }
  "approval": { /* §6.2 */ } }
```

- There are only three: **add a device**, **remove a device or helper**, and **re-register a
  device's lock** (after its face or fingerprint enrollment changed). Everything else (servers, a
  helper, the paper, relays) changes only at a refresh.
- **A device's current lock** is the lock in the epoch record (or in the add that brought it in),
  followed along lock changes: a lock change applies when its `replaces` is the device's current lock
  (`null` when it has none). If two lock changes replace the same lock, both are void and the device
  is lockless until it makes another lock change. Lock changes are approved only by `pair` or
  `paper` (§6.2).
- **Indices without coordination.** An added device's three indices are
  `2^16 + (int(SHA-256("keykin-index/1" ‖ g ‖ epoch id ‖ key ‖ salt ‖ j)[0..4], big-endian) mod 2^30)`
  for `j = 0, 1, 2` (`salt` and `j` as 4-byte big-endian integers). The inviting device picks the lowest `salt` whose indices collide with nothing it
  knows. If two changes of the epoch ever claim the same index, both adds are void and the new
  devices join again. Every index, here and in epoch records, is a FROST identifier given as a 32-byte
  big-endian scalar (`frost-core`'s `Identifier::deserialize`), not the 16-bit constructor.
- **Order does not matter.** The membership is the epoch record's members, plus every valid add,
  minus every key in a valid remove or in `removed`. A remove always wins over an add of the same key.
- A change is **valid** when it is signed by `g`, names the current epoch, and its approval names
  `device` members (never a helper) who were in the membership (the epoch record's members or devices
  added by changes of that epoch), with signatures every member verifies. A later removal of the approver does not undo it, so every member reaches the same answer
  whatever order changes arrive in.
- **Freshness is the co-signer's job, once.** Only a server co-signing a change checks that its
  approval is fresh: the challenge, the waited statements' age, that the approver is not already
  removed as far as the server knows. Everyone else, later or on joining, checks only the group
  signature, the approver's membership and the structure. (The co-signer's signature is the evidence
  that the check was made.) The window between an approver's removal and the news reaching a server
  is a stated limit (§10).
- **Epochs and changes.** A change naming an older epoch is refused, with one exception: a `remove`
  naming the epoch just before the current one is accepted for 7 days after the commit (members keep
  that epoch's record and changes that long) and applies in the current epoch too. A refresh plan MUST
  list every removal its sender knows of, and servers check that it also keeps every device added in
  the epoch (`refresh.md`). A member that receives a change naming an epoch newer than its own fetches
  that epoch's record first.
- Changes never expire within their epoch. Every server keeps the whole set and gives it out
  (`changes_get {epoch}` → `changes`). A member catching up asks **every** server and takes the union,
  so one server leaving out a removal changes nothing. A refresh folds the set into the next epoch record and starts a new empty one.
- While a server holds a pending refresh plan (`refresh.md`), it refuses new adds (`error busy`); a
  `remove` aborts the plan.

### 3.3 Invariants

The membership is valid only if all of these hold. Servers MUST refuse to co-sign an epoch record or
change that breaks one, and every member MUST refuse to adopt one.

- **I1.** No member holds more than 3 shares.
- **I2.** Servers together hold 3 shares or fewer.
- **I3.** There is at most one `backup`, holding 2 shares.
- **I4.** A round whose participants include no device-class member is a **recovery round** and
  needs a recovery session (§6.5).
- **I5.** Any set of members that contains no `device` and no `server` is worth less than 4, with
  `backup` shares counted as 0 (they are unreadable until a server releases them after its wait,
  §7.2). One consequence: at most one `helper`.

Also: each server holds exactly 1 share, each device and helper exactly 3; indices are unique; and
the epoch record has **at least 3 servers** (I2 then means exactly 3), so one dead server never
blocks signing. A server that leaves is in `removed` for good; to come back it joins with a new member
key. (Apps
add public servers automatically, alongside any server the person runs.) Changes only add devices
and remove devices or helpers, or change a lock, so they cannot break I1, I2, I3 or I5.

### 3.4 Checking

A member adopting an **epoch record** MUST check that:

1. it is kind 30242, its `d` tag is `keykin` (or, read-only, `cosign` or `frost`), its `v` and
   `epoch` tags equal the content's, and the signature verifies under `g`, the group key this member
   already knows (from its own creation of the account, or from the code it scanned, §4);
2. its epoch number is one more than the record it holds and `prev` is that record's id (or it is
   the record it was handed at join), and its `refresh` evidence verifies (`refresh.md`);
3. `C0` is the group point, and for every share it holds, `s_i·G == P_i`;
4. **a device, in addition, rebuilds the commitment from first-hand facts**: its own 3 points and
   the group point fix a degree-3 polynomial, so it computes `C0…C3` from them and refuses any record
   whose commitment differs. No member list can fool this;
5. the invariants hold, and no key in its `members` is in any `removed` it has seen.

A member taking a **change** MUST check that it is kind 24302, its `v` and `epoch` tags equal the
content's, it is signed by `g`, and it is valid (§3.2). A refused record or change is shown on a
device (§1.1). Members never go back to a lower epoch.

## 4. Joining

Adding a device uses this handshake, between refreshes or as part of one. A joining member trusts
nothing it did not get from a code the person scanned, from the group key, or from the check both
screens show. (This closes live finding #17.)

### 4.1 The codes and the check

Either side can show the code, so a desktop without a camera can still join.

- **Invite**, shown by a member device: `keykin:join?g=<group key>&m=<inviter member key>&s=<16
  random bytes, base64url>&x=<expiry, unix>&r=<relay>&r=<relay>…`
- **Join code**, shown by the new device: `keykin:hello?n=<new member key>&s=<…>&x=<…>&r=<relay>…`

Codes MAY be carried in a QRST code or an `https` bounce link; the fields are the same. `x` SHOULD be
at most 10 minutes ahead. Readers MUST also accept `cosign:` in place of `keykin:`.

**The check, always.** Anyone who sees a code can race the honest device to answer it, whichever
direction it goes. So after the hello, the side that received it answers with a fresh 16-byte `t`
(`join_nonce`), and both screens show (§1.1) a 6-digit number,
`int(SHA-256("keykin-join/1" ‖ g ‖ m ‖ n ‖ s ‖ t)[0..8], big-endian) mod 10^6` (keys as 32 raw
bytes, `s` and `t` as 16 raw bytes; in the join-code direction `g` and `m` are those in the
`welcome_offer`). The **new device shows** it and the person **types** it on the inviting device,
which goes on only if it matches. The hello fixes `n` before `t` exists, so nobody can grind a key
whose number matches.

### 4.2 The handshake

1. **Hello.** The side that scanned writes to the other, sealed to the key in the code:
   - invite direction: the new device sends `join_hello {n, s, lock}`: its member key, the secret,
     and its lock public key if it has one;
   - join-code direction: the inviter sends `welcome_offer {g, m, s}`, and the new device answers
     `join_hello {n, s, lock}` sealed to `m`. The inviter MUST accept only a `join_hello` sealed by
     the code's `n`, with `n` equal to it; that key, and no other, is the one added.

   A side MUST drop a hello or offer without the right `s`, after `x`, or after it already accepted
   one for this `s`. The receiver of the hello sends `join_nonce {t}`, sealed to the hello's sender;
   that sender MUST accept a `join_nonce` only from the key it sent the hello to.
2. **The change.** After the check, the inviting device gets the add approved (§6.2: its lock, a
   second device with the typed join check, or the paper) and gets the change co-signed by a server.
   A new member is always a `device`; it never chooses its own kind.
3. **Repair.** For each new index, the inviting device (3 shares) and one server (1) run the repair of
   `frost-core`'s `repairable` module with all 4 shares as helpers: each helper share computes its
   Lagrange-weighted deltas, the helpers exchange them (`repair_delta`), and each sums what it received
   into one `sigma`, sealed to the new device (`repair_sigma`). A server MUST take part only for indices
   that a valid change assigns to that new device. No member ever sees the new share.
4. **Welcome.** The inviting device seals to the new device (`welcome`): the epoch record, the set of
   changes, the relays, the release key, the backup material (§7.2) and the data key (§4.5).
5. **Checks.** The new device MUST refuse to finish unless:
   - the `welcome` is sealed by `m`;
   - the epoch record passes §3.4 against `g` (the invite's, or the offer's, which the device then
     shows as the account it joined, §1.1), and the change adding it is valid and names its key and
     lock;
   - it has `repair_sigma`s from `m` and from a server of the membership, and for every new index the
     summed share satisfies `s_i·G == P_i`. If the sum fails, the join fails and the device says so;
     it cannot tell which helper sent a bad part, so the inviter retries with another server.

   Then it sends `ack` to the inviter and to every server, and destroys the sigmas.

Why this holds: nobody without 4 points can produce a change signed by `g`, the inviter's
contribution cannot be forged, and a racer's hello fails the check.

### 4.3 The paper backup

The paper holds a **backup key pair**, not shares: the backup secret, the group key `g`, and the
servers' host keys and relays, so a recovery can start from the paper alone. Its shares exist only
wrapped (§7.2). The read-back (step 4) checks every field. It is made at
account creation or in a refresh, never between, and it is checked on the device that prints it:

1. The device makes the backup key pair.
2. The device and one server repair the backup's indices on the epoch's polynomial (in a refresh,
   with pending shares); every `repair_sigma` is sealed to the backup key. The device, which holds the
   backup secret at this moment, opens them, sums them and checks the shares against `P_i`.
3. The device wraps the shares and the data key (§7.2) and signs the inner layer with the backup key.
   The epoch record pins the inner layer's hash (`backup`), so members refuse any other copy.
4. The device keeps the backup secret, encrypted at rest (§7.3), until the person has printed or saved
   it **and shown it is readable** by scanning it back or re-entering it (§1.1), then destroys it and
   the shares. Until then that device alone is worth 5 points, the same as an nsec on it; it SHOULD
   prompt to finish the backup.

The paper never changes during its epoch.

### 4.4 Recovery join

In a recovery session (§6.5), the new device joins with the backup holder's app in place of the
inviting device: the repair helpers are the backup (2) and two servers (1 + 1), the welcome is sealed
by the backup key, and step 5 requires sigmas from the backup and both servers.

### 4.5 The data key

A random 32-byte key, never derived from the group key or any to-self conversation key and never
published. Devices hold it whole, in storage that is never backed up or synced (on iPhone, never in
iCloud Keychain or a restorable backup). Helpers, servers and backups never get it, except that a copy
is in the backup material, so a recovery loses no data (§7.2). It changes only at a refresh; devices
keep older ones so they can read older data, and data services re-encrypt lazily.

### 4.6 One member per machine

A machine should be **one** member, however many apps and browsers on it sign. Two members on one
laptop would be 6 points: that laptop alone would be the key. This is a SHOULD on member apps, not a
wire change.

- **With a desktop member app installed**, browser extensions on that machine hold no pieces. They pass
  NIP-07 requests to the app over the browser's native messaging, and the app is the member. This is
  how NIP-55 apps on Android share one member, and how the iPhone's Safari extension relays to its app.
  Every browser on the machine reaches the same app, so several browsers share one member.
- **With no desktop app**, one extension is the member itself, as today. A second browser on the same
  machine SHOULD NOT join as a second member. It connects to the account the way a site does (a grant
  through the member, Doors module), or the person installs the desktop app.
- **The app registers a native-messaging host.** An extension checks for it before acting as a member.
  If it finds the app, it does not join; if it already is the member, it **hands its membership over**:
  1. It passes **everything a `welcome` carries** (§4.2 step 4) to the app over native messaging: the
     member key and shares, the epoch record and the set of changes, the release key, the backup
     material and the data key, plus its site grants and its history.
  2. The app stores all of it durably, reloads it from storage, checks `s_i·G == P_i` for every share
     against the epoch record, and only then confirms.
  3. The extension then destroys its copy and becomes a relay.

  The membership doesn't change: same member key, same indices. So nothing in the account changes and
  no approval is needed. A copy that survives the handover (a crash between steps 2 and 3, a profile
  restored from a backup) is the same 3 shares twice, not 6 points. An app holds **one membership per
  account** and refuses a second handover for an account it already serves.
- **Retiring an extension.** When an extension that holds a membership finds the app, it compares
  first:
  - if the app holds the **same** member key for the same `g`, the extension's copy is a leftover:
    it just deletes it locally and sends nothing;
  - if the app holds a **different**, current member key for the same `g` (the app joined
    separately, so the laptop is two members), the extension removes itself: a `remove` naming its own
    key (§6.4);
  - if the app serves no membership for this `g`, the extension hands over as above.

  An extension never removes itself in any other case, so it can never remove the machine's only
  member.
- A lock belongs to the member app (Touch ID through the Secure Enclave). A handed-over membership has
  no lock until the app registers one by a lock change (§3.2).

Native messaging is not authenticated against other local software: a program running as the person
could register a fake host and receive the extension's shares at handover, or see the requests it
relays. Such a program can already read the extension's own storage (§7.3), so this adds nothing a
local thief doesn't already have; §10 says so.

## 5. Signing

### 5.1 The round

**Two parties: one call.** The coordinator (a device-class member, or an `own` server asking a device)
sends `sign` to one co-signer:

```jsonc
{ "type": "sign", "epoch": "<epoch id>", "event": { /* the full unsigned event, pubkey = g */ },
  "signers": [1, 2, 3, 4],                               // every index in this round
  "commitments": [ { "i": 1, "D": "…", "E": "…" }, … ],  // exactly the coordinator's indices
  "approval": { /* optional lock assertion, §5.8 */ }, "hold": "<wait id, optional, §5.8>" }
```

The co-signer checks (§5.7), makes fresh nonces for its own indices, and answers `partial` with its
commitments and its signature shares together:

```jsonc
{ "type": "partial", "commitments": [ { "i": 4, "D": "…", "E": "…" } ], "z": [ { "i": 4, "z": "…" } ] }
```

The coordinator then computes its own shares, aggregates, checks the result as an ordinary BIP-340
signature on the event id, and publishes. It MUST check each partial against `P_i` derived from the
named epoch's commitment (`verify_signature_share`) and name the member whose partial fails. All
shares in one round are of the epoch the request names.

**More than two parties: two calls.** When a round needs more than one co-signer (a recovery round,
§6.5), the coordinator first sends `commit {signers}` to each and gets back `commitments`; each
co-signer keeps those nonces in memory only, for at most 120 s, for that one request id. Then it sends
`sign` with the full commitment list and `after: <the commit request's id>` to each, under a new id,
and each answers `partial` from the nonces it kept for `after`. A co-signer MUST check that its own
entries in the list are the commitments it returned for `after`, and MUST refuse a second `sign`
naming the same `after`.

- **Binding.** Binding factors and the group commitment MUST be computed over the full commitment list
  for `signers`, every index of every participant. A co-signer MUST refuse a commitment list that does
  not cover exactly the other participants' indices, or that contains the identity point.
- **Several co-signers in the one-call form.** A coordinator MAY ask several at once (reference: the
  fastest first, the rest after 300 ms). Each request is an independent round with its own coordinator
  nonces and its own id. It completes with the first valid partial and discards the nonces of the
  others.
- **Formal check.** The one-call form lets a co-signer pick its nonce after seeing the coordinator's.
  Six reviews found no attack (the co-signer moves last; the coordinator is where standard FROST puts a
  signer in round 2), but it needs a formal check before 1.0 (§13).

### 5.2 Nonces

- A member MUST generate nonces only for a request it is answering or sending, keep them in memory
  only, and use each once. Nonces MUST NOT be written to disk, shared storage, logs or anything a
  snapshot, a restore or a second process could bring back. After a restart, every round in flight is
  lost.
- **Hedged randomness.** The random input to `nonce_generate` MUST be
  `SHA-256(fresh OS randomness ‖ share ‖ context)`, where context is, for a co-signer, the SHA-256 of the
  request; and for a coordinator, `event id ‖ signers ‖ request id ‖ co-signer key`.
- A coordinator MUST compute its own signature shares at most once per nonce. A retry uses fresh nonces
  under a new request id.

### 5.3 Retries

A co-signer that gets a request whose `(sender, id)` it already answered MUST return the same answer it
sent, **only if** the new request is byte-identical (same SHA-256 of the RFC 8785 canonical body) to the
first. Otherwise it MUST refuse with `id_reused`. It keeps its answers, never its nonces.

### 5.4 Never a bare digest

Co-signers MUST receive the full event, compute its id themselves (NIP-01) and check that `pubkey` is
`g`. There is no message that signs a hash.

### 5.5 Decryption

For NIP-04, NIP-44 and NIP-59, a device needs `x·Q` for a peer point `Q`. It sends
`ecdh {epoch, points: [Q…], signers}` to a co-signer, where `signers` is its own indices plus the
co-signer's and is worth 4 (checked as in §5.7 item 2). Every `Q` MUST be a valid point other than the
identity. For **each** of its indices `i` and each `Q`, the co-signer answers `ecdh_partial` with the
weighted value `Y = λ_i·s_i·Q` (`λ_i` the Lagrange coefficient of `i` in `signers`) and a proof that
`Y` and `λ_i·P_i` share a discrete log:

```
k = H("keykin/ecdh-k/1" ‖ fresh OS randomness ‖ s_i ‖ Q ‖ SHA-256(request)) mod n
R1 = k·G;  R2 = k·Q;  W_i = λ_i·P_i
e = H("keykin/ecdh-dleq/1" ‖ g ‖ epoch id ‖ i ‖ W_i ‖ Q ‖ Y ‖ R1 ‖ R2) mod n
z = k + e·λ_i·s_i       verify: z·G == R1 + e·W_i  and  z·Q == R2 + e·Y
```

(`H` is SHA-256; points 33-byte compressed, integers 4-byte big-endian, scalars 32 bytes.)

- Because the answer is weighted for a set that includes the asker's indices, it is useless unless the
  asker adds its own 3 points' worth. A member key with no shares learns nothing.
- The coordinator MUST refuse an answer unless its indices equal that member's indices exactly (none
  missing, none extra, no repeats) and every proof verifies with `P_i` derived from the epoch's
  commitment. A refusal is that member failing, by name. An answer without proofs is a failure.
- Co-signers MUST answer `ecdh` only from a current `device`, so no server, `own` or not, ever
  coordinates a decryption.

### 5.6 Lifetimes and replays

Every request carries `cls`. Each message type allows only some classes:

| `cls` | Lifetime | Allowed for |
|---|---|---|
| `sign` | 60 s (receivers MAY use 45 s) | `sign`, `commit`, `ecdh` |
| `ask` | 120 s | `sign`, `commit`, `ecdh`, `challenge`, approvals |
| `member` | 7 days | `hold`, `release_request`, deliveries |

- A receiver measures age with its own clock from the rumor's `created_at` (when the request was sent),
  or from the inbox's `age` (§8.2) if that is larger. It MUST refuse a request older than its lifetime
  plus 30 s, or dated more than 30 s ahead.
- The **event's** `created_at` (when the person wrote it) never decides whether a request is fresh. A
  draft written offline waits in the device's outbox, keeps its time, and is signed with a fresh `sign`
  request when the device is online again.
- A receiver MUST remember `(sender, id)` until the request's lifetime has passed, and treat a second
  request with it by §5.3. Servers MUST keep these across restarts. A server MAY cap them per member
  (reference: 10,000), refusing new requests from that member when full rather than forgetting old ids.

### 5.7 What every co-signer checks

Before giving a partial, a co-signer MUST check that:

1. the sender is a member of the current membership and may coordinate (§2);
2. `signers` is exactly the sender's indices plus this co-signer's (plus, in the two-call form, the
   other co-signers'), is worth at least 4, all of the named epoch, and the commitments cover it
   exactly (§5.1);
3. the request is fresh and not a replay (§5.6);
4. `event.pubkey` is `g`, and, for a **replaceable or addressable** kind (0, 3, 10000–19999,
   30000–39999), the event's `created_at` is no more than 10 minutes ahead of its own clock: a version
   dated ahead would block every later change until that date. Other kinds may be dated ahead, so a
   person can schedule a post;
5. if the event is **kind 30242 or kind 24302, whatever its tags**, it is account machinery: it MUST be
   a valid epoch record (`refresh.md`) or a valid change (§3.2), and a device MUST never sign one on a
   site's request;
6. if the round is a recovery round (I4), the recovery session's rules are met (§6.5);
7. the stateless destructive rule (§5.8).

A device co-signing for another device-class member also applies its own destructive policy (Device
policy module) and asks the person when that says to.

### 5.8 The stateless destructive rule

Servers keep no history, so they cannot tell that a follow list shrank. They can recognise a few events
that are destructive on their face, and for these a server MUST require **either** an `approval` (a lock
assertion from the coordinating device over `"sign" ‖ event id`, §6.1, valid for that event at any
co-signer and any retry), **or** a passed hold:

- every request to vanish (kind 62);
- a **mass deletion**: a kind 5 with 5 or more `e`/`a` targets, or a kind 5 that would take this account
  past 5 deletion targets co-signed by this server without approval in the last 10 minutes (a burst;
  reference numbers, counted per account at each server, no history kept; a thief spreading deletions
  over three servers gets about three times that, still far less than a stolen nsec allows);
- kind 0 whose content is `{}` or has no non-empty `name`, `display_name`, `about` or `picture`;
- kind 3, 10000–10030 or 30000–30030 with no tags other than `d`;
- kind 10002 with no `r` tags.

**Holding** is a wait (§6.3) on `{"hold": <event id>}`: the device sends `hold {event}`; servers start a
wait and tell every member and channel; after `W` the device sends `sign` with `hold: <wait id>` and a
server co-signs if its own wait passed and nobody cancelled. A server keeps at most 10 holds per device
at a time (reference).

A single deletion needs neither: the device holds it for 10 seconds with Undo (Device policy module) and
then signs it like any event.

This is a backstop, and it is easy to step around for lists: a follow list cut to one junk entry is not
empty. The device is the real gate, and its policy holds far more. What that leaves open is in §10.

## 6. Account changes

### 6.1 The lock

A lock is a P-256 key generated in secure hardware that signs only after a fresh **biometric** match and
is invalidated when the enrolled biometrics change:

- iPhone and Mac: Secure Enclave with `biometryCurrentSet`;
- Android: Keystore with `BIOMETRIC_STRONG` only and `setInvalidatedByBiometricEnrollment(true)`.

A key that accepts a passcode or PIN instead is **not a lock**. Browser passkeys (WebAuthn) do not count,
because a site cannot stop them falling back to a PIN. So a phone with only a passcode, a browser
extension, and a Mac without Touch ID have no lock. A device's lock is set when it joins. When it stops working (a new face or fingerprint was
enrolled), the device is lockless until it re-registers one by a lock change (§3.2), approved by a
second device or the paper, or at a refresh.

A **lock assertion** has one encoding everywhere, WebAuthn's structure:
`{ "authData": "<b64url>", "clientData": "<b64url of JSON>", "sig": "<b64url DER>" }`.

A verifier MUST check that `clientData.type` is `"webauthn.get"`; that `clientData.challenge` is
`base64url(SHA-256("keykin-lock/1" ‖ g ‖ what))`; that `authData` starts with the member's `rp` and has
the user-present and user-verified flags set; and that `sig` verifies over
`authData ‖ SHA-256(clientData)` with the member's `pub`. `what` is:

- for a destructive event, `"sign" ‖ event id` (§5.8);
- for an account change, `"change" ‖ SHA-256(JCS(change)) ‖ epoch id`;
- for a cancel, `"cancel" ‖ wait id`;
- for a refresh, `"refresh" ‖ SHA-256(JCS(plan without approval))`;
- for any other request (`take_out`, removing a notice channel), `type ‖ id ‖ SHA-256(JCS(body
  without the assertion))`.

A `pair` signs the same string as a lock would for that request.

A `paper` approval's backup signature covers the change hash and a challenge from the server it is
sent to; only that server checks the challenge (§3.2).

Native apps build the same structure themselves. Servers cannot tell that a lock is in hardware or
biometric-only (no attestation is required); that is a stated limit (§10), not a check.

### 6.2 Approvals

An account change (a change of §3.2, a refresh, an export) is approved by exactly one of these, carried
in its `approval`. Signed items carry **detached** BIP-340 signatures by the signer's member key over
`SHA-256("keykin-<type>/1" ‖ g ‖ JCS(body))`, because a NIP-59 seal proves nothing to a third party.

- **`lock`**: `{ "member": <key>, "assertion": … }`, the asking device's lock (§6.1).
- **`pair`**: `[ { "member": <key>, "sig": … }, { "member": <key>, "code_sig": … } ]` from two distinct
  devices, each after asking its person (§1.1). The first device shows a 6-digit code,
  `int(SHA-256("keykin-pair/1" ‖ g ‖ change hash ‖ r)[0..8]) mod 10^6` with a fresh 16-byte `r` it sends
  along; the person **types** it on the second device, which signs only if it matches. For adding a
  device, the code is the join check shown on the new device (§4.1). Two devices are 6 points, already
  the key, but the typed code proves the person can see both.
- **`paper`**: `{ "member": <device key>, "sig": …, "backup_sig": … }`: a device together with the
  paper, the backup key signing the change hash over a fresh server `challenge`. A device and the paper
  are 5 points, already the key.
- **`recovery`**: `{ "release_request": …, "waited": [<statement>, <statement>], "backup_sig": … }`: the
  paper alone, in a recovery session (§6.5), after two servers' waits. The backup key signs **this
  change's** hash, and servers take it only from the backup holder's own connection in that session.

There is **no "wait instead"**: a device with no lock, on its own, cannot make account changes. It uses a
second device or the paper. A helper never approves anything.

| Change | Approval |
|---|---|
| Add a `device` (§3.2) | `lock`, `pair` or `paper`; or `recovery` |
| Re-register a device's lock (§3.2) | `pair` or `paper`; or `recovery` |
| Report a `device` or `helper` lost (§6.4) | `lock`, `pair` or `paper`; or `recovery` |
| A device removes itself (§6.4) | its own member key's signature |
| "Refresh now" (servers, helper, paper, locks, relays, data and release keys) | `lock`, `pair` or `paper`; or `recovery` (`refresh.md`) |
| Export a child key (§6.6) | `lock`, `pair` or `paper` |
| Remove or replace a notice channel (§8.1) | `lock`, `pair` or `paper` |
| Add a notice channel | any device, no approval (refused during a recovery wait) |

### 6.3 Waits

- There are only two kinds of wait, both `W` on each server's own clock: a **recovery** (§6.5) and a
  **hold** (§5.8). A server starts one, tells every member (an `ask` push and an inbox notice) and every
  notice channel (§8.1), and when its own wait has passed, pushes the requester (`ask`) and signs a
  **waited statement**: `{ "server": <host key>, "kind": "recovery" | "hold", "wait": <wait id>,
  "start": <unix>, "end": <unix>, "sig": <BIP-340 by the host key over SHA-256("keykin-waited/1" ‖ g ‖
  kind ‖ wait ‖ start ‖ end)> }` (`start` and `end` as 8-byte big-endian unix seconds). A hold's wait id is `SHA-256("hold" ‖ event id)`; a recovery's is
  `SHA-256("recovery" ‖ backup key ‖ epoch id ‖ r)`, with `r` a random value the holder puts in every
  `release_request`, so every server names the same wait. Verifiers MUST check that `end − start ≥ W`;
  a co-signer also accepts a statement only within 7 days of its `end` (§3.2).
- **Cancel** `cancel {wait}`, from a `device` with a lock assertion or from two devices (`pair`), ends
  the wait at that server, which tells everyone. A device sends it to every server and repeats until
  each one answers. A helper never cancels. The requester may always
  `withdraw` its own. A server MUST NOT issue a waited statement or a release bundle until it has fetched
  its deliveries from its peers (§7.1), so a missed `cancel` still counts; a peer that has not answered
  for an hour is skipped.
- **A recovery freezes holds.** When a server starts a recovery wait, it ends every running hold and,
  until the recovery wait is cancelled or the recovery session ends, refuses new holds and new notice
  channels. (A thief who knows a locked phone's passcode can reset its face; the lock then stops working,
  and everything the thief can still do is a hold or everyday signing.)
- Signing carries on as normal during any wait.

### 6.4 Report lost

- A change `{"remove": <key>}` names a `device` or a `helper`, with its approval (§6.2). A lockless
  single device cannot report another; the person uses a second device or the paper.
- **A device may always remove itself**: a `remove` naming its own key, approved by its own member key's
  detached signature, needs nothing else. It is how an extension retires in favour of its machine's
  app (§4.6), and a thief gains nothing by it.
- The change goes to every server and every device as a delivery (§7.1). From the moment a member has
  it, servers MUST refuse every round with the removed member and drop its push addresses, and devices
  MUST refuse to co-sign with it. It is never delayed.
- **Removal is final.** Nobody is put back; a device removed by mistake joins again.
- **What removal does not do.** The removed device's shares, the release key and the data key do not
  change. Every member refusing it is the protection (§10). "Refresh now" re-deals the shares, so the
  removed device's pieces no longer combine with any honest member's; apps SHOULD offer it after a
  removal once it exists (it is parked, §12). What the removed device itself kept, it keeps (§10).

### 6.5 Recovery

A round with no device-class member (I4) happens only in a recovery session.

1. The backup holder picks a random `r`, asks each server for a `challenge`, and sends each a
   `release_request {r}` signed by the backup key over that server's challenge. Servers pass it to their peers as a delivery (§7.1), so a server that was down starts its
   own wait before it acts for the account again.
2. Each server starts a recovery wait (`W`, §6.3), tells every member and channel, and freezes holds. A
   locked device, or two devices together, can cancel it; the holder can withdraw it.
3. When its own wait has passed, a server seals the **release bundle** to the backup key: the current
   release key, the epoch record, the set of changes, and its waited statement (`release`).
4. The holder fetches the backup material from any server or device (§7.2), checks its inner layer
   against the epoch record's `backup` hash and the backup key's signature, opens it, and checks the
   shares against the commitment.
5. For 7 days after its own wait ended (the **recovery session**), each server takes part, in the
   two-call form (§5.1), in rounds of the backup plus two servers: but only for a recovery join (§4.4),
   changes approved by `recovery` (§6.2), and a refresh. Not ordinary events.
6. The recovery app then destroys the backup's shares and the release bundle. The paper stays the
   same: a new paper needs "Refresh now", which is parked (§12). Once refresh exists, the new device
   runs it to make a new paper with a **new backup key**.

So a stolen paper needs two servers that each take part after their wait, with every device told.

### 6.6 Exporting keys

- **The master key is never exported.** A server MUST NOT seal its share to anyone for a `master` group,
  and members MUST NOT offer to combine a master group's shares into an nsec. (Someone combining their
  own shares with their own tools cannot be stopped, and this does not try.)
- **A child key** may be exported in stages: in Core 1.x any child; in a later version only children
  with `origin: import`; then none. Export is `take_out {}` from a device with an approval (§6.2); each
  server seals its share to that device and tells every member.
- A server treats a group as a child only if it adopted, first-hand at the group's creation, a first
  epoch record that says `role: child` (Key families module). An account made by importing a 0.12
  account's nsec (§11.2) is always `master`.
- An export is permanent.

## 7. Keeping what you hold

### 7.1 Deliveries kept until acknowledged

Everything a member needs from others (the welcome, repair sigmas, the epoch record and changes, the
release key, the backup material, and every `cancel`, `withdraw` and `release_request`) is a
**delivery**. Every server of the account MUST keep each delivery for every member, other servers
included, until that member sends `ack` for it or is removed, and MUST hand it over when asked (§8.2).
A server that was offline MUST fetch its deliveries from its peers before it co-signs, issues a waited
statement or releases anything again, skipping a peer that has not answered for an hour. Changes are
kept for the whole epoch (§3.2). Deliveries for a removed member, and for the backup (which never
fetches), are dropped; `deliver` from a removed member is refused.

Deliveries travel **through HTTPS, server inboxes, or live kind 21059 wraps** (which relays do not
store), never as stored kind 1059 copies on relays: anything that carries a share or a key must not
sit in public archives.

### 7.2 The backup material and the release key

The backup's shares exist only as **backup material**: the shares (made and checked once per epoch,
§4.3) and a copy of the data key, wrapped first with NIP-44 to the backup key and signed by the backup
key (the **inner layer**, whose SHA-256 is the epoch record's `backup`), then with XChaCha20-Poly1305
under the release key. Every server and every device keeps the current copy (so device + paper still
works if every server is gone), and members refuse any copy whose inner layer does not match. Helpers and
backups never hold the release key.

So helper + paper (3 + 2) cannot sign without a server's wait (I5). Device + paper works at once, because
the device holds the release key.

### 7.3 Storage at rest and destruction

- On phones and desktops, shares and the member key at rest MUST be encrypted under a key specific to
  this membership, kept in platform secure storage (Keychain "this device only", Android Keystore, an OS
  keyring). Destroying means **deleting that key** (closes #7 where the platform can delete keys), not
  only the ciphertext.
- That storage key MUST NOT require the person's face, fingerprint or passcode to use, and signing MUST
  NOT be limited to while the device is unlocked: background signing works as it does with an nsec today.
  (iPhone keeps keys sealed between a restart and the first unlock; that is the platform, not a rule.)
  The lock (§6.1) is a separate key, used only for approvals.
- A removed or wiped member MUST destroy everything it holds, with no snapshot, backup, version history
  or log line that keeps it. Where storage keeps history that cannot be turned off (for example 30-day
  point-in-time recovery), only ciphertext may be stored there, with the key kept outside it.
- On iPhone, shares and keys MUST be excluded from iCloud and restorable backups.
- A browser extension SHOULD encrypt what it stores where that costs no extra prompt, and otherwise
  stores it plainly in the extension's own storage. That is still better than an nsec kept the same way:
  a copied profile gives 3 points, not the key.

## 8. Push and inbox

### 8.1 Registration

- A device registers with **each** server, per account, by `push_register` (sealed, so signed by its
  member key): `{ "addresses": [ { "cls": "sign" | "ask" | "notice", "url": "…", "p256dh": "…", "auth":
  "…" } ] }`. One address per wake class. The newest set, by the rumor's `created_at`, replaces the old
  one. `push_unregister {}` removes them all.
- Each server signs its pushes with its own VAPID key (RFC 8292), the `vapid` key in the epoch record.
  Gateways issue a separate random address per server and per account, pinned to that server's VAPID key
  when the device asks for it, so the address is useless to anyone else and servers cannot link one
  phone's accounts.
- A server drops an address that returns 404 or 410, drops a removed member's addresses, and MUST NOT
  copy addresses to other servers.
- **Notice channels.** A device MAY register `notify_register { "email": "…" }` or
  `{ "webhook": "https://…" }` with a server. Servers MAY support them; a server that does MUST send every
  wait notice there too, never content beyond "a change to your account is waiting; it completes on
  <date> unless you stop it". Any device may **add** a channel; removing or replacing one needs approval
  (§6.2), and the old channel is told.

### 8.2 Sending and the inbox

- Servers send standard Web Push (RFC 8030), encrypted with RFC 8291 `aes128gcm`. The payload is JSON
  `{ "v": 1, "cls": "…", "id": "<request, notice or wait id>", "srv": "<host key>", "wrap": <the sealed
  message, only if it fits>, "sig": "<BIP-340 by the host key over SHA-256(JCS of the other fields)>" }`,
  padded so every encrypted body is the same length and no more than 2,560 bytes (reference 2,400). A
  sealed `sign` for an ordinary note is about 3.9 KB, so in practice the device fetches; `wrap` is for
  small notices.
- Anything for a member that may be asleep goes in that server's **inbox** first, and only then is
  pushed. A member leaves something for another member with `deliver {to, wrap}`: `to` must be a current
  member, the wrap's `p` tag must be `to`, and the server counts it against the sender's caps (reference:
  32 waiting per sender and recipient, with its own push budget). Kind 21059 is used only towards members
  known to be awake (§9.1).
- `inbox_get {}` returns `{ "items": [ { "iid": "…", "age": <seconds held>, "wrap": {…} } ], "waits":
  [ <every recovery or hold running for the account, with its end> ] }`; `inbox_ack { "iids": […] }`
  removes items. Items expire with their lifetime class; deliveries (§7.1) stay until acknowledged.
- **Opening the app MUST fetch every server's inbox**, with no gateway involved. A dead gateway slows a
  device down; it never cuts it off.
- Wait notices go as `ask` pushes from **every** server to **every** member, with the wait id, so devices
  merge the copies.
- Servers MUST cap each account's inbox (reference: 512 items or 4 MB, ordinary notices dropped oldest
  first; deliveries and wait notices never, until their wait ends) and pushes per address (reference: 60
  an hour, with wait notices always sent).

### 8.3 Gateways

A gateway turns Web Push into APNs (or FCM). Each app maker runs its own; servers do not care which. A
gateway MUST keep no state but its address table, no logs of payloads, never see content (it forwards
the encrypted body), check the VAPID signature against the key pinned to the address, and rate-limit
each address. Its addresses MUST be random ids, never raw device tokens. Android apps using UnifiedPush
need no gateway. (Delivery details for APNs, such as priority 10 for `sign` and `ask`, are guidance in
the iOS appendix of the Doors module.)

## 9. Transport

### 9.1 The envelope

Every member message is a **kind 24301 rumor** whose content is JSON
`{ "v": 1, "type": "…", "g": "<group key>", "epoch": "<epoch id>", "id": "<request id>", "cls": "…", … }`,
sealed (kind 13) by the sender's member key and gift-wrapped (NIP-59) to the recipient's member key.
The seal's key is the sender: there is no other sender field.

- **Live** (towards servers, and towards members known to be awake): kind 21059, re-sent until answered.
- **Stored** (towards a member that may be asleep): the server's inbox (§8.2). Messages that carry no
  share, key, epoch record or change MAY also go to relays as kind 1059 with a NIP-40 `expiration` at the
  end of their class.
- **Never stored on relays:** anything that carries a share, a key, an epoch record or a change goes
  only live (kind 21059), over HTTPS, or through an inbox, never as kind 1059 (§7.1).
- A plaintext over 24,000 bytes is split into `{ "type": "part", "of": "<id>", "k": k, "m": total,
  "data": "<base64>" }` rumors, reassembled by `(sender, of)`. Receivers MUST refuse a message over 512 KB
  in total and drop parts whose message has expired.
- Errors: `{ "type": "error", "re": "<id>", "code": "…" }`. Unknown `type` → `unsupported`.

### 9.2 Relays and HTTPS

- **Relays MUST** work for everything. Members subscribe on the epoch record's `relays` (SHOULD be 3 or
  more, from different operators) to kinds 1059 and 21059 with `#p` = their member key. A server also
  listens on the relays in its own announcement, and devices always also use each server's announced
  relays (and HTTPS).
- **HTTPS SHOULD** be offered by servers that can. `POST <https>/keykin/v1` with a JSON array of gift
  wraps addressed to the server; the answer is a JSON array of gift wraps. Same format, so a member can
  switch between the two at any message. An iPhone's notification extension uses HTTPS when it is there,
  because it is faster.

### 9.3 What a server may be made to reach

Members name relays, push addresses, webhooks and HTTPS endpoints. A server MUST NOT connect to private,
loopback, link-local, carrier-grade NAT or cloud-metadata addresses because a member or a stranger named
them; it MUST resolve and check at every connect, MUST NOT follow redirects, and SHOULD cap new accounts
per IP per day (reference 10), messages per account per minute (120) and request size (512 KB). An open
server MAY ask for proof of work (NIP-13) on enrollment.

### 9.4 Messages

| `type` | From → to | § |
|---|---|---|
| `welcome_offer` / `join_hello` / `join_nonce` | inviter → new device / new device → inviter / receiver of the hello → sender | 4.1, 4.2 |
| `welcome` | inviting device (or backup holder) → new device | 4.2, 4.4 |
| `repair_delta` / `repair_sigma` | helper ↔ helper / helper → new member or backup key | 4.2, 4.3 |
| `commit` / `commitments` | coordinator → co-signer / back (two-call form only) | 5.1 |
| `sign` / `partial` | coordinator → co-signer / back | 5.1 |
| `ecdh` / `ecdh_partial` | device → co-signer / back | 5.5 |
| `hold` | device → servers | 5.8 |
| `pair_request` / `pair_sign` | first device → second device (via `deliver`) / back | 6.2 |
| `change` | any member → members (a signed change) | 3.2 |
| `changes_get` / `changes` | member → server / back | 3.2 |
| `cancel` / `withdraw` | device → servers / sender → servers | 6.3 |
| `challenge` / `release_request` / `release` | server ↔ backup holder | 6.2, 6.5 |
| `take_out` / `released` | device → servers / back (children only) | 6.6 |
| `ack` | member → servers | 4.2, 7.1 |
| `notice` | server → members | 6.3, 8.2 |
| `push_register` / `push_unregister` / `notify_register` | device → server | 8.1 |
| `inbox_get` / `inbox` / `inbox_ack` / `deliver` | member ↔ server | 8.2 |
| `part`, `error` | anyone | 9.1 |

`refresh.md` adds its own messages. That is the whole of Core. Cosign 0.12 has 55 message types in
`server/core/group.ts`; everything not here belongs to a module or goes.

## 10. Security properties, and their limits

**What holds.**

- One member signs nothing: not a device (3), not a server (1), not the backup (2), not a helper (3).
- All servers of an epoch together (3) can never sign, and neither can two colluding operators. Servers
  change only in a refresh, which re-deals, so old server pieces never add up with new ones.
- A server can delay or withhold its share and see what it co-signs. It cannot sign, cannot make an
  epoch record or a change, cannot add a member that others believe (live finding #1), cannot read
  messages (decryption answers are useless without a device's own points), and cannot fake a push.
- A joining device trusts only its scan, the group key and the check on both screens (#17).
- A lock is a biometric-only signature that servers check, not a device's word (#4). A face reset on a
  stolen phone kills its lock.
- **No account change without a lock, two devices with a typed code, or the paper.** A thief holding one
  phone without its lock cannot add a device, report the owner's devices, start a refresh or touch the
  paper. They can sign everyday events, and start holds, until the owner reports the phone from a second
  device or with the paper.
- Everyday changes are independent and safe in any order, so the account cannot fork and a device that
  was away catches up by fetching them.
- A stolen paper needs two servers that each waited, with every device and channel told; the owner's
  locked device, or two devices, can stop it.
- The paper is checked when it is made, signed by its own key and pinned in the epoch record, so no one
  can silently spoil it.
- Nonces never touch storage and are hedged, so no restore or snapshot replays one.

**What does not, said plainly.**

- **While "Refresh now" is parked, the structure is fixed.** An account keeps the servers, helper and
  paper it was created with. A dead server cannot be replaced: with 3 servers, one dead still leaves
  signing and recovery working; two dead leave signing (device + the last server) but no paper
  recovery. The data key never changes. After a paper recovery the same paper stays in use. These go
  away when refresh is reworked.

- **Removed devices keep valid pieces.** The key underneath never changes, so whatever a removed
  device kept still fits it. Between refreshes: a removed device plus any one server that ignores the
  block (hacked, buggy, restored from an old backup) is 4 points, and it can read private data written
  later. "Refresh now" changes that: honest members destroy their old pieces, so the removed device's
  3 no longer combine with any honest server's, and the data key changes. But **pieces of the same
  epoch that someone kept still combine with each other, for ever**: a removed device (3) plus the old
  paper (2) is the key, and so is a removed device plus a dishonest server's kept old share. That is
  why the old paper must be destroyed after a refresh. After a serious leak of the key itself, the fix
  is a new key with key families (later).
- **A stolen paper plus two dishonest servers** is the key. Today one operator runs every server. And a
  paper recovery that nobody cancels leaves the thief with a device, so the key for good.
- **The paper needs two live servers** to recover; with fewer, it can only be used together with a
  device.
- **One operator today.** All three live servers are run by one person, so "two servers' waits" and
  "every server refuses" are one party's word until other operators exist.
- **Two stolen devices** (6 points) sign without any server and skip every server rule. On one
  machine, the one-member rule (§4.6) means a laptop with the desktop app and its browsers is one
  member, 3 points. The limit remains where the rule can't apply: two browsers on one machine that each
  joined separately with no desktop app, or apps that ignore the SHOULD.
- **Local software on a member's machine** that runs as the person can read an extension's stored
  shares, fake the native-messaging host at a handover, and see the requests an extension relays. That
  is 3 points and the account's traffic on that machine, the same as for an nsec stored there, which
  is the bar.
- **A stolen device plus one dishonest server** is 4 points: if the device's shares can be extracted,
  that is the key itself, offline and for good.
- **A stolen device with no lock plus one honest server** can sign everyday events, and overwrite lists
  and the profile, until the owner reports it: the server's rule (§5.8) catches only events that are
  destructive on their face.
- **A lockless single-device owner** can't report a stolen phone lost by itself; the paper (3-day
  recovery) or a notice channel is how they act. With neither, nothing tells them, but the thief can
  still only sign everyday events and start holds.
- **A change approved just before its approver's removal reached a server stays valid.** The window is
  how long a `remove` takes to arrive.
- **Helper plus one server** signs, by design: the person opted in to that.
- **A lock accepts any enrolled biometric**, a partner's finger included, as the phone itself does.
- **Locks are unattested.** Servers cannot tell a hardware, biometric-only key from a software one, and a
  tampered app can make its own "lock".
- **Browser profiles.** An extension keeps shares a copied profile can carry away unless the browser
  offers prompt-free secure storage (live finding #5). That is 3 points, not the key: better than an nsec
  in the same storage, which is the bar. An extension never has a lock.
- **Until the paper is printed**, the device that made it holds 5 points (§4.3).
- **iPhone push.** Waking an iPhone needs Apple and the app maker's gateway. The gateway sees when each
  phone is woken and by which servers, not why. If it is down, signing still works when the app is
  opened, from other devices, or through any other Keykin app; notices are what suffer.
- **Membership leaks.** Epoch records and changes are never published, but any member could leak them.
- **Imported keys and exports are for ever.** A key that was ever whole stays whole wherever it was.
- **The one-call round is not yet formally checked** (§5.1).

### 10.1 Live findings this core closes

| Finding | Closed by |
|---|---|
| #17 joining phone trusts any welcome | §4 (group-signed changes, inviter's sigma, the typed check with its nonce) |
| #4 lock taken on trust | §6.1 (biometric-only, checked), §6.2 |
| #1 injected member can act | §3 (only group-signed epoch records and changes; kinds fixed) |
| #7 wipe leaves shares recoverable | §7.3 (browsers: §10) |
| #2 paper added with any key | papers only at creation or refresh (§4.3), checked, signed and pinned |
| #3 report-lost race | §6.2, §6.4 (lock, two devices with a typed code, or the paper) |
| #8, #9 server archive and ECDH oracle | §2 (no history), §5.5 (devices only, weighted) |
| #12 paper promotes itself | kinds never change; a backup is never a device |
| #13 stranded server, #14 removal in a pending refresh | deliveries (§7.1); a `remove` crosses epochs (§3.2) and aborts a plan (`refresh.md`) |
| #16a/b optional or partial proofs | §5.5 |
| #5 extension shares unencrypted | encrypted where it costs no prompt (§7.3); otherwise 3 points, which beats the bar (§10) |
| #10, #11, #15 | Doors and Device policy modules (grants live on devices) |

## 11. Versions, moving from Cosign 0.12, the rename

### 11.1 Versions

- Core follows semantic versioning. Any wire change bumps the major version, which is `v` in every
  rumor, every epoch record, every change and every push payload.
- Unknown fields are ignored. Unknown message types are refused (`unsupported`). Unknown member kinds are
  kept (§3.1).
- Servers SHOULD support versions N and N−1. A device that meets a record, change or message with a major
  version it does not know MUST refuse to sign and show that it needs an update (§1.1).

### 11.2 Moving a Cosign 0.12 account to Keykin

There is **no in-place move**. Cosign 0.12 never pinned its members' lock keys, so nothing a 0.12
member says can be trusted to run one.

A 0.12 account moves by **import**: the person brings the account's nsec (for the user's own account,
from their password manager) to a Keykin device, which creates a fresh Keykin account with the same
npub and new pieces (Account admin module, "import": deal, then wipe; `origin: import`). Then the old
account is retired: each 0.12 server is asked to forget (0.12's guarded `forget`), and the 0.12 apps
wipe their copies. The npub stays the same, so followers notice nothing.

The key was whole when it was imported, so it is "ever whole" (§10). That was already true of the
user's account.

### 11.3 The rename

Readers MUST accept the old names for ever: the record `d` tag `frost` and `cosign`, the server
announcement `d` tag `cosign-server`, `cosign:` codes, and Cosign paper backups (same key format, same
meaning). Writers use the `keykin` names. Kind numbers 24301, 24302, 30242, 30243 and 10243 stay
provisional until upstream assigns them.

## 12. Modules (not part of Core)

Each is a short document of its own, and none may weaken anything above.

- **Refresh now** ([`refresh.md`](refresh.md)), **parked**: the ceremony for structural changes
  (servers, a helper, the paper, relays, new data and release keys), every staying member online
  together. Its own red team (round 2, on draft 3) still found 1 critical and 2 high problems, all at
  its seams with the core: members a refresh removes are never told, so a leaving server and a
  leaving helper still make 4 points; an abort can race the commit and void a valid new paper; and a
  dishonest partner can show members commitments it did not use. Fixing them needs new machinery
  (notifying and retiring leaving members, ordering aborts against commits, binding every
  confirmation to one commitment), so it is parked until the core has been lived with.
- **Account admin**: creating a key (DKG, import), adding and removing devices on screen, retire, delete
  (NIP-62 plus destroying shares and forgetting push addresses), the take-out bundle, the passkey page on
  servers for reporting a device lost.
- **Server profile**: the duties as an operator sees them, abuse defaults, the 30-day shutdown notice,
  telling the person calmly after a week that a server is quiet and offering "Refresh now",
  announcements (kind 30243/10243), the operator notice.
- **Device policy**: the destructive check, Undo from the device's own history, re-confirming staged
  events (a staged replaceable event older than the newest known is destructive), honest quiet notices.
- **Doors and grants**: NIP-07, NIP-46 (per-site signer keys, bunker://, auth_url), NIP-55, the QRST
  signer-ticket, the same-device door on iPhone, grants and scopes, the iOS push appendix.
- **Backup**: 24 words, finding servers from the paper, recovery contacts, the escape hatch (device +
  paper or two devices run a refresh that replaces dead servers), heir.
- **Helper**: the opt-in (joins at a refresh).
- **Key families**: claim, accept, release; the challenge window; child groups. This is the answer to a
  serious leak of the key itself.

## 13. Open items

- **Formal check** of the one-call round (§5.1).
- **Outside reviewer** sign-off on the core.
- **Refresh now**, parked (§12).
- Repair with mixed-weight helpers relies on `frost-core`'s `repairable` module; its behaviour with a
  helper holding 3 indices must be pinned by vectors.

## 14. Test vectors

The vectors are in `docs/keykin/vectors/` (`vectors.md` describes them; `vectors.json` is generated
by `gen_vectors.py`). Done when the TypeScript and Kotlin implementations both
pass it and a fuzzed parser has run against every message. The interop plan is
`docs/keykin/interop-plan.md`.

## Changes in draft 7

The user's third cut (2026-11-02, after red-team round 6):

- **Everyday changes are an order-free set.** Adding a device and reporting one lost are self-contained
  signed changes (kind 24302), valid in any order; indices come from a hash; members keep and fetch the
  whole set. The numbered chain of records, drafts, `draft_held` and fork rules are gone (round 6 H1, H2,
  M4, L2).
- **Structural changes only in "Refresh now"** (`refresh.md`): servers, a helper, the paper, locks,
  relays, data and release keys. Re-dealing there means a server swap never gives the servers 4 points
  (H3), and the paper is made with the epoch's pending shares before the record is signed (H4).
- **Locks are biometric-only** (H5); browser passkeys don't count.
- **Every two-device approval has a typed code** (H6).
- **Recovery approvals** are signed by the backup key per change and taken only from the holder (C1).
- A recovery ends running holds (M1); `deliver` addresses inbox items by the wrap's `p` tag (M2);
  migration is one refresh with every staying member confirming (M3); the release-key rotation on
  removal is gone (L1); §10 states the remaining limits (L2, L3).

## Changes in draft 8

The user's fourth cut (2026-11-02, after red-team round 7):

- **No in-place move from 0.12** (§11.2): an account moves by importing its nsec (round 7 H4).
- **Honest refresh** (§6.4, §10, `refresh.md`): refresh kills honest members' old pieces; pieces
  someone kept still combine; the old paper must be destroyed (C1).
- **Lock re-registration** is an everyday change, approved by `pair` or `paper` (§3.2, §6.1; M5).
- Round 7's slips: freshness is checked only by the co-signer, once (H2, M2); a `remove` crosses
  epochs (H3); a dead peer is skipped after an hour (H5); catch-up takes the union of servers' change
  sets (L4); recovery waits share an id and statements say their kind (M3); the new device shows the
  join check and the person types it on the inviter (M4); the refresh lock text and the paper
  challenge are defined (L1); deliveries for removed members and the backup are dropped (L3).

## Changes in draft 8.1

From red-team round 8, which found no critical or high problem in the core (its three highs were in
`refresh.md`): a device's current lock is defined (M5); approvers are devices and every member checks
their signatures (M6); `take_out` and notice-channel encodings, and `pair` signing the lock string
(M6); cross-epoch changes simplified to a `remove` of the previous epoch for 7 days (M4); two apps on
one machine are two devices, stated (M7); the paper carries `g`, server host keys and relays, and the
read-back checks them (M8); shares may travel as live 21059 but never stored 1059 (M9); 32-byte index
encoding (L3); leaving servers rejoin with a new key (L4); "at least 3 servers" (L5); any enrolled
biometric (L6); cancels go to every server until each answers (L9).

## Changes in draft 8.3

The user's one-member-per-machine rule (2026-11-02): §4.6 (a desktop app is the machine's member and
extensions relay to it; with no app one extension is the member; handover moves the membership without
changing it; a separately joined extension removes itself); a device may remove itself (§6.4); §10's
"two apps on one laptop" limit narrowed to the cases the rule can't cover, and the local-software limit
stated.

## Changes in draft 8.4

The one-member-per-machine rule's red team found two gaps in the handover, both fixed: it now carries
everything a `welcome` does plus grants and history, committed in a set order (store, reload, check,
confirm, then delete) with no test round; and an extension removes itself only when the app holds a
*different* current member key for the same account, so a leftover copy can never remove the
machine's only member. An app also holds one membership per account.
