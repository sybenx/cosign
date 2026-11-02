# Keykin Core

Draft 1 · 2026-11-02 · `draft` `optional` · not built

Keykin keeps one Nostr key for life without any single device, server or company holding it.
The key is split with FROST (RFC 9591) into weighted shares: each of the user's devices holds 3,
each server 1, a paper backup 2, and signing takes 4. So the device you're using plus any one
server signs, two of your devices sign, and all the servers together never can.

This document is the **core**: the smallest set of rules two independent implementations need in
order to work together and keep the account safe. Everything a person sees, and every optional
feature, lives in a module (§12). Sites change nothing: they keep using NIP-07, NIP-46, NIP-55 and
the QRST signer-ticket, which the Doors module covers.

**How to read it.** MUST, SHOULD and MAY apply to wire behaviour and to what a member stores, and
nothing else. Screens, words and timings an app shows are never normative here. "Reference"
numbers are defaults an implementation may change without breaking anyone.

Keykin is the new working name of Cosign. Cosign 0.12 (built, described in `../COSIGN.md`) is the
prototype this replaces; §11 says how existing accounts move over. Old `cosign` names stay
readable for ever.

---

## 1. Terms

- **Group key** `g`: the account's Nostr key (x-only, BIP-340). Its private half never exists
  whole anywhere (§6.7).
- **Share**: one FROST share `s_i = f(i)` at a unique index `i ≥ 1`, worth one point.
  `f` has degree 3; threshold `t = 4`.
- **Member**: anything holding shares. It has a **member key** (secp256k1) that seals and
  authenticates its messages. Member kinds:

  | Kind | Shares | What it is |
  |---|---|---|
  | `device` | 3 | An app on hardware the user owns: phone, tablet, desktop app, browser extension. |
  | `helper` | 3 | A family or friend's always-on box, only on the user's opt-in. |
  | `server` | 1 | An always-on service: public, a friend's, or the user's own. |
  | `backup` | 2 | A backup key (paper, or friends holding it jointly). Nothing online holds its shares. |

- **Device-class**: `device` and `helper`. Only these coordinate everyday signing.
- **Group record**: the signed list of members, their kinds and indices, and the polynomial
  commitment (§3).
- **Epoch**: one version of the shares. A refresh (§7.2) starts a new epoch with the same `g`.
- **Lock**: a P-256 key in secure hardware that signs only after a fresh face or fingerprint
  (§6.1). A passcode alone is not a lock.
- **Wait**: a delay, 3 days by default (`W`), that every server applies on its own clock to an
  account change made without a lock (§6.2).
- **Release key**: a random 32-byte key held by devices and servers, never by helpers or backups,
  that wraps the backup's shares a second time (§7.5).
- **Data key**: a random 32-byte key held whole by devices only, for reading the account's own
  private data. It can read, never sign (§4.5).
- **Request**: any member message that asks for an answer. Each has an `id` (16 random bytes, hex)
  and a lifetime class (§5.6).

## 2. Who does what

**Devices do the work.** A device coordinates its own signing rounds, judges what is destructive,
asks the person, keeps the account's history and does Undo. When it can, it does anything a server
would.

**Servers do the minimum.** Per account, a server MUST keep only:

1. its one share for the current epoch, and a pending one during a refresh (§7.2);
2. the current group record and, during a refresh, the next one;
3. the current release key;
4. waits in progress, recovery sessions, and removed members' 7-day windows (§6);
5. push addresses (§8.1) and the short inbox (§8.2), including update deliveries kept until
   acknowledged (§7.3);
6. answered request ids until each expires (§5.6).

A server MUST NOT keep signed events, list versions, site grants or logs of what it signed. It
co-signs, enforces waits and the stateless destructive rule (§5.8), sends wake-up pushes, and helps
with repair and refresh. That is all.

| | device | helper | server | backup |
|---|---|---|---|---|
| Coordinate everyday signing | yes | yes | only if `own` (§3.1), and only by asking a device | no |
| Co-sign for others | yes | yes | yes | no |
| Get decryption partials (§5.5) | yes | no | no | no |
| Vouch for a new member, report lost, cancel a wait | yes | **no** | no | no |
| Hold the release key | yes | no | yes | after release only |
| Hold the data key | yes | no | no | no |

## 3. The group record

### 3.1 Format

A **kind 30242** event signed by the group key (4 points, so no single member can make one), with
tags `["d","keykin"]`, `["v","1"]` and `["epoch","<n>"]`. Its content is JSON:

```jsonc
{
  "v": 1,
  "g": "<x-only group key, hex>",
  "epoch": { "n": 7, "id": "<16 random bytes, hex>" },
  "prev": "<event id of the record this replaces, or null for the first>",
  "t": 4,
  "commitment": ["<C0>", "<C1>", "<C2>", "<C3>"],   // 33-byte compressed points, hex
  "role": "master",            // or "child" (§6.7); set once, never changed
  "origin": "dkg",             // or "import"; set once, never changed
  "relays": ["wss://…", "wss://…", "wss://…"],
  "members": [
    { "key": "<member key>", "kind": "device", "shares": [1, 2, 3],
      "lock": { "pub": "<65-byte P-256 point, hex>", "rp": "<32-byte rpIdHash, hex>" } },
    { "key": "<member key>", "kind": "server", "shares": [4],
      "host": "<host key>", "operator": "<operator pubkey>", "own": false,
      "https": "https://…" , "vapid": "<65-byte P-256 point, hex>" },
    { "key": "<backup key>", "kind": "backup", "shares": [5, 6] }
  ],
  "removed": [ { "key": "<member key>", "epoch": 6 } ],
  "next": 7
}
```

- `commitment` is the Feldman commitment to `f`: `C_k = a_k·G`, with `C0` the group point (in the
  form `frost-secp256k1-tr` stores it, after any BIP-340 negation). The point of share `i` is
  always **derived**, `P_i = Σ C_k·i^k`, and never taken from a message.
- `lock` is absent for a member without one. `own` marks a server the user runs; it counts as one
  of the user's devices for privacy, nothing else.
- `next` is the next unused index. Indices are never reused.
- `removed` is positive: a member is removed only by appearing here, never by being missing.
- Members MUST keep unknown fields and unknown member kinds, and MUST show unknown kinds to the
  person rather than drop them. For the invariants an unknown kind counts as **not device-class**
  and **as a server** for I2, whichever is stricter.

The record is passed only between members, inside sealed messages (§9). Members MUST NOT publish
it to relays: it names the account's servers and devices. (A member could still leak it; §10.)

### 3.2 Invariants

A record is valid only if all of these hold. Servers MUST refuse to co-sign a record that breaks
one, and every member MUST refuse to adopt one.

- **I1.** No member holds more than 3 shares.
- **I2.** Servers together hold 3 shares or fewer.
- **I3.** No two `backup` members together reach 4.
- **I4.** A round whose participants include no device-class member is a **recovery round** and
  needs the wait (§6.6).
- **I5.** Any set of members that contains no `device` and no `server` is worth less than 4, with
  `backup` shares counted as 0 (they are unreadable until a server releases them after its wait,
  §7.5). One consequence: at most one `helper`.

Also: each server holds exactly 1 share; each device and helper exactly 3; each backup exactly 2;
indices are unique across members and `removed`.

### 3.3 Checking a record

A member adopting a record MUST check, in order:

1. the event signature verifies under `g`, and `g` is the group key this member already knows
   (from its own creation of the account, or from the code it scanned, §4);
2. `epoch.n` is exactly one more than the record it holds, and `prev` is that record's event id
   (or the record is the one it was handed at join);
3. `C0` is the group point, and for every share it holds, `s_i·G == P_i`;
4. **a device, in addition, rebuilds the commitment from first-hand facts**: its own 3 points and
   the group point determine a degree-3 polynomial, so it computes `C0…C3` from them and refuses
   any record whose commitment differs. A member list cannot fool this, however it was built;
5. the invariants (§3.2);
6. the change from the previous record is one the rules allow (§6.3), and every member kind and
   every key↔index pair it already knew is unchanged except by those rules.

A record that fails any check is refused and the person is told on a device. Members keep the
highest valid record they have seen and never go back to a lower epoch.

## 4. Joining

Adding any member uses one handshake. It closes live finding #17: a joining device trusts nothing
it did not get from a code the person scanned or from the group key.

### 4.1 The codes

Either side can show the code, so a desktop without a camera can still join.

- **Invite**, shown by a member device: `keykin:join?g=<group key>&m=<inviter member key>&s=<16
  random bytes, base64url>&x=<expiry, unix>&r=<relay>&r=<relay>…`
- **Join code**, shown by the new member: `keykin:hello?n=<new member key>&s=<…>&x=<…>&r=<relay>…`

Codes MAY be carried in a QRST code or an `https` bounce link; the fields are the same. `x` SHOULD
be at most 10 minutes ahead. Readers MUST also accept `cosign:` in place of `keykin:`.

When the code was read by a camera, nothing more is needed. When it arrived as a link or pasted
text, both screens MUST show a 6-digit check, the first 20 bits of
`SHA-256("keykin-join/1" ‖ g ‖ m ‖ n ‖ s)` as a decimal number, and the person confirms they match
before step 3 below.

### 4.2 The handshake

1. **Hello.** The side that scanned writes to the other, sealed to the key in the code
   (`join_hello`): its own member key, `s`, and for a new device its lock public key (if it has
   one) and a kind. A side that receives a `join_hello` without the right `s`, after `x`, or after
   it already accepted one for this `s`, MUST drop it.
2. **The new record.** The inviting device builds the next record with the new member at fresh
   indices from `next`, its kind as the person chose it, and its lock key. The kind is set here
   and only here: a member never chooses its own kind, and a helper can never enroll as a device.
   The inviter gets the record co-signed by a server, which applies the gate for this change
   (§6.3), including any wait.
3. **Repair.** For each new index, the inviting device (3 shares) and one server (1) run the
   repair of `frost-core`'s `repairable` module with all 4 shares as helpers: each helper share
   computes its Lagrange-weighted deltas, the helpers exchange them, and each sums what it received
   into one `sigma`, sealed to the new member key (`repair_sigma`). A server MUST take part only
   for indices that the new co-signed record assigns to that new member key. No member ever sees
   the new share.
4. **Welcome.** The inviting device seals to the new member (`welcome`): the signed record, the
   relays, the release key (devices and servers only), and the data keys (devices only, §4.5).
5. **Checks.** The new member MUST refuse to finish unless:
   - the `welcome` is sealed by `m`, when it scanned an invite;
   - the record passes §3.3 against the `g` from the invite (with a join code, against the `g` the
     welcome names, which the device MUST then show to the person as the account it joined);
   - the record lists its own member key, at the kind it asked for, with these indices;
   - it has `repair_sigma`s from at least two distinct members of that record, one of them the
     inviter, and for every new index the summed share satisfies `s_i·G == P_i`.

   Then it acknowledges (`ack`) to the inviter and to every server, and destroys the sigmas.

Why this holds: an outsider who sees the hello cannot produce a record signed by `g`, and the
inviter's own contribution cannot be forged, so a welcome from anyone else fails step 5. With a
join code, the new member has only the code's secret `s` to trust until it sees the record; a
person who reads the code off the screen at the same moment can race (§10).

### 4.3 Adding a server

The device uses the server's announcement or a code from the server's operator (Server profile
module) in place of the code above; the hello goes to the server's host key. The server receives
the record and the release key, never a data key. Who may run open enrollment, invite codes or
proof of work is the server profile module's business.

### 4.4 Adding a backup

A backup member never comes online, so step 3's sigmas go to the backup key instead, wrapped twice
(§7.5) and stored. Nothing is sent to it, and it needs no hello: the device that creates it makes
the key pair and gives the secret only to the paper (or to friends, by a recovery module).

### 4.5 The data key

A random 32-byte key, never derived from the group key or any to-self conversation key and never
published. Devices hold it whole, in storage that is never backed up or synced (on iPhone, never in
iCloud Keychain or a restorable backup). Helpers, servers and backups never get it. A refresh (§7.2)
brings a new one; devices keep older ones so they can read older data, and data services
re-encrypt lazily. A thief keeps whatever data key they already copied, and nothing newer.

`welcome` and refresh deliveries carry `data_keys: [{ "epoch": "<epoch id>", "key": "<hex>" }]`,
at least the current and the previous.

## 5. Signing

### 5.1 The round, in one call

The coordinator (a device-class member, or an `own` server asking a device) sends `sign` to one
co-signer:

```jsonc
{ "type": "sign", "event": { /* the full unsigned event, pubkey = g */ },
  "signers": [1, 2, 3, 4],                       // every index in this round
  "commitments": [ { "i": 1, "D": "…", "E": "…" }, … ],  // the coordinator's own indices
  "approval": { /* optional lock assertion, §5.8 */ }, "hold": "<wait id, optional, §5.8>" }
```

The co-signer checks (§5.7), makes fresh nonces for its own indices, and answers `partial` with
its commitments and its signature shares together:

```jsonc
{ "type": "partial", "commitments": [ { "i": 4, "D": "…", "E": "…" } ], "z": [ { "i": 4, "z": "…" } ] }
```

The coordinator then computes its own shares, aggregates, checks the result as an ordinary BIP-340
signature on the event id, and publishes. It MUST check each partial against `P_i` derived from
the record (RFC 9591 `verify_signature_share`) and name the member whose partial fails.

- **Binding.** The binding factors and the group commitment MUST be computed over the full
  commitment list for `signers`, every index of every participant, as RFC 9591 does.
- **Several co-signers.** A coordinator MAY ask several co-signers at once (reference: the
  fastest first, the rest after 300 ms). Each request is an independent round with its own
  coordinator nonces. It completes with the first valid partial and discards the nonces of the
  others.
- **Formal check.** This one-round form lets a co-signer pick its nonce after seeing the
  coordinator's. It needs a formal security check before 1.0 (§13).

### 5.2 Nonces

- A member MUST generate nonces only for a request it is answering or sending, keep them in
  memory only, and use each once. Nonces MUST NOT be written to disk, shared storage, logs or
  anything a snapshot, a restore or a second process could bring back. After a restart, every
  round in flight is lost.
- The randomness passed to RFC 9591 `nonce_generate` MUST be fresh operating-system randomness
  hashed together with the SHA-256 of the request, so a machine restored from a snapshot with
  the same random state still makes different nonces for a different request.
- A coordinator MUST compute its own signature shares at most once per nonce. If it must retry
  with a different co-signer or the same one, it uses fresh nonces under a new request `id`.

### 5.3 Retries

A co-signer that gets a `sign` whose `(sender, id)` it already answered MUST return the same
`partial` it sent, **only if** the new request is byte-identical (same SHA-256 of the canonical
body, RFC 8785) to the first. Otherwise it MUST refuse with `id_reused`. It keeps its answer, not
its nonces.

### 5.4 Never a bare digest

Co-signers MUST receive the full event, compute its id themselves (NIP-01) and check that `pubkey`
is `g`. There is no message that signs a hash.

### 5.5 Decryption

For NIP-04, NIP-44 and NIP-59, a device needs `x·Q` for a peer point `Q`. It sends
`ecdh {points: [Q…]}` to a co-signer. The co-signer answers `ecdh_partial` with, for **each** of
its indices `i` and each `Q`, `Y = s_i·Q` and a proof that `Y` and `P_i` share the same discrete
log:

```
k random;  R1 = k·G;  R2 = k·Q
e = H("keykin/ecdh-dleq/1" ‖ g ‖ epoch.id ‖ i ‖ P_i ‖ Q ‖ Y ‖ R1 ‖ R2) mod n
z = k + e·s_i          verify: z·G == R1 + e·P_i  and  z·Q == R2 + e·Y
```

(`H` is SHA-256; points are 33-byte compressed, integers 4-byte big-endian, scalars 32 bytes.)

- The coordinator applies the Lagrange coefficients itself. It MUST refuse an answer unless the
  set of indices in it equals that member's indices in the record exactly (no missing, no extra,
  no repeats), every proof verifies with `P_i` derived from the record, and then treat a refusal
  as that member failing, by name. An answer without proofs is a failure (closes #16a).
- Co-signers MUST answer `ecdh` only from a `device` in the current record. Never a helper, a
  server, a backup or a removed member.
- A server that is not `own` MUST NOT coordinate a decryption.

### 5.6 Lifetimes and replays

Every request carries `cls`. The lifetime of each class:

| `cls` | Lifetime | Used for |
|---|---|---|
| `sign` | 60 s (receivers MAY use 45 s) | a signature someone is waiting for |
| `ask` | 120 s | a request a person is being asked about |
| `member` | 7 days | drafts staged offline, account changes, deliveries |

- A receiver measures age with its own clock from the rumor's `created_at` (the time the request
  was sent), or from the inbox's `age` (§8.2) if that is larger. It MUST refuse a request older
  than its lifetime plus 30 s, or dated more than 30 s ahead.
- The **event's** `created_at` (when the person wrote it) never decides whether a request is fresh.
  A draft written offline keeps its time and is signed days later under `member`.
- A receiver MUST remember `(sender, id)` until the request's lifetime has passed and refuse a
  second, different request with it (§5.3). Servers MUST keep these across restarts. A server MAY
  cap how many it keeps per member (reference: 10,000), refusing new requests from that member
  when full rather than forgetting old ids.

### 5.7 What every co-signer checks

Before giving a partial, a co-signer MUST check that:

1. the sender is a member in its current record, not removed, and may coordinate (§2);
2. `signers` is exactly the sender's indices plus its own and is worth at least 4, all from the
   current epoch;
3. the request is fresh and not a replay (§5.6);
4. `event.pubkey` is `g` and the event's `created_at` is no more than **10 minutes** ahead of its
   own clock; a later one is refused, whatever the kind;
5. if the event is a group record (kind 30242 with `d` of `keykin`, `cosign` or `frost`), the
   change is valid and its gate is met (§3.3, §6.3); a device MUST never sign a group record on a
   site's request;
6. if the round is a recovery round (I4), its rules are met (§6.6);
7. the stateless destructive rule (§5.8).

A device co-signing for another device-class member also applies its own destructive policy
(Device policy module) and asks the person when that says to.

### 5.8 The stateless destructive rule

Servers keep no history, so they cannot tell that a follow list shrank. They can still recognise a
few events that are destructive on their face. For these, a server MUST require **either** a lock
assertion in `approval` over the event id (§6.1) from the coordinating device, **or** that the
wait has passed (`hold`):

- request to vanish (kind 62);
- a deletion (kind 5) with 5 or more `e`/`a` targets, or any `a` target whose kind is 0, 3,
  10000–10030 or 30000–30030;
- kind 0 whose content is `{}` or has no non-empty `name`, `display_name`, `about` or `picture`;
- kind 3, 10000–10030 or 30000–30030 with no tags other than `d`;
- kind 10002 with no `r` tags.

**Holding** works like any wait: the device sends `hold {event}` (`member` class); each server
starts a wait (§6.2) and tells every member; after `W` the device sends `sign` with `hold: <wait
id>` and servers co-sign if their own wait passed and nobody cancelled. This is a second opinion
only. The device is the real gate, and its policy (Device policy module) holds far more than this.

## 6. Account changes

### 6.1 The lock

A lock is a P-256 key generated in secure hardware (Secure Enclave, Android Keystore with user
authentication, or a device-bound WebAuthn credential with user verification) that signs only
after the current face or fingerprint. A phone with only a passcode, an extension without a
platform authenticator, and a Mac without Touch ID have **no lock**. A member with no lock simply
has no `lock` in the record.

A **lock assertion** has one encoding everywhere, WebAuthn's:
`{ "authData": "<b64url>", "clientData": "<b64url of JSON>", "sig": "<b64url DER>" }`.

A verifier MUST check that `clientData.type` is `"webauthn.get"`; that `clientData.challenge` is
`base64url(SHA-256("keykin-lock/1" ‖ g ‖ epoch.id ‖ id ‖ type ‖ SHA-256(JCS(body))))`, where `id`
and `type` are the request's and `body` is the request without its `approval`; that
`authData` starts with the member's `rp` and has the user-present and user-verified flags set; and
that `sig` verifies over `authData ‖ SHA-256(clientData)` with the member's `pub`. Native apps
build the same structure themselves. Servers cannot tell that the key is in hardware (no
attestation is required); that is a stated limit (§10), not a check.

### 6.2 Waits

- A server starts a wait when it gets a gated change without the lock its gate needs. It records
  the change's hash and the start time **on its own clock**, and immediately tells every member
  (an `ask` push, an inbox notice, §8). It never trusts another member's clock.
- During a wait the requester re-sends the change (`member` class); the server goes ahead only
  once its own `W` has passed. Signing and everything else carry on as normal.
- **Cancel**: `cancel {wait}` from a `device` with a valid lock assertion ends the wait at that
  server, which tells every member. A helper cannot cancel; nor can a device with no lock (§13 Q1).
- Every wait a member started ends when that member is removed.
- `W` is 3 days. A short wait `w` is 1 hour (reference).

### 6.3 What each change needs

Every account change is a new group record (§3), which a server co-signs only once the gate is
met. "Lock" means a lock assertion from the device that asks, over that record.

| Change | Gate |
|---|---|
| Add a `device` | the inviting device's lock → instant; or `vouch` from a second device → instant; else `W` |
| Add a `server`, `helper` or `backup` | lock and `w`; else `W` |
| Remove a `device` (report lost) | any device; never delayed (§6.5) |
| Remove a `server`, `helper` or `backup` | lock; else `W` |
| Refresh with no change of members | any device, no lock (§7.2) |
| Change `relays` | any device, no lock |
| A device registers a lock it did not have | `W` (else a thief gives a passcode-only phone their own face) |
| A device replaces its lock | its old lock → instant; else `W` |
| Change `role` or `origin`, or a member's kind or indices | never (only removal and a new join) |

A `helper` never vouches, reports, cancels or asks for any of these. One record carries one change,
except that a refresh may also carry removals.

### 6.4 Vouching

`vouch {record}` from a second `device`, sealed to the servers, says that device agrees to this
exact record (by event id of the unsigned draft). Two distinct devices agreeing make an add
instant without a lock: two devices could sign without any server anyway.

### 6.5 Report lost

- `remove {key}` from a device (with its lock assertion if it has a lock). From the moment a server
  receives it, the server MUST refuse every round with that member and every wait it started. It
  is never delayed and needs no other approval.
- The reporting device then refreshes without the removed member (§7.2), which puts it in
  `removed`.
- **Removal is final.** Nobody is put back; a device removed by mistake joins again.
- **Mutual removal.** For 7 days from when each server marked it removed (its own clock), a removed
  device may send exactly one message: `remove` naming the member that removed it. The server then
  removes both and tells everyone, and drops the remover's refresh. Nothing else is accepted from a
  removed member. So a thief who reports first can at most take the owner's device out with it,
  and the account falls to the remaining members.

### 6.6 Recovery rounds

A round with no device-class member (I4) happens only when the backup is in use.

1. The backup holder sends `release_request` signed by the backup key over a fresh server
   challenge (`challenge` / `release_request`), to each server.
2. Each server starts a wait (`W`, §6.2) for it and tells every member. Any device with its lock
   can cancel.
3. When its own wait has passed, a server seals the **release bundle** to the backup key: the
   current release key and the current record (`release`).
4. The holder fetches the backup's stored contributions (§7.5), opens them, sums the 2 shares and
   checks them against the record.
5. For 7 days after its own wait ended (a **recovery session**), each server co-signs with the
   backup member, but only group records that add a device or remove members, the repair for that
   device, and a refresh. Not ordinary events.

So a stolen paper needs two servers that each waited, with every device told. A refresh follows
every use of the backup and makes a new backup.

### 6.7 Exporting keys

- **The master key is never exported.** A server MUST NOT seal its share to anyone, and no message
  exists that asks it to. Members MUST NOT offer to combine a `master` group's shares into an nsec.
  (Someone combining their own shares with their own tools cannot be stopped, and this does not
  try.)
- **A child key** (`role: child`, Key families module) may be exported in stages: in Core 1.x any
  child; in a later version only children with `origin: import`; then none. Export is
  `take_out {}` from a device; each server seals its share to that device only after a lock (and
  `w`) or `W`, and tells every member.
- An export is permanent: refresh never changes the key.

## 7. Staying current

### 7.1 Repair

Repair (§4.2 step 3) is also how a server or a backup gets new shares, and how a member that
missed too many epochs comes back: it is removed and joins again at new indices.

### 7.2 Refresh

A refresh moves every remaining member to a new epoch, same `g`. It runs after any removal, after
the backup is used, and periodically (reference: every 30 days, by any online device, no lock;
servers refuse a periodic one if their epoch is under 25 days old). With no device online nothing
happens and nothing is deleted.

1. **Plan.** The device sends `refresh_plan`: the next epoch `{n, id}`, the holders (current members
   minus any removed now), and its own **dealing**: a random degree-3 polynomial with zero constant
   term, its commitments, and for every holder index a delta sealed to that holder's member key.
   It also seals a new release key to every device and server holder and a new data key to every
   device holder.
2. **Dealing.** At least one server also deals (`refresh_deal`), the same way. A server MUST check
   that the holders are exactly the current members minus those named in `removed` (and, for a
   periodic refresh, minus servers dropped under the Server profile module's dead-server rule), and
   that the plan's epoch is its own plus one.
3. **Pending.** Each holder adds every delta for its indices to its share, keeps the result as
   **pending**, and checks it against the new commitment `C' = C + Σ dealers' commitments`
   (`C'0 = C0`). It goes on signing in the current epoch.
4. **Check and commit.** The device drafts the next record with `C'` and gets it signed by one
   server with **pending** shares. That signature both proves the new shares work and authenticates
   the record. The signed record is the commit: the device sends it to every member.
5. **Adopt.** A member adopts the signed record once its pending share verifies against it, then
   destroys its old share (§7.4). A member that learns of a signed next record while missing its
   deltas fetches them (§7.3).
6. **Drop.** A server drops a pending epoch if no signed record for it arrives within 48 hours,
   and tells the plan's sender (`error refresh_dropped`).
7. **Removal wins.** A plan that removes members replaces any pending periodic plan; every server
   that drops a plan for this reason MUST say so to its sender. A removal never looks finished when
   it is not.
8. **Backup.** After adoption, a device and a server make the new backup contributions (§7.5).

### 7.3 Deliveries kept until acknowledged

Everything a member needs to stay current (refresh deltas, release and data keys, the next record,
repair sigmas, the welcome) is a **delivery**. Every server of the account MUST keep each delivery
for every member, other servers included, until that member sends `ack` for it or is removed, and
MUST hand it over when asked (§8.2). A server MAY cap deliveries at 12 epochs per member (reference);
a member further behind joins again. This closes the stranded-server gap (live finding #13): a
server away for a week catches up from its peers.

Deliveries also go to the account's relays as kind 1059 with expiration 30 days, as a fallback.

### 7.4 Destroying old shares, and storage at rest

- A member MUST destroy its old-epoch share once it adopts the new record, and a removed or wiped
  member MUST destroy everything it holds, with no snapshot, backup, version history or log line
  that keeps it.
- Shares at rest MUST be encrypted under a key that is specific to this membership and epoch and
  is itself kept in platform secure storage (Keychain "this device only", Android Keystore,
  WebAuthn PRF, an OS keyring). Destroying a share means **deleting that key** (closes #7), not
  only the ciphertext.
- Where storage keeps history that cannot be turned off (for example 30-day point-in-time
  recovery), only such ciphertext may be stored there, with the key kept outside it.
- On iPhone, shares and keys MUST be excluded from iCloud and restorable backups.
- A browser member that cannot keep its key out of plain profile storage MUST NOT register a lock,
  and SHOULD tell the person its shares are only as safe as the browser profile (live finding #5).

### 7.5 The backup and the release key

At setup and after every refresh, a device and a server compute the backup's 2 shares by repair,
at the backup's indices, for the new epoch. Each contributing member wraps **only its own sigmas**
twice: first NIP-44 to the backup key, then with XChaCha20-Poly1305 under the epoch's release key.
It stores them on every server and on the account's relays as kind 1059 **with no expiration**.
No online member can open them, and helpers and backups do not hold the release key.

So helper + paper (3 + 2) cannot sign without a server's wait (I5), and neither can a helper plus
friends holding the backup key. Device + paper still works at once, because the device holds the
release key. Old epochs' contributions do not combine with current shares, so it does not matter
if a relay keeps them.

## 8. Push and inbox

### 8.1 Registration

- A device registers with **each** server, per account, by `push_register` (sealed, so signed by
  its member key): `{ "addresses": [ { "cls": "sign" | "ask" | "notice", "url": "…", "p256dh":
  "…", "auth": "…" } ] }`. One address per wake class, never one per header. The newest set
  replaces the old one. `push_unregister {}` removes them all.
- Each server signs its pushes with its own VAPID key (RFC 8292), the `vapid` key in the record.
  Gateways issue a separate random address per server and per account, pinned to that server's
  VAPID key when the device asks for it, so the address is useless to anyone else and servers
  cannot link one phone's accounts.
- A server drops an address that returns 404 or 410, and MUST NOT copy addresses to other servers.
- A device re-registers when anything changed, on every app open.

### 8.2 Sending and the inbox

- Servers send standard Web Push (RFC 8030), encrypted with RFC 8291 `aes128gcm`. The payload is
  JSON `{ "v": 1, "cls": "…", "id": "<request or notice id>", "srv": "<host key>", "wrap": <the
  sealed message, only if it fits>, "sig": "<host key signature over SHA-256(JCS of the other
  fields)>" }`, padded so every encrypted body is the same length and no more than 2,560 bytes
  (reference 2,400). A message that does not fit is fetched.
- Anything for a member that may be asleep goes in that server's **inbox** first, and only then is
  pushed. The vanishing kind 21059 is used only towards members known to be awake (§9.2).
- `inbox_get {}` returns `{ "items": [ { "iid": "…", "age": <seconds held>, "wrap": {…} } ] }`;
  `inbox_ack { "iids": […] }` removes them. Items expire with their lifetime class; deliveries
  (§7.3) stay until acknowledged.
- **Opening the app MUST fetch every server's inbox**, with no gateway involved. A dead gateway
  slows a device down; it never cuts it off.
- Wait notices go as `ask` pushes from **every** server to **every** member; devices merge the
  copies by wait id.
- Servers MUST cap each account's inbox (reference: 512 items or 4 MB, notices dropped oldest
  first, deliveries never) and pushes per address (reference: 60 an hour).

### 8.3 Gateways

A gateway turns Web Push into APNs (or FCM). Each app maker runs its own; servers do not care
which. A gateway MUST keep no state but its address table, no logs of payloads, never see content
(it forwards the encrypted body), check the VAPID signature against the key pinned to the address,
and rate-limit each address. Its addresses MUST be random ids, never raw device tokens. Android
apps using UnifiedPush need no gateway. (Delivery details for APNs, such as priority 10 for `sign`
and `ask`, are guidance in the iOS appendix of the Doors module.)

## 9. Transport

### 9.1 The envelope

Every member message is a **kind 24301 rumor** whose content is JSON
`{ "v": 1, "type": "…", "g": "<group key>", "epoch": "<epoch id>", "id": "<request id>", "cls": "…", … }`,
sealed (kind 13) by the sender's member key and gift-wrapped (NIP-59) to the recipient's member
key. The seal's key is the sender: there is no other sender field.

- **Live** (towards servers, and towards devices known to be awake): kind 21059, re-sent until
  answered.
- **Stored** (towards a member that may be asleep): the server's inbox, plus kind 1059 with a
  NIP-40 `expiration` at the end of its lifetime class.
- **Backup contributions**: kind 1059 with no expiration (§7.5).
- A plaintext over 24,000 bytes is split into `{ "type": "part", "of": "<id>", "n": k, "m": total,
  "data": "<base64>" }` rumors and reassembled by `of`. Receivers MUST refuse a message over
  512 KB in total and drop parts whose message has expired.
- Errors: `{ "type": "error", "re": "<id>", "code": "…" }`. Unknown `type` → `unsupported`.

### 9.2 Relays and HTTPS

- **Relays MUST** work for everything. Members subscribe on the record's `relays` (SHOULD be 3 or
  more, from different operators) to kinds 1059 and 21059 with `#p` = their member key. A server
  also listens on the relays in its own announcement.
- **HTTPS SHOULD** be offered by servers that can. `POST <https>/keykin/v1` with a JSON array of
  gift wraps addressed to the server; the answer is a JSON array of gift wraps. Same format, so a
  member can switch between the two at any message. An iPhone's notification extension uses HTTPS
  when it is there, because it is faster.

### 9.3 What a server may be made to reach

Members name relays, push addresses and HTTPS endpoints. A server MUST NOT connect to private,
loopback, link-local, carrier-grade NAT or cloud-metadata addresses because a member or a stranger
named them; it MUST resolve and check at every connect, MUST NOT follow redirects, and SHOULD cap
new accounts per IP per day (reference 10), messages per account per minute (120) and request size
(512 KB). An open server MAY ask for proof of work (NIP-13) on enrollment.

### 9.4 Messages

| `type` | From → to | § |
|---|---|---|
| `join_hello` | scanner → shower of the code | 4.2 |
| `welcome` | inviting device → new member | 4.2 |
| `repair_delta` / `repair_sigma` | helper share ↔ helper share / helper → new member or backup store | 4.2, 7.5 |
| `sign` / `partial` | coordinator → co-signer / back | 5.1 |
| `ecdh` / `ecdh_partial` | device → co-signer / back | 5.5 |
| `hold` | device → servers | 5.8 |
| `vouch` | second device → servers | 6.4 |
| `cancel` | device → servers | 6.2 |
| `remove` | device → servers and members | 6.5 |
| `challenge` / `release_request` / `release` | server ↔ backup holder | 6.6 |
| `take_out` / `released` | device → servers / back (children only) | 6.7 |
| `refresh_plan` / `refresh_deal` | device → servers / server → members | 7.2 |
| `record` | any member → members (a signed record, the commit) | 7.2 |
| `ack` | member → servers and dealers | 4.2, 7.3 |
| `notice` | server → members | 6.2, 8.2 |
| `push_register` / `push_unregister` | device → server | 8.1 |
| `inbox_get` / `inbox` / `inbox_ack` | member ↔ server | 8.2 |
| `part`, `error` | anyone | 9.1 |

That is the whole of Core. Cosign 0.12 has 55 message types in `server/core/group.ts`; everything
not here belongs to a module or goes (§11.3).

## 10. Security properties, and their limits

**What holds.**

- One member signs nothing: not a device (3), not a server (1), not the backup (2), not a helper (3).
- All servers together (3) can never sign, and neither can two colluding operators.
- A server can delay or withhold its share and see what it co-signs. It cannot sign, cannot make a
  record (that takes the group key), cannot add a member that other members will believe (live
  finding #1), cannot read messages (decryption partials go to devices only), and cannot fake a
  push (pushes are signed).
- A joining device trusts only what its scan and the group key vouch for (live finding #17).
- A lock is a signature servers check, not a device's word (live finding #4).
- A wiped member's shares are gone with their key (live finding #7).
- A stolen paper needs two servers that each waited, with every device told and able to cancel.
- A stolen device is cut off at every honest server the moment it is reported. A thief who reports
  first can only take an honest device down with it.
- Nonces never touch storage, so no restore or snapshot replays one.

**What does not, said plainly.**

- **One operator today.** All three live servers are run by one person, so every wait is in one
  party's hands until other operators exist. With a stolen paper that one party has 4 points.
- **Two stolen devices** (6 points) sign without any server and skip every server rule.
- **A stolen device plus one dishonest server** is 4 points: the everyday pair. Reporting the
  device lost stops it at every honest server, not at that one.
- **Helper plus one server** signs, by design: the person opted in to that.
- **Locks are unattested.** Servers cannot tell a hardware key from a software one. A tampered app
  can make its own "lock". A WebAuthn passkey that syncs to a cloud account is only as strong as
  that account; implementations SHOULD use device-bound credentials.
- **Browser profiles.** An extension without platform secure storage keeps shares that a copied
  profile can carry away (live finding #5). It never counts as locked.
- **iPhone push.** Waking an iPhone needs Apple and the app maker's gateway. The gateway sees when
  each phone is woken and by which servers, not why. If it is down, signing still works when the
  app is opened, from other devices, or through any other Keykin app; notices are what suffer.
- **A join code read off the screen** by someone else at the same moment can be raced (§4.2).
  Invites in the other direction cannot.
- **Membership leaks.** The record is never published, but any member could leak it, and with it
  how many devices and which servers the account has.
- **Decryption is an oracle for devices.** A device can ask for `s_i·Q` on any point. Only devices
  may ask, and a device already holds 3 points.
- **Imported keys and exports are for ever.** A key that was ever whole (imported, or a child that
  was exported) stays whole wherever it was. Refresh cannot help. Key families can move followers,
  not fix the leak.
- **Clocks.** A server with a wrong clock shortens or lengthens only its own wait.
- **The one-call round is not yet formally checked** (§5.1).

### 10.1 Live findings this core closes

| Finding | Closed by |
|---|---|
| #17 joining phone trusts any welcome | §4 |
| #4 lock taken on trust | §6.1 |
| #1 injected member can act | §3 (members only from a group-signed record, kinds pinned) |
| #7 wipe leaves shares recoverable | §7.4 |
| #5 extension shares unencrypted | §7.4 (where the browser allows; otherwise never "locked", §10) |
| #2 paper added with any key | §6.3 (lock and `w`, or `W`) |
| #3 report-lost race | §6.5 |
| #8, #9 server archive and ECDH oracle | §2 (no history), §5.5 (devices only) |
| #12 paper promotes itself | §3.3 (kinds never change) |
| #13 stranded server, #14 removal dropped in a pending refresh | §7.3, §7.2 step 7 |
| #16a optional proofs | §5.5 |
| #10, #11, #15 | Doors and Device policy modules (grants live on devices) |

## 11. Versions, migration, the rename

### 11.1 Versions

- Core follows semantic versioning. Any wire change bumps the major version, which is `v` in every
  rumor, every record and every push payload.
- Unknown fields are ignored. Unknown message types are refused (`unsupported`). Unknown member
  kinds are kept and shown (§3.1).
- Servers SHOULD support versions N and N−1. A device that sees a record or a message with a major
  version it does not know MUST refuse to sign and tell the person to update.

### 11.2 Moving a Cosign 0.12 account to Keykin

The group key and the npub stay the same.

1. Servers are updated to speak both. Nothing changes for the person yet.
2. A device builds the first record from first-hand facts only: the commitment from its own 3
   points and the group key (§3.3 step 4); a member is kept only if its points derive from that
   commitment and it is a member the device learned first-hand or every server agrees on; others
   are left out and join again. Kinds are pinned as the device knows them, never from a server's
   list.
3. That record is signed by the device and a server (record version 1, `prev: null`), and a
   refresh follows at once: new release key, data key, backup contributions, and lock keys for
   devices that have them.
4. Do it first on a throwaway account, with the paper checked, before the main npub.

Accounts that never migrate keep working with servers that still speak Cosign 0.12.

### 11.3 The rename

Readers MUST accept the old names for ever: the record `d` tag `frost` and `cosign`, the server
announcement `d` tag `cosign-server`, `cosign:` codes, and Cosign paper backups (same key format,
same meaning). Writers use the `keykin` names. Kind numbers 24301, 30242, 30243 and 10243 stay
provisional until upstream assigns them.

## 12. Modules (not part of Core)

Each is a short document of its own, and none may weaken anything above.

- **Account admin**: creating a key (DKG, import), the screens for adding and removing devices,
  retire, delete (NIP-62 plus destroying shares and forgetting push addresses), take-out bundle.
- **Server profile**: the duties as an operator sees them, abuse defaults, the 30-day shutdown
  notice, dead-server rules, announcements (kind 30243/10243), the operator notice.
- **Device policy**: the destructive check, Undo from the device's own history, re-confirming
  staged events (a staged replaceable event older than the newest known is destructive), honest
  quiet notices.
- **Doors and grants**: NIP-07, NIP-46 (per-site signer keys, bunker://, auth_url), NIP-55, the
  QRST signer-ticket, the same-device door on iPhone, grants and scopes, the iOS push appendix.
- **Backup**: paper, 24 words, finding servers from the paper, recovery contacts, the escape hatch
  (device + paper or two devices replace dead servers by a record they sign themselves), heir.
- **Helper**: the opt-in.
- **Key families**: claim, accept, release; the challenge window.

## 13. Open questions

For the user (plain words, batched in the report):

1. **Q1.** A phone with only a passcode can't cancel a wait. Otherwise a thief holding it could
   block your paper recovery for ever. The cost: if someone steals your paper and your phone has
   no face or fingerprint set up, the phone can't stop them.
2. **Q2.** Events dated more than 10 minutes ahead are refused, all kinds. Scheduled posts would
   need another way.
3. **Q3.** Servers ask for a face/fingerprint (or a 3-day wait) before co-signing a few obviously
   destructive events, including deleting 5 or more posts at once. Passcode-only phones would wait.
4. **Q4.** A removed device may no longer cancel waits during its 7 days (it can still report the
   device that removed it). Decision log, 2026-11-02.

For reviewers:

- The one-call round (§5.1) needs a formal check: a co-signer picks its nonce after seeing the
  coordinator's commitments, and answers in the same message.
- Repair with mixed-weight helpers (§4.2) relies on `frost-core`'s `repairable` module; its
  behaviour with a helper holding 3 indices must be pinned by vectors.

## 14. Test vectors (plan)

Done when one vectors file exists, the TypeScript and Kotlin implementations both pass it, and a
fuzzed parser has run against every message. Files, each with positive and negative cases:

1. **FROST round**: one-call `sign`/`partial` for a device (3 indices) plus a server (1), odd and
   even group keys; a bad partial named; a `signers` set that is not exactly sender plus
   co-signer; a byte-different retry with a reused id (`id_reused`); a byte-identical retry
   (cached answer).
2. **Nonces**: the same random state with two requests gives two different nonces.
3. **ECDH proofs**: valid; missing index; extra index; repeated index; wrong `P_i`; no proofs.
4. **Record**: valid chain; wrong signature; skipped epoch; wrong `prev`; commitment not
   rebuildable from a device's points; each of I1–I5 broken; a kind changed; an index re-pointed;
   an unknown kind kept and counted strictly.
5. **Join**: honest flow; a welcome from a stranger; a record for another group; one sigma only;
   the inviter's sigma missing; a sum that misses the commitment; the 6-digit check.
6. **Lock assertions**: valid; UV flag missing; wrong `rp`; challenge over a different body;
   signature over a different record.
7. **Gates**: each row of §6.3, met and not met; mutual removal inside and after 7 days; a removed
   member's other messages refused; a helper trying to vouch or cancel.
8. **Lifetimes**: each class at, inside and past its lifetime; 30 s ahead; event `created_at` 11
   minutes ahead refused; a 6-day-old staged draft accepted under `member`.
9. **Stateless destructive rule**: each listed shape, with and without approval or hold.
10. **Refresh**: two dealers; a plan with an extra or missing holder; a pending drop after 48 h; a
    removal replacing a periodic plan; a member catching up from deliveries after 3 epochs.
11. **Backup**: double wrap and unwrap; helper plus paper refused without release; recovery session
    limits.
12. **Push**: payload padding and size limit; signature check; per-class addresses.
13. **Transport**: chunking and reassembly; a 513 KB message refused; an expired part dropped.
14. **Migration**: a Cosign 0.12 group with an injected member is migrated without it.

Interop gate (from the plan): nak, Grimoire, nostr-tools, NDK and Amethyst pass a scripted
sign-in, post, held delete and NIP-44 test against a prototype.
