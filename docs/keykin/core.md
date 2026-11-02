# Keykin Core

Draft 6 · 2026-11-02 · `draft` `optional` · not built

Keykin keeps one Nostr key for life without any single device, server or company holding it.
The key is split with FROST into weighted shares: each of the user's devices holds 3, each server
1, a paper backup 2, and signing takes 4. So the device you're using plus any one server signs, two
of your devices sign, and all the servers together never can.

This document is the **core**: the smallest set of rules two independent implementations need to
work together and keep the account safe. Everything a person sees, and every optional feature,
lives in a module (§12). Sites change nothing: they keep using NIP-07, NIP-46, NIP-55 and the QRST
signer-ticket, which the Doors module covers.

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

Drafts 5 and 6 are the simplified core. Independent red teams kept finding serious problems in the
same features, so the user cut them (decision log, 2026-11-02; reasoning in `simplification.md`):
**shares are never re-dealt** (no refresh), and **every account change needs a lock, a second
device, or the paper**; there is no "wait 3 days instead". The change lists are at the end.

---

## 1. Terms

- **Group key** `g`: the account's Nostr key (x-only, BIP-340). Its private half never exists whole
  anywhere (§6.7).
- **Ciphersuite**: `FROST-secp256k1-SHA256-TR-v1`, as implemented by the Zcash Foundation's
  `frost-secp256k1-tr` 2.x: RFC 9591's FROST(secp256k1, SHA-256) with the BIP-340 challenge as H2,
  the group key and shares brought to even y at key generation (`into_even_y`), and each signer's
  nonce negated when the group commitment `R` has odd y. Plain RFC 9591 does not interoperate with
  this, and neither does Cosign 0.12's hand-rolled `server/frost.ts` (§11.2).
- **Share**: one FROST share `s_i = f(i)` at a unique index `i ≥ 1`, worth one point. `f` has degree
  3; threshold `t = 4`. Shares are made once (at key creation, or by repair for a new member) and
  never change.
- **Member**: anything holding shares. It has a **member key** (secp256k1) that seals and
  authenticates its messages. Member kinds:

  | Kind | Shares | What it is |
  |---|---|---|
  | `device` | 3 | An app on hardware the user owns: phone, tablet, desktop app, browser extension. |
  | `helper` | 3 | A family or friend's always-on box, only on the user's opt-in. |
  | `server` | 1 | An always-on service: public, a friend's, or the user's own. |
  | `backup` | 1 or 2 | A backup key (paper, friends holding it jointly, an heir). Nothing online holds its shares. |

- **Device-class**: `device` and `helper`. Only these coordinate everyday signing.
- **Group record**: the signed list of members, their kinds and indices, and the polynomial
  commitment (§3). Its version number `n` goes up with every change of members.
- **Lock**: a P-256 key in secure hardware that signs only after a fresh face or fingerprint
  (§6.1). A passcode alone is not a lock.
- **Wait**: a delay, 3 days by default (`W`), that servers apply on their own clocks to exactly two
  things: a paper recovery (§6.6) and a held mass deletion (§5.8).
- **Release key**: a random 32-byte key held by devices and servers, never by helpers or backups,
  that wraps the backup's shares a second time (§7.2).
- **Data key**: a random 32-byte key held whole by devices only, for reading the account's own
  private data. It can read, never sign, and never changes in the core (§4.6).
- **Request**: any member message that asks for an answer. Each has an `id` (16 random bytes, hex)
  and a lifetime class (§5.6).

### 1.1 Security displays

These are the only things this document requires an app to show, because the protocol's safety
depends on a person seeing them:

1. the 6-digit join check, on both screens, with the person confirming on both before a join goes
   ahead (§4.1);
2. the account a device joined, when it joined from a join code (§4.2);
3. a refused record, with the member it came from (§3.3);
4. that an update is needed, when a device meets a version it does not know (§11.1);
5. a vouch or a two-device action: the device acts only after its person agrees there and then,
   and for a vouch, types the 6-digit check shown on the new device (§6.4);
6. the paper: before a device forgets the backup secret, the person shows the paper is readable by
   scanning it back or re-entering it (§4.4).

## 2. Who does what

**Devices do the work.** A device coordinates its own signing rounds, judges what is destructive,
asks the person, keeps the account's history and does Undo. When it can, it does anything a server
would.

**Servers do the minimum.** Per account, a server MUST keep only:

1. its one share;
2. the current group record, and at most one draft of the next (§3.4);
3. the current release key and the wrapped backup material (§7.2);
4. waits in progress (recoveries and holds) with their notices, and recovery sessions (§6);
5. push addresses and notice channels (§8.1), and the short inbox, including deliveries kept until
   acknowledged (§7.1);
6. answered request ids until each expires (§5.6), and its own counters for §5.8.

A server MUST NOT keep signed events, list versions, site grants or logs of what it signed. It
co-signs, enforces waits and the stateless destructive rule (§5.8), sends wake-up pushes, and helps
with repair. That is all.

| | device | helper | server | backup |
|---|---|---|---|---|
| Coordinate everyday signing | yes | yes | only if `own` (§3.1), and only by asking a device | only in a recovery session (§6.6) |
| Co-sign for others | yes | yes | yes | no |
| Get decryption answers (§5.5) | yes | no | no | no |
| Approve an account change (§6.3) | with its lock, with a second device, or with the paper | **no** | no | with a device, or through recovery |
| Cancel a wait | with its lock, or with a second device | **no** | no | no (the holder withdraws its own) |
| Hold the release key | yes | no | yes | after release only |
| Hold the data key | yes | no | no | no |

## 3. The group record

### 3.1 Format

A **kind 30242** event signed by the group key (4 points, so no single member can make one), with
tags `["d","keykin"]`, `["v","1"]` and `["n","<n>"]`. Its content is JSON:

```jsonc
{
  "v": 1,
  "g": "<x-only group key, hex>",
  "n": 7,
  "prev": "<event id of the record this replaces, or null for the first>",
  "t": 4,
  "commitment": ["<C0>", "<C1>", "<C2>", "<C3>"],   // 33-byte compressed points, hex, even-y form
  "role": "master",            // or "child" (§6.7); set in the first record only
  "origin": "dkg",             // or "import"; set in the first record only
  "relays": ["wss://…", "wss://…", "wss://…"],
  "members": [
    { "key": "<member key>", "kind": "device", "shares": [1, 2, 3],
      "lock": { "pub": "<65-byte P-256 point, hex>", "rp": "<32-byte rpIdHash, hex>" } },
    { "key": "<member key>", "kind": "server", "shares": [4],
      "host": "<host key>", "operator": "<operator pubkey>", "own": false,
      "https": "https://…", "vapid": "<65-byte P-256 point, hex>" },
    { "key": "<backup key>", "kind": "backup", "shares": [5, 6] }
  ],
  "removed": [ { "key": "<member key>", "n": 6 } ],
  "next": 7,
  "backup": "<SHA-256 of the backup material's inner layer, §7.2>",
  "gate": { /* evidence that this change's gate was met, §6.3 */ }
}
```

- `commitment` is the Feldman commitment to `f`: `C_k = a_k·G`, with `C0` the group point. It never
  changes. The point of share `i` is always **derived**, `P_i = Σ C_k·i^k`, and never taken from a
  message.
- `lock` is absent for a member without one. `own` marks a server the user runs; it counts as one of
  the user's devices for privacy, nothing else.
- `next` is the next unused index. Indices are never reused.
- `removed` is positive: a member is removed only by appearing here, never by being missing. A key
  in `removed` never appears in `members` again, and its indices are never given out again.
- **Unknown member kinds** are kept, and a device shows them. For the invariants, an unknown kind's
  shares count towards I2 as if it were a server, and as neither device nor server in I5; the
  exact-share-count rule does not apply to it. A member that meets an unknown kind MUST NOT co-sign
  a further change to that record until it is updated, but signs everything else.

The record is passed only between members, inside sealed messages (§9). Members MUST NOT publish it
to relays: it names the account's servers and devices. (A member could still leak it; §10.)

### 3.2 Invariants

A record is valid only if all of these hold. Servers MUST refuse to co-sign a record that breaks
one, and every member MUST refuse to adopt one.

- **I1.** No member holds more than 3 shares.
- **I2.** Servers together hold 3 shares or fewer.
- **I3.** `backup` members together hold 2 shares or fewer.
- **I4.** A round whose participants include no device-class member is a **recovery round** and
  needs a recovery session (§6.6).
- **I5.** Any set of members that contains no `device` and no `server` is worth less than 4, with
  `backup` shares counted as 0 (they are unreadable until a server releases them after its wait,
  §7.2). One consequence: at most one `helper`.

Also: each server holds exactly 1 share, each device and helper exactly 3, each backup 1 or 2;
indices are unique across members and `removed`; and there are **at least 3 servers**, so one dead
server never blocks anything. (Apps add public servers automatically, alongside any server the
person runs.)

### 3.3 Checking a record

A member adopting a record MUST check, in order:

1. it is **kind 30242**, its `d` tag is `keykin` (or, read-only, `cosign` or `frost`), its `v` and
   `n` tags equal the content's, and the event signature verifies under `g`, the group key this
   member already knows (from its own creation of the account, or from the code it scanned, §4);
2. `n` is exactly one more than the record it holds, and `prev` is that record's event id (or the
   record is the one it was handed at join);
3. `commitment` is the same as before (or, at join, `C0` is the group point), and for every share
   it holds, `s_i·G == P_i`;
4. **a device, in addition, rebuilds the commitment from first-hand facts**: its own 3 points and
   the group point fix a degree-3 polynomial, so it computes `C0…C3` from them and refuses any
   record whose commitment differs. No member list can fool this;
5. the invariants (§3.2);
6. the change from the previous record is one §6.3 allows, its `gate` evidence verifies, and every
   member kind and key↔index pair it already knew is unchanged except by those rules.

A record that fails any check is refused, and a device shows it (§1.1). Members keep the highest
valid record they have seen and never go back to a lower one.

### 3.4 One change at a time

- A draft of record `n+1` is accepted only from a `device` (or, in a recovery session, the backup
  holder), with its gate already met (§6.3). Making a record takes seconds.
- A server says `draft_held {n+1, draft id}` **once per record number**, signed by its host key,
  and remembers that it did (across restarts) until a record `n+1` is adopted. While it holds one
  draft it answers any other with `error busy`; the sender retries after a random delay (reference
  5–60 s). A server may let go of a draft it holds after 10 minutes, but never says `draft_held`
  for another draft of the same `n+1`.
- A server co-signs record `n+1` only if the record's `gate` carries `draft_held` statements for
  that draft from more than half of the servers that stay in the account (those not removed by this
  very change). Two different records for `n+1` can therefore never both be co-signed, and every
  member checks the statements too.

## 4. Joining

Adding any member uses one handshake. A joining member trusts nothing it did not get from a code the
person scanned, from the group key, or from the check both screens show. (This closes live finding
#17.)

### 4.1 The codes and the check

Either side can show the code, so a desktop without a camera can still join.

- **Invite**, shown by a member device: `keykin:join?g=<group key>&m=<inviter member key>&s=<16
  random bytes, base64url>&x=<expiry, unix>&r=<relay>&r=<relay>…`
- **Join code**, shown by the new member: `keykin:hello?n=<new member key>&s=<…>&x=<…>&r=<relay>…`

Codes MAY be carried in a QRST code or an `https` bounce link; the fields are the same. `x` SHOULD
be at most 10 minutes ahead. Readers MUST also accept `cosign:` in place of `keykin:`.

**The check, always.** Anyone who sees a code can race the honest device to answer it, whichever
direction it goes. So after the hello, the side that received it answers with a fresh 16-byte `t`
(`join_nonce`), and both screens show (§1.1) a 6-digit number,
`int(SHA-256("keykin-join/1" ‖ g ‖ m ‖ n ‖ s ‖ t)[0..8], big-endian) mod 10^6` (keys as 32 raw
bytes, `s` and `t` as 16 raw bytes; in the join-code direction `g` and `m` are those in the
`welcome_offer`). The person confirms on both devices that they match before step 2. The hello fixes
`n` before `t` exists, so nobody can grind a key whose number matches.

### 4.2 The handshake

1. **Hello.** The side that scanned writes to the other, sealed to the key in the code:
   - invite direction: the new member sends `join_hello {n, s, lock, kind}`: its member key, the
     secret, its lock public key if it has one, and the kind it asks to be;
   - join-code direction: the inviter sends `welcome_offer {g, m, s}`, and the new member answers
     `join_hello {n, s, lock, kind}` sealed to `m`.

   A side MUST drop a hello or offer without the right `s`, after `x`, or after it already accepted
   one for this `s`. In the join-code direction the inviter MUST accept only a `join_hello` sealed
   by the code's `n`, with `n` equal to it; that key, and no other, is the one added. The receiver of the hello sends `join_nonce {t}`, sealed to the hello's sender;
   that sender MUST accept a `join_nonce` only from the key it sent the hello to.
2. **The record.** After the check, the inviting device gets the change approved (§6.3: its lock,
   a second device's vouch, or the paper) and drafts the next record with the new member at fresh
   indices from `next`, the kind as the person chose it, and its lock key, and gets it co-signed.
   The kind is set here and only here: a member never chooses its own kind, and a helper can never
   enroll as a device.
3. **Repair.** For each new index, the inviting device (3 shares) and one server (1) run the repair
   of `frost-core`'s `repairable` module with all 4 shares as helpers: each helper share computes its
   Lagrange-weighted deltas, the helpers exchange them (`repair_delta`), and each sums what it
   received into one `sigma`, sealed to the new member (`repair_sigma`) together with `sigma·G`. A
   server MUST take part only for indices that a co-signed record assigns to that new member. No
   member ever sees the new share.
4. **Welcome.** The inviting device seals to the new member (`welcome`): the signed record, the
   relays, and, for a device or a server, the release key and the wrapped backup material (§7.2);
   for a device also the data keys (§4.6).
5. **Checks.** The new member MUST refuse to finish unless:
   - the `welcome` is sealed by `m`;
   - the record passes §3.3 against `g` (the invite's, or the offer's, which the device then shows as
     the account it joined, §1.1);
   - the record lists its own member key, at the kind it asked for, with these indices, and its lock
     key;
   - it has `repair_sigma`s from at least two distinct members of that record, one of them `m`, and
     for every new index the summed share satisfies `s_i·G == P_i`. If the sum fails, the join fails
     and the new member says so; it cannot tell which helper sent a bad part, and the inviter retries
     with another server.

   Then it sends `ack` to the inviter and to every server, and destroys the sigmas.

Why this holds: nobody without 4 points can produce a record signed by `g`, the inviter's
contribution cannot be forged, and a racer's hello fails the check.

### 4.3 Adding a server

The device uses the server's announcement or a code from the server's operator (Server profile
module) in place of the code above. The announcement names the server's member key, which is `n`
and the key everything for the server is sealed to; the check is shown on the device and on the
operator's page if it has one. A dead server is replaced in one record that removes it and adds the
new one. The server receives the record, the release key and
the wrapped backup material, never a data key.

### 4.4 The paper backup

The paper holds a **backup key pair**, not shares. Its shares exist only wrapped (§7.2). It is made,
and checked, on one device:

1. The device makes the backup key pair. Adding it is the change `{"add": {backup key, "backup"}}`
   (at account creation it is part of the first record, which needs no gate); replacing the paper is
   one change, `{"replace_backup": {new backup key}}`, which removes the old backup and adds the new
   one in the same record, so I3 always holds. Either needs the approval of §6.3.
2. The device and one server repair the backup's indices; every `repair_sigma` is sealed to the
   backup key. The device, which holds the backup secret at this moment, opens them, sums them and
   checks the shares against `P_i`.
3. The device wraps the shares and the data key (§7.2), signs the inner layer with the backup key,
   sends the material to every server and device, and destroys the shares. Only a device sends
   backup material, and members accept only material whose inner layer hashes to the record's
   `backup` and carries the backup key's signature. So nobody can swap in junk later.
4. The device keeps the backup secret, encrypted at rest (§7.3), until the person has printed or
   saved it **and shown it is readable** by scanning it back or re-entering it (§1.1), then destroys
   it. Until then that device alone is worth 5 points, the same as an nsec on it; it SHOULD prompt to
   finish the backup.

The paper is checked when it is made and never changes afterwards.

### 4.5 Recovery join

In a recovery session (§6.6), the new device joins with the backup holder's app in place of the
inviting device: the repair helpers are the backup (2) and two servers (1 + 1), the welcome is sealed
by the backup key, and step 5 requires sigmas from the backup and both servers.

### 4.6 The data key

A random 32-byte key, never derived from the group key or any to-self conversation key and never
published. Devices hold it whole, in storage that is never backed up or synced (on iPhone, never in
iCloud Keychain or a restorable backup). Helpers, servers and backups never get it, except that a copy
wrapped like the backup's shares is kept with the backup material, so a recovery loses no data
(§7.2). The data key **never changes** in the core: a removed device could read private data written
later, as a stolen nsec could. Changing it comes with the optional refresh module (§12).

`welcome` carries the data key.

## 5. Signing

### 5.1 The round

**Two parties: one call.** The coordinator (a device-class member, or an `own` server asking a
device) sends `sign` to one co-signer:

```jsonc
{ "type": "sign", "event": { /* the full unsigned event, pubkey = g */ },
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
record (`verify_signature_share`) and name the member whose partial fails.

**More than two parties: two calls.** When a round needs more than one co-signer (a recovery round,
§6.6), the coordinator first sends `commit {signers}` to each and gets back `commitments`; each
co-signer keeps those nonces in memory only, for at most 120 s, for that one request id. Then it sends
`sign` with the full commitment list and `after: <the commit request's id>` to each, under a new id,
and each answers `partial` from the nonces it kept for `after`. A co-signer MUST check that its own
entries in the list are the commitments it returned for `after`, and MUST refuse a second `sign`
naming the same `after`.

- **Binding.** Binding factors and the group commitment MUST be computed over the full commitment
  list for `signers`, every index of every participant. A co-signer MUST refuse a commitment list that
  does not cover exactly the other participants' indices, or that contains the identity point.
- **Several co-signers in the one-call form.** A coordinator MAY ask several at once (reference: the
  fastest first, the rest after 300 ms). Each request is an independent round with its own coordinator
  nonces and its own id. It completes with the first valid partial and discards the nonces of the
  others.
- **Formal check.** The one-call form lets a co-signer pick its nonce after seeing the coordinator's.
  Four reviews found no attack (the co-signer moves last; the coordinator is where standard FROST puts
  a signer in round 2), but it needs a formal check before 1.0 (§13).

### 5.2 Nonces

- A member MUST generate nonces only for a request it is answering or sending, keep them in memory
  only, and use each once. Nonces MUST NOT be written to disk, shared storage, logs or anything a
  snapshot, a restore or a second process could bring back. After a restart, every round in flight is
  lost.
- **Hedged randomness.** The random input to `nonce_generate` MUST be
  `SHA-256(fresh OS randomness ‖ share ‖ context)`, where context is, for a co-signer, the SHA-256 of
  the request; and for a coordinator, `event id ‖ signers ‖ request id ‖ co-signer key`.
- A coordinator MUST compute its own signature shares at most once per nonce. A retry uses fresh
  nonces under a new request id.

### 5.3 Retries

A co-signer that gets a request whose `(sender, id)` it already answered MUST return the same answer it
sent, **only if** the new request is byte-identical (same SHA-256 of the RFC 8785 canonical body) to
the first. Otherwise it MUST refuse with `id_reused`. It keeps its answers, never its nonces.

### 5.4 Never a bare digest

Co-signers MUST receive the full event, compute its id themselves (NIP-01) and check that `pubkey` is
`g`. There is no message that signs a hash.

### 5.5 Decryption

For NIP-04, NIP-44 and NIP-59, a device needs `x·Q` for a peer point `Q`. It sends
`ecdh {points: [Q…], signers}` to a co-signer, where `signers` is its own indices plus the
co-signer's and is worth 4 (checked as in §5.7 item 2). Every `Q` MUST be a valid point other than the
identity. For **each** of its indices `i` and each `Q`, the co-signer answers `ecdh_partial` with the
weighted value `Y = λ_i·s_i·Q` (`λ_i` the Lagrange coefficient of `i` in `signers`) and a proof that
`Y` and `λ_i·P_i` share a discrete log:

```
k = H("keykin/ecdh-k/1" ‖ fresh OS randomness ‖ s_i ‖ Q ‖ SHA-256(request)) mod n
R1 = k·G;  R2 = k·Q;  W_i = λ_i·P_i
e = H("keykin/ecdh-dleq/1" ‖ g ‖ i ‖ W_i ‖ Q ‖ Y ‖ R1 ‖ R2) mod n
z = k + e·λ_i·s_i       verify: z·G == R1 + e·W_i  and  z·Q == R2 + e·Y
```

(`H` is SHA-256; points 33-byte compressed, integers 4-byte big-endian, scalars 32 bytes.)

- Because the answer is weighted for a set that includes the asker's indices, it is useless unless the
  asker adds its own 3 points' worth. A member key with no shares learns nothing.
- The coordinator MUST refuse an answer unless its indices equal that member's indices in the record
  exactly (none missing, none extra, no repeats) and every proof verifies with `P_i` derived from the
  record. A refusal is that member failing, by name. An answer without proofs is a failure.
- Co-signers MUST answer `ecdh` only from a `device` in the current record, so no server, `own` or
  not, ever coordinates a decryption.

### 5.6 Lifetimes and replays

Every request carries `cls`. Each message type allows only some classes:

| `cls` | Lifetime | Allowed for |
|---|---|---|
| `sign` | 60 s (receivers MAY use 45 s) | `sign`, `commit`, `ecdh` |
| `ask` | 120 s | `sign`, `commit`, `ecdh`, `challenge` |
| `member` | 7 days | `hold`, account changes, `release_request`, deliveries |

- A receiver measures age with its own clock from the rumor's `created_at` (when the request was
  sent), or from the inbox's `age` (§8.2) if that is larger. It MUST refuse a request older than its
  lifetime plus 30 s, or dated more than 30 s ahead.
- The **event's** `created_at` (when the person wrote it) never decides whether a request is fresh. A
  draft written offline waits in the device's outbox, keeps its time, and is signed with a fresh
  `sign` request when the device is online again.
- A receiver MUST remember `(sender, id)` until the request's lifetime has passed, and treat a second
  request with it by §5.3. Servers MUST keep these across restarts. A server MAY cap them per member
  (reference: 10,000), refusing new requests from that member when full rather than forgetting old ids.

### 5.7 What every co-signer checks

Before giving a partial, a co-signer MUST check that:

1. the sender is a member in its current record, not removed, and may coordinate (§2);
2. `signers` is exactly the sender's indices plus this co-signer's (plus, in the two-call form, the
   other co-signers'), is worth at least 4, and the commitments cover it exactly (§5.1);
3. the request is fresh and not a replay (§5.6);
4. `event.pubkey` is `g`, and, for a **replaceable or addressable** kind (0, 3, 10000–19999,
   30000–39999), the event's `created_at` is no more than 10 minutes ahead of its own clock: a version
   dated ahead would block every later change until that date. Other kinds may be dated ahead, so a
   person can schedule a post;
5. if the event is **kind 30242, whatever its `d` tag**, it is a record: it MUST be a valid change with
   its gate met (§3.3, §6.3) and the draft this server holds (§3.4). A device MUST never sign a kind
   30242 on a site's request;
6. if the round is a recovery round (I4), the recovery session's rules are met (§6.6);
7. the stateless destructive rule (§5.8).

A device co-signing for another device-class member also applies its own destructive policy (Device
policy module) and asks the person when that says to.

### 5.8 The stateless destructive rule

Servers keep no history, so they cannot tell that a follow list shrank. They can recognise a few
events that are destructive on their face, and for these a server MUST require **either** an
`approval` (a lock assertion from the coordinating device over `"sign" ‖ event id`, §6.1, valid for
that event at any co-signer and any retry), **or** a passed wait (`hold`):

- every request to vanish (kind 62);
- a **mass deletion**: a kind 5 with 5 or more `e`/`a` targets, or a kind 5 that would take this
  account past 5 deletion targets co-signed by this server without approval in the last 10 minutes (a
  burst; reference numbers, counted per account at each server, no history kept; a thief spreading
  deletions over three servers gets about three times that, still far less than a stolen nsec allows);
- kind 0 whose content is `{}` or has no non-empty `name`, `display_name`, `about` or `picture`;
- kind 3, 10000–10030 or 30000–30030 with no tags other than `d`;
- kind 10002 with no `r` tags.

**Holding** is a wait (§6.2) on `{"hold": <event id>}`: the device sends `hold {event}` (`member`
class); servers start a wait and tell every member and channel; after `W` the device sends `sign`
with `hold: <wait id>` and a server co-signs if its own wait passed and nobody cancelled. A server
keeps at most 10 holds per device at a time (reference).

A single deletion needs neither: the device holds it for 10 seconds with Undo (Device policy module)
and then signs it like any event.

This is a backstop, and it is easy to step around for lists: a follow list cut to one junk entry is not
empty. The device is the real gate, and its policy holds far more. What that leaves open is in §10.

## 6. Account changes

### 6.1 The lock

A lock is a P-256 key generated in secure hardware (Secure Enclave, Android Keystore with user
authentication, or a device-bound WebAuthn credential with user verification) that signs only after
the current face or fingerprint. A phone with only a passcode, an extension without a platform
authenticator, and a Mac without Touch ID have **no lock**. A member with no lock has no `lock` in the
record.

A **lock assertion** has one encoding everywhere, WebAuthn's:
`{ "authData": "<b64url>", "clientData": "<b64url of JSON>", "sig": "<b64url DER>" }`.

A verifier MUST check that `clientData.type` is `"webauthn.get"`; that `clientData.challenge` is
`base64url(SHA-256("keykin-lock/1" ‖ g ‖ what))`; that `authData` starts with the member's `rp` and
has the user-present and user-verified flags set; and that `sig` verifies over
`authData ‖ SHA-256(clientData)` with the member's `pub`. `what` is:

- for a destructive event, `"sign" ‖ event id` (§5.8);
- for an account change, `"change" ‖ change id ‖ expiry` (§6.2), which has no record number in it,
  so the assertion survives other records committing in between, and stops working at its expiry,
  which MUST be at most 7 days after it was made;
- for any other request, `type ‖ id ‖ SHA-256(JCS(body without the assertion))`.

Native apps build the same structure themselves. Servers cannot tell that a lock is in hardware (no
attestation is required); that is a stated limit (§10), not a check.

### 6.2 Changes and waits

- A **change** is a small JSON object that says what is to happen, without any record number:
  `{"add": {key, kind, lock}}`, `{"remove": <key>}`, `{"replace_backup": {key}}`,
  `{"lock": <new lock>}` (always the asking device's own), `{"relays": [...]}`, `{"notify": …}`,
  `{"hold": <event id>}`. Its **change id** is `SHA-256(JCS(change))`.
- There are only two kinds of wait, both `W` on each server's own clock: a **recovery** (§6.6) and a
  **hold** (§5.8). A server starts one, tells every member (an `ask` push and an inbox notice) and
  every notice channel (§8.1), and when its own wait has passed, pushes the requester (`ask`) and
  signs a **waited statement**: `{ "server": <host key>, "wait": <change id>, "start": <unix>,
  "end": <unix>, "sig": <BIP-340 by the host key over SHA-256("keykin-waited/1" ‖ g ‖ wait ‖ start ‖
  end)> }`. Verifiers MUST check that `end − start ≥ W` and accept a statement only within 7 days of
  its `end`.
- **Cancel** `cancel {wait}`, from a `device` with a lock assertion or from two distinct devices
  together (§6.3 `pair`), ends the wait at that server, which tells everyone. A helper never cancels.
  The requester may always `withdraw` its own. A server MUST NOT issue a waited statement or a
  release bundle until it has fetched its deliveries from its peers (§7.1), so a missed `cancel`
  still counts.
- **A running recovery freezes lockless requests.** From the moment a server starts a recovery wait
  until the wait is cancelled or the recovery session ends, it refuses every request that carries no
  lock assertion and is not one of a pair: `relays` changes, new notice channels and holds. (A thief
  who knows a locked phone's passcode can reset its face; from then on their requests are lockless.)
- Signing and everything else carry on as normal during any wait.

### 6.3 What each change needs

Every account change becomes a new group record (§3). A server co-signs it only once it is
approved, and the record carries the evidence in `gate`, so every member can check it. Signed items
in `gate` carry **detached** BIP-340 signatures by the signer's member key over
`SHA-256("keykin-<type>/1" ‖ g ‖ JCS(body))`, because a NIP-59 seal proves nothing to a third party.

**An account change is approved by one of:**

- `{ "lock": { "member": <key>, "assertion": … } }`: the asking device's lock, over the change (§6.1);
- `{ "pair": [ { "member": <key>, "change": <change id>, "sig": … }, { … } ] }`: two distinct devices
  (6 points, already the key), each after asking its person (§1.1); for an add, one of them is a
  vouch (§6.4);
- `{ "paper": { "member": <device key>, "backup_sig": … } }`: a device together with the paper, the
  backup key signing the change id over a fresh server `challenge` (5 points, already the key);
- `{ "recovery": { "release_request": …, "waited": [<statement>, <statement>] } }`: the paper alone,
  in a recovery session (§6.6), after two servers' waits.

There is **no "wait instead"**: a device with no lock, on its own, cannot make account changes. It
uses a second device or the paper.

| Change | Approval |
|---|---|
| Add a `device`, `server` or `helper` | any of the four |
| Report a `device` or `helper` lost (§6.5) | `lock`, `pair` or `paper`; or `recovery` |
| Remove a `server`; replace a dead server (one record) | any of the four |
| Add or replace the backup (`replace_backup`) | `lock`, `pair` or `paper`; or `recovery` |
| Register or replace this device's own lock | `pair` or `paper` (or the old lock, to replace it); or `recovery` |
| Remove or replace a notice channel | `lock`, `pair` or `paper` |
| Change `relays`; add a notice channel | any device, no approval (refused during a recovery wait) |
| Change `role`, `origin`, `commitment`, or a member's kind or indices | never |

A `helper` never approves anything. One record carries one change (a server swap counts as one).

### 6.4 Vouching

A vouch is the second device's half of a `pair` for an add. Its request carries the join's
`g, m, n, s, t`, and the device MUST ask its person to **type the 6-digit check shown on the new
device** before signing (§1.1). A single "Yes" tap is not enough: a thief holding one of two
devices could get it from a tired owner.

### 6.5 Report lost

- `remove {key}` names a `device` or a `helper`, with its approval (§6.3). A lockless single device
  cannot report another; the person uses a second device or the paper.
- It goes to every server and every device as a delivery (§7.1). From the moment a member has it,
  servers MUST refuse every round with the removed member and drop its push addresses, and devices
  MUST refuse to co-sign with it. It is never delayed.
- The reporting device then drafts the next record with the member in `removed`, and sends a new
  release key to every remaining device and server together with the backup material re-wrapped
  under it (only the outer layer changes, §7.2), as **one delivery tagged with that record's `n`**;
  members apply the newest by `n`.
- **Removal is final.** Nobody is put back; a device removed by mistake joins again. Nothing is
  accepted from a removed member.
- **What removal does not do.** The removed device's shares and the data key are not changed: the
  core never re-deals (§12, Refresh). Every member refusing it is the protection. §10 says what that
  leaves open.

### 6.6 Recovery

A round with no device-class member (I4) happens only in a recovery session.

1. The backup holder asks each server for a `challenge` and sends `release_request`, signed by the
   backup key over it. Servers pass it to their peers as a delivery (§7.1), so a server that was down
   starts its own wait and freezes before it acts for the account again.
2. Each server starts a recovery wait (`W`, §6.2), tells every member and channel, and freezes
   lockless requests. A locked device, or two devices together, can cancel it; the holder can
   withdraw it.
3. When its own wait has passed, a server seals the **release bundle** to the backup key: the current
   release key, the current record, and its waited statement (`release`).
4. The holder fetches the backup material from any server or device (§7.2), checks it against the
   record's `backup` hash and the backup key's signature, opens it, and checks the shares against the
   record.
5. For 7 days after its own wait ended (the **recovery session**), each server takes part, in the
   two-call form (§5.1), in rounds of the backup plus two servers: but only for a recovery join (§4.5)
   and group records approved by `recovery` (§6.3). Not ordinary events.
6. Before the session ends, the new device replaces the backup (§4.4) with a **new backup key**, and
   the recovery app destroys the old backup's shares and the release bundle.

So a stolen paper needs two servers that each take part after their wait, with every device told.

### 6.7 Exporting keys

- **The master key is never exported.** A server MUST NOT seal its share to anyone for a `master`
  group, and members MUST NOT offer to combine a master group's shares into an nsec. (Someone combining
  their own shares with their own tools cannot be stopped, and this does not try.)
- **A child key** may be exported in stages: in Core 1.x any child; in a later version only children
  with `origin: import`; then none. Export is `take_out {}` from a device; each server seals its share
  to that device only with the approval of §6.3 (lock, pair or paper), and tells every member.
- A server treats a group as a child only if it adopted, first-hand at the group's creation, a first
  record that says `role: child` (Key families module). A record made by migration (§11.2) is always
  `master`.
- An export is permanent.

## 7. Keeping what you hold

### 7.1 Deliveries kept until acknowledged

Everything a member needs from others (the welcome, repair sigmas, release and data keys, the next
record, wrapped backup material, and every `remove`, `cancel`, `withdraw` and `release_request`) is a
**delivery**. A newer delivery of the same kind for the same member replaces an older one. Every server of the account MUST keep each delivery for every member, other servers
included, until that member sends `ack` for it or is removed, and MUST hand it over when asked (§8.2).
A server that was offline MUST fetch its deliveries from its peers before it co-signs, issues a
waited statement or releases anything again.

Deliveries travel **only live or through server inboxes**, never as copies on relays: anything that
carries a share or a key must not sit in public archives.

### 7.2 The backup material and the release key

The backup's shares exist only as **backup material**: the shares (made and checked once, §4.4) and
a copy of the data key, wrapped first with NIP-44 to the backup key and signed by the backup key
(the **inner layer**, whose SHA-256 is the record's `backup`), then with XChaCha20-Poly1305 under the
release key. Every server and every device keeps the current copy (so device + paper still works if
every server is gone), and members refuse any copy whose inner layer does not match. Helpers and
backups never hold the release key.

So helper + paper (3 + 2) cannot sign without a server's wait (I5), and neither can a helper plus
friends holding the backup key. Device + paper works at once, because the device holds the release key.

When a device is removed, the reporting device makes a new release key and re-wraps the outer layer of
the material under it (§6.5). The inner layer, and the paper, never change.

### 7.3 Storage at rest and destruction

- On phones and desktops, shares and the member key at rest MUST be encrypted under a key specific to
  this membership, kept in platform secure storage (Keychain "this device only", Android Keystore, an
  OS keyring). Destroying means **deleting that key** (closes #7 where the platform can delete keys),
  not only the ciphertext.
- That storage key MUST NOT require the person's face, fingerprint or passcode to use, and signing
  MUST NOT be limited to while the device is unlocked: background signing works as it does with an nsec
  today. (iPhone keeps keys sealed between a restart and the first unlock; that is the platform, not a
  rule.) The lock (§6.1) is a separate key, used only for the guarded actions.
- A removed or wiped member MUST destroy everything it holds, with no snapshot, backup, version
  history or log line that keeps it. Where storage keeps history that cannot be turned off (for example
  30-day point-in-time recovery), only ciphertext may be stored there, with the key kept outside it.
- On iPhone, shares and keys MUST be excluded from iCloud and restorable backups.
- A browser extension SHOULD encrypt what it stores where that costs no extra prompt, and otherwise
  stores it plainly in the extension's own storage. That is still better than an nsec kept the same
  way: a copied profile gives 3 points, not the key. It MUST NOT register a lock it cannot keep out of
  that storage.

## 8. Push and inbox

### 8.1 Registration

- A device registers with **each** server, per account, by `push_register` (sealed, so signed by its
  member key): `{ "addresses": [ { "cls": "sign" | "ask" | "notice", "url": "…", "p256dh": "…",
  "auth": "…" } ] }`. One address per wake class. The newest set, by the rumor's `created_at`,
  replaces the old one. `push_unregister {}` removes them all.
- Each server signs its pushes with its own VAPID key (RFC 8292), the `vapid` key in the record.
  Gateways issue a separate random address per server and per account, pinned to that server's VAPID
  key when the device asks for it, so the address is useless to anyone else and servers cannot link one
  phone's accounts.
- A server drops an address that returns 404 or 410, drops a removed member's addresses, and MUST NOT
  copy addresses to other servers.
- **Notice channels.** A device MAY register `notify_register { "email": "…" }` or
  `{ "webhook": "https://…" }` with a server. Servers MAY support them; a server that does MUST send
  every wait notice there too, never content beyond "a change to your account is waiting; it completes
  on <date> unless you stop it". Any device may **add** a channel; removing or replacing one needs
  approval (§6.3), and the old channel is told.

### 8.2 Sending and the inbox

- Servers send standard Web Push (RFC 8030), encrypted with RFC 8291 `aes128gcm`. The payload is JSON
  `{ "v": 1, "cls": "…", "id": "<request, notice or wait id>", "srv": "<host key>", "wrap": <the
  sealed message, only if it fits>, "sig": "<BIP-340 by the host key over SHA-256(JCS of the other
  fields)>" }`, padded so every encrypted body is the same length and no more than 2,560 bytes
  (reference 2,400). A sealed `sign` for an ordinary note is about 3.9 KB, so in practice the device
  fetches; `wrap` is for small notices.
- Anything for a member that may be asleep goes in that server's **inbox** first, and only then is
  pushed. Kind 21059 is used only towards members known to be awake (§9.1).
- `inbox_get {}` returns `{ "items": [ { "iid": "…", "age": <seconds held>, "wrap": {…} } ], "waits":
  [ <every recovery or hold running for the account, with its change and end> ] }`; `inbox_ack { "iids": […] }`
  removes items. Items expire with their lifetime class; deliveries (§7.1) stay until acknowledged.
- **Opening the app MUST fetch every server's inbox**, with no gateway involved. A dead gateway slows a
  device down; it never cuts it off.
- Wait notices go as `ask` pushes from **every** server to **every** member, with the wait id, so
  devices merge the copies.
- Servers MUST cap each account's inbox (reference: 512 items or 4 MB, ordinary notices dropped oldest
  first; deliveries and wait notices never, until their wait ends) and pushes per address (reference:
  60 an hour, with wait notices always sent).

### 8.3 Gateways

A gateway turns Web Push into APNs (or FCM). Each app maker runs its own; servers do not care which. A
gateway MUST keep no state but its address table, no logs of payloads, never see content (it forwards
the encrypted body), check the VAPID signature against the key pinned to the address, and rate-limit
each address. Its addresses MUST be random ids, never raw device tokens. Android apps using
UnifiedPush need no gateway. (Delivery details for APNs, such as priority 10 for `sign` and `ask`, are
guidance in the iOS appendix of the Doors module.)

## 9. Transport

### 9.1 The envelope

Every member message is a **kind 24301 rumor** whose content is JSON
`{ "v": 1, "type": "…", "g": "<group key>", "n": <record n>, "id": "<request id>", "cls": "…", … }`,
sealed (kind 13) by the sender's member key and gift-wrapped (NIP-59) to the recipient's member key.
The seal's key is the sender: there is no other sender field.

- **Live** (towards servers, and towards members known to be awake): kind 21059, re-sent until
  answered.
- **Stored** (towards a member that may be asleep): the server's inbox (§8.2). Messages that carry no
  share or key MAY also go to relays as kind 1059 with a NIP-40 `expiration` at the end of their class.
- **Never on relays:** anything that carries a share or a key (§7.1).
- A plaintext over 24,000 bytes is split into `{ "type": "part", "of": "<id>", "k": k, "m": total,
  "data": "<base64>" }` rumors, reassembled by `(sender, of)`. Receivers MUST refuse a message over
  512 KB in total and drop parts whose message has expired.
- Errors: `{ "type": "error", "re": "<id>", "code": "…" }`. Unknown `type` → `unsupported`.

### 9.2 Relays and HTTPS

- **Relays MUST** work for everything. Members subscribe on the record's `relays` (SHOULD be 3 or more,
  from different operators) to kinds 1059 and 21059 with `#p` = their member key. A server also
  listens on the relays in its own announcement, and devices always also use each server's announced
  relays (and HTTPS), whatever the record's `relays` say, so a bad relay change cannot cut a server
  off.
- **HTTPS SHOULD** be offered by servers that can. `POST <https>/keykin/v1` with a JSON array of gift
  wraps addressed to the server; the answer is a JSON array of gift wraps. Same format, so a member
  can switch between the two at any message. An iPhone's notification extension uses HTTPS when it is
  there, because it is faster.

### 9.3 What a server may be made to reach

Members name relays, push addresses, webhooks and HTTPS endpoints. A server MUST NOT connect to
private, loopback, link-local, carrier-grade NAT or cloud-metadata addresses because a member or a
stranger named them; it MUST resolve and check at every connect, MUST NOT follow redirects, and SHOULD
cap new accounts per IP per day (reference 10), messages per account per minute (120) and request size
(512 KB). An open server MAY ask for proof of work (NIP-13) on enrollment.

### 9.4 Messages

| `type` | From → to | § |
|---|---|---|
| `welcome_offer` / `join_hello` / `join_nonce` | inviter → new member / new member → inviter / receiver of the hello → sender | 4.1, 4.2 |
| `welcome` | inviting device (or backup holder) → new member | 4.2, 4.5 |
| `repair_delta` / `repair_sigma` | helper ↔ helper / helper → new member or backup key | 4.2, 4.4 |
| `commit` / `commitments` | coordinator → co-signer / back (two-call form only) | 5.1 |
| `sign` / `partial` | coordinator → co-signer / back | 5.1 |
| `ecdh` / `ecdh_partial` | device → co-signer / back | 5.5 |
| `hold` | device → servers | 5.8 |
| `draft` / `draft_held` | device → servers / server → device | 3.4 |
| `pair` / `vouch` | second device → servers (its half of an approval) | 6.3, 6.4 |
| `cancel` / `withdraw` | device → servers / sender → servers | 6.2, 3.4 |
| `remove` | device → servers and devices | 6.5 |
| `challenge` / `release_request` / `release` | server ↔ backup holder | 6.2, 6.6 |
| `take_out` / `released` | device → servers / back (children only) | 6.7 |
| `record` | any member → members (a signed record) | 3 |
| `ack` | member → servers | 4.2, 7.1 |
| `notice` | server → members | 6.2, 8.2 |
| `push_register` / `push_unregister` / `notify_register` | device → server | 8.1 |
| `inbox_get` / `inbox` / `inbox_ack` | member ↔ server | 8.2 |
| `part`, `error` | anyone | 9.1 |

That is the whole of Core. Cosign 0.12 has 55 message types in `server/core/group.ts`; everything not
here belongs to a module or goes.

## 10. Security properties, and their limits

**What holds.**

- One member signs nothing: not a device (3), not a server (1), not the backup (2), not a helper (3).
- All servers together (3) can never sign, and neither can two colluding operators.
- A server can delay or withhold its share and see what it co-signs. It cannot sign, cannot make a
  record, cannot add a member that others believe (live finding #1), cannot read messages (decryption
  answers are useless without a device's own points), and cannot fake a push.
- A joining member trusts only its scan, the group key and the check on both screens (#17).
- A lock is a signature servers check, not a device's word (#4).
- **No account change without a lock, a second device, or the paper.** A thief holding one phone
  without its face or fingerprint (including a locked phone whose face they reset) cannot add a
  device, register a lock, report the owner's devices, remove a server or touch the paper. They can
  sign everyday events until the owner reports the phone from a second device or with the paper.
- A record needs a majority of servers' `draft_held`, so the account cannot fork.
- A stolen paper needs two servers that each waited, with every device and channel told; the owner's
  locked device, or two devices, can stop it.
- The paper is checked when it is made, its material is signed by the backup key and pinned in the
  record, and it never changes, so no one can silently spoil it later.
- Nonces never touch storage and are hedged, so no restore or snapshot replays one.

**What does not, said plainly.**

- **Removed devices and dropped servers keep valid pieces.** Shares are never re-dealt, so the pieces
  of a removed device, or of a server taken out, still fit the key. Every member refusing them is the
  protection. A removed device plus any one server that ignores the block (hacked, buggy, restored from
  an old backup) is 4 points; a dropped server's piece plus a stolen device is 4 points with no honest
  server involved. After a serious leak, the fix is a new key with key families (later), not a re-deal.
- **A removed device keeps the data key**, so it can read private data written later, as a stolen nsec
  could. Changing it comes with the optional refresh module.
- **A removed device plus the paper** is the key with no server: the device kept the old release key
  and the backup material. That needs two thefts.
- **A stolen paper plus two dishonest servers** is the key. Today one operator runs every server. And
  a paper recovery that nobody cancels leaves the thief with a device, so the key for good.
- **The paper needs two live servers** to recover; with fewer, it can only be used together with a
  device.
- **One operator today.** All three live servers are run by one person, so "two servers' waited
  statements" and "every server refuses" are one party's word until other operators exist.
- **Two stolen devices** (6 points) sign without any server and skip every server rule.
- **A stolen device plus one dishonest server** is 4 points: if the device's shares can be extracted,
  that is the key itself, offline and for good.
- **A stolen device with no lock plus one honest server** can sign everyday events, and overwrite
  lists and the profile, until the owner reports it: the server's rule (§5.8) catches only events that
  are destructive on their face. Mass deletions and vanishing wait; single deletions go through after
  the device's 10-second hold.
- **A lockless single-device owner** can't report a stolen phone lost by itself; the paper (3-day
  recovery, which freezes the thief) or a notice channel is how they act. With neither, nothing tells
  them, but the thief can still only sign everyday events.
- **Helper plus one server** signs, by design: the person opted in to that.
- **Locks are unattested.** Servers cannot tell a hardware key from a software one, and a tampered app
  can make its own "lock". A passkey that syncs to a cloud account is only as strong as that account;
  implementations SHOULD use device-bound credentials.
- **Browser profiles.** An extension without prompt-free secure storage keeps shares a copied profile
  can carry away (live finding #5). That is 3 points, not the key: better than an nsec in the same
  storage, which is the bar. It never counts as locked.
- **Until the paper is printed**, the device that made it holds 5 points (§4.4).
- **iPhone push.** Waking an iPhone needs Apple and the app maker's gateway. The gateway sees when
  each phone is woken and by which servers, not why. If it is down, signing still works when the app is
  opened, from other devices, or through any other Keykin app; notices are what suffer.
- **Membership leaks.** The record is never published, but any member could leak it.
- **Imported keys and exports are for ever.** A key that was ever whole stays whole wherever it was.
- **The one-call round is not yet formally checked** (§5.1).

### 10.1 Live findings this core closes

| Finding | Closed by |
|---|---|
| #17 joining phone trusts any welcome | §4 (group-signed record, inviter's sigma, the check with its nonce) |
| #4 lock taken on trust | §6.1, and gate evidence in the record (§6.3) |
| #1 injected member can act | §3 (only kind 30242 records signed by `g`, kinds pinned), §11.2 |
| #7 wipe leaves shares recoverable | §7.3 (browsers: §10) |
| #2 paper added with any key | §6.3 (approval needed), §4.4 (checked at creation, signed, pinned) |
| #3 report-lost race | §6.3, §6.5 (lock, two devices or the paper) |
| #8, #9 server archive and ECDH oracle | §2 (no history), §5.5 (devices only, weighted) |
| #12 paper promotes itself | §3.3 (kinds never change) |
| #13 stranded server, #14 removal in a pending refresh | no refresh any more; deliveries (§7.1) |
| #16a/b optional or partial proofs | §5.5 |
| #5 extension shares unencrypted | encrypted where it costs no prompt (§7.3); otherwise 3 points, which beats the bar (§10) |
| #10, #11, #15 | Doors and Device policy modules (grants live on devices) |

## 11. Versions, migration, the rename

### 11.1 Versions

- Core follows semantic versioning. Any wire change bumps the major version, which is `v` in every
  rumor, every record and every push payload.
- Unknown fields are ignored. Unknown message types are refused (`unsupported`). Unknown member kinds
  are kept (§3.1).
- Servers SHOULD support versions N and N−1. A device that meets a record or message with a major
  version it does not know MUST refuse to sign and show that it needs an update (§1.1).

### 11.2 Moving a Cosign 0.12 account to Keykin

The group key and the npub stay the same. Cosign 0.12 signs with its own FROST scheme
(`server/frost.ts`, binding tag `cosign/rho`), so servers keep it as version N−1 until every member
has moved.

1. Servers are updated to speak both. Nothing changes for the person yet.
2. A device builds the first record from first-hand facts only: the commitment from its own 3 points
   and the group key (§3.3 step 4); a member is kept only if this device ran its repair or key
   generation, or verified a partial from that member's indices against the derived points. Agreement
   among servers counts for nothing. Everyone else joins again. Kinds are as this device knows them.
3. The first record is always `role: master`, approved by the migrating device's lock or a second
   0.12 device, with every device and channel told. Servers take the first that arrives, refuse one
   from or listing a member removed under 0.12, and never give out indices that 0.12 used. Then the
   device makes a new release key, data key and paper (§4.4), and devices register their locks
   (approved by a `pair` or the new paper).
4. Once a server has adopted the first Keykin record for an account, it stops taking Cosign 0.12
   traffic for it; 0.12 members still to move join again (§4).
5. Do it first on a throwaway account, with the paper checked, before the main npub.

A 0.12 account's pieces from before the move, including any device removed under 0.12, stay valid
mathematically (§10). Accounts that never migrate keep working with servers that still speak Cosign
0.12.

### 11.3 The rename

Readers MUST accept the old names for ever: the record `d` tag `frost` and `cosign`, the server
announcement `d` tag `cosign-server`, `cosign:` codes, and Cosign paper backups (same key format, same
meaning). Writers use the `keykin` names. Kind numbers 24301, 30242, 30243 and 10243 stay provisional
until upstream assigns them.

## 12. Modules (not part of Core)

Each is a short document of its own, and none may weaken anything above.

- **Account admin**: creating a key (DKG, import), adding and removing devices on screen, retire,
  delete (NIP-62 plus destroying shares and forgetting push addresses), the take-out bundle, the
  passkey page on servers for reporting a device lost.
- **Server profile**: the duties as an operator sees them, abuse defaults, the 30-day shutdown notice,
  when to suggest removing a quiet server, announcements (kind 30243/10243), the operator notice.
- **Device policy**: the destructive check, Undo from the device's own history, re-confirming staged
  events (a staged replaceable event older than the newest known is destructive), honest quiet notices.
- **Doors and grants**: NIP-07, NIP-46 (per-site signer keys, bunker://, auth_url), NIP-55, the QRST
  signer-ticket, the same-device door on iPhone, grants and scopes, the iOS push appendix.
- **Backup**: 24 words, finding servers from the paper, recovery contacts, the escape hatch (device +
  paper or two devices replace dead servers by a record they sign themselves), heir.
- **Helper**: the opt-in.
- **Key families**: claim, accept, release; the challenge window; child groups. This is the answer to a
  serious leak.
- **Refresh (optional)**: "Refresh now", started by hand when every member is online together:
  re-deals the shares so removed pieces stop fitting, changes the data key, and reprints the paper.
  Its own document and red team (`refresh.md`).

## 13. Open items

- **Formal check** of the one-call round (§5.1).
- **Outside reviewer** sign-off on the core.
- Repair with mixed-weight helpers relies on `frost-core`'s `repairable` module; its behaviour with a
  helper holding 3 indices must be pinned by vectors.

## 14. Test vectors

The vectors file is `docs/keykin/vectors.md` (its plan and first cases). Done when the TypeScript and
Kotlin implementations both pass it and a fuzzed parser has run against every message. The interop
plan is `docs/keykin/interop-plan.md`.

## Changes in draft 5

The user's cut (2026-11-02, after red-team round 4; see `simplification.md`):

- **Refresh removed.** Shares never change; no dealers, `pending_ok`, delta checks, per-epoch backup
  re-making, previous-epoch fallback or second-device check. The record's `epoch` became a version
  number `n`. Refresh is listed as an optional future module.
- **Report lost needs a lock or two devices** (or the paper, through recovery). Mutual removal, the
  7-day window and notices to removed phones are gone.
- **`deposit` removed.** **Forks** are prevented by a majority of servers holding a draft, instead of
  merge rules.
- **The paper is made and checked once**, on the device that prints it (§4.4), and delivered to every
  server and device.
- **Simpler cancel rules** (§6.2): any device or the paper for lockless changes; a locked device or two
  devices for a recovery.
- Round 4's other findings that survive the cut, taken: two devices may cancel a recovery and report a
  device; helpers can be reported like devices; a two-server account with one server gone still works
  (waited statements from every server not being removed); the welcome carries the backup material;
  lock assertions for changes expire; held drafts expire; staged drafts are signed with a fresh `sign`
  request; one encoding for the destructive approval; the paper cannot cancel its own removal.

## Changes in draft 6

The user's second cut (2026-11-02, after red-team round 5):

- **Every account change needs a lock, a second device, or the paper** (§6.3). The "else wait 3 days"
  path, waited statements for changes, the short wait `w`, most of the cancel rules and the lockless
  freeze rules are gone. Waits remain only for paper recovery and held mass deletions.
- **The data key never changes** in the core (§4.6); re-keying is in the refresh module.
- **At least 3 servers** (§3.2); a dead server is replaced in one record (§4.3).
- Round 5's slips: the join-code hello must come from the code's key (§4.2); the backup material is
  signed by the backup key and pinned in the record (§4.4, §7.2); `draft_held` once per record number
  and carried in the record (§3.4); `replace_backup` as one change; the paper read back before its
  secret is forgotten; the release key rotation is one delivery tagged with `n`; devices act on
  `remove` too; newer deliveries replace older; 0.12 traffic stops once migrated; holds capped; the
  bad-helper claim corrected; a missed `cancel` blocks waited statements and releases too; gate
  items name their member; lock expiry capped; §10 gains the paper's limits.
