# Keykin Core

Draft 4 · 2026-11-02 · `draft` `optional` · not built

Keykin keeps one Nostr key for life without any single device, server or company holding it.
The key is split with FROST into weighted shares: each of the user's devices holds 3, each server
1, a paper backup 2, and signing takes 4. So the device you're using plus any one server signs, two
of your devices sign, and all the servers together never can.

This document is the **core**: the smallest set of rules two independent implementations need to
work together and keep the account safe. Everything a person sees, and every optional feature,
lives in a module (§12). Sites change nothing: they keep using NIP-07, NIP-46, NIP-55 and the QRST
signer-ticket, which the Doors module covers.

**The bar.** An nsec kept in a password manager. Every rule here must beat it on security *and*
on how it feels to use; a rule that costs a person effort without beating it does not belong. So
nothing here puts a face or fingerprint in front of everyday or background signing, or opening the
stored shares.

**How to read it.** MUST, SHOULD and MAY apply to wire behaviour and to what a member stores. The
only exceptions are the few **security displays** in §1.1, which are part of the protocol's
security. Everything else a person sees is up to the app. "Reference" numbers are defaults an
implementation may change without breaking anyone.

Keykin is the new working name of Cosign. Cosign 0.12 (built, described in `../COSIGN.md`) is the
prototype this replaces; §11 says how existing accounts move over. Old `cosign` names stay
readable for ever.

Drafts 2–4 fold in three independent red teams (`keykin-core-redteam-1.md`, `-2.md` and `-3.md`
in the shared notes); the change lists are at the end.

---

## 1. Terms

- **Group key** `g`: the account's Nostr key (x-only, BIP-340). Its private half never exists
  whole anywhere (§6.7).
- **Ciphersuite**: `FROST-secp256k1-SHA256-TR-v1`, as implemented by the Zcash Foundation's
  `frost-secp256k1-tr` 2.x: RFC 9591's FROST(secp256k1, SHA-256) with the BIP-340 challenge as
  H2, the group key and shares brought to even y at key generation (`into_even_y`), and each
  signer's nonce negated when the group commitment `R` has odd y. Plain RFC 9591 does not
  interoperate with this, and neither does Cosign 0.12's hand-rolled `server/frost.ts` (§11.2).
- **Share**: one FROST share `s_i = f(i)` at a unique index `i ≥ 1`, worth one point. `f` has
  degree 3; threshold `t = 4`.
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
  commitment (§3).
- **Epoch**: one version of the shares. A refresh (§7.2) starts a new epoch with the same `g`.
- **Lock**: a P-256 key in secure hardware that signs only after a fresh face or fingerprint
  (§6.1). A passcode alone is not a lock.
- **Wait**: a delay, 3 days by default (`W`), that servers apply on their own clocks to an
  account change made without a lock (§6.2). A short wait `w` is 1 hour.
- **Release key**: a random 32-byte key held by devices and servers, never by helpers or backups,
  that wraps the backup's shares a second time (§7.5).
- **Data key**: a random 32-byte key held whole by devices only, for reading the account's own
  private data. It can read, never sign (§4.6).
- **Request**: any member message that asks for an answer. Each has an `id` (16 random bytes, hex)
  and a lifetime class (§5.6).

### 1.1 Security displays

These are the only things this document requires an app to show, because the protocol's safety
depends on a person seeing them:

1. the 6-digit join check, on both screens, and the person confirms on both before a join goes
   ahead (§4.1);
2. the account a device joined, when it joined from a join code (§4.2);
3. a refused record or a refused delta, with the member it came from (§3.3, §7.2);
4. that an update is needed, when a device meets a version it does not know (§11.1);
5. a vouch: a device vouches only after its person types the 6-digit check shown on the new device
   (§6.4); likewise a two-device cancel asks each person (§6.2).

## 2. Who does what

**Devices do the work.** A device coordinates its own signing rounds, judges what is destructive,
asks the person, keeps the account's history and does Undo. When it can, it does anything a server
would.

**Servers do the minimum.** Per account, a server MUST keep only:

1. its one share for the current epoch, a pending one during a refresh (§7.2), and the previous
   one as a recovery-only fallback until it is released (§7.5);
2. the current group record, and at most one draft or plan for the next epoch (§3.4);
3. the current release key and backup contributions, and the previous epoch's as the same
   fallback (§7.5);
4. waits in progress with their notices, recovery sessions, and removed members' 7-day windows
   (§6);
5. push addresses and notice channels (§8.1), and the short inbox, including deliveries kept
   until acknowledged (§7.3, §8.2);
6. answered request ids until each expires (§5.6), and its own counters for §5.8.

A server MUST NOT keep signed events, list versions, site grants or logs of what it signed. It
co-signs, enforces waits and the stateless destructive rule (§5.8), sends wake-up pushes, and helps
with repair and refresh. That is all.

| | device | helper | server | backup |
|---|---|---|---|---|
| Coordinate everyday signing | yes | yes | only if `own` (§3.1), and only by asking a device | only in a recovery session (§6.6) |
| Co-sign for others | yes | yes | yes | no |
| Get decryption partials (§5.5) | yes | no | no | no |
| Vouch for a new member, report lost | yes | **no** | no | no |
| Cancel a wait | yes, with its lock | **no** | no | only waits started without a lock (§6.2) |
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
  "commitment": ["<C0>", "<C1>", "<C2>", "<C3>"],   // 33-byte compressed points, hex, even-y form
  "role": "master",            // or "child" (§6.7); set in the first record only
  "origin": "dkg",             // or "import"; set in the first record only
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
  "next": 7,
  "gate": { /* evidence that this change's gate was met, §6.3 */ }
}
```

- `commitment` is the Feldman commitment to `f`: `C_k = a_k·G`, with `C0` the group point. The
  point of share `i` is always **derived**, `P_i = Σ C_k·i^k`, and never taken from a message.
- `lock` is absent for a member without one. `own` marks a server the user runs; it counts as one
  of the user's devices for privacy, nothing else.
- `next` is the next unused index. Indices are never reused.
- `removed` is positive: a member is removed only by appearing here, never by being missing.
- **Unknown member kinds** are kept, and a device shows them (§1.1). For the invariants, an
  unknown kind's shares count towards I2 as if it were a server, and as neither device nor server
  in I5; the exact-share-count rule does not apply to it. A member that meets an unknown kind MUST
  NOT co-sign a further change to that record until it is updated, but signs everything else.

The record is passed only between members, inside sealed messages (§9). Members MUST NOT publish
it to relays: it names the account's servers and devices. (A member could still leak it; §10.)

### 3.2 Invariants

A record is valid only if all of these hold. Servers MUST refuse to co-sign a record that breaks
one, and every member MUST refuse to adopt one.

- **I1.** No member holds more than 3 shares.
- **I2.** Servers together hold 3 shares or fewer.
- **I3.** `backup` members together hold 2 shares or fewer (so the paper is 2, or a paper of 1
  and an heir of 1).
- **I4.** A round whose participants include no device-class member is a **recovery round** and
  needs a recovery session (§6.6).
- **I5.** Any set of members that contains no `device` and no `server` is worth less than 4, with
  `backup` shares counted as 0 (they are unreadable until a server releases them after its wait,
  §7.5). One consequence: at most one `helper`.

Also: each server holds exactly 1 share, each device and helper exactly 3, each backup 1 or 2;
indices are unique across members and `removed`; there are at least 2 servers.

### 3.3 Checking a record

A member adopting a record MUST check, in order:

1. it is **kind 30242**, its `d` tag is `keykin` (or, read-only, `cosign` or `frost`), its `v` and
   `epoch` tags equal the content's, and the event signature verifies under `g`, the group key this
   member already knows (from its own creation of the account, or from the code it scanned, §4);
2. `epoch.n` is exactly one more than the record it holds, and `prev` is that record's event id
   (or the record is the one it was handed at join);
3. `C0` is the group point, and for every share it holds, `s_i·G == P_i`;
4. **a device, in addition, rebuilds the commitment from first-hand facts**: its own 3 points and
   the group point fix a degree-3 polynomial, so it computes `C0…C3` from them and refuses any
   record whose commitment differs. No member list can fool this;
5. the invariants (§3.2);
6. the change from the previous record is one §6.3 allows, its `gate` evidence verifies (§6.3),
   and every member kind and key↔index pair it already knew is unchanged except by those rules.

A record that fails any check is refused, and a device shows it (§1.1). Members keep the highest
valid record they have seen and never go back to a lower epoch.

### 3.4 One change at a time

- Waits run on **changes**, not records (§6.2), so any number of waits can run at once and a
  record commits only when its gate is already met. Making the record then takes seconds.
- A server holds **at most one** draft record or refresh plan for epoch `n+1`. The first to arrive
  holds it; any other gets `error busy`, and its sender retries after a random delay (reference:
  5–60 s). A removal (§6.5) always takes the place of a held draft or plan that removes nobody,
  whose sender is told `error superseded`. `withdraw {id}` lets a sender drop its own draft, plan or
  wait. A plan or draft is accepted only from a `device` (or, in a recovery session, the backup).
- A server co-signs a record for `n+1` only if it is the draft it holds.
- If two valid records for the same `n+1` ever appear, the one that removes members wins; between
  two that both do or both don't, the first one this member received wins. Holders keep their
  pending shares from both refreshes until the fork resolves. If the losing record changed no
  shares, its change is made again on top; if it was a refresh, members who adopted it say so
  (§1.1) and join again.
- A key in `removed` never appears in `members` again.

## 4. Joining

Adding any member uses one handshake. It closes live finding #17: a joining member trusts nothing
it did not get from a code the person scanned, from the group key, or from the check both screens
show.

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
`welcome_offer`), and the person confirms on both devices that they match before step 2. The hello
fixes `n` before `t` exists, so nobody can grind a key whose number matches.

### 4.2 The handshake

1. **Hello.** The side that scanned writes to the other, sealed to the key in the code:
   - invite direction: the new member sends `join_hello {n, s, lock, kind}`: its member key,
     the secret, its lock public key if it has one, and the kind it asks to be;
   - join-code direction: the inviter sends `welcome_offer {g, m, s}`, and the new member answers
     `join_hello {n, s, lock, kind}` sealed to `m`.

   A side MUST drop a hello or offer without the right `s`, after `x`, or after it already
   accepted one for this `s`. The receiver of the hello then sends `join_nonce {t}`.
2. **The new record.** After the check, the inviting device asks for the change
   `{"add": {key, kind, lock}}` (indices are given only when the record is made, so other changes
   in between do not void a wait). When the gate is met it builds the next record with the new
   member at fresh indices from `next`, the kind as the person chose it, and its lock key. If the
   gate is a wait, the new member waits too (its join is `member` class) and the welcome comes
   after the commit; servers push the inviting device when the wait passes. The
   kind is set here and only here: a member never chooses its own kind, and a helper can never
   enroll as a device. The inviter gets the record co-signed by a server, which applies the gate
   for this change (§6.3), including any wait.
3. **Repair.** For each new index, the inviting device (3 shares) and one server (1) run the repair
   of `frost-core`'s `repairable` module with all 4 shares as helpers: each helper share computes
   its Lagrange-weighted deltas, the helpers exchange them (`repair_delta`), and each sums what it
   received into one `sigma`, sealed to the new member's key (`repair_sigma`), together
   with `sigma·G`. A server MUST take part only for indices that a co-signed record assigns to
   that new member, or for a backup's indices at a refresh (§7.5). No member ever sees the new
   share.
4. **Welcome.** The inviting device seals to the new member (`welcome`): the signed
   record, the relays, the release key (devices and servers only), and the data keys (devices only,
   §4.6).
5. **Checks.** The new member MUST refuse to finish unless:
   - the `welcome` is sealed by `m`;
   - the record passes §3.3 against `g` (the invite's, or the offer's, which the device then shows
     as the account it joined, §1.1);
   - the record lists its own member key, at the kind it asked for, with these indices, and its
     lock key;
   - it has `repair_sigma`s from at least two distinct members of that record, one of them `m`,
     and for every new index the summed share satisfies `s_i·G == P_i`. If the sum fails, each
     `sigma·G` shows which helper sent a bad part.

   Then it sends `ack {epoch}` to the inviter and to every server, and destroys the sigmas.

Why this holds: nobody without 4 points can produce a record signed by `g`, the inviter's
contribution cannot be forged, and a racer's hello fails the check.

### 4.3 Adding a server

The device uses the server's announcement or a code from the server's operator (Server profile
module) in place of the code above, and the check is shown on the device against the server's
host key. The server receives the record and the release key, never a data key.

### 4.4 Adding a backup

A backup member never comes online. Step 3's sigmas go to the backup key instead, wrapped twice
and stored (§7.5). It needs no hello and no check: the device that creates it makes the key pair,
gives the secret only to the paper (or, by a recovery module, to friends), and MUST NOT keep it.
The backup is created at setup even if nothing is printed yet, in the account's first record, which
needs no gate.

### 4.5 Recovery join

In a recovery session (§6.6), the new device joins with the backup holder's app in place of the
inviting device: the repair helpers are the backup (2) and two servers (1 + 1), the welcome is
sealed by the backup key, and step 5 requires sigmas from the backup and both servers.

### 4.6 The data key

A random 32-byte key, never derived from the group key or any to-self conversation key and never
published. Devices hold it whole, in storage that is never backed up or synced (on iPhone, never in
iCloud Keychain or a restorable backup). Helpers, servers and backups never get it. A refresh
(§7.2) brings a new one; devices keep older ones so they can read older data, and data services
re-encrypt lazily. A thief keeps whatever data key they already copied, and nothing newer.

`welcome` and refresh deliveries carry `data_keys: [{ "epoch": "<epoch id>", "key": "<hex>" }]`,
at least the current and the previous.

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

**More than two parties: two calls.** When a round needs more than one co-signer (a recovery
round, §6.6), the coordinator first sends `commit {signers}` to each and gets back `commitments`;
each co-signer keeps those nonces in memory only, for at most 120 s, for that one request id. Then
it sends `sign` with the full commitment list and `after: <the commit request's id>` to each,
under a new id, and each answers `partial` with its shares from the nonces it kept for `after`. A co-signer MUST
check that its own entries in the list are the commitments it returned for `after`, and MUST refuse
a second `sign` naming the same `after`.

- **Binding.** Binding factors and the group commitment MUST be computed over the full commitment
  list for `signers`, every index of every participant. A co-signer MUST refuse a commitment list
  that does not cover exactly the other participants' indices, or that contains the identity point.
- **Several co-signers in the one-call form.** A coordinator MAY ask several at once (reference:
  the fastest first, the rest after 300 ms). Each request is an independent round with its own
  coordinator nonces and its own id. It completes with the first valid partial and discards the
  nonces of the others.
- **Formal check.** The one-call form lets a co-signer pick its nonce after seeing the
  coordinator's. The red team found no attack (the co-signer moves last; the coordinator is where
  standard FROST puts a signer in round 2), but it needs a formal check before 1.0 (§13).

### 5.2 Nonces

- A member MUST generate nonces only for a request it is answering or sending, keep them in memory
  only, and use each once. Nonces MUST NOT be written to disk, shared storage, logs or anything a
  snapshot, a restore or a second process could bring back. After a restart, every round in flight
  is lost.
- **Hedged randomness.** The random input to `nonce_generate` MUST be
  `SHA-256(fresh OS randomness ‖ share ‖ context)`, where context is, for a co-signer, the SHA-256 of
  the request; and for a coordinator, `event id ‖ signers ‖ request id ‖ co-signer key`. So a
  machine restored from a snapshot with the same random state still makes different nonces for any
  different round.
- A coordinator MUST compute its own signature shares at most once per nonce. A retry uses fresh
  nonces under a new request id.

### 5.3 Retries

A co-signer that gets a request whose `(sender, id)` it already answered MUST return the same answer
it sent, **only if** the new request is byte-identical (same SHA-256 of the RFC 8785 canonical
body) to the first. Otherwise it MUST refuse with `id_reused`. It keeps its answers, never its
nonces.

### 5.4 Never a bare digest

Co-signers MUST receive the full event, compute its id themselves (NIP-01) and check that `pubkey`
is `g`. There is no message that signs a hash.

### 5.5 Decryption

For NIP-04, NIP-44 and NIP-59, a device needs `x·Q` for a peer point `Q`. It sends
`ecdh {points: [Q…], signers}` to a co-signer, where `signers` is its own indices plus the
co-signer's and is worth 4. For **each** of its indices `i` and each `Q`, the co-signer answers
`ecdh_partial` with the weighted value `Y = λ_i·s_i·Q` (`λ_i` the Lagrange coefficient of `i` in
`signers`) and a proof that `Y` and `λ_i·P_i` share a discrete log:

```
k = H("keykin/ecdh-k/1" ‖ fresh OS randomness ‖ s_i ‖ Q ‖ SHA-256(request)) mod n
R1 = k·G;  R2 = k·Q;  W_i = λ_i·P_i
e = H("keykin/ecdh-dleq/1" ‖ g ‖ epoch.id ‖ i ‖ W_i ‖ Q ‖ Y ‖ R1 ‖ R2) mod n
z = k + e·λ_i·s_i       verify: z·G == R1 + e·W_i  and  z·Q == R2 + e·Y
```

(`H` is SHA-256; points 33-byte compressed, integers 4-byte big-endian, scalars 32 bytes.)

- Because the answer is weighted for a set that includes the asker's indices, it is useless unless
  the asker adds its own 3 points' worth. A member key with no shares learns nothing.
- The coordinator MUST refuse an answer unless its indices equal that member's indices in the
  record exactly (none missing, none extra, no repeats) and every proof verifies with `P_i` derived
  from the record. A refusal is that member failing, by name. An answer without proofs is a
  failure (closes #16a).
- Every `Q` MUST be a valid point other than the identity, and `signers` is checked as in §5.7
  item 2.
- Co-signers MUST answer `ecdh` only from a `device` in the current record. Never a helper, a
  server, a backup or a removed member.
- So no server, `own` or not, ever coordinates a decryption.

### 5.6 Lifetimes and replays

Every request carries `cls`. Each message type allows only some classes:

| `cls` | Lifetime | Allowed for |
|---|---|---|
| `sign` | 60 s (receivers MAY use 45 s) | `sign`, `commit`, `ecdh` |
| `ask` | 120 s | `sign`, `commit`, `ecdh`, `challenge` |
| `member` | 7 days | `sign` (a draft staged offline), `hold`, account changes, deliveries, `deposit` |

- A receiver measures age with its own clock from the rumor's `created_at` (when the request was
  sent), or from the inbox's `age` (§8.2) if that is larger. It MUST refuse a request older than
  its lifetime plus 30 s, or dated more than 30 s ahead.
- The **event's** `created_at` (when the person wrote it) never decides whether a request is fresh.
  A draft written offline keeps its time and is signed days later under `member`.
- A receiver MUST remember `(sender, id)` until the request's lifetime has passed, and treat a
  second request with it by §5.3. Servers MUST keep these across restarts. A server MAY cap them
  per member (reference: 10,000), refusing new requests from that member when full rather than
  forgetting old ids.

### 5.7 What every co-signer checks

Before giving a partial, a co-signer MUST check that:

1. the sender is a member in its current record, not removed, and may coordinate (§2);
2. `signers` is exactly the sender's indices plus this co-signer's (plus, in the two-call form,
   the other co-signers'), is worth at least 4, and the commitments cover it exactly (§5.1);
3. the request is fresh and not a replay (§5.6);
4. `event.pubkey` is `g`, and, for a **replaceable or addressable** kind (0, 3, 10000–19999,
   30000–39999), the event's `created_at` is no more than 10 minutes ahead of its own clock: a
   version dated ahead would block every later change until that date. Other kinds may be dated
   ahead, so a person can schedule a post;
5. if the event is **kind 30242, whatever its `d` tag**, it is a record: it MUST be a valid change
   with its gate met (§3.3, §6.3) and the draft this server holds (§3.4). A device MUST never sign a
   kind 30242 on a site's request;
6. if the round is a recovery round (I4), the recovery session's rules are met (§6.6);
7. the stateless destructive rule (§5.8).

A device co-signing for another device-class member also applies its own destructive policy (Device
policy module) and asks the person when that says to.

### 5.8 The stateless destructive rule

Servers keep no history, so they cannot tell that a follow list shrank. They can recognise a few
events that are destructive on their face, and for these a server MUST require **either** an
`approval` (a lock assertion from the coordinating device over
`(g, epoch.id, "sign", event id)`, valid for that event at any co-signer and any retry), **or** a
passed wait (`hold`):

- every request to vanish (kind 62);
- a **mass deletion**: a kind 5 with 5 or more `e`/`a` targets, or a kind 5 that would take this account past 5 deletion targets
  co-signed by this server without approval in the last 10 minutes (a burst; reference numbers,
  counted per account at each server, no history kept; a thief spreading deletions over three
  servers gets about three times that, still far less than a stolen nsec allows);
- kind 0 whose content is `{}` or has no non-empty `name`, `display_name`, `about` or `picture`;
- kind 3, 10000–10030 or 30000–30030 with no tags other than `d`;
- kind 10002 with no `r` tags.

**Holding** works like any wait, on the change `{"hold": <event id>}`: the device sends
`hold {event}` (`member` class); servers start a
wait (§6.2) and tell every member and channel; after `W` the device sends `sign` with `hold: <wait
id>` and a server co-signs if its own wait passed and nobody cancelled.

A single deletion needs neither: the device holds it for 10 seconds with Undo (Device policy
module) and then signs it like any event.

This is a backstop, and it is easy to step around for lists: a follow list cut to one junk entry is
not empty. The device is the real gate, and its policy (Device policy module) holds far more. What
that leaves open is in §10.

## 6. Account changes

### 6.1 The lock

A lock is a P-256 key generated in secure hardware (Secure Enclave, Android Keystore with user
authentication, or a device-bound WebAuthn credential with user verification) that signs only
after the current face or fingerprint. A phone with only a passcode, an extension without a
platform authenticator, and a Mac without Touch ID have **no lock**. A member with no lock has no
`lock` in the record.

A **lock assertion** has one encoding everywhere, WebAuthn's:
`{ "authData": "<b64url>", "clientData": "<b64url of JSON>", "sig": "<b64url DER>" }`.

A verifier MUST check that `clientData.type` is `"webauthn.get"`; that `clientData.challenge` is
`base64url(SHA-256("keykin-lock/1" ‖ g ‖ what))`; that `authData` starts with the
member's `rp` and has the user-present and user-verified flags set; and that `sig` verifies over
`authData ‖ SHA-256(clientData)` with the member's `pub`. `what` is:

- for a destructive event, `"sign" ‖ event id` (§5.8);
- for an account change, `"change" ‖ wait id` (§6.2), which has no epoch in it, so the assertion
  survives other records committing in between;
- for any other request, its `type ‖ epoch.id ‖ id ‖ SHA-256(JCS(body without the assertion))`.

Native apps build the same structure themselves. Servers cannot tell that a lock is in hardware
(no attestation is required); that is a stated limit (§10), not a check.

### 6.2 Changes and waits

- A **change** is a small JSON object that says what is to happen, without any epoch:
  `{"add": <member entry>}`, `{"remove": <key>}`, `{"lock": <new lock>, "key": <member>}`,
  `{"relays": [...]}`. Its **wait id** is `SHA-256(JCS(change))`, so every server names the same
  wait, and a wait survives other records committing meanwhile.
- A server starts a wait when it gets a gated change without the lock its gate needs, records the
  start **on its own clock**, and immediately tells every member (an `ask` push and an inbox
  notice) and every notice channel (§8.1). Several waits may run at once.
- When its own wait has passed, the server pushes the requester (`ask`) and signs a **waited
  statement**:
  `{ "server": <host key>, "wait": <id>, "start": <unix>, "end": <unix>, "sig": <BIP-340 by the host
  key over SHA-256("keykin-waited/1" ‖ g ‖ wait ‖ start ‖ end)> }`. Verifiers MUST check that
  `end − start` is at least the wait the gate needs (`W` or `w`), and accept a statement only
  within 7 days of its `end`.
- A request is **lockless** when it carried no valid lock assertion, whatever the member's record
  entry says. (A thief who knows a locked phone's passcode can reset its face; their requests are
  still lockless.)
- **Cancel** `cancel {wait}` ends the wait at that server, which tells everyone. It may come from:
  - a `device`, with a lock assertion;
  - two distinct devices, each with a detached signature, each having asked its person (§1.1);
  - the `backup` key, signing a fresh server `challenge`, for any wait on a lockless request.
    The owner's paper is their proof when the only device is the one that was stolen.

  A helper cannot cancel, and nor can a single device with no lock. The requester may `withdraw`
  its own.
- **Recovery ends lockless waits and freezes lockless requests.** When a server starts a recovery
  wait (§6.6), it **ends** every running wait on a lockless request and tells everyone. Until the
  recovery session ends, it refuses every lockless request: gated changes, `relays` changes,
  refresh plans, `remove`, and waited statements for any of them. Only the recovery session's own
  changes go ahead. Removing the backup does not end the backup's own wait.
- Every wait a member started ends when that member is removed.
- Signing and everything else carry on as normal during any wait.

### 6.3 What each change needs

Every account change becomes a new group record (§3). A server co-signs it only once the gate is
met, and the record carries the evidence in `gate`, so every other member can check it too. Signed
items in `gate` carry **detached** BIP-340 signatures by the signer's member key over
`SHA-256("keykin-<type>/1" ‖ g ‖ JCS(body))`, because a NIP-59 seal proves nothing to a third party.

- `{ "lock": <assertion> }` from the asking device, over the change (§6.1);
- `{ "vouch": [<vouch>, <vouch>] }` from two distinct devices (§6.4);
- `{ "waited": [<statement>, …] }`: from **at least two** of the record's servers for a change
  gated on `W`; from **one** for a lock-gated change that also needs `w`;
- `{ "removal": <remove> }` for a report lost (§6.5);
- `{ "recovery": { "release_request": …, "waited": [<statement>, <statement>] } }` for a change in a
  recovery session, with the statements of the two servers' release waits (§6.6).

| Change | Gate |
|---|---|
| Add a `device` | the inviting device's lock; or two devices' vouches; else `W` waited |
| Add a `server`, `helper` or `backup` | lock and `w` waited; else `W` waited |
| Remove a `device` (report lost) | any device; never delayed (§6.5) |
| Remove a `server`, `helper` or `backup` | lock; else `W` waited |
| Refresh with no change of members | any device, no lock (§7.2) |
| Change `relays` | any device, no lock |
| A device registers a lock it did not have | `W` waited (else a thief gives a passcode-only phone their own face) |
| A device replaces its lock | its old lock; else `W` waited |
| Change `role` or `origin`, or a member's kind or indices | never (only removal and a new join) |
| In a recovery session: add the new device, remove members, replace the backup | the `recovery` gate |

A `helper` never vouches, reports, cancels or asks for any of these. One record carries one change,
except that a refresh may also carry removals. Accounts SHOULD have 3 servers, so that one dead
server never leaves fewer than two for a `W`-gated change.

### 6.4 Vouching

`vouch {wait}` from a `device`, with a detached signature, names the wait id of an exact change and
says that device agrees to it. The request it answers carries the join's `g, m, n, s, t`, and the
device MUST ask its person to **type the 6-digit check shown on the new device** before vouching
(§1.1). A single "Yes" tap is not enough: a thief holding one of two devices could get it from a
tired owner. Typing the number proves the person can see the new device. Two distinct devices
agreeing make an add instant without a lock: two devices could sign without any server anyway.

### 6.5 Report lost

- `remove {key}` from a `device` (with its lock assertion if it has a lock, and a detached
  signature). It names a `device` only; removing any other kind is a change gated by §6.3. It goes
  to every server as a delivery (§7.3), so a server that was down catches up before it co-signs
  again. From the moment a server has it, the server MUST refuse every round with the removed
  member and every wait it started. It is never delayed and needs no other approval.
- The removed device gets one last `notice` push ("removed by …"), and keeps its inbox and notices
  for its 7-day window, so an owner whose phone a thief reported first still hears what the thief
  does next. After that its push addresses are dropped.
- The reporting device then refreshes without the removed member (§7.2), which puts it in
  `removed`; the record's gate is the `remove`.
- **Removal is final.** Nobody is put back; a device removed by mistake joins again.
- **Mutual removal.** For 7 days from when each server marked it removed (its own clock), a device
  removed by **another device** may send exactly one message: `remove` naming that device. The
  server then removes both, tells everyone, and drops the remover's refresh if it has not been
  committed (once committed, the next refresh removes both). A device removed in a recovery session
  cannot answer back. Nothing else is accepted from a removed member. So a thief who reports first
  can at most take the owner's device out with it.

### 6.6 Recovery

A round with no device-class member (I4) happens only in a recovery session.

1. The backup holder asks each server for a `challenge` and sends `release_request`, signed by the
   backup key over it. Servers pass it to their peers as a delivery (§7.3), so a server that was
   down starts its own wait and freezes before it co-signs again.
2. Each server starts a wait (`W`, §6.2), tells every member and channel, ends lockless waits and
   freezes lockless requests (§6.2). Any device with its lock, or the requester, can stop it.
3. When its own wait has passed, a server seals the **release bundle** to the backup key: the
   current release key, the current record, and its waited statement (`release`).
4. The holder fetches the backup's current contributions and the wrapped data keys from the
   servers (§7.5), opens them, sums the 2 shares and checks them against the record and each
   part's `sigma·G`.
5. For 7 days after its own wait ended (the **recovery session**), each server takes part, in the
   two-call form (§5.1), in rounds of the backup plus two servers: but only for a recovery join
   (§4.5), group records that add that device or remove members (the `recovery` gate, §6.3), and a
   refresh. Not ordinary events.
6. After the refresh that follows, the recovery app MUST destroy the backup's shares and the
   release bundle; the new backup is under a **new backup key** (§7.5).

So a stolen paper needs two servers that each take part after their wait, with every device told.

### 6.7 Exporting keys

- **The master key is never exported.** A server MUST NOT seal its share to anyone for a `master`
  group, and members MUST NOT offer to combine a master group's shares into an nsec. (Someone
  combining their own shares with their own tools cannot be stopped, and this does not try.)
- **A child key** may be exported in stages: in Core 1.x any child; in a later version only
  children with `origin: import`; then none. Export is `take_out {}` from a device; each server
  seals its share to that device only after a lock and `w`, or `W`, and tells every
  member.
- A server treats a group as a child only if it adopted, first-hand at the group's creation, a
  first record that says `role: child` (Key families module). A record made by migration (§11.2) is
  always `master`.
- An export is permanent: refresh never changes the key.

## 7. Staying current

### 7.1 Repair

Repair (§4.2 step 3) is also how a server or a backup gets shares, and how a member that missed too
many epochs comes back: it is removed and joins again at new indices.

### 7.2 Refresh

A refresh moves every remaining member to a new epoch, same `g`. It runs after any removal, after
the backup is used, and periodically (reference: every 30 days, by any online device, no lock;
servers refuse a periodic one if their epoch is under 25 days old). Servers refuse a periodic plan
from an account's only device unless it carries that device's lock. With no device online nothing happens and nothing is deleted. A server that
has gone quiet is not dropped by a refresh; it is removed first, by a §6.3 change.

1. **Plan.** The device sends `refresh_plan` (§3.4) to every server: the next epoch `{n, id}`, the
   holders (current members minus any removed now), the **dealers** (itself and one named server),
   and its own **dealing**: a random degree-3 polynomial with zero constant term, its commitments,
   and for every holder index a delta sealed to that holder. It also seals a new release key to
   every device and server holder, and a new data key to every device holder. A server MUST check,
   on receipt, that the holders are exactly the current members minus those removed (with a
   valid `remove` or gate for each), and that the plan's epoch is its own plus one.
2. **Dealing.** The named server deals (`refresh_deal`), the same way. No one else deals, and every
   holder sums exactly the named dealers' deltas, so everyone computes the same
   `C' = C + Σ dealers' commitments` (`C'0 = C0`).
3. **Pending.** Each holder checks each delta against **its dealer's** commitments
   (`δ·G == Σ D_k·i^k`). A bad delta is refused with `error bad_delta` naming the dealer and
   carrying the opened delta, to the plan's sender and every server, and shown (§1.1). Servers check
   the claim against the dealer's commitments: a proven claim withdraws the plan; an unproven one
   only marks the claimer as not answering. A holder adds the
   good deltas to its share, keeps the result as **pending**, checks it against `C'`, and sends
   `pending_ok {plan}` with a detached signature to every server. It goes on signing in the current
   epoch.
4. **Backup.** With pending shares, the device and the named server compute the new backup
   contributions and wrapped data keys (§7.5) and store them at every server. Servers check that
   the contributions' `sigma·G` sum to each backup index's `P_b` under `C'`. Because no one can
   open a wrapped part, the dealing device also seals its own backup `sigma`s to **one other
   device** holder (not being removed), which checks each against its `sigma·G` before it sends
   `pending_ok`. (The dealer's part alone says nothing about the backup share without the server's.)
5. **Check and commit.** Once **every device holder** not being removed has sent `pending_ok`
   (they wake by push and check in milliseconds), the named server and at least one other server
   have too (or, after 24 hours, the named server alone), and the backup contributions are
   stored, the device drafts the next record with `C'` and gets it signed by the named server with
   **pending** shares. That signature proves the new shares work and authenticates the record. The
   signed record is the commit; the device sends it to every member (`record`). Members that had
   not yet said `pending_ok` catch up from deliveries (§7.3). A device that never answers holds up
   only this plan, which is dropped at 48 hours (step 7); report it lost if it is gone.
6. **Adopt.** A member adopts the signed record once its pending share verifies against it, then
   destroys its old share (§7.4).
7. **Drop.** A server drops a pending plan if no signed record for it arrives within 48 hours, or
   on `withdraw`, and tells the plan's sender (`error refresh_dropped`).
8. **Removal wins.** A plan that removes members replaces any pending periodic plan (§3.4); every
   server that drops a plan for this reason says so to its sender. A removal never looks finished
   when it is not.

### 7.3 Deliveries kept until acknowledged

Everything a member needs to stay current (refresh deltas, release and data keys, the next record,
repair sigmas, the welcome) is a **delivery**. Every server of the account MUST keep each delivery
for every member, other servers included, until that member sends `ack` for it or is removed, and
MUST hand it over when asked (§8.2). A server MAY cap deliveries at 12 epochs per member
(reference); a member further behind joins again. This closes the stranded-server gap (live
finding #13): a server away for a week catches up from its peers. A server that was offline MUST
fetch its deliveries from its peers before it co-signs again, so it never misses a `remove`,
`cancel` or `withdraw` (which are deliveries to every server).

Deliveries travel **only through server inboxes**, never as copies on relays: anything that carries
a share must not sit in public archives.

### 7.4 Destroying old shares, and storage at rest

- A member MUST destroy its old-epoch share once it adopts the new record. A removed or wiped member MUST destroy everything it holds,
  member key included, with no snapshot, backup, version history or log line that keeps it.
- On phones and desktops, shares and the member key at rest MUST be encrypted under
  a key specific to this membership, kept in platform secure storage (Keychain "this device only",
  Android Keystore, an OS keyring), and shares additionally under a per-epoch key. Destroying means
  **deleting that key** (closes #7 where the platform can delete keys), not only the ciphertext.
- That storage key MUST NOT require the person's face, fingerprint or passcode to use, and signing
  MUST NOT be limited to while the device is unlocked: background signing works as it does with an
  nsec today. (iPhone keeps keys sealed between a restart and the first unlock; that is the
  platform, not a rule.) The lock (§6.1) is a separate key, used only for the guarded actions.
- Where storage keeps history that cannot be turned off (for example 30-day point-in-time
  recovery), only such ciphertext may be stored there, with the key kept outside it.
- On iPhone, shares and keys MUST be excluded from iCloud and restorable backups.
- A browser extension SHOULD encrypt what it stores where that costs no extra prompt (for example
  a key the browser or OS keeps for it), and otherwise stores it plainly in the extension's own
  storage. That is still better than an nsec kept the same way: a copied profile gives 3 points,
  not the key. It MUST NOT register a lock it cannot keep out of that storage.

### 7.5 The backup and the release key

At setup and at every refresh (§7.2 step 4), a device and a server compute the backup's shares by
repair, at the backup's indices, for the new epoch. Each contributing member wraps **only its own
sigmas** twice: first NIP-44 to the backup key, then with XChaCha20-Poly1305 under the new epoch's
release key, and stores them at every server with each `sigma·G` in the clear. The device also
stores the account's data keys, wrapped the same two ways, so a recovery loses no data. All of
this is also a delivery to **every device**, which keeps the current set, so device + paper (and
the escape hatch) still work if every server is gone. No online member can open them, and helpers
and backups do not hold the release key.

**A known-good fallback.** Servers keep the previous epoch's backup contributions, release key and
their own previous share until a device other than the dealer has checked the new backup part
(§7.2 step 4), and use them **only in a recovery session**. A lone device has no one to check its
part, so for it the fallback stays until the next refresh that another device checks. This way a
dealer that wrapped junk (a thief who reported the owner's phone first, say) cannot silently
destroy the paper. Otherwise servers delete the older epoch at adoption.

So helper + paper (3 + 2) cannot sign without a server's wait (I5), and neither can a helper plus
friends holding the backup key. Device + paper still works at once, because the device holds the
release key.

After a recovery, the new backup is under a **new backup key** (added under the `recovery` gate);
the old paper is worthless.

## 8. Push and inbox

### 8.1 Registration

- A device registers with **each** server, per account, by `push_register` (sealed, so signed by its
  member key): `{ "addresses": [ { "cls": "sign" | "ask" | "notice", "url": "…", "p256dh": "…",
  "auth": "…" } ] }`. One address per wake class, never one per header. The newest set, by the
  rumor's `created_at`, replaces the old one. `push_unregister {}` removes them all.
- Each server signs its pushes with its own VAPID key (RFC 8292), the `vapid` key in the record.
  Gateways issue a separate random address per server and per account, pinned to that server's
  VAPID key when the device asks for it, so the address is useless to anyone else and servers
  cannot link one phone's accounts.
- A server drops an address that returns 404 or 410, drops a removed member's addresses, and MUST
  NOT copy addresses to other servers.
- **Notice channels.** A device MAY register `notify_register { "email": "…" } ` or
  `{ "webhook": "https://…" }` with a server, for the account. Servers MAY support them; a server
  that does MUST send every wait notice there too, never content beyond "a change to your account
  is waiting; it completes on <date> unless you stop it". These reach the owner when the only
  device is the stolen one. A lockless request may only **add** a channel; removing or replacing
  one needs a lock or `W`, and the old channel is told.

### 8.2 Sending and the inbox

- Servers send standard Web Push (RFC 8030), encrypted with RFC 8291 `aes128gcm`. The payload is
  JSON `{ "v": 1, "cls": "…", "id": "<request, notice or wait id>", "srv": "<host key>", "wrap":
  <the sealed message, only if it fits>, "sig": "<BIP-340 by the host key over SHA-256(JCS of the
  other fields)>" }`, padded so every encrypted body is the same length and no more than 2,560
  bytes (reference 2,400). A sealed `sign` for an ordinary note is about 3.9 KB, so in practice the
  device fetches; `wrap` is for small notices.
- Anything for a member that may be asleep goes in that server's **inbox** first, and only then is
  pushed. Kind 21059 is used only towards members known to be awake (§9.1).
- `inbox_get {}` returns `{ "items": [ { "iid": "…", "age": <seconds held>, "wrap": {…} } ],
  "waits": [ <every wait running for the account, with its change and end> ] }`;
  `inbox_ack { "iids": […] }` removes them. Items expire with their lifetime class; deliveries
  (§7.3) stay until acknowledged.
- `deposit {to, wrap}` from a current member leaves a sealed message in this server's inbox for
  member `to` and pushes it. Servers accept it only from current members, only to current members,
  and count it against the sender's caps, with its own cap per sender and recipient (reference:
  32 waiting) and its own push budget, never the one `ask` notices use. This is how members reach
  each other when one is asleep.
- **Opening the app MUST fetch every server's inbox**, with no gateway involved. A dead gateway
  slows a device down; it never cuts it off.
- Wait notices go as `ask` pushes from **every** server to **every** member, with the wait id, so
  devices merge the copies.
- Servers MUST cap each account's inbox (reference: 512 items or 4 MB, ordinary notices dropped
  oldest first; deliveries and wait notices never, until their wait ends) and pushes per address (reference: 60 an hour).

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
sealed (kind 13) by the sender's member key and gift-wrapped (NIP-59). The seal's key is the
sender: there is no other sender field.

- **Never on relays.** Anything that carries a share, a release key or a data key (welcome,
  `repair_sigma`, refresh deltas and keys, `release`, `take_out` answers) travels live or through
  server inboxes only, so it never sits in a public archive waiting for a member key to leak.
- **Live** (towards servers, and towards members known to be awake): kind 21059, re-sent until
  answered.
- **Stored** (towards a member that may be asleep): the server's inbox (§8.2). Messages that carry
  no share MAY also go to relays as kind 1059 with a NIP-40 `expiration` at the end of their class.
- A plaintext over 24,000 bytes is split into `{ "type": "part", "of": "<id>", "n": k, "m": total,
  "data": "<base64>" }` rumors, reassembled by `(sender, of)`. Receivers MUST refuse a message over
  512 KB in total and drop parts whose message has expired.
- Errors: `{ "type": "error", "re": "<id>", "code": "…" }`. Unknown `type` → `unsupported`.

### 9.2 Relays and HTTPS

- **Relays MUST** work for everything. Members subscribe on the record's `relays` (SHOULD be 3 or
  more, from different operators) to kinds 1059 and 21059 with `#p` = their member key. A server also listens on the relays in its own announcement, and
  devices always also use each server's announced relays (and HTTPS), whatever the record's
  `relays` say, so a bad relay change cannot cut a server off.
- **HTTPS SHOULD** be offered by servers that can. `POST <https>/keykin/v1` with a JSON array of
  gift wraps addressed to the server; the answer is a JSON array of gift wraps. Same format, so a
  member can switch between the two at any message. An iPhone's notification extension uses HTTPS
  when it is there, because it is faster.

### 9.3 What a server may be made to reach

Members name relays, push addresses, webhooks and HTTPS endpoints. A server MUST NOT connect to
private, loopback, link-local, carrier-grade NAT or cloud-metadata addresses because a member or a
stranger named them; it MUST resolve and check at every connect, MUST NOT follow redirects, and
SHOULD cap new accounts per IP per day (reference 10), messages per account per minute (120) and
request size (512 KB). An open server MAY ask for proof of work (NIP-13) on enrollment.

### 9.4 Messages

| `type` | From → to | § |
|---|---|---|
| `welcome_offer` / `join_hello` / `join_nonce` | inviter → new member / new member → inviter / receiver of the hello → sender | 4.1, 4.2 |
| `welcome` | inviting device (or backup holder) → new member | 4.2, 4.5 |
| `repair_delta` / `repair_sigma` | helper ↔ helper / helper → new member, or into backup storage | 4.2, 7.5 |
| `commit` / `commitments` | coordinator → co-signer / back (two-call form only) | 5.1 |
| `sign` / `partial` | coordinator → co-signer / back | 5.1 |
| `ecdh` / `ecdh_partial` | device → co-signer / back | 5.5 |
| `hold` | device → servers | 5.8 |
| `vouch` | second device → servers | 6.4 |
| `cancel` | device or backup → servers | 6.2 |
| `remove` | device → servers and members | 6.5 |
| `challenge` / `release_request` / `release` | server ↔ backup holder | 6.2, 6.6 |
| `take_out` / `released` | device → servers / back (children only) | 6.7 |
| `refresh_plan` / `refresh_deal` / `pending_ok` / `withdraw` | device → servers / server → members / holder → servers | 7.2 |
| `record` | any member → members (a signed record, the commit) | 7.2 |
| `ack` | member → servers and dealers | 4.2, 7.3 |
| `notice` | server → members | 6.2, 8.2 |
| `push_register` / `push_unregister` / `notify_register` | device → server | 8.1 |
| `inbox_get` / `inbox` / `inbox_ack` / `deposit` | member ↔ server | 8.2 |
| `part`, `error` | anyone | 9.1 |

That is the whole of Core. Cosign 0.12 has 55 message types in `server/core/group.ts`; everything
not here belongs to a module or goes (§11.3).

## 10. Security properties, and their limits

**What holds.**

- One member signs nothing: not a device (3), not a server (1), not the backup (2), not a helper (3).
- All servers together (3) can never sign, and neither can two colluding operators.
- A server can delay or withhold its share and see what it co-signs. It cannot sign, cannot make a
  record, cannot add a member that others believe (live finding #1), cannot read messages
  (decryption answers are useless without a device's own points), and cannot fake a push.
- A joining member trusts only its scan, the group key and the check on both screens (#17).
- A lock is a signature servers check, not a device's word (#4).
- Shares and member keys are destroyed with their keys, and nothing that carries a share is
  published to relays (#7, where the platform can delete keys).
- A gate met at one server is visible to all: a lock, two vouches, or waited statements from two
  servers.
- A stolen paper needs two servers that each waited, with every device and channel told, and the
  owner's paper can cancel waits a lockless thief starts.
- A stolen device is cut off at every honest server the moment it is reported. A thief who reports
  first can only take an honest device down with it.
- Nonces never touch storage and are hedged, so no restore or snapshot replays one.

**What does not, said plainly.**

- **One operator today.** All three live servers are run by one person, so "two servers' waited
  statements" are one party's word until other operators exist. With a stolen paper that one party
  has 4 points.
- **Two stolen devices** (6 points) sign without any server and skip every server rule.
- **A stolen device plus one dishonest server** is 4 points. If the device's shares can be
  extracted, that is the key itself, offline and for good. If not, reporting the device lost stops
  it at every honest server.
- **A stolen device with no lock plus one honest server** can still overwrite lists and the
  profile: the server's rule (§5.8) catches only events that are destructive on their face, and the
  thief is the person as far as the device's policy knows. Mass deletions and vanishing wait;
  single deletions go through after the device's 10-second hold.
- **A single-device account whose phone is stolen without a lock**: the thief can sign everyday
  events until the owner acts, and can complete lockless changes if nobody notices for 3 days. The
  owner's protections are the paper (start a recovery, which freezes lockless changes, or cancel
  the thief's waits) and a notice channel (§8.1). With neither, nothing tells them.
- **Helper plus one server** signs, by design: the person opted in to that.
- **Locks are unattested.** Servers cannot tell a hardware key from a software one, and a tampered
  app can make its own "lock". A passkey that syncs to a cloud account is only as strong as that
  account; implementations SHOULD use device-bound credentials.
- **Browser profiles.** An extension without prompt-free secure storage keeps shares a copied
  profile can carry away (live finding #5). That is 3 points, not the key: better than an nsec in
  the same storage, which is the bar. It never counts as locked.
- **Old epochs.** A removed member keeps whatever old shares and release key it had. Servers delete
  old backup contributions, but if one kept a copy, that plus a removed device's old shares plus a
  later-stolen paper of that epoch would give the key. Paper rotation after removals limits this.
- **iPhone push.** Waking an iPhone needs Apple and the app maker's gateway. The gateway sees when
  each phone is woken and by which servers, not why. If it is down, signing still works when the
  app is opened, from other devices, or through any other Keykin app; notices are what suffer.
- **Membership leaks.** The record is never published, but any member could leak it, and with it
  how many devices and which servers the account has.
- **Imported keys and exports are for ever.** A key that was ever whole (imported, or a child that
  was exported) stays whole wherever it was. Refresh cannot help. Key families move followers; they
  do not fix the leak.
- **The one-call round is not yet formally checked** (§5.1).

### 10.1 Live findings this core closes

| Finding | Closed by |
|---|---|
| #17 joining phone trusts any welcome | §4 (group-signed record, inviter's sigma, the check always shown) |
| #4 lock taken on trust | §6.1, and gate evidence in the record (§6.3) |
| #1 injected member can act | §3 (only kind 30242 records signed by `g`, kinds pinned), §11.2 |
| #7 wipe leaves shares recoverable | §7.4, §9.1 (browsers: see §10) |
| #2 paper added with any key | §6.3, plus the paper's cancel and the freeze (§6.2) |
| #3 report-lost race | §6.5, §6.2 |
| #8, #9 server archive and ECDH oracle | §2 (no history), §5.5 (devices only, weighted) |
| #12 paper promotes itself | §3.3 (kinds never change) |
| #13 stranded server, #14 removal dropped in a pending refresh | §7.3, §3.4, §7.2 step 8 |
| #16a/b optional or partial proofs | §5.5 |
| #5 extension shares unencrypted | encrypted where it costs no prompt (§7.4); otherwise 3 points, not the key, which beats the bar (§10) |
| #10, #11, #15 | Doors and Device policy modules (grants live on devices) |

## 11. Versions, migration, the rename

### 11.1 Versions

- Core follows semantic versioning. Any wire change bumps the major version, which is `v` in every
  rumor, every record and every push payload.
- Unknown fields are ignored. Unknown message types are refused (`unsupported`). Unknown member
  kinds are kept (§3.1).
- Servers SHOULD support versions N and N−1. A device that meets a record or message with a major
  version it does not know MUST refuse to sign and show that it needs an update (§1.1).

### 11.2 Moving a Cosign 0.12 account to Keykin

The group key and the npub stay the same. Cosign 0.12 signs with its own FROST scheme
(`server/frost.ts`, binding tag `cosign/rho`), so servers keep it as version N−1 until every
member has moved.

1. Servers are updated to speak both. Nothing changes for the person yet.
2. A device builds the first record from first-hand facts only: the commitment from its own 3
   points and the group key (§3.3 step 4); a member is kept only if this device ran its repair or
   key generation, or verified a partial from that member's indices against the derived points.
   Agreement among servers counts for nothing. Everyone else joins again. Kinds are as this device
   knows them.
3. The first record is always `role: master`, and is gated by `W` with waited statements from two
   servers, with every device and channel told. Servers refuse one from a member removed under
   0.12, take the first that arrives, and accept a `cancel` signed by any 0.12 device or the 0.12
   paper key. Then a refresh follows at once: new release key,
   data key, backup contributions, and lock keys for devices that have them.
4. Do it first on a throwaway account, with the paper checked, before the main npub.

Accounts that never migrate keep working with servers that still speak Cosign 0.12.

### 11.3 The rename

Readers MUST accept the old names for ever: the record `d` tag `frost` and `cosign`, the server
announcement `d` tag `cosign-server`, `cosign:` codes, and Cosign paper backups (same key format,
same meaning). Writers use the `keykin` names. Kind numbers 24301, 30242, 30243 and 10243 stay
provisional until upstream assigns them.

## 12. Modules (not part of Core)

Each is a short document of its own, and none may weaken anything above.

- **Account admin**: creating a key (DKG, import), adding and removing devices on screen, retire,
  delete (NIP-62 plus destroying shares and forgetting push addresses), the take-out bundle, the
  passkey page on servers for reporting a device lost.
- **Server profile**: the duties as an operator sees them, abuse defaults, the 30-day shutdown
  notice, when to suggest removing a quiet server, announcements (kind 30243/10243), the operator
  notice.
- **Device policy**: the destructive check, Undo from the device's own history, re-confirming
  staged events (a staged replaceable event older than the newest known is destructive), honest
  quiet notices.
- **Doors and grants**: NIP-07, NIP-46 (per-site signer keys, bunker://, auth_url), NIP-55, the
  QRST signer-ticket, the same-device door on iPhone, grants and scopes, the iOS push appendix.
- **Backup**: paper, 24 words, finding servers from the paper, recovery contacts, the escape hatch
  (device + paper or two devices replace dead servers by a record they sign themselves), heir.
- **Helper**: the opt-in.
- **Key families**: claim, accept, release; the challenge window; child groups.

## 13. Open questions

Answered by the user on 2026-11-02 (decision log): passcode-only phones can't cancel a recovery
wait; only replaceable and addressable events may not be dated ahead; single deletions get a
10-second Undo, only mass deletions and wipes are gated; removed devices can't cancel waits; the
6-digit join check is always shown.

For reviewers:

- The one-call round (§5.1) needs a formal check.
- Repair with mixed-weight helpers relies on `frost-core`'s `repairable` module; its behaviour with
  a helper holding 3 indices must be pinned by vectors.
- The 3-days-plus-paper story for a stolen lockless single phone (§10) is the weakest default case.
  Is the notice channel enough, or should the passkey report page move into Core?

## 14. Test vectors (plan)

Done when one vectors file exists, the TypeScript and Kotlin implementations both pass it, and a
fuzzed parser has run against every message. Files, each with positive and negative cases:

1. **FROST round**: one-call `sign`/`partial` for a device (3 indices) plus a server (1), odd and
   even group keys, with odd-y `R`; the two-call form for backup + two servers; a bad partial named;
   a `signers` set that is not exactly the participants; commitments that miss an index or contain
   the identity; a byte-different retry with a reused id; a byte-identical retry.
2. **Nonces**: the same random state with two different requests gives two different nonces, on
   both the co-signer and the coordinator side; DLEQ `k` likewise.
3. **ECDH**: valid weighted answers; missing, extra and repeated indices; wrong `P_i`; no proofs;
   a key with no shares asking two members gets nothing usable.
4. **Record**: valid chain; wrong kind or `d`; tags disagreeing with content; a kind 1 with record
   content refused as a record; wrong signature; skipped epoch; wrong `prev`; commitment not
   rebuildable from a device's points; each of I1–I5 broken; a kind changed; an index re-pointed;
   an unknown kind kept and frozen; two records for one epoch (lower id wins); bad `gate` evidence.
5. **Join**: honest flow in both directions; a racer's hello (check mismatch); a welcome from a
   stranger; a record for another group; one sigma only; the inviter's sigma missing; a sum that
   misses the commitment, with the bad helper named; the check computed from given bytes.
6. **Lock assertions**: valid for each `what`; UV flag missing; wrong `rp`; challenge over a
   different body; replayed across two co-signers for one destructive event (allowed).
7. **Gates and waits** (a lock-replacement after a face reset is lockless; recovery ends it): each row of §6.3, met and not met; waited statements from one server only;
   the paper cancelling a lockless wait; a lockless change during a recovery wait; mutual removal
   inside and after 7 days; a removed member's other messages refused; a helper trying to vouch or
   cancel; `remove` naming a backup refused.
8. **Lifetimes**: each class at, inside and past its lifetime, and a class not allowed for its type;
   30 s ahead; an event 11 minutes ahead refused; a 6-day-old staged draft accepted under `member`.
9. **Stateless destructive rule**: each listed shape, with and without approval or hold.
10. **Refresh**: two dealers; a plan with an extra or missing holder; a second plan refused `busy` (first to arrive holds);
    a bad delta named; a commit with only one `pending_ok` before 24 h refused; a dealing by an
    unnamed member ignored; a removal plan superseding a periodic one; an unproven `bad_delta`;
    commit waiting for every device; the previous-epoch fallback used in recovery; a pending drop after
    48 h; a removal replacing a periodic plan; a member catching up from deliveries after 3 epochs.
11. **Backup**: double wrap and unwrap; helper plus paper refused without release; recovery session
    limits; recovery join; old contributions deleted at adoption.
12. **Push**: payload padding and size limit; signature check; per-class addresses; addresses
    dropped on removal; `deposit` from a non-member refused.
13. **Transport**: chunking and reassembly per sender; a 513 KB message refused; an expired part
    dropped; share-bearing messages never on relays.
14. **Migration**: a Cosign 0.12 group with an injected member is migrated without it; a migration
    record with `role: child` refused.

Interop gate (from the plan): nak, Grimoire, nostr-tools, NDK and Amethyst pass a scripted
sign-in, post, held delete and NIP-44 test against a prototype.

## Changes in draft 2

From red team 1 (all findings taken):

- **C1** paper may cancel lockless waits; a recovery wait freezes lockless changes; notice channels
  (email/webhook) are a core wire item (§6.2, §8.1, §10).
- **C2** records must be kind 30242 with the right `d` and matching tags; every kind 30242 is
  treated as a record by co-signers (§3.3, §5.7).
- **H1** the join check is always shown, both directions (§4.1). **H2** receive keys; share-bearing
  payloads never on relays; the member key under the storage rules (§7.3, §7.4, §9.1). **H3**
  `remove` names devices only (§6.5). **H4** one change at a time, `pending_ok` from every server
  before a commit, a deterministic fork rule (§3.4, §7.2). **H5** two-call round, recovery session
  and recovery join (§5.1, §4.5, §6.6). **H6** migration first-hand only, always `master`, gated
  (§11.2, §6.7). **H7** every deletion and vanish gated; the gap stated (§5.8, §10).
- **M1** gate evidence in the record, waited statements from two servers (§6.3). **M2** weighted
  ECDH answers (§5.5). **M3** hedged nonces for coordinators and DLEQ (§5.2, §5.5). **M4** approval
  bound to the event id (§6.1). **M5** backup contributions from pending shares, before the commit,
  with `sigma·G` (§7.2, §7.5). **M6** old contributions deleted, not on relays (§7.5, §10). **M7**
  per-dealer delta check, `bad_delta` (§7.2). **M8** `welcome_offer` and a full `join_hello` (§4.2).
  **M9** `deposit` (§8.2). **M10** ciphersuite named (§1).
- **L1** check formula and encodings (§4.1). **L2** unknown kinds (§3.1). **L3** server state list
  completed; no core rule depends on a module (§2, §7.2). **L4** backups of 1 or 2, a new key after
  recovery, the secret never kept (§3.2, §4.4, §7.5). **L5** push details (§8). **L6** parts per
  sender, commitment coverage, classes per type (§5.1, §5.6, §9.1). **L7** §10 claims corrected.
  **L8** security displays named (§1.1).

## Changes in draft 3

From red team 2 (`keykin-core-redteam-2.md`), each judged against the bar (an nsec in a password
manager, on security and on ease of use):

- **Dropped:** receive keys (they stranded sleeping devices for almost no gain; share-bearing
  messages simply stay off relays), and the `a`-target deletion clause (it gated deleting one
  article and stopped nothing).
- **Simplified:** waits run on changes, not records, so several can run at once and a wait no
  longer blocks everything else for 3 days (§3.4, §6.2); a refresh names its two dealers and
  commits after two servers' `pending_ok`, or one after 24 hours, so a dead server no longer
  blocks it (§7.2); lock-gated changes need one server's short-wait statement (§6.3); forks re-apply
  the losing change instead of rejoining (§3.4).
- **Fixed:** mutual removal cannot be used against a recovery (§6.5); a `recovery` gate (§6.3);
  the recovery freeze covers every lockless action (§6.2); detached signatures for vouches,
  removals and `pending_ok` (§6.3); vouching asks the person (§1.1, §6.4); a removed device still
  hears for 7 days (§6.5); `remove`/`cancel`/`withdraw` are deliveries (§6.5, §7.3); data keys
  survive a recovery (§7.5); a lone lockless device skips periodic refresh and backup parts are
  checked (§7.2); wait length checked (§6.2); `after` in the two-call round (§5.1); lower plan id
  wins (§3.4); servers' own relays always used (§9.2); both screens confirm a join, removals checked
  at plan time, backup shares destroyed after recovery.

## Changes in draft 4

From red team 3 (`keykin-core-redteam-3.md`), over the whole of draft 3, each judged against the bar:

- **C1** a dealer could wrap junk as the paper's half and lose the account after report-first: a
  second device checks the dealer's backup part, servers keep the previous epoch as a recovery-only
  fallback until it is checked, servers (not apps) refuse a lone device's lockless periodic
  refresh, and a commit waits for every device (§7.2, §7.5).
- **C2** a thief with a locked phone's passcode could reset the face and veto recovery: the freeze
  and the paper's cancel now go by whether the *request* carried a lock, a recovery ends lockless
  waits, and `release_request` is a delivery (§6.2, §6.6).
- **H1** a vouch means typing the new device's 6-digit check, not a tap (§6.4). **H2** a fresh `t`
  after the hello stops grinding the check (§4.1). **H3** wait notices are never dropped, `inbox_get`
  lists running waits, deposits have their own caps (§8.2). **H4** backup material is delivered to
  every device too (§7.5).
- **M1** lock assertions for changes carry no epoch. **M2** fork and draft ties: removals win, then
  first to arrive. **M3** a lockless request can only add a notice channel. **M4** add changes carry
  no indices; the waiting join; the setup backup in the first record; the recovery gate covers the
  new backup. **M5** migration cancel and removed members. **M6** `bad_delta` must be proven. **M7**
  two lockless devices together can cancel.
- **L1** waited statements expire after 7 days. **L2** removed keys never return. **L3** two-call
  checks. **L4** burst rule per server, stated. **L5** `Q` validated; no server coordinates a
  decryption. **L6** kept. **L7** inconsistencies fixed.
