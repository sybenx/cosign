# Keykin Core

Draft 14.25 · 2026-11-05 · `draft` `optional` · not built

Keykin keeps one Nostr key for life without any single device, server or company holding it.
The key is split with FROST into weighted shares: each of the user's devices holds 3, each server
1, a paper backup 2, and signing takes 4. So the device you're using plus any one server signs, two
of your devices sign, and all the servers together never can.

This document is the **core**: the smallest set of rules two independent implementations need to
work together and keep the account safe. That includes **Upkeep** (§6.7): replacing servers, the
helper and the paper, which the user requires to work. Everything a person sees, and every other
optional feature, lives in a module (§12). Sites change nothing: they keep using NIP-07, NIP-46, NIP-55 and
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

**How it got this shape.** Independent red teams kept finding serious problems in the same places,
and the user cut them (decision log, 2026-11-02; reasoning in `simplification.md`):

- every account change needs a biometric lock, a second device with a typed code, or the paper;
- everyday changes (add a device, report one lost, paper recovery) are independent signed approvals,
  safe in any order;
- servers, the helper and the paper sit in fixed seats; replacing one repairs the same share for the
  newcomer, and every replacement and report-lost carries a redeal that kills old pieces (Upkeep,
  §6.7, from the hub's design panel). Nothing needs everyone online;
- there is no in-place move from Cosign 0.12: an account moves by importing its nsec (§11.2).

---

## 1. Terms

- **Group key** `g`: the account's Nostr key (x-only, BIP-340). Its private half never exists whole
  anywhere (§6.8).
- **Ciphersuite**: `FROST-secp256k1-SHA256-TR-v1`, as implemented by the Zcash Foundation's
  `frost-secp256k1-tr` 2.x: RFC 9591's FROST(secp256k1, SHA-256) with the BIP-340 challenge as H2,
  the group key and shares brought to even y at key generation (`into_even_y`), and each signer's
  nonce negated when the group commitment `R` has odd y. Plain RFC 9591 does not interoperate with
  this, and neither does Cosign 0.12's hand-rolled `server/frost.ts` (§11.2).
- **Share**: one FROST share `s_i = f(i)` at a unique index `i ≥ 1`, worth one point. `f` has degree
  3; threshold `t = 4`.
- **Epoch record**: the account's creation record (§3.1). In Core 1.x it never moves: it pins the
  group key, the commitment `C` at creation, the seats and the first members.
- **Seat**: the fixed share indices of a server, the paper or the helper (§3.1). A replacement takes
  over the same seat.
- **Redeal** and **state**: a redeal adds a fresh zero-constant polynomial to every share; a member's
  state is the set of redeals it has applied (§6.7.1).
- **Member**: anything holding shares. It has a **member key** (secp256k1) that seals and
  authenticates its messages. Member kinds:

  | Kind | Shares | What it is | Joins |
  |---|---|---|---|
  | `device` | 3 | An app on hardware the user owns: phone, tablet, desktop app, browser extension. | any time (§4) |
  | `helper` | 3 | A family or friend's always-on box, only on the user's opt-in. | by a `seat` change (§6.7) |
  | `server` | 1 | An always-on service: public, a friend's, or the user's own. | at creation, or by a `seat` change |
  | `backup` | 2 | The paper backup key. Nothing online holds its shares. | at creation, or by a `paper` change |

- **Device-class**: `device` and `helper`. Only these coordinate everyday signing.
- **Change**: a signed, self-contained account change: adding a device, removing a device,
  re-registering a device's lock, and the Upkeep changes `seat`, `paper` and `redeal` (§3.2, §6.7).
  Changes can be applied in any order.
- **Membership**: the epoch record plus every valid change.
- **Lock**: a P-256 key in secure hardware that signs only after a fresh **biometric** match and stops
  working when the enrolled faces or fingerprints change (§6.1). A passcode never counts.
- **Approval**: what an account change needs: a lock, two devices with a typed code, a device with
  the paper, or a paper recovery (§6.2).
- **Wait**: a delay, 3 days (`W`), a Core constant, so the same for every member of an account, which checks waited statements against it, that servers apply on their own clocks to exactly two
  things in the core: a paper recovery (§6.5) and a held mass deletion (§5.8). The Backup module adds an
  heir wait (§6.3).
- **Release seeds**: random 32-byte keys held by devices and seated servers, never by helpers or
  backups, that wrap the backup material's items a second time (§7.2). Every redeal adds one.
- **Data key**: a random 32-byte key held whole by devices only, for reading the account's own
  private data. It can read, never sign, and changes with every redeal (`dk(S)`, §4.5).
- **Request**: any member message that asks for an answer. Each has an `id` (16 random bytes, hex)
  and a lifetime class (§5.6).

### 1.1 Security displays

These are the only things this document requires an app to show, because the protocol's safety
depends on a person seeing them:

1. the 6-digit join check, shown on the side that scanned the code and **typed** by the person on the side
   that showed it, before a join goes ahead (§4.1);
2. the account a device joined, when it joined from a join code (§4.2);
3. a refused epoch record or change, with the member it came from (§3.4);
4. that an update is needed, when a device meets a version it does not know (§11.1);
5. a two-device approval: the first device shows a 6-digit code and the person **types** it on the
   second device; for adding a device, the code is the join check, typed on the second device as the scanning side shows it (§6.2);
6. the paper: before a device forgets the backup secret, the person shows the paper is readable by
   scanning it back or re-entering it (§4.3), unless they declined a paper (on a lockless device it is kept
   until a lock is registered or a paper is read back, §4.3);
7. a new paper: "Keep your old paper until this app says the new one is ready", and only after the
   conflict check, "You can destroy the old paper" (§6.7.6 F7);
8. a device restoring its pieces or catching up seeds by `rerepair`, `need_repair` or `need_seeds`
   ("*Laptop* restored its pieces", with a "Report lost" button), and devices "added by a device you
   removed" (§6.7).

## 2. Who does what

**Devices do the work.** A device coordinates its own signing rounds, judges what is destructive,
asks the person, keeps the account's history and does Undo. When it can, it does anything a server
would.

**Servers do the minimum.** Per account, a server MUST keep only:

1. its share at its current state (§6.7.1);
2. the epoch record and the set of changes, for ever (§3), the current signpost's event id, and after it
   is retired only the change that retired it plus the hashes of the keys allowed to fetch it (§6.7.5);
3. every release seed of its state and the paper release seed (§4.5), and the backup material, seed items included (§7.2), and, servers only, the seed-only items for the current K;
4. running waits (recoveries, holds and heir waits, with an heir's 30-day cooldown) with their notices,
   and recovery sessions (§6);
5. push addresses and notice channels (§8.1), and the inbox, including deliveries kept until
   acknowledged (§7.1);
6. answered request ids until each expires (§5.6), its own counters for §5.8, and every helper stop in
   force (§5.7);
7. if the person opted in, the account's NIP-46 signer public keys, each with its client public key,
   relays and home device, for watching (below);
8. if the person set up an heir (Backup module), the heir record (the envelope, the heir's public key and
   the commitments to the envelope key) and its own piece of the envelope key;
9. the newest version it has verified of each server list its operator configured it to follow, and its own seat keys, enrol secrets and the inert
   uploads for incoming seats (Server profile module);
10. after an account is deleted (Account admin module), only `SHA-256(g)`, the epoch record, the approved
   `account_delete` and the changes that prove its approval (the approving devices' adds and lock changes, and for a
   `paper` approval the change that made that backup key current).

A server MUST NOT keep signed events, list versions, site grants or logs of what it signed. It
co-signs, checks approvals, enforces the two waits and the stateless destructive rule (§5.8), sends
wake-up pushes, and helps with repair (`need_repair`, `rerepair`). That is all.

**Watching for NIP-46 (opt-in).** If the person turns it on for a server (default off), that server
MAY keep a list of the account's NIP-46 signer **public** keys (with each one's client key, relays and
home device), watch those relays for kind 24133 events
addressed to them, keep each one in the inbox of the device that holds the grant (about 2 minutes,
`ask` class), and push that device. It never holds a signer key or a grant, so it can't read the
requests, only see when a site is talking to the account. This is how a sleeping iPhone answers a
borrowed computer or a desktop site.

| | device | helper | server | backup |
|---|---|---|---|---|
| Coordinate everyday signing | yes | yes | no | only in a recovery session (§6.5) |
| Co-sign for others | yes | **no** | yes | no |
| Get decryption answers (§5.5) | yes | no | no | no |
| Approve an account change (§6.2) | with its lock, with a second device, or with the paper | **no** | no | with a device, or in a recovery |
| Cancel a wait | with its lock, or with a second device (an heir wait with neither, Backup module) | **no** | no | no (the holder withdraws its own) |
| Hold the release seeds | yes | no | yes, while seated | after release only |
| Hold the data key | yes | no | no | no |

## 3. Membership

### 3.1 The epoch record

A **kind 30242** event signed by the group key (4 points, so no single member can make one), with
tags `["d","keykin"]`, `["v","1"]` and `["epoch","<number>"]`. Its content is JSON:

```jsonc
{
  "v": 1,
  "g": "<x-only group key, hex>",
  "epoch": { "n": 1, "id": "<16 random bytes, hex>" },
  "prev": null,
  "t": 4,
  "commitment": ["<C0>", "<C1>", "<C2>", "<C3>"],   // 33-byte compressed points, hex, even-y form
  "role": "master",            // or "child" (§6.8); set at creation only
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
  "backup": "<SHA-256 of the backup material's inner layer at creation, §7.2>",
  "seats": { "servers": [4, 7, 8], "backup": [5, 6], "helper": [h1, h2, h3] }
}
```

- `commitment` is the Feldman commitment to `f` at creation: `C_k = a_k·G`, with `C0` the group point,
  which never changes. A member's current commitment is `C_S` (§6.7.1). The point of share `i` is
  always **derived**, `P_i^S = Σ C_S,k·i^k`, and never taken from a message. `backup` and `commitment`
  are creation pins; later papers are pinned by their `paper` change.
- `seats` are fixed at creation and never change. Server and backup seats are the creation indices;
  the helper's are `2^16 + (int(SHA-256("keykin-seat/1" ‖ g ‖ "helper" ‖ j)[0..4], big-endian) mod
  2^30)` for `j = 0, 1, 2`, reserved even when there is no helper.
- `lock` is absent for a member without one. `own` marks a server the user runs; it counts as one of
  the user's devices for privacy, nothing else.
- `removed` only grows, across epochs. A key in it is never a member again, in this epoch or any
  later one.
- **Unknown member kinds** are kept, and a device shows them. For the invariants, an unknown kind's
  shares count towards I2 as if it were a server, and as neither device nor server in I5. A member
  that meets an unknown kind MUST NOT co-sign Upkeep changes until it is updated, but signs everything
  else.

The epoch record and the changes are passed only between members, inside sealed messages (§9).
Members MUST NOT publish them to relays: they name the account's servers and devices.

### 3.2 Changes

A change is a **kind 24302** event signed by the group key, with tags `["v","1"]` and
`["epoch","<epoch id>"]`. Its content is JSON:

```jsonc
{ "v": 1, "g": "<group key>", "epoch": "<epoch id>",
    "change": { "add": { "key": "<member key>", "kind": "device", "lock": { … } | null, "salt": 0 } },  // lock always present
            // or { "remove": "<member key>" }
            // or { "lock": { "member": "<device key>", "replaces": "<old lock pub, or null>", "new": { "pub": "…", "rp": "…" } } }
            // or { "seat": … }, { "paper": … }, { "redeal": … }   (§6.7.2)
  "approval": { /* §6.2 */ } }
```

- Everyday changes: **add a device**, **remove a device** (the helper leaves by a seat change), and **re-register a device's
  lock** (after its face or fingerprint enrollment changed). Upkeep changes: **seat**, **paper** and
  **redeal** (§6.7.2). Relays change with a seat change's new member entries.
- **A device's current lock** is the lock in the epoch record (or in the add that brought it in),
  followed along lock changes: a lock change applies when its `replaces` is the device's current lock
  (`null` when it has none). If two lock changes replace the same lock, both are void and the device
  is lockless until it makes another lock change, which names `replaces: "void:<id of one voided
  change>"`. Two lock changes with the same `new` lock count as one. Lock changes are approved only by `pair` or
  `paper` (§6.2).
- **Indices without coordination.** An added device's three indices are
  `2^16 + (int(SHA-256("keykin-index/1" ‖ g ‖ epoch id ‖ key ‖ salt ‖ j)[0..4], big-endian) mod 2^30)`
  for `j = 0, 1, 2` (`salt` and `j` as 4-byte big-endian integers). The inviting device picks the lowest `salt` whose indices collide with nothing it
  knows, the seats included. If two changes of the epoch ever claim the same index, or add the same key with different salts, every such add is void (an identical add twice counts once), its key goes into `removed`, and the new
  devices join again. Every index, here and in epoch records, is a FROST identifier given as a 32-byte
  big-endian scalar (`frost-core`'s `Identifier::deserialize`), not the 16-bit constructor.
- **Order does not matter.** The membership is the epoch record's members, plus every valid add,
  minus every key in a valid remove or in `removed`. A remove always wins over an add of the same key.
- A change is **valid** when it is signed by `g`, names the current epoch, and its approval names
  `device` members (never a helper) who were in the membership (the epoch record's members or devices
  added by changes of that epoch), with signatures every member verifies. An approver is any key with a
  group-signed add, void or not, and a lock assertion verifies under any lock that device ever had, so
  validity never depends on the order changes arrive in. (The co-signer's one freshness check uses the
  lock current in its view.) A later removal of the approver does not undo it, so every member reaches the same answer
  whatever order changes arrive in.
- **Freshness is the co-signer's job, once.** Only a server co-signing a change checks that its
  approval is fresh: the challenge, the waited statements' age, that the approver is not already
  removed as far as the server knows. Everyone else, later or on joining, checks only the group
  signature, the approver's membership and the structure. (The co-signer's signature is the evidence
  that the check was made.) The window between an approver's removal and the news reaching a server
  is a stated limit (§10).
- **Requests with no co-signer** (`account_delete`, `take_out`, `helper_resume`, removing a notice
  channel) have no such evidence, so **every** receiver checks them itself: a server or device accepts one
  only if each approver is a current device in its own view, after fetching changes from its peers (a peer
  that hasn't answered for an hour is skipped, as in §6.3); and a server takes a peer's `deleted` only from
  a current seat holder. A device keeps re-sending such a request until each server answers; a server
  that never answers is treated as dead after 7 days (§6.7.6 F1).
- Changes never expire. Every server keeps the whole set for ever (about 10 KB a year) and gives it out
  (`changes_get` → `changes`). A member catching up asks **every** server and takes the union, so one
  server leaving out a removal changes nothing. `changes_get` from a removed key always returns the
  change that removed it.

### 3.3 Invariants

The membership is valid only if all of these hold. Servers MUST refuse to co-sign an epoch record or
change that breaks one, and every member MUST refuse to adopt one.

- **I1.** No member holds more than 3 shares.
- **I2.** A server holds exactly one server seat, and each seat has at most one current holder, so
  servers only ever hold the 3 server-seat indices.
- **I3.** The backup holds exactly the backup seat.
- **I4.** A round whose participants include no device-class member is a **recovery round** and
  needs a recovery session (§6.5).
- **I5.** Any set of members that contains no `device` and no `server` is worth less than 4, with
  `backup` shares counted as 0 (they are unreadable until a server releases them after its wait,
  §7.2). One consequence: at most one `helper`.
- **I6.** A helper holds exactly the helper seat. Its member entry names its `host` key, and no host holds
  both the helper seat and a server seat (checked like I2's host rule).
- **I7.** A seat's `new` holder is not a current member key or host and is not in `removed`. A host that
  held a seat before may be seated again, in any seat, with a fresh member key.

Also: each device holds exactly 3 shares; device indices never collide with each other or with a
seat; and there are **exactly 3 server seats**, so one dead server never blocks signing. (Apps add
public servers automatically, alongside any server the person runs.) Because a replacement takes the
same seat and the same share value, no sequence of seat changes can give servers more than 3 distinct
points in any one state.

### 3.4 Checking

A member adopting an **epoch record** MUST check that:

1. it is kind 30242, its `d` tag is `keykin` (or, read-only, `cosign` or `frost`), its `v` and
   `epoch` tags equal the content's, and the signature verifies under `g`, the group key this member
   already knows (from its own creation of the account, or from the code it scanned, §4);
2. it is the account's only epoch record (`prev` is null), the one the member created or was handed at
   join;
3. `C0` is the group point, and for every share it holds, `s_i·G == P_i^S` at its state;
4. **a device, in addition, rebuilds the commitment from first-hand facts**: its own 3 points and
   the group point fix a degree-3 polynomial, so it computes `C_S` from them and refuses any record or
   redeal whose commitments disagree. It does this again after every applied redeal. No member list can
   fool this;
5. the invariants hold, and no key in its `members` is in any `removed` it has seen.

A member taking a **change** MUST check that it is kind 24302, its `v` and `epoch` tags equal the
content's, it is signed by `g`, and it is valid (§3.2, §6.7.2). A refused record or change is shown on
a device (§1.1). A member never signs at a state it has left (§6.7.1).

## 4. Joining

Adding a device uses this handshake. Seating a server or the helper uses the same check and repair
(§6.7). A joining member trusts
nothing it did not get from a code the person scanned, from the group key, or from the join check the person typed (§4.1). (This closes live finding #17.)

### 4.1 The codes and the check

Either side can show the code, so a desktop without a camera can still join.

- A helper's join code adds `h=<host key>`, and its `join_hello` carries the host key's signature over `n`,
  binding the host to the member key (I6).
- **Invite**, shown by a member device: `keykin:join?g=<group key>&m=<inviter member key>&s=<16
  random bytes, base64url>&x=<expiry, unix>&r=<relay>&r=<relay>…`
- **Join code**, shown by the new device: `keykin:hello?n=<new member key>&s=<…>&x=<…>&r=<relay>…`

Codes MAY be carried in a QRST code or an `https` bounce link; the fields are the same. `x` SHOULD be
at most 10 minutes ahead. Readers MUST also accept `cosign:` in place of `keykin:`.

**The check, always.** Anyone who sees a code can race the honest device to answer it, whichever
direction it goes. So after the hello, the side that received it answers with a fresh 16-byte `t`
(`join_nonce`), and both sides compute a 6-digit number,
`int(SHA-256("keykin-join/1" ‖ g ‖ m ‖ n ‖ s ‖ t)[0..8], big-endian) mod 10^6` (keys as 32 raw
bytes, `s` and `t` as 16 raw bytes; in the join-code direction `g` and `m` are those in the
`welcome_offer`). The **side that scanned shows** it, and the person **types** it on the **side that showed the code**,
which is the side someone else could have answered; that side goes on only if it matches. The side that
scanned needs no check of its own: it sealed to the key it scanned, so only that key can answer it.

- **Invite direction:** the new device shows the number and the person types it on the inviting device.
- **Join-code direction:** the inviting device shows the number and the person types it on the new
  device, which then sends `join_confirm {s, t}` sealed to `m`. The inviter starts the add (§4.2 step 2)
  only after a `join_confirm` sealed by `n` with its own `s` and `t`, and the new device takes a
  `welcome` only after it sent one. A helper's setup page (Helper module) takes the typed digits the
  same way.

Safety rests on each side accepting one hello (or offer) per `s` and sealing to the key it scanned: a
racer who answers first ends up in a session for which the honest device shows no number, so the person
has nothing to type. Before it confirms, a new device that gets a second `welcome_offer` for the same `s`
(sealed by another `m`, or naming another `g`) stops and asks for a fresh code, with a new `s` and a new
`n` ("Someone else answered this code. Show a new one."); after its `join_confirm` it ignores further
offers. In the invite direction an inviter that gets a second `join_hello` for its `s` before the check
shows the same message and makes a new invite.

### 4.2 The handshake

1. **Hello.** The side that scanned writes to the other, sealed to the key in the code:
   - invite direction: the new device sends `join_hello {n, s, lock}`: its member key, the secret,
     and its lock public key if it has one;
      - join-code direction: the inviter sends `welcome_offer {g, m, s}`, sealed by `m`, and the new device answers
     `join_hello {n, s, lock}` sealed to `m`. The inviter MUST accept only a `join_hello` sealed by
     the code's `n`, with `n` equal to it; that key, and no other, is the one added.

   A side MUST drop a hello or offer without the right `s`, after `x`, or after it already accepted
   one for this `s`. The receiver of the hello sends `join_nonce {t}`, sealed to the hello's sender;
   that sender MUST accept a `join_nonce` only from the key it sent the hello to.
2. **The change.** After the check (and, in the join-code direction, the `join_confirm`), the inviting device gets the add approved (§6.2: its lock, a
   second device with the typed join check, or the paper) and gets the change co-signed by a server.
   A new member is always a `device`; it never chooses its own kind.
3. **Repair.** At the current state (named in every message), for each new index, the inviting device
   (3 shares) and one server (1) run the repair of
   `frost-core`'s `repairable` module with all 4 shares as helpers: each helper share computes its
   Lagrange-weighted deltas, the helpers exchange them (`repair_delta`), and each sums what it received
   into one `sigma`, sealed to the new device (`repair_sigma`). A server MUST take part only for indices
   that a valid change assigns to that new device. No member ever sees the new share.
4. **Welcome.** The inviting device seals to the new device (`welcome`): the epoch record, the set of
   changes, the relays, the state, every release seed of the state and the paper release seed (§4.5), the backup material (every item,
   §7.2), the base data key and every data-key seed (§4.5), and any kept backup secret (§4.3 step 4).
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
contribution cannot be forged, and a racer's hello or offer leaves the honest side with no number to type (§4.1).

### 4.3 The paper backup

The paper holds a **backup key pair**, not shares: the backup secret, the group key `g`, and the
servers' host keys and relays, so a recovery can start from the paper alone. Its shares exist only
wrapped (§7.2). The read-back (step 4) checks every field. It is made at account creation, or by a
`paper` change (§6.7.6 F7), and it is checked on the device that prints it:

1. The device makes the backup key pair.
2. The device and one server repair the backup seat at the current state; every `repair_sigma` is
   sealed to the backup key. The device, which holds the
   backup secret at this moment, opens them, sums them and checks the shares against `P_i`.
3. The device wraps the shares and the base data key, makes the seed items (§4.5, §7.2), and signs the inner layer with the backup key.
   The epoch record (at creation) or the `paper` change (later) pins the inner layer's hash, so members
   refuse any other copy. A `paper` change commits only together with its material.
4. The device keeps the backup secret, encrypted at rest (§7.3), until the person has printed or saved
   it **and shown it is readable** by scanning it back or re-entering it (§1.1), then destroys it and
   the shares. If the person declines, or leaves the flow unfinished for 24 hours, the device destroys
   them and the account has no paper until a later F7 (Account admin module), **except on a device with no
   lock**: there it keeps them sealed (§7.3) until **any device of the account has a lock** or a paper has
   been read back, so a lockless account can always add a device. While neither exists, **every** lockless
   device holds a sealed copy: the welcome of each new device carries it (step 4 of §4.2), so losing one
   lockless device never traps the other. Each holder is worth 5 points, like an nsec kept in it, and the
   kept secret approves what a `paper` approval would. It is always the **current** backup key's secret: an
   F7 on such an account (friends' pieces with no paper, say) keeps the new key's secret the same way: the
   device that ran it sends `kept_new {secret}`, sealed, to every lockless device as a delivery, only after
   F7 step 5; each accepts it only from a current device, and only if the secret's public key is the
   current backup key, then replaces its copy.
   A lock counts as registered once a lock change is co-signed, or once a device added with a lock has had
   its add co-signed **and** acknowledged its welcome (§4.2 step 5). Then, or when a paper is read back,
   the device that sees it sends `kept_done {}` (naming that change, or the read-back; a lock change only
   once it is valid) to every device as a delivery; holders take it only from a current device and, for a lock, only after checking the named
   change, and destroy their copies. The app then suggests, quietly, a new paper, since a copy taken
   earlier keeps paper power until the backup key is replaced. It SHOULD prompt, quietly, to finish the
   backup.

After that, each redeal appends a **paper delta** for it (§7.2), so a paper reaches every later state
without being reprinted.

### 4.4 Recovery join

In a recovery session (§6.5), the new device joins with the backup holder's app in place of the
inviting device: the repair helpers are the backup (2) and two servers (1 + 1), the welcome is sealed
by the backup key, and step 5 requires sigmas from the backup and both servers.

### 4.5 The data key

A random 32-byte key, never derived from the group key or any to-self conversation key and never
published. Devices hold it whole, in storage that is never backed up or synced (on iPhone, never in
iCloud Keychain or a restorable backup). Helpers, servers and backups never get it, except that a copy
is in the backup material, so a recovery loses no data (§7.2). It is
`dk(S) = HKDF("keykin-dk/1", base data key ‖ seeds of S, sorted)` (HKDF-SHA256, empty salt, the
string as info, 32 bytes; the same for the signpost's device-copy key): every redeal brings a new seed (sent
to devices only, §6.7.3), so it rotates with every redeal, and a removed device never gets a later seed.
Data names the state hash it was written under; devices keep older keys to read older data, and data services re-encrypt lazily.

- **Every seed is kept.** A device keeps, for the account's life, the seed of every co-signed redeal it
  ever received, **abandoned and stranded ones included**: a device whose state once held an abandoned id
  (§6.7.1) wrote data under that state, and that data stays readable only with its seed. Welcomes,
  handovers and `need_seeds` carry all of them, each as `{id, seed}` and checked against its change's `dk`.
- **The paper carries them too.** Beside the base item, **seed items** hold every seed the printing device holds, abandoned and stranded
  ones included, and the `paper` change lists their ids in the clear (`seeds`, §6.7.2, §7.2). Before F7
  step 3 the device asks for any it lacks by `need_seeds`, waiting at most an hour, checks each against
  its change's `dk`, and, while it still holds K, opens its own seed items and checks every listed seed
  again. Seeds it couldn't get come from other devices' re-issues. Later redeals' seeds come in their paper items.
- **Seed-only re-issue.** For every seed it holds, every device re-issues it to each new K (and each seed it receives later), whatever the paper's `seeds` says, so one faulty printer can't be the only copy, in **seed-only items**: up to 1,000 of the seed items' binary records each, NIP-44 to K from a fresh ephemeral key (its
  public key in the clear), signed by the device, wrapped under the release seed of the redeal that
  travelled with K's `paper` change (the creation release seed for a creation paper) and naming it. It
  sends it to the servers (`paper_reissue`, signed as `detached("paper-reissue-seed", …)`), once per redeal and K, re-sending it until two servers (or every live server, when fewer than two are live) confirm it by hash (a server that hasn't yet seen the redeal refuses at first). A device sends one batch per K plus one per later seed, so the cost is a few kilobytes per device per paper, and it needs no bookkeeping: abandoned, stranded and late seeds are all covered. A device stops sending to a K once it is no longer current, and servers drop a K's seed-only items once it is in `removed`. The item says it is seed-only; servers accept one only for a co-signed redeal and the current K, from a current device, keep each distinct one from a device for that K, up to 64 per device and K (a device sends one batch per K plus one per later seed), keep them after that device is removed, and pass it to their peers and to
  incoming seat holders like other items (§7.1). Because every holder of a seed sends its own, one bad
  device can't be the only copy, and nobody needs to check them: the holder keeps any whose seed matches
  the change's `dk`.
- **The paper release seed is never lost.** The **paper release seed** is the release seed of the redeal
  that travelled with the current paper's `paper` change, or the creation release seed for a creation
  paper. While K is current, every server and device keeps it, even if that redeal is stranded or
  abandoned; every welcome (§4.2, §6.7.4), handover (§4.6) and `need_seeds` answer carries it, to servers
  and devices; and every release bundle (§6.5 step 3) carries it. It wraps the base item, the seed items and every
  seed-only item for K.
- **Apps never see `dk(S)`.** The device API gives an app `dataKeys.derive(ids, info)`, which returns
  `HKDF-SHA256(salt = empty, ikm = dk(S), info, L = 32)` for the state `S` named by the sorted redeal-id
  list `ids`, any list whose seeds this device holds (not only states it was in); it refuses if it lacks a seed (core's own catch-up fetches missing seeds, once per gap), and refuses a list that isn't a state: every id must be a co-signed redeal whose `base` is inside the list, and no id may sit beside a redeal that abandons it. It never sends `need_seeds` for an app. `info` is `utf8(domain) ‖ 0x00 ‖ the app's bytes`, with `domain` an identity, listed or open domain for that app (app-private data, below; §5.9), so no app can derive a key Core or a module uses (theirs all start with `keykin`), except the `open` vault domains, which apps and the member share by design (Doors and grants §3.7). Also `dataKeys.current()` (`{ids, state}`),
  `dataKeys.states()` (every state this device has held, newest first) and `dataKeys.onRotate(cb)`
  (called once a redeal has applied here).
- **App-private data.** NIP-44 to the account's own key is a shared pool: any site or app granted
  `private-data` (Doors and grants) reads all of it, as with a pasted nsec, and other apps rely on that
  pool to interoperate. An app that wants records other apps can't read keeps them under a key from
  `dataKeys.derive` on its own domain instead (as Keykin's own grant events, device names and policy
  history already do with `keykin-…` keys). Those records are not to-self ciphertexts, so no door, scope
  or decrypt opens them.
  - **Who can read them:** an app granted that domain, and the account's member devices themselves (any
    current device, a paper recovery, and a removed device for records sealed before its removal). After
    a removal, records stay out of the removed device's reach only once they are re-sealed after the
    redeal. The open `nostr-vault/…` domains (§5.9) are shared by every vault app and isolate nothing.
  - **Rotation.** The app names the state in each record, re-seals when `onRotate` fires and, since that
    only fires while it runs, compares `dataKeys.current()` at every start. Every device derives the same
    key for a state, so two devices re-sealing at once write equivalent records; the newest version wins as
    for any record.
  - **Which domain.** An app whose identity the OS proves owns, silently and with no list or question, its **identity domain**:
    a first segment of exactly `id-<lowercase hex SHA-256 of utf8(identity)>`, for derivation only, never
    signatures. The identity is `android:<package>:<original signing-certificate SHA-256>` (the first
    certificate of a v3 rotation lineage; the device checks the package is among the calling uid's
    packages) or `apple:<team id>:<signing identifier>`, only when the caller's audit token satisfies the code
    requirement `anchor apple generic and certificate leaf[subject.OU] = "<team id>" and identifier
    "<signing identifier>"` (Developer ID or Mac App Store signing) and the build runs with the hardened
    runtime and without `get-task-allow`, `allow-dyld-environment-variables` or
    `disable-library-validation`. On a desktop this keeps an app's records from sites and from other apps' grants, not
    from local software running as the person, which can already read the app's storage or drive it
    (§10); an app that runs code from outside its signature (an Electron app with its run-as-node and
    inspect fuses on, a plugin host) can't keep even that. An APK signed by several certificates gets none. A rotated-out Android key keeps access
    to its records, as it would to the app itself. Browser extensions get no identity domain and may derive only under open domains (§5.9), since an extension's id differs across browsers and copies by its manifest key; Linux and Windows programs get none, since the OS can't prove them; both use the pool or open domains. Records are readable by that build on every device of
    that platform; builds signed differently (a store build and an F-Droid build) are different apps.
    To share records across platforms, an app uses a domain an app list gives to all its builds.
    `dataKeys.derive` is allowed only under the app's identity domain, a domain a followed list gives it,
    or an open domain; never under a domain granted by hand otherwise. Programs the OS can't identify (a
    per-grant secret on Linux or Windows) get no identity domain and use the pool.
  - **Where it works.** The device API is reached on Android through the member app's bound service
    (the caller's signing certificate identifies it), on desktops through native messaging or a local
    socket, and in browsers through extension messaging (§5.9). iOS apps other than the member app, and
    websites, have no device API: they reach the account only through a door, and use the pool. So does
    any app on a signer that isn't Keykin.
  - **Leaving.** Before an account leaves Keykin (§6.8) or the app moves to another signer, the app copies
    the records it wants to keep into the pool, or loses them.

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
  If it finds the app, it does not join; if it already is the member, it **hands its membership over**,
  after finishing or abandoning any round, join, pair session or hold it has in flight:
  1. It passes **everything a `welcome` carries** (§4.2 step 4) to the app over native messaging: the
     member key and shares, the state, the epoch record and the set of changes, every release seed, the
     backup material, the base data key and every data-key seed, any backup secret it kept (§4.3 step 4),
     plus its site grants and its history.
  2. The app stores all of it durably, reloads it from storage, runs the full checks of §3.4 on the
     epoch record and changes, checks that the member key is a current device holding exactly those
     indices and that `s_i·G == P_i` for every share, registers its own push addresses (replacing the
     extension's), and only then confirms.
  3. The extension then destroys its copy and becomes a relay.

  The membership doesn't change: same member key, same indices, same state. So nothing in the account
  changes, no approval and no redeal are needed. During a handover the extension acknowledges nothing,
  and abandons any redeal it dealt that is not yet co-signed. A copy that survives the handover (a crash between steps 2 and 3, a profile
  restored from a backup) is the same 3 shares twice, not 6 points. An app holds **one membership per
  account** and refuses a second handover for an account it already serves.
- **Retiring an extension.** When an extension that holds a membership finds the app, it first asks the app to sign a fresh challenge with the member key it claims (as `SHA-256("keykin-retire/1" ‖ g ‖ challenge)`) and to re-run the share check. An app
  reports only a membership that passed handover step 2 or join step 5 (§4.2). Then it compares:
  - if the app holds the **same** member key for the same `g`, the extension's copy is a leftover:
    it just deletes it locally and sends nothing;
  - if the app holds a **different** member key for the same `g` that is a current device in the
    extension's own view (the app joined separately, so the laptop is two members), the extension
    removes itself (§6.4), and destroys its copy once a server has acknowledged the `remove`;
  - if the extension's own key is already removed, it destroys its copy; if the app holds a removed
    key, the app drops it and the extension hands over;
  - if the app serves no membership for this `g`, the extension hands over as above.

  An extension never removes itself in any other case, nor while it is inviting the app to join, so it
  can never remove the machine's only member. An app that is asked to take a handover again for the
  same member key accepts it as a retry.
- A lock belongs to the member app (Touch ID through the Secure Enclave). A handed-over membership has
  no lock until the app registers one by a lock change (§3.2), which a handed-over kept backup secret may
  approve as a paper would.

Native messaging is not authenticated against other local software: a program running as the person
could register a fake host and receive the extension's shares at handover, or see the requests it
relays. Such a program can already read the extension's own storage (§7.3), so this adds nothing a
local thief doesn't already have; §10 says so.

## 5. Signing

### 5.1 The round

**Two parties: one call.** The coordinator (a device-class member)
sends `sign` to one co-signer:

```jsonc
{ "type": "sign", "epoch": "<epoch id>", "state": "<SHA-256 of sorted redeal ids>", "event": { /* the full unsigned event, pubkey = g */ },
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
signature on the event id, and publishes. It MUST check each partial against `P_i^S` derived from the
named state's commitment (`verify_signature_share`) and name the member whose partial fails. All
shares in one round are of the state the request names; a co-signer at another state answers `stale
{ids}` (§6.7.1).

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
- **Hedged randomness.** The hedge is `SHA-256(fresh OS randomness ‖ share ‖ context)`, where context is,
  for a co-signer, the SHA-256 of the request ‖ the event's position in the request (4 bytes); and for a
  coordinator, `event id ‖ signers ‖ request id ‖ co-signer key`. It seeds a stream: the random input to the `k`-th call of `nonce_generate` (FROST calls it
  twice per index, for the hiding and the binding nonce) is `SHA-256(hedge ‖ k)`, `k` a 4-byte big-endian
  counter from 0, so the two nonces never coincide.
- **One nonce pair signs one event.** A member MUST NOT use a nonce pair for more than one event, in any
  request: a list's events each get their own (§6.7.10).
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
`ecdh {epoch, state, points: [Q…], signers}` to a co-signer, where `signers` is its own indices plus the
co-signer's and is worth 4 (checked as in §5.7 item 2). Every `Q` MUST be a valid point other than the
identity. For **each** of its indices `i` and each `Q`, the co-signer answers `ecdh_partial` with the
weighted value `Y = λ_i·s_i·Q` (`λ_i` the Lagrange coefficient of `i` in `signers`) and a proof that
`Y` and `λ_i·P_i` share a discrete log:

```
k = H("keykin/ecdh-k/1" ‖ fresh OS randomness ‖ s_i ‖ Q ‖ SHA-256(request)) mod n
R1 = k·G;  R2 = k·Q;  W_i = λ_i·P_i
e = H("keykin/ecdh-dleq/1" ‖ g ‖ epoch id ‖ state ‖ i ‖ W_i ‖ Q ‖ Y ‖ R1 ‖ R2) mod n
z = k + e·λ_i·s_i       verify: z·G == R1 + e·W_i  and  z·Q == R2 + e·Y
```

(`H` is SHA-256; points 33-byte compressed, integers 4-byte big-endian, scalars 32 bytes.) The answer is
`ecdh_partial {answers}`, where `answers[q]` lists, for the `q`-th point, one `{i, Y, R1, R2, z}` per index
of the co-signer.

- Because the answer is weighted for a set that includes the asker's indices, it is useless unless the
  asker adds its own 3 points' worth. A member key with no shares learns nothing.
- The coordinator MUST refuse an answer unless its indices equal that member's indices exactly (none
  missing, none extra, no repeats) and every proof verifies with `P_i^S` derived from the state's
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

Types not in the table: deliveries and requests a sender repeats until answered (`cancel`, `withdraw`,
`upload`, `upload_held`, `push_register`, `push_unregister`, `notify_register`, `paper_reissue`, `reissue_eph`,
`helper_stop`, `helper_resume`, `account_delete`, `stop_relay`, `kept_done`, `kept_new`, `repair_ok`) are
`member`; every other request (`changes_get`, `inbox_get`, `need_repair`, `rerepair`, `need_seeds`,
`state_get`, `state`, `seated?`, `forward_get`, `reissue_get`, `take_out`, `pair_request`, `pair_sign`) is `ask`.

- A receiver measures age with its own clock from the rumor's `created_at` (when the request was sent),
  or from the inbox's `age` (§8.2) if that is larger. It MUST refuse a request older than its lifetime
  plus 30 s, or dated more than 30 s ahead.
- The **event's** `created_at` (when the person wrote it) never decides whether a request is fresh. A
  draft written offline waits in the device's outbox, keeps its time (except a replaceable draft that
  Device policy rebases with a fresh time), and is signed with a fresh `sign` request when the device is
  online again.
- A receiver MUST remember `(sender, id)` until the request's lifetime has passed, and treat a second
  request with it by §5.3. Servers MUST keep these across restarts. A server MAY cap them per member
  (reference: 10,000), refusing new requests from that member when full rather than forgetting old ids.

### 5.7 What every co-signer checks

Before giving a partial, a co-signer MUST check that:

1. the sender is a member of the current membership and may coordinate (§2);
2. `signers` is exactly the sender's indices plus this co-signer's (plus, in the two-call form, the
   other co-signers'), is worth at least 4, all at the named state, and the commitments cover it
   exactly (§5.1);
3. the request is fresh and not a replay (§5.6);
4. `event.pubkey` is `g`, and, for a **replaceable or addressable** kind (0, 3, 10000–19999,
   30000–39999), the event's `created_at` is no more than 10 minutes ahead of its own clock: a version
   dated ahead would block every later change until that date. A deletion (kind 5) may not be dated
   ahead either (the same 10 minutes), since under NIP-09 it would delete future versions of its targets. Other kinds may be
   dated ahead, so a person can schedule a post;
5. if the event is **kind 30242 or kind 24302, whatever its tags, or a kind 30078 with the account's
   signpost `d`, or a kind 5 targeting a signpost**, it is account machinery: it MUST be a valid change
   (§3.2, §6.7.2) or a signpost from a device with the right `n` (§6.7.5); a signpost delete is always
   refused; and a device MUST never sign
   one on a site's request (an epoch record is made only at creation);
6. if the round is a recovery round (I4), the recovery session's rules are met (§6.5);
7. the stateless destructive rule (§5.8);
8. if the coordinator is the **helper**: the helper is not stopped (below), and the event is one of kind 1
   (notes and replies), 1111 (comments), 7 (reactions), 6 and 16 (reposts), 9734 (zap requests), 20, 21
   and 22 (media posts) or 22242 (relay auth), dated no more than 10 minutes ahead (a helper never needs
   future dates; scheduled posts are signed by devices). Anything else is refused. (Servers can't see the account's
   relay lists, so the helper's relay sign-in isn't limited here; the Helper module says so.) A helper never co-signs, and a
   device never co-signs a round the helper coordinates, so every helper round has a server in it.

**Stopping the helper.** Any current device may send `helper_stop {id, by}`, with a fresh 16-byte `id`
and naming the stopping device, with no approval, as a delivery to every server: it only takes power away.
It stops **the helper seat**, whoever holds it. A server that has any stop in force refuses every round
the helper coordinates or takes part in.
- **Stops are account state, not requests.** A server keeps every stop in force for as long as it is in
  force (core §2 item 6), and every **cleared** stop id too, carries both in seat holders' welcomes, and
  passes them to its peers with `stop_relay {stop, by}` (each peer checks `by` against its own view); they never expire. A stop whose id is cleared never comes back in force.
  Devices re-send stops to every incoming seat holder, and are told about resumes. Servers list the stop
  ids in force (in `inbox_get`'s answer) to current devices, so any device can resume a stop another device
  sent. Cleared ids are kept for a year. A member may have at
  most 3 stops in force; beyond that a server answers "already stopped".
- **Only a named clear ends a stop.** `helper_resume {ids}`, with an approval (`lock`, `pair` or `paper`,
  checked by every receiver as in §3.2; for `paper`, with a challenge from every server, as for
  `account_delete`), clears exactly the stop ids it names; a **helper seat** change
  clears only the stop ids it names in `clears_stops: [ids]`. A stop the resuming device hadn't seen stays
  in force. No other seat change touches a stop. So a late or missed message can only leave the helper
  stopped, never running.
- A device shows "Stopped" only once a server confirms it, and the helper is told.
- A stopped helper still receives redeals; only removing it cuts its pieces off.
- Before co-signing a helper round, a server fetches its peers' deliveries (at most every 10 minutes), so a
  stop sent to one server reaches the others.

A device co-signing for another device-class member also applies its own destructive policy (Device
policy module) and refuses when that says to; it never prompts, because nobody may be looking at it.

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
- kind 0 whose content has no non-empty `name`, `display_name`, `about` or `picture`;
- kind 3, 10000–10030 or 30000–30030 with no tags other than `d` **and an empty `content`** (the zero-length string; whitespace or `{}` is not
  empty);
- kind 10002 with no `r` tag whose value starts with `wss://` or `ws://` (byte-exact, case-sensitive);
- a key-family event of any kind: family, release, leaked or accept (kinds 1244–1247, Key families module;
  a site never gets one signed). These kinds are provisional and MUST be pinned before Core 1.0; if the NIP
  assigns others, this list changes in a minor version before families are enabled.

These tests are exact: kind 0's content is parsed as a JSON object, and content that isn't one, or has a
duplicate key, counts as empty; a field is non-empty only if it is a string with a non-whitespace
character. A tag counts only if it has at least two elements, empty strings included (`[]` and `["r"]` count as no
tag at all; `["p",""]` counts),
and a kind 5's targets are its distinct (`e` or `a`, value) pairs. §9.5 gives the parse rules and the
whitespace set.

**Holding** is a wait (§6.3) on `{"hold": <event id>}`: the device sends `hold {event}`; servers start a
wait and tell every member and channel; after `W` the device sends `sign` with `hold: <wait id>` and a
server co-signs if its own wait passed and nobody cancelled. A server keeps at most 10 holds per device
at a time (reference).

A single deletion needs neither: the device holds it for 10 seconds with Undo (Device policy module) and
then signs it like any event.

This is a backstop, and it is easy to step around for lists: a follow list cut to one junk entry is not
empty. The device is the real gate, and its policy holds far more. What that leaves open is in §10.

### 5.9 Member-key signatures for apps

Apps built on a Keykin account sometimes need a device to vouch for something with its own member key
(the encrypted-sync spec's `ksig`, for one). Core allows exactly one form, so no such signature can ever
be read as one Core makes, and no Core flow can be made to produce one.

- **Form.** `sig = BIP-340(member key, SHA-256(utf8(domain) ‖ 0x00 ‖ message))`, by the device's own
  member key, never the account key. `domain` is at most 128 bytes and matches
  `[a-z0-9][a-z0-9.-]*(/[a-z0-9.-]+)*/(0|[1-9][0-9]*)` (lowercase segments ending in a version, as
  `nostr-vault/ksig/1`); the `0x00` ends it. `message` is the app's bytes, at most 65,536. A member key
  belongs to one account (§4.6), so `g` is not in the digest. The device hashes the message itself; it
  never signs a digest an app hands it (§5.4). The vectors are `vectors/membersig.json`.
- **Reserved, and how Core signs.** A domain that starts with `keykin` or `cosign` belongs to Core, its modules and Cosign 0.12, and a device refuses it for an app. A domain whose first segment starts with `id-` is an identity domain (§4.5): a device allows it, for `dataKeys.derive` only, to the app whose identity it hashes, refuses any malformed one, and no list or hand grant can give it. A browser extension may derive only under open domains, whatever a list says. Every member-key signature Core and its modules make for themselves is a Nostr event id (a seal, §9.1, whose preimage starts with `[`) or `SHA-256` over a `keykin-…/1` tag followed by fixed fields: `detached(type, body)` (§6.2),
  `keykin-self/1` (§6.4), Doors' `keykin-grant/1` and `keykin-grant-set/1`, and the three challenge
  signatures (`keykin-retire/1`, §4.6; `keykin-seated-ask/1` and `keykin-forward-ask/1`, §6.7.5). The
  other items "signed by a member key" are `detached` with these types, hyphens and all, over the item as sent without its signature: `paper-reissue` and `paper-reissue-seed` (§6.7.6, §4.5), `policy-snapshot` (Device policy) and `label` (Account admin's device names). A member key never signs raw bytes a server, site or app chose. When the member itself acts as an app (Doors' vaults, §3.7), it signs under the app's domain like any app, and the app lists it follows name it for those domains. The reserved prefixes are the guarantee: every Core preimage starts with `keykin` or `[`, which no app domain may, and the `0x00` that ends a domain keeps two apps' preimages apart.
- **Who may ask.** A domain is granted to an app, not claimed by it. An **app list** is a signed list,
  published like a server list (§6.7.7) and versioned on its own, that names domains and the app
  identities that may use each. Any app maker or community may publish one, and no list is special. A device follows the app lists its
  app pins and any the person adds, with a warning. A domain named by any list it follows goes only to an
  app that **every** followed list naming that domain allows, and is `open` only if every such list marks
  it open. A list the person added may not name a domain or segment that a pinned list names; such entries
  are ignored. So adding a list can only narrow, never widen, what a pinned list allows. An entry may name a whole first segment (`nostr-vault`), covering every domain whose first `/`-separated segment is exactly that, for signatures (§5.9) and data-key derivation (§4.5) alike. A device signs only for a listed app on its own machine, under the device API, and
  checks the identity the way the OS can prove it: an Android signing-certificate digest, an Apple team id checked against the caller's audit token with the code requirement and hardened-runtime rule of §4.5, a browser's own extension id. A person may also grant an app a domain by
  hand, for signatures only (`dataKeys.derive` needs an identity domain, a domain a followed list gives that app, or an open domain, §4.5), with one question naming the app and the domain ("Let Notes sign for `notes.example/sig/1`?"),
  but **never a domain a followed list names**, unless it is `open` (above) (lists for vault apps mark `nostr-vault/ksig/1`, `nostr-vault/owner/1` and `nostr-vault/keyring/1`; `open` is per domain, never for a whole segment; a hand grant of an open domain covers both signatures and `dataKeys.derive` under it, and the question says so): an open domain may be granted by hand to any app, with the lists' wording for the question ("Let *Notes* use all your vaults, in every app, on this device?"). Other listed domains go only to the apps allowed above, and the device checks the current lists on every call, so a hand grant ends once a followed list names its domain. Where the OS can't prove
  the caller (native messaging and local sockets on Linux or Windows), the grant comes with a per-grant
  secret the app keeps in its own storage and presents on every call. Never through a door (NIP-07,
  NIP-46, NIP-55): a site can't ask. Signing itself needs no prompt, and the device logs each use.
- **Only devices.** Servers and the helper hold member keys too (Server profile derives a seat's), so
  they never sign here and never appear below.
- **What a verifier needs.** The device API also gives an app:
  - `members.devices()`: `{self, asOf, keys}`, the current **device** member keys from this device's view
    (the epoch record and changes in force), this device's own key, the `state` it is at (§5.1's hash of
    the sorted redeal ids), and for each key `added_by` and `flagged` (§6.7.6 F5's "added by a device you removed"; a flagged key is current, but an app SHOULD treat it as removed for an allowlist until the person keeps it, which the Keykin app records with `members.keep(key)`);
  - `members.removed(since)`: a durable log, kept for the account's life, of `{key, why, change, state}`
    for every key that leaves the device set here, `why` being `remove`, `self` or `void` (§3.2's
    conflicting adds), and `state` `null` until that change's redeal has applied, then the post-redeal
    hash. `members.onRemoved` is called for each new or updated entry, and also when a key is flagged.
    An entry appears as soon as the key is out, so an app can revoke at once, and again with `state` when
    the redeal lands. An app that was not running reads the log on its next start.

  A member-key signature proves only that the key signed, not when: a removed device's key can still
  sign. Whether a key counts is the verifier's check against `devices()` now; an app that needs to know
  when can put the signer's `state` in `message`. On a platform where the OS can't prove the caller, a
  local program that steals an app's grant secret signs as that app (§10).

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
second device or the paper.

A **lock assertion** has one encoding everywhere, WebAuthn's structure:
`{ "authData": "<b64url>", "clientData": "<b64url of JSON>", "sig": "<b64url DER>" }`.

A verifier MUST check that `clientData.type` is `"webauthn.get"`; that `clientData.challenge` is
`base64url(SHA-256("keykin-lock/1" ‖ g ‖ what))`; that `authData` starts with the member's `rp` and has
the user-present and user-verified flags set; and that `sig` verifies over
`authData ‖ SHA-256(clientData)` with the member's `pub`. `what` is:

- for a destructive event, `"sign" ‖ event id` (§5.8);
- for an account change, `"change" ‖ list hash ‖ epoch id ‖ expiry`, where the list hash is
  `SHA-256(JCS(list))` as §6.7.2 defines it (a single change is a list of one), with the expiry (8-byte
  big-endian unix seconds) at most 24 hours away;
- for a cancel, `"cancel" ‖ wait id`;
- for any other request (`take_out`, `account_delete`, removing a notice channel), `type ‖ id ‖ SHA-256(JCS(body
  without the assertion))`.

A `pair` signs the same string as a lock would for that request.

A `paper` approval's backup signature covers the change hash and a challenge from the server it is
sent to; only that server checks the challenge (§3.2).

Native apps build the same structure themselves. Servers cannot tell that a lock is in hardware or
biometric-only (no attestation is required); that is a stated limit (§10), not a check.

### 6.2 Approvals

An account change (a change of §3.2 or a list of them, §6.7.2; an export) is approved by exactly one of these, carried
in its `approval`. Signed items carry **detached** BIP-340 signatures by the signer's member key over
`SHA-256("keykin-<type>/1" ‖ g ‖ JCS(body))`, because a NIP-59 seal proves nothing to a third party.

Every approval of a change also carries `"expiry": <unix>`, the expiry in the lock's `what` (§6.1), shared
by `lock`, `pair` and `paper`; `detached(type, body)` below means a BIP-340 signature over
`SHA-256("keykin-<type>/1" ‖ g ‖ JCS(body))`.

- **`lock`**: `{ "member": <key>, "assertion": … }`, the asking device's lock (§6.1).
- **`pair`**: `[ { "member": <key>, "sig": … }, { "member": <key>, "code_sig": … } ]` from two distinct
  devices, each after asking its person (§1.1). The first device shows a 6-digit code,
  `int(SHA-256("keykin-pair/1" ‖ g ‖ change hash ‖ r)[0..8]) mod 10^6` with a fresh 16-byte `r` it sends
  along; the person **types** it on the second device, which signs only if it matches. For adding a device, the code is the join check (§4.1), as the side that scanned shows it: the inviting device sends the second device `{n, s, t}` (with `r` = `t`) so it can compute the check, and both signatures still cover `what`, which binds the change hash. Two devices are 6 points, already
  the key, but the typed code proves the person can see both. `r` travels in the first entry
  (`{member, sig, r}`); the code itself never travels. Both `sig` and `code_sig` are
  `detached("pair", {"what": hex(what), "r": r})`, with `what` as a lock would sign it (§6.1). A `cancel`
  by two devices uses the same encoding.
- **`paper`**: `{ "member": <device key>, "sig": …, "backup": <backup key>, "challenge": …, "server":
  <host key>, "backup_sig": … }`: a device together with the paper, the backup key signing the change hash
  over a fresh `challenge` from the named server. `sig` is `detached("paper", {"what": hex(what)})` by the
  device; `backup_sig` is `detached("paper", {"list": list hash, "challenge": challenge})` by the backup
  key, or, for a request that isn't a list (`take_out`, `account_delete`, a notice channel), `detached("paper",
  {"what": hex(what), "challenge": challenge})`. A request with no co-signer that every server checks
  (`account_delete`, `helper_resume`) carries `"challenges": [{server, challenge, backup_sig}]`, one per
  server, in place of the single `challenge` and `backup_sig`. A device and the paper are 5 points, already
  the key.
- **`recovery`**: `{ "release_request": …, "waited": [<statement>, <statement>], "backup": <backup key>,
  "backup_sig": … }`: the paper alone, in a recovery session (§6.5), after two servers' waits. The backup
  key signs **this change's** hash, `detached("recovery", {"list": list hash})`, and servers take it only
  in a round the backup holder coordinates in that session (F9). A `release_request`'s own signature is
  `detached("release_request", {"r": r, "challenge": challenge})`.

There is **no "wait instead"**: a device with no lock, on its own, cannot make account changes. It uses a
second device or the paper. A helper never approves anything.

| Change | Approval |
|---|---|
| Add a `device` (§3.2) | `lock`, `pair` or `paper`; or `recovery` |
| Re-register a device's lock (§3.2) | `pair` or `paper`; or `recovery` |
| `[remove, redeal]`: report a `device` lost (§6.4) | `lock`, `pair` or `paper`; or `recovery` |
| A device removes itself (§6.4) | `self` (its own member key's signature) |
| `[seat …, redeal]`: add, swap or remove a server; add the helper (§6.7) | `lock`, `pair` or `paper`; or `recovery` |
| `[paper, redeal]`: a new paper (§6.7.6 F7) | `lock`, `pair` or `paper`; or `recovery` |
| `[redeal]` alone: a stranded redeal's replacement (§6.7.1) | `lock`, `pair` or `paper`; or `recovery` |
| A list no current seat holder co-signed (every server dead, F3) | `pair`, `paper` or `recovery` only |
| Export a child key (§6.8) | `lock`, `pair` or `paper` |
| Remove or replace a notice channel (§8.1) | `lock`, `pair` or `paper` |
| Delete the account (`account_delete`, Account admin module) | `lock`, `pair` or `paper` |
| Add a notice channel | any device, no approval (refused during a recovery wait) |
| Stop the helper (`helper_stop`, §5.7) | any device, no approval |
| Resume a stopped helper (`helper_resume`, §5.7) | `lock`, `pair` or `paper` |

### 6.3 Waits

- There are only two kinds of wait in the core, both `W` on each server's own clock: a **recovery**
  (§6.5) and a **hold** (§5.8). The Backup module adds a third, the **heir** wait (default 180 days),
  which any current device may cancel with no lock; it releases only the heir's envelope pieces, never
  a share or a release seed. A server starts one, tells every member (an `ask` push and an inbox notice) and every
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

- A change `{"remove": <key>}` names a `device` (the helper leaves by a seat change, §6.7.2), in one list with a redeal (§6.7.2), with
  its approval (§6.2). The removed member gets no delta and no seed. A lockless single device cannot
  report another; the person uses a second device or the paper.
- **A `self` remove** exists only for the §4.6 case: an extension retiring in favour of its machine's app,
  which joined separately. It is `{"remove": <own key>, "to": <app member key>}` with the approval
  `"self": { "member": <key>, "sig": …, "app_sig": … }`: detached signatures by the leaving key and by the
  named app's member key over `SHA-256("keykin-self/1" ‖ g ‖ change hash)`. A server co-signs it only while both are
  current devices and they are different keys. The app deals a redeal with it under the same two-key
  approval (`[remove, redeal]`), so a copied extension profile doesn't stay at the live state. In every
  other case a device leaves by an ordinary report-lost (`[remove, redeal]`, §6.2).
- The change goes to every server and every device as a delivery (§7.1). From the moment a member has
  it, servers MUST refuse every round with the removed member, and devices MUST refuse to co-sign with
  it. It is never delayed, and never waits for its redeal.
- **Removal notice.** The remove (or a reseat) is also delivered to the removed member, kept 7 days,
  with one visible push before its push addresses are dropped (§8.1). A member that verifies a
  group-signed change removing it destroys everything it holds for the account under that key.
- **Removal is final.** Nobody is put back; a device removed by mistake joins again.
- **What the redeal does, and doesn't.** Every honest member applies the redeal and destroys its old
  share, so the removed device's pieces no longer combine with any honest member's, and the data and
  release keys rotate. What the removed device itself kept still combines with other pieces kept from
  the same state (§10).

### 6.5 Recovery

A round with no device-class member (I4) happens only in a recovery session.

0. The holder finds the current servers (§6.7.5): it asks the server lists it trusts, follows the forwarding notes
   from the servers printed on the paper, and reads the signpost. The group-signed seat changes decide.
1. The backup holder picks a random `r`, asks each server for a `challenge`, and sends each a
   `release_request {r}` signed by the backup key over that server's challenge. Servers pass it to their peers as a delivery (§7.1), so a server that was down starts its
   own wait before it acts for the account again.
2. Each server starts a recovery wait (`W`, §6.3), tells every member and channel, and freezes holds. A
   locked device, or two devices together, can cancel it; the holder can withdraw it.
3. When its own wait has passed, a server seals the **release bundle** to the backup key (the holder
   unions the release seeds from all its servers): the current release seeds of its state and the paper release seed (§4.5), the epoch record, the set of changes, the backup material (every item, seed items and seed-only items for K included) and its waited
   statement (`release`). Members serve the material only to members, or in a release after the wait.
4. The holder checks the material's base against the pinned hash and the backup key's signature,
   opens it (a base made by F7 is wrapped under the release seed of the redeal in that `paper` change's
   own list, found by the list hash), adds the paper deltas of exactly the redeals in the servers' current state, and checks
   the sum against `P_b^S` (§6.7.6 F11).
5. For 7 days after its own wait ended (the **recovery session**), each server takes part, in the
   two-call form (§5.1), in rounds of the backup plus two servers: but only for a recovery join (§4.4)
   and changes approved by `recovery` (§6.2): reseats, a report-lost `[remove, redeal]`, a new paper and a
   redeal (§6.7.6 F9). Not
   ordinary events.
6. The recovery app then destroys the backup's shares and the release bundle, and offers a new paper
   (F7), never forcing it.

So a stolen paper needs two servers that each take part after their wait, with every device told.

### 6.7 Upkeep: replacing servers, the helper and the paper

Servers, the helper and the paper can always be replaced, without everyone online and without getting
stuck. Two ideas make that safe:

- **Seats.** Each server, the paper and the helper occupy a fixed seat: fixed share indices, set at
  creation (§3.1). A replacement is repaired **at the same index**, so it receives the same share value
  the old holder had. However many holders a seat has had, they count as one point in any one state. A
  newcomer never adds weight.
- **Redeals.** Every seat change and every report-lost comes with a **redeal**: a fresh random
  degree-3 polynomial with zero constant term, added to every member's share. Honest members' old
  pieces then stop combining with new ones, and the data key and the release seeds move on with it.

#### 6.7.1 State

- A member's **state** `S` is the set of redeal ids it has applied. Its share at index `i` is
  `f(i) + Σ_{r∈S} δ_r(i)`, and the commitment it checks against is `C_S = C + Σ_{r∈S} D_r` (with `C`
  the epoch record's commitment and `D_r` the redeal's). `P_i^S` is always derived, never taken from a
  message.
- Every signing round, decryption, repair and co-sign request carries `state = SHA-256(sorted ids)`
  (the 16-byte ids sorted bytewise and concatenated; the empty state hashes the empty string). A
  mismatch is answered with `stale {ids}`; the side missing ids fetches them (§7.1), applies them and
  retries.
- **Applying a redeal:**
  0. a device verifies the redeal's paper item (§7.2) after working out `δ(b1)`, `δ(b2)` (step 3's
     computation, done first) and before destroying the old share or `δ(i)`, and records one "paper item verified" bit for the redeal. `paper_eph` is `{redeal, item hash, eph secret}`, sealed by the dealer. The device checks that it names this redeal and its `paper_item`, and that its public key is the item's ephemeral key, derives the NIP-44 conversation key itself from `paper_eph` and `paper_to`, exactly as
     the backup key will from its side, opens the item with it, and checks the contents: `δ(b1)` and
     `δ(b2)` equal its own (`δ(b)·G == Σ D_k·b^k`), and the seed equals the `dk_seed` delivery, whose hash is the change's `dk`. It never
     takes a conversation key from the dealer: a dealer could otherwise seal the item so that a key it sent
     opens it while `paper_to` can't, and devices would drop their copies of a paper item nobody can
     recover from. It then destroys `paper_eph`, whether the check passed or not. A `paper_eph` that is missing, names another redeal or item, or whose public key isn't the item's `eph` counts as missing: the device fetches it from its peers' deliveries, and if it is still missing it applies the redeal, leaves the bit unset and re-issues (§6.7.6), with no dot. If a `paper_eph` bound to this item doesn't open it or opens it to wrong contents, the dealer is at fault: the device still applies the redeal, leaves the bit unset (so it keeps its paper values), re-issues the item, and shows a quiet line on Backup naming the dealing device ("*Laptop* sent a bad backup piece"), which the person can dismiss; the paper dot (§6.7.9) shows only while no item for the current K is verified;
  1. check `δ(i)·G == Σ_k D_k·i^k` for each of its indices;
  2. add it, and check `s'·G == P_i^{S'}`; a device also rebuilds `C_{S'}` from its own 3 points and `g`
     (§3.4 step 4);
  3. destroy, at once, the old share and `δ(i)`. A device also works out `δ(b1)`, `δ(b2)` (from the
     redeal's full `δ`: its own 3 values plus `δ(0) = 0`) and keeps them, encrypted at rest, **until the paper item for the current backup key is verified** (§6.7.6; the "verified" bit is kept per backup key), then destroys them. The redeal's data-key seed is never destroyed (§4.5). The device
     running an F7 also keeps them for redeals applied during it, until the new K's items are confirmed (the paper change committed, and its own re-issued items held by two servers) or its
     approval expires, so it can re-issue the items the new paper misses;
  4. send `ack`.
- **Never sign at a state you have left.** Honest members can't: they destroyed it.
- Servers apply every redeal they know before co-signing an Upkeep change; repair helpers do too. Before
  everyday signing they fetch nothing extra: `stale` already brings both sides to the same state.
- **Stranded redeals.** Nothing ever steps back. Every redeal names the state it was dealt on
  (`base`). A member that lacks a redeal others applied is brought forward by `rerepair` (§6.7.4). If a
  redeal can't be completed (its deltas are lost and fewer than 4 live points hold its state), the app
  asks for one fresh redeal, with one approval. That redeal is dealt on the state 4 live points share and
  carries `abandons: [r]`.
  - A member whose state contains an abandoned id never applies the fresh redeal's deltas. It rerepairs
    to the fresh redeal's state instead, with a proof at its own current state. `rerepair` may drop only
    ids that a valid `abandons` names.
  - A redeal whose id has been abandoned is never applied by anyone, even if its deltas reappear, and
    neither is any redeal whose `base` contains an abandoned id. Co-signers refuse to co-sign such a
    redeal in the first place.
  - A fresh redeal MUST NOT abandon a redeal that travelled with a `remove`. If such a redeal is
    stranded, the fresh one is dealt in a new `[redeal]` that excludes the same removed member (its
    deltas and seeds never go to it). After every apply, a device checks that for each `remove` it knows
    some applied redeal excluded that member, and if none did, it deals one (one approval).
  - If the paper's base contains an abandoned redeal, the paper can no longer be completed; devices
    detect this and show the quiet dot for a new paper (F7).
  - If two fresh redeals abandon the same id, both apply (they are additive), and members `rerepair` to
    the state that holds both.
  - A removed member never gets the fresh redeal's deltas or seeds.
  - If no state has 4 live points (the servers at one state, the last device at another), a device plus
    the paper, or a paper recovery, brings the account forward (§6.7.8).
  - A redeal counts as co-signed only when its upload is held by at least two live post-change seat
    holders, or by every one when fewer are live; they say so with `upload_held`, which the co-signer
    collects, so a co-sign can't strand it on the co-signer alone.

  A repair at a named state sets the member's state, so no redeal is ever applied twice.

#### 6.7.2 The three Upkeep changes

They are changes of §3.2 (kind 24302, group-signed, valid in any order).

- **`seat`**: `{"seat": {"seat": "server:<idx>" | "helper", "new": <member entry> | null, "replaces":
  <key | null | "void:<id>">, "clears_stops": [<stop ids>] (helper seat only, optional)}}`. A new server's member entry carries its `enroll` reply, signed by its
  host key and binding its member key, VAPID key and endpoints to it (Server profile module). Co-signers
  and repair helpers verify that reply before co-signing or repairing.
  - A seat's current holder follows the epoch record's holder along valid seat changes, exactly as a
    lock does (§3.2). `new: null` empties the seat (removing a server or the helper without replacing
    it).
  - Two seat changes for one seat with the same `new`, or with the same host under different member keys,
    count as one (the lower list hash's `new` wins; the losing member key goes into `removed`). Otherwise, with different `new`, both are void and
    the seat stays empty until a `void:<id>` reseat. Two seat changes for **different seats** with the
    same `new.host` whose approvals' expiries are within 24 hours of each other are both void, and both
    `new` keys go into `removed`: only changes approved at about the same time can put one host in two seats
    at once, since co-signers refuse a host already seated in their view (I2). This depends only on the
    changes themselves, so every member reaches the same answer in any order; a host that held a seat
    before may hold another later (I7).
  - The helper leaves only by `seat helper→null`; a `remove` never names a seat holder.
  - Every key that stops being a seat's current holder, `replaces` or voided `new`, goes into `removed`,
    and gets the removal notice (§6.4).
- **`paper`**: `{"paper": {"key": K, "replaces": <old backup key>, "inner": <hash>, "state": <sorted redeal ids in its base>, "seeds": <sorted ids of every redeal whose seed its seed items carry>}}`. Its co-signer checks that `replaces` is the current backup key. A co-signed paper
  change puts `replaces` into `removed`. If two paper changes conflict, the lowest list hash wins and the
  loser's key goes into `removed`. `paper` approvals, `challenge` / `release_request` and recovery
  sessions are accepted **only from the current backup key**, and servers end any wait on a replaced key
  at the co-sign.
- **`redeal`**: `{"redeal": {"id": <16 bytes>, "dealer": <device key>, "D": [D1, D2, D3], "paper_to": K,
  "paper_item": <hash>, "dk": <hash>, "rs": <hash>, "base": <sorted ids>, "abandons": [<ids>]}}`,
  carrying the dealer's detached signature. `D0` is
  the identity and is implicit. A `D` that contains the identity, or a `δ` that is all zero, is refused.
  `paper_to` is the backup key that is current **after** the list the redeal is in (in
  `[paper K', redeal]` it is K'). `rs` is `SHA-256` of the new release seed itself, `dk` of the data-key
  seed (each seed is sealed separately to each recipient, so the hash is of the seed), and `paper_item` of the new material item (§7.2). In a `[paper, redeal]` list, the new paper's
  base item is wrapped under that redeal's release seed. At creation, a creation release seed wraps the
  base item, and it travels with the other seeds.

**Approval lists.** Changes that belong together are approved together as one **list**: a seat change
and its redeal, a remove and its redeal, a paper change and its redeal.

- The list is a JSON array of changes in which the redeal is a placeholder and a paper change has no `inner`, no `state` and no `seeds`. Module fields of a change (such as Backup's `holders` and `heir`) are part of the
  approved list like any other field. Its hash, `SHA-256(JCS(list))`, is the "change hash" everywhere: the lock assertion's `what` is
  `"change" ‖ list hash ‖ epoch id ‖ expiry` (§6.1), and a pair code uses the same hash. The expiry is at
  most 24 hours away and checked by the co-signer.
- In the list, the redeal appears only as `{"redeal": {"dealer": <device key>}}`: it binds **who** deals,
  not what. Only that device may deal it, and it may deal a fresh one after a failure until the approval
  expires.
- A paper change appears without `inner`, `state` or `seeds`, because the material doesn't exist yet when the person
  approves (§6.7.6 F7).
- The changes of one list are co-signed together and delivered as one. A `remove` and its redeal never
  travel apart.
- **Each change event carries its list.** Every kind 24302 event of a list has `"list": [...]` in its
  content, in the approved (placeholder) form, so a member holding one event can recompute the list hash.
  The event's `change` MUST match one entry of the list (a redeal by its `dealer`, a paper without
  `inner` and `state`).

Further rules:

- `seat`, `paper` and `redeal` need `lock`, `pair`, `paper` or `recovery` (§6.2), never less. An
  unapproved seat change would let a lockless thief seat its own server, and an unapproved redeal would
  let it spoil the paper.
- **Mandatory redeal.** Every list with a `seat` or a `remove` MUST include one redeal, a `self` remove
  included (§6.4), where the app taking over deals it. The §4.6
  handover needs none (same key, same indices).
- **No current seat holder co-signed** (every server dead, §6.7.6 F3): such a list is accepted only with
  `pair`, `paper` or `recovery` approval, and the paper challenge then comes from a server being seated.
  A co-signer attaches a host-key `cosig`, stored with the change and served by `changes_get`. A change
  without one is shown to every device as a notice; it is never invalid for lacking one.

#### 6.7.3 Dealing

- The listed dealer deals the redeal. It holds `δ` **only in process memory, until the co-sign**. It
  answers `missing [keys]` only before the co-sign, and destroys `δ` at the co-sign or on any failure.
  After a failure it deals a fresh redeal under the same approval while that approval is unexpired.
  Every gap after the co-sign is closed by `rerepair`.
- Before the co-sign, the dealer uploads these deliveries, addressed only to the members of the
  **post-change** view (never an outgoing seat holder or a member the list removes), to every live
  post-change seat holder and every incoming holder:

  | Delivery | Sealed to | Contents |
  |---|---|---|
  | `delta` | each member | `δ(i)` for each of its indices |
  | `paper_eph` | devices only | the paper item's ephemeral secret key (§6.7.1 step 0) |
  | `dk_seed` | devices only | the data-key seed |
  | `release_seed` | devices, and current and incoming seat servers (never helpers, never retired holders) | the redeal's release seed |
  | `paper_item` | every server and device | the new material item (§7.2) |

  Before dealing, the dealer fetches the account's changes from its live servers (`changes_get`), so its post-list view names every current member; a device that missed a join would otherwise leave the new member without a delta. If a server still answers `missing`, the dealer fetches again and deals a fresh redeal, with a new id, under the same approval (the placeholder list, and so the list hash and any `paper` challenge, stay the same). The dealer sends them with `upload {list, approval, items[]}`, which must carry the approval list and its valid approval, or it is refused. Uploads are inert until the co-sign and expire after 7 days. A
  co-signer applies a redeal, and destroys its old share, only once it holds the group-signed list.
- **The co-signer of a redeal:**
  - fetches its live peers first, so it knows of every paper change;
  - checks the approval and the dealer's signature;
  - holds a delta for every member in its post-list view, incoming seat holders included and the backup
    excluded (the backup gets the `paper_item` instead), plus the `paper_item`, the `release_seed`, and a `paper_eph` and a `dk_seed` for every post-list device (by each sealed delivery's declared type and recipient; their contents are the devices' check, §6.7.1 step 0), and otherwise answers `missing`;
  - refuses if `paper_to` is not the post-list current backup key, or if the item's hash doesn't match;
  - drops deltas addressed to removed keys.

  A single server may co-sign a list alone.
- **The co-signer of a paper change:**
  - fetches every live peer first;
  - accepts a paper change whose `state` lacks some co-signed redeals it knows: devices re-issue the
    items for those redeals to K (§6.7.6), and F7 step 5 waits for them;
  - checks that `replaces` is the current backup key;
  - receives the base item and the seed items in the same request and checks that they hash to `inner` (§7.2) and are signed by K, and that `seeds` lists every redeal in `state` (any other seed, abandoned, stranded or dealt during the F7, is covered by seed-only re-issues when some device holds it; a seed no current device holds is lost on every path, paper or not);

  A repair towards a new backup key K happens only with a valid, fresh approval naming K, at the current
  state. The approving device makes it once per K.

#### 6.7.4 Filling seats and catching up

- **`need_repair`.** A seat's **current** holder that holds no share yet asks for one, authorised by the
  valid seat change that made it current (or a device by its add). It is **never answered for the
  backup seat**: the paper gets its shares only when it is made (§4.3, F7), so nobody holding a paper key
  can have the paper's pieces repaired to them. **Any helpers worth 4 points**
  answer by repair at the seat's index and the current state: a device and a server, the helper and a
  server, two devices, or a device and the paper (so new servers can be filled even when every old one
  is dead). It always gives the same value. Each server answers it **once per key and index that
  succeeded**: success is the owner's `repair_ok {participant}`, sent to each helper after its share
  checks; until a helper has it, the answer isn't used up. A repair whose sum fails the share check
  doesn't count, and the asker names the bad
  helper so the next try uses another. Repair
  helpers refuse a host that already holds another seat in their view, so concurrent seat lists can't
  repair one host into two seats.
- **`rerepair {indices, state, proof}`.** A current member repairs its own existing indices at a named
  state, for any redeal it lacks. The proof is a Schnorr proof of knowledge of its share at an earlier
  state in its own chain, bound to a fresh server challenge. It is allowed only at the indices its seat
  chain or add gives it, never for the backup seat, and never for a removed member. Every device is told,
  with a "Report lost" button ("*Laptop* restored its pieces", §1.1), and so is every answered `need_seeds`, since a copy of a member's storage could otherwise catch up unseen, except one that carries the asker's own live, unexpired F7 approval naming K and arrives before that F7's step 3, which the answering device checks and shows only as a quiet line ("*Laptop* is making a new paper") (§4.5).
- **`need_seeds`.** Any current device seals the data-key and release seeds to another current device
  that asks, and the release seeds (only, the paper release seed included, §4.5) to a current seat server that asks.
- **An incoming seat holder**, once welcomed, fetches every unacknowledged delivery, for every member,
  from its live peers.
- **`state_get`** asks a member for its state (`state {ids}`). `rerepair`'s challenge is the ordinary
  server `challenge`.
- **What a welcome carries.**
  - A device's welcome (§4.2 step 4) and a handover (§4.6) carry: the state, the base data key and every
    data-key seed, every release seed of the state and the paper release seed, and the backup material (every item).
  - A seat holder's welcome carries: the epoch record, the change set, its seat, the state, every release seed of the state and the paper release seed (servers only), the backup material and any `helper_stop` in force. It never carries
    the data key or data-key seeds.

#### 6.7.5 Finding today's servers, and retired servers

A paper must always be able to find today's servers, even after every server printed on it has been
replaced. Three routes, tried in order:

1. **Ask the server lists.** The paper app takes the signed server lists it trusts (§6.7.7) and asks each listed host `seated? {H(key), challenge, sig}`, with a `challenge` that host issued (the paper doesn't know the epoch id yet, so `seated?` and its challenge are answered at the host, which looks through every seat it holds), where the key is the backup key or, from a
   device, its member key, and `sig` is that key's signature over `SHA-256("keykin-seated-ask/1" ‖ H(key) ‖ challenge)` (a server answers only if it verifies). A server that holds a seat for an account where that key is the current backup
   key or a current device answers with a reply sealed to the key: a list of entries, one per matching seat, each `{g, epoch, servers: [{key, host, https, relays}]}` (for each current seat server: its member key, host key, HTTPS endpoint and relays; an heir key gets the same without member keys), carrying its host signature outside the seal, over `SHA-256("keykin-seated/1" ‖ H(key) ‖ challenge ‖ ciphertext)`, so the asker can check
   it. The answer is a hint: the asker trusts `g`, the epoch id and the servers only once two servers return matching epoch records and change sets (Backup module §2), and checks the servers against the change set. This needs no relays and no published event. A server that holds an heir record (Backup module)
   also answers `seated?` and `forward_get` signed by that record's heir key.
2. **Follow the forwarding notes.** A retired server, after destroying everything else, keeps for the
   account only the group-signed change that retired it and the hashes of the keys allowed to ask for it
   (the backup keys, device keys, other seat servers' keys and any heir key it knew). It serves that change to a
   request signed by one of them, over `SHA-256("keykin-forward-ask/1" ‖ H(key) ‖ challenge)` with the server's challenge. That is a forwarding note with no secrets. From
   the printed servers, the paper app walks the notes to today's servers.
3. **The signpost**, for servers the person runs themself that are on no list the recovering app trusts. It is a kind
   30078 event signed by `g`, with `d = hex(SHA-256("keykin-beacon/1" ‖ backup key))`.
   - Its clear fields are `n`, the count of every seat and paper change in the change set (co-signed or
     F3, void ones included),
     so it only ever grows; and `h = SHA-256("keykin-beacon/1" ‖ epoch id ‖ JCS(current server entries))`.
   - The rest is two sealed copies of the current servers' host keys, HTTPS endpoints and relays: one
     NIP-44 to the backup key, and one under `HKDF(base data key, "keykin-beacon/1")` for a device that
     slept through every server being replaced.
   - It is published at creation, to the paper's printed relays and the current ones. Any device that
     learns of a seat or paper change it did not make, or finds the signpost missing or its device copy
     wrong, republishes it. Servers seated later learn the current signpost's event id from their welcome.
   - Readers take the highest `n` whose decrypted copy matches `h`. A holder with only the 24 words checks `h` once it knows the epoch id: from the QR code or account card if it has one, else from the epoch record and change set that two servers the signpost names return matching. It tries the highest `n` first and never falls back to a lower `n` because the newer signpost's servers can't be reached; it retries instead.
   - **Guards.** A device MUST NOT sign, on a site's request, a kind 30078 with any of the account's
     signpost `d` values, or a kind 5 targeting one. Co-signers keep the current signpost's event id
     (one hash per backup key). They refuse every kind 5 that targets a signpost by `e` or `a`, from
     anyone (an `e` value matches the signpost id; an `a` value hits when it contains both `g` and a signpost `d` anywhere in it, whatever its kind part or splitting, since relays read `a` values loosely (`030078`, `30078 `, extra `:` fields) and two 64-hex-character values name nothing else; hex is compared ignoring case; a kind 62 vanish request still removes the signpost, with the approval §5.8 requires), and co-sign a signpost only from a device, with the right `n` and an `h` that matches their
     own view.
   - Servers never act on the signpost.

A device that has seen no seat change for 90 days runs the same lookup on app open, even if its known
servers answer.

**Retired servers.** A server learns it was replaced from the group-signed change itself:

- Servers and devices deliver that change to it as a removal notice (§6.4). Devices keep retrying to each
  retired server's endpoints at a low rate, for as long as the device knows it.
- A device that gets a wait notice or a push from a retired server answers with the removal notice and a
  `cancel`.
- Peers keep the change that removed each key for ever, so `changes_get` always returns it.
- A server that verifies a group-signed change removing it destroys everything it holds under that member
  key except its forwarding note. (The same host may hold another, current seat of the account under a
  fresh key, I7; that stays.)
- Before it starts a wait or releases anything, a server runs `changes_get` against every peer it
  knows.
- A server that was offline for more than 7 days stays **passive** for the account (no waits, no
  releases) until a live peer that is itself a **current** seat holder (one that has seen no change
  removing it, and whose own forwarding-note check finds none) confirms, by `changes_get`, that it
  still holds its seat. Retired servers serve their forwarding notes to servers too, so two servers
  retired together can't confirm each other. If no peer is
  live, the paper holder's `release_request` lifts passivity once the server has run its full wait and
  found no change removing it at any peer or device it can reach.

#### 6.7.6 Flows

One approval covers each list. The dealer uploads, one server co-signs, the dealer destroys `δ`,
incoming holders are repaired in the foreground, and the signpost is republished. Example account:
phone A (3), laptop B (3), servers S1–S3 (1 each), paper (2).

- **F1, one server dies.** A peer has been quiet for 7 days, or sent a 30-day shutdown notice (confirmed by a live answer, Server profile §4.1), and a live server pushes an `ask` naming a candidate Y.
  - The card reads "S3 stopped answering. Move its piece to Y?" One Face ID (or a pair, or the paper)
    approves `[seat server:i3→Y, redeal]`.
  - S1 co-signs, and A and S1 repair `i3` for Y at the new state.
  - B catches up from its inbox.
  - No reprint.
- **F2, two servers die.** One approval covers `[seat i2→Y2, seat i3→Y3, redeal]`; S1 co-signs.
- **F3, every server dies.** Approval is by `paper` (A + paper) or `pair` (A + B with the typed code).
  - `[seat×3, redeal]` goes through with no co-sign; Y1–Y3 issue the paper challenge and notify devices.
  - A and B (or A and the paper) fill the three seats by `need_repair`.
  - A sends removal notices to the old servers' endpoints.
- **F4, swap or remove a server.** As F1, with `new: null` for a removal. An honest old server destroys
  everything; a dishonest one keeps a dead point at the old state.
- **F5, report lost.** One approval covers `[remove R, redeal]`. R gets no delta and no seed. If R added
  devices just before, the app flags them as "added by a device you removed".
- **F6, helper.** Add: the typed join check (§4.1), then `[seat helper→H, redeal]`; A plus one server
  repair the helper's seat. Remove: `[seat helper→null, redeal]`.
- **F7, a new paper.**
  1. A makes K. One approval covers `[paper {K, replaces}, redeal (paper_to K)]` (without `inner`, `state` and `seeds`; it expires in 24 hours).
  2. A and one server repair the backup seat towards K under that approval. A checks the shares, wraps
     the base item and signs it with K. A is worth 5 points for this moment (§4.3).
  3. The person prints or writes the paper and reads it back. The screen says "Keep your old paper until
     this app says the new one is ready."
  4. A deals the list's redeal now (§6.7.3), then sends the paper change with `inner`, `seeds`, the base item, the seed items (made in step 2, after the `need_seeds` wait) and `state` (the state the repair in step 2 was done at) and the redeal together, as one list; the
     co-signer checks and co-signs. If the redeal's co-sign fails, A deals a fresh one under the same
     approval, without a new paper. Devices re-issue items only for redeals outside that
     `state`.
  5. After a check against every live server, for conflicting paper changes and for redeals whose items
     went to the old paper, the screen says "You can destroy the old paper", and servers end any wait on
     the old key.

  If A dies before step 4, nothing has changed. If the approval expires, the person approves again and
  starts from step 1 with a new K. There is never a second repair towards the same K.
- **F8, data key and release seeds.** Every redeal moves both on. A bare `[redeal]` exists but is never
  needed by hand.
- **F9, after a paper-only recovery.** `recovery` approvals cover reseats, report-lost, a new paper (offered, not
  forced) and a redeal. The recovery app's new device deals the redeal, once it has joined (§4.4), but
  every `recovery`-approved change is **co-signed only in a round the holder coordinates** (the backup
  plus two servers, two-call form, §6.5 step 5), never in an everyday round of the new device.
- **F10, the group key leaks.** A new npub; followers can move to it if a key family was settled before
  the leak (Key families module).
- **F11, paper-only recovery after changes.**
  1. The holder finds the current servers (§6.7.5) and runs §6.5.
  2. After the wait it receives every release seed of the servers' state, the paper release seed and the material items.
  3. It sums the base and one paper item per redeal of exactly the redeals in that state (checking each seed against its change's `dk`), leaving stranded ones out, and checks the sum against `P_b^S`.
  4. For data keys it keeps the seed items' seeds, the seeds of its state's paper items and of every seed-only item it can open, stranded and
     abandoned ones included, each checked against its change's `dk`, and passes them all to the devices
     it makes.

**A device keeps a "paper item verified" bit** for each redeal it applied by delta (§6.7.1). If one not in
the paper's `state` lacks a verified item for the current K, the device **re-issues** it from the paper
values it kept (§6.7.1 step 3: `δ(b1)`, `δ(b2)`, the data-key seed). It seals them to K, from a fresh ephemeral key, as a supplementary item under that redeal's release seed, signs it with its member key (`detached("paper-reissue", …)`, §5.9), publishes the item's `δ(b)·G` values in the clear, delivers it (`paper_reissue`) to the servers, and delivers `reissue_eph {redeal, K, item hash, eph secret}` to the other devices only, as an ordinary delivery that is live at once (§8.2). A device re-issues at most once per redeal and K. Seed-only items (§4.5) are separate: they carry no clear values, take their own slot, and need no verification by other devices. Servers accept items only
for the current K, from current devices, and, for a full re-issue, only when the clear `δ(b)·G` match the redeal's commitments (`Σ D_k·b^k`); they keep the **first** valid one from each device per redeal and K, never replace it, pass it to their peers, and keep it after that device is removed. Other devices fetch the re-issuer's item (`reissue_get`, an `ask`-class request) from at least two live servers and check that both hold the one whose hash `reissue_eph` names (if not, or if `reissue_eph` names another K than the current one, or its eph secret's public key isn't the item's `eph`, it counts as missing: they wait and retry, with no dot, and after 7 days re-issue their own; a device that holds values and lacks a verified item re-issues at once only when no other device's `reissue_eph` for that redeal and K has reached it), check the clear values the same way, then open it with a conversation key they derive from the eph secret and K, as in §6.7.1 step 0, and compare its contents with the paper values they kept. Only then do they set their own bit and destroy their kept values. A device that kept no values for that redeal (it had already verified an item for the old K before an F7) has nothing left to lose: it checks the item's clear `δ(b)·G` against `Σ D_k·b^k`, sets its bit, and shows nothing (the holder checks the seed against `dk` at recovery, F11 step 3). A device that can't open the item it fetched, or finds other values, keeps them, re-issues its own once, and shows the same dismissable line naming the re-issuer; it ignores any later `reissue_eph` from the same device for that redeal and K. The re-issuer sets its own bit once two servers confirm, by hash, that they hold its item (or every live server, when fewer than two are live); a server that answers otherwise counts as not confirming, and the device asks another, with no dot. That line names a re-issuer only on proof: an item it signed, held by two servers, that a `reissue_eph` it sealed for that item and K doesn't open or opens to wrong values. Servers pass re-issued items to incoming seat holders like any other item (§7.1). A device asleep past a `reissue_eph`'s 7 days re-issues its own instead, which is safe.
The holder opens each item, the dealer's included, and checks its `δ(b)` against `Σ D_k·b^k` (and a re-issued one against its clear values), dropping any that fail, and the sum against `P_b^S`. This is not a repair: K learns only what devices
already know. A **new paper** (F7, the quiet dot) is for a paper that is lost or exposed, or when no
current device can re-issue.

#### 6.7.7 Choosing a replacement

- **Server lists are open.** Any app maker, operator or community may publish a signed server list
  (Server profile module) under its own list key; no list is special, and Keykin has no canonical one.
  An app pins the list keys it trusts and their minimum versions. The person may add a list by hand in settings, after a warning that its publisher will propose their servers; a hand-added list's floor is the first version the device verifies. Each device decides on one list, its **chosen list**: the person's choice,
  else its app's first pin. Operators are invited to run servers and to get them onto lists, or to
  publish their own.
- The server that sends the `ask` names a candidate. The `ask` names the list key. A device accepts the candidate only if it is the deterministic pick `hash(g ‖ dead key ‖ seat ‖ version)` over the **newest version it knows of its chosen list** (at least the pin); for an `ask` that names another list, it uses its own pick from its chosen list. The pick is taken from that seat's own slice of the chosen list (its servers dealt round-robin to the three server seats), never putting two seats on one
  `operator` while another eligible one exists. If that pick refuses the seat or doesn't answer within a
  minute, the device takes the next server in the slice, in list order, and the `ask` names which one.
  It checks for itself that the server is dead (or has a shutdown notice confirmed by a live answer, Server profile §4.1, or answers `deleted` or "unknown account" for an account its peers still serve, for a day) before it shows the card; such a server triggers the F1 card on its own. When there is no other operator, the card says "All your servers are run by X".

#### 6.7.8 Failure handling

There are no aborts, no busy state, no leases and no clock that matters.

| Case | What happens |
|---|---|
| Dealer dies before the co-sign | Nothing changed. Inert uploads expire in 7 days and block nothing after 1 hour. |
| Dealer dies after the co-sign | Deltas are at one or more seat holders and spread (§7.1); a member that lacks one uses `rerepair`. |
| Seated but not repaired | `need_repair`, from any 4 points. |
| Every holder of a redeal's deltas is lost | A fresh `[redeal]` on the state 4 live points share; members ahead are repaired forward. Nothing steps back. |
| Seat conflict | Same `new`: one. Different `new`, or one host in two seats: both void, both removed, one `void:` reseat. Liveness only. |
| Two paper changes | Lowest hash wins; the old paper stays "keep" until the conflict check passes. |
| A retired server comes back unaware | Offline over 7 days, it stays passive; it checks `changes_get` with its peers before any wait or release; removal notices reach it. |
| A device asleep while every known server was replaced | The public-list lookup, forwarding notes or the signpost name today's servers; incoming holders hold its deliveries; `need_seeds` covers the seeds. |
| A paper missing a piece | A device re-issues the item; a new paper only when none can. |
| No state has 4 live points | Only a paper recovery helps. |
| Fewer than 4 live points | Stuck, as with any threshold scheme. Examples: a lone device (locked or not) with no paper and every server dead; or every device lost with fewer than 2 live servers. |

#### 6.7.9 What the person sees (non-normative defaults)

- After 7 days with every server unreachable from 2 or more networks: a calm card offering to move all
  three (F3).
- After a report-lost or a server swap, or when a paper misses a piece: one quiet cue, a filled dot on
  Backup, suggesting a new paper. Never a banner, never forced.
- About once a year per dead server: one Face ID. If every server is gone: scan the paper.
- When a phone's lock stops working (a new face or fingerprint was enrolled), the app says so on the
  next open: "Your lock stopped working. Scan your paper or use a second device to restore it." A lone
  device without a lock gets a quiet suggestion, never a push, to add a second device (a browser
  extension on a laptop counts).
- When, over 7 days, a server left at least 3 `sign` requests on 2 different days unanswered for their
  whole lifetime (no valid partial, even late, and no `error`), while another server co-signed each of
  them: one quiet line on Backup, "S3 hasn't helped sign this week", with a "Move its piece" button (F4).
  An `error` answer (a burst, a hold, `stale`) never counts, so a site can't bring the line by making a
  server refuse. No card, no dot; the person can hide it for a week, and it goes away once the server
  gives a valid partial on two days. It may show for a server that is only slow, or one a relay cuts off;
  it is information, never a trigger.

#### 6.7.10 Who may ask, and what co-signers also refuse

Pinned from the reference implementation (batch 2):

- **Repair sigmas go only to the index's owner.** A helper seals a `repair_sigma` only to the current
  owner of that index in its view, never to whoever asked, and never for the backup seat except in an F7
  repair towards that F7's own `K` under its approval (§4.3 step 2). Who may ask:
  - a join repair (§4.2): a current device other than the new device, or the backup holder in its recovery
    session (§4.4);
  - `need_repair`: the seat's current holder, or a current device filling that seat;
  - `rerepair`: the index's owner, with its proof.

  Repair requests carry `participant` (the index being repaired), `seal_to` (its owner's key), `why` (the
  change that makes it the owner), `state` and `helpers` (each helper's member key and indices); for F7,
  the `[paper, redeal]` list and its approval; for `rerepair`, `{challenge, state, proof: {i, R, z}}`.
- **A helper checks the helper list against its own view** before it computes anything: every entry is a
  current member listing exactly its own indices, the helper itself is among them, nobody appears twice,
  the list is worth at least 4, and the index's new owner is not a helper. The backup may be a helper only
  in its recovery session (§4.4), or alongside a current device under a valid `paper` approval for the
  change being filled (F3, a device with the paper). Otherwise a device could list a server's index as its own and receive every
  delta that server makes.
- **`rerepair` proof:** Schnorr over `e = H("keykin-rerepair/1" ‖ g ‖ owner key ‖ i (4 bytes) ‖ P_i^{S_old}
  ‖ R ‖ challenge)`, with a challenge the server issued to that owner.
- **Challenges** are bound to the key they were issued to (for a `paper` approval, the backup key). A
  `paper` challenge is used once **per list hash**: it serves that list's co-sign and, for F7, the repair
  towards K under the same approval, and a retry of the same list may reuse it. Other challenges are used
  once per request id.
- **A list is co-signed in one request.** Every event of a list travels in one `sign` request
  (`list_events`), each with **its own** nonce commitments from the coordinator; the co-signer answers
  with one commitment pair and one partial per event and index (in the two-call form, `commit {count}`
  asks for that many pairs first). The co-signer checks the approval and the trial (below) once, at the
  pre-redeal state, and gives partials for every event or for none. No member applies a list's redeal until it holds every
  event of that list group-signed. So a `seat` or `remove` never commits without its redeal, nor a redeal
  without them.
- **A paper change's material** travels in the `sign` request as `material` (the base item), checked as
  `SHA-256(item) == inner`, addressed to `K` and signed by `K`.
- **Uploads** (§6.7.3) are accepted only from the list's `{redeal: {dealer}}`, a current device, once per
  redeal id, and never after that redeal is co-signed.
- **Signposts:** a device that publishes a signpost delivers its event id to every server (a delivery), so
  every co-signer can refuse a kind 5 aimed at it by `e`.
- **One key, one member.** No key is two members, across kinds: co-signers refuse an add, a seat's `new`
  or a `paper` key that is already a member or is in `removed`.
- **Co-signers try the change.** Besides the invariants (§3.3), a co-signer refuses a change after which a
  member disappears that the list doesn't name, an add whose indices meet any known index, and a lock
  change whose `replaces` isn't the device's current lock.

### 6.8 Exporting keys

- **The master key is never exported.** A server MUST NOT seal its share to anyone for a `master` group,
  and members MUST NOT offer to combine a master group's shares into an nsec. (Someone combining their
  own shares with their own tools cannot be stopped, and this does not try.)
- **A child key** may be exported in stages: in Core 1.x any child; in a later version only children
  with `origin: import`; then none. Export is `take_out {}` from a device with an approval (§6.2); each
  server seals its share to that device and tells every member.
- A server treats a group as a child only if it adopted, first-hand at the group's creation, a first
  epoch record that says `role: child` (Key families module). An account made by importing a 0.12
  account's nsec (§11.2) is `master`, unless the person imports it as the child of a new master (Key
  families module), in which case its first epoch record says `role: child` and `origin: import`.
- An export is permanent.

## 7. Keeping what you hold

### 7.1 Deliveries kept until acknowledged

Everything a member needs from others (the welcome, repair sigmas, the epoch record and changes, the
redeal deliveries of §6.7.3, the backup material, and every `cancel`, `withdraw` and
`release_request`) is a **delivery**. Every server of the account MUST keep each delivery for every member, other servers
included, until that member sends `ack` for it or is removed, and MUST hand it over when asked (§8.2).
A server that was offline MUST fetch its deliveries from its peers before it co-signs, issues a waited
statement or releases anything again, skipping a peer that has not answered for an hour. Changes are
kept for ever (§3.2). Deliveries for a removed member are dropped, except its removal notice, kept 7
days (§6.4); deliveries for the backup (which never fetches) are dropped; `deliver` from a removed
member is refused. Data-key seeds, `paper_eph` and `reissue_eph` go to devices only. Uploads made before a
co-sign are inert and expire after 7 days (§6.7.3).

Deliveries travel **through HTTPS, server inboxes, or live kind 21059 wraps** (which relays do not
store), never as stored kind 1059 copies on relays: anything that carries a share or a key must not
sit in public archives.

### 7.2 The backup material and the release seeds

The backup's shares exist only as **backup material**, a set of items that simply add up:

- the **base item**: the shares at the paper's `state` (made and checked once, §4.3) and the base data
  key, NIP-44 to the backup key and signed by it;
- beside it, zero or more **seed items**: base64 of binary `id (16 bytes) ‖ seed (32 bytes)` records, at
  most 1,000 per item, one for every redeal the paper change's `seeds` lists (§4.5), each NIP-44 to the
  backup key, signed by it and wrapped like the base item. The epoch record (at creation) or the `paper`
  change pins `inner = SHA-256(JCS([base item hash, seed item hashes…]))`;
- one **paper item** per later redeal: NIP-44 from a fresh ephemeral key, used for that item only and
  carried in the item's clear `eph` field (inside the release-seed wrap, so K reads it before decrypting),
  to that redeal's `paper_to`,
  carrying `{δ(b1), δ(b2), data-key seed}`.

Each item is wrapped a second time, with XChaCha20-Poly1305, under **its own redeal's release seed** (seed and seed-only items: under the paper release seed, §4.5) (the
base item under the release seed made with it). Two redeals at once each add their own item, and the
set is simply the union, counting one item per redeal at recovery (§6.7.6 F11 step 3). Every server and every device keeps every item, every release seed of its state and the paper release seed (§4.5) (so device + paper still works if every server is gone). Members refuse an item whose hash doesn't match its change (re-issued and seed-only items: §6.7.6, §4.5). Helpers and backups never hold release seeds; a recovery receives them only after the
wait (§6.5).

So helper + paper (3 + 2) cannot sign without a server's wait (I5). Device + paper works at once, because
the device holds the release seeds. After every apply, a device checks that each applied redeal not in
the paper's base has a paper item for the current backup key (§6.7.6).

### 7.3 Storage at rest and destruction

- On phones and desktops, shares and the member key at rest MUST be encrypted under a key specific to
  this membership, kept in platform secure storage (Keychain "this device only", Android Keystore, an OS
  keyring). Destroying means **deleting that key** (closes #7 where the platform can delete keys), not
  only the ciphertext.
- That storage key MUST NOT require the person's face, fingerprint or passcode to use, and signing MUST
  NOT be limited to while the device is unlocked: background signing works as it does with an nsec today.
  (iPhone keeps keys sealed between a restart and the first unlock; that is the platform, not a rule.)
  The lock (§6.1) is a separate key, used only for approvals.
- On applying a redeal a member destroys at once the old share and `δ(i)`; a device keeps the paper
  values of §6.7.1 step 3 only until the current paper's item for that redeal is verified.
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
- A server drops an address that returns 404 or 410, and MUST NOT copy addresses to other servers. A
  removed member gets one visible push saying it was removed, and then its addresses are dropped.
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
  pushed. A member leaves something for another member with `deliver {to, wrap, slot?}`; a delivery with a
  `slot` replaces the sender's earlier one in the same slot for that recipient (a module's cumulative
  reports use this): `to` must be a current
  member, the wrap's `p` tag must be `to`, and the server counts it against the sender's caps (reference:
  32 waiting per sender and recipient, with its own push budget). Kind 21059 is used only towards members
  known to be awake (§9.1).
- `inbox_get {}` returns `{ "items": [ { "iid": "…", "age": <seconds held>, "wrap": {…} } ], "waits":
  [ <every recovery, hold or heir wait running for the account, with its end> ] }`; `inbox_ack { "iids": […] }`
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
| `welcome_offer` / `join_hello` / `join_nonce` / `join_confirm` | inviter → new device / new device → inviter / receiver of the hello → sender / new device → inviter (join-code direction) | 4.1, 4.2 |
| `welcome` | inviting device (or backup holder) → new device | 4.2, 4.4 |
| `repair_delta` / `repair_sigma` | helper ↔ helper / helper → new member or backup key | 4.2, 4.3 |
| `commit` / `commitments` | coordinator → co-signer / back (two-call form only) | 5.1 |
| `sign` / `partial` | coordinator → co-signer / back | 5.1 |
| `ecdh` / `ecdh_partial` | device → co-signer / back | 5.5 |
| `hold` | device → servers | 5.8 |
| `helper_stop` / `helper_resume` | device → servers | 5.7 |
| `stop_relay` | server → peers | 5.7 |
| `kept_done` / `kept_new` | device → devices (delivery) | 4.3 |
| `repair_ok` | new owner → repair helpers | 6.7.4 |
| `pair_request` / `pair_sign` | first device → second device (via `deliver`) / back | 6.2 |
| `change` | any member → members (a signed change) | 3.2 |
| `changes_get` / `changes` | member → server / back | 3.2 |
| `cancel` / `withdraw` | device → servers / sender → servers | 6.3 |
| `challenge` / `release_request` / `release` | server ↔ backup holder | 6.2, 6.5 |
| `take_out` / `released` | device → servers / back (children only) | 6.8 |
| `ack` | member → servers | 4.2, 7.1 |
| `notice` | server → members | 6.3, 8.2 |
| `push_register` / `push_unregister` / `notify_register` | device → server | 8.1 |
| `inbox_get` / `inbox` / `inbox_ack` / `deliver` | member ↔ server | 8.2 |
| `delta` / `paper_eph` / `dk_seed` / `release_seed` / `paper_item` | dealer → members (deliveries) | 6.7.3 |
| `stale` / `missing` | co-signer → requester | 6.7.1, 6.7.3 |
| `need_repair` / `rerepair` / `need_seeds` / `state_get` / `state` | member → servers / devices | 6.7.4 |
| `upload` / `upload_held` | dealer → seat holders / seat holder → co-signer | 6.7.3, 6.7.1 |
| `paper_reissue` / `reissue_eph` / `reissue_get` | device → servers / device → devices (delivery) / device → servers (the kept item comes back) | 6.7.6 |
| `seated?` / `seated` / `forward_get` / `forward` | paper app or device → servers / back | 6.7.5 |

| `part`, `error` | anyone | 9.1 |

The signpost (kind 30078) is the one Core event published on relays (§6.7.5); modules may publish their own (Doors and grants: grant events). That is the whole of Core. Cosign 0.12 has 55 message types in
`server/core/group.ts`; everything not here belongs to a module or goes.

### 9.5 Reading and writing JSON

Two implementations must decide every input the same way, so Core fixes how JSON is read and written. The
profile covers every **Keykin body** (any JSON Core or a module defines: rumor contents (§9.1), epoch
records and changes (§3), approvals, signposts, server lists, module events' contents, and a lock
assertion's `clientData` (§6.1)) and every **event object** Core parses: rumors, seals and gift wraps,
Keykin's own events, and every event a member is asked to co-sign.

- **Strict UTF-8 and RFC 8259.** Bytes are decoded fatally: a NIP-44 plaintext, a `clientData` or any
  other JSON text holding invalid UTF-8 (overlong forms, encoded surrogates, values beyond U+10FFFF) is
  `malformed`, never repaired with U+FFFD. The text is then one RFC 8259 JSON value: no byte order mark,
  comments, trailing commas, single quotes or `NaN`, and nothing around the value but RFC 8259's `ws`
  (space, tab, line feed, carriage return).
- **No key twice.** An object that names a key twice, at any depth, is `malformed`; it is never "last one
  wins" or "first one wins". Keys and strings are compared by code point after escapes are undone (`"a"`
  and `"\u0061"` are the same key), with no Unicode normalisation.
- **No lone surrogates.** A string or key holding an unpaired surrogate, raw or escaped (`"\ud800"`), is
  `malformed`.
- **No control characters but five.** A string or key holding, after escapes are undone (so raw or
  escaped), U+0000–U+001F other than U+0008, U+0009, U+000A, U+000C and U+000D is `malformed`. Every
  string, in NIP-01's id serialization and in JCS alike, is then written exactly so: `"` as `\"`, `\` as
  `\\`, the five as `\b \t \n \f \r`, and every other character as raw UTF-8 (`<`, `&`, U+007F, U+2028 and
  characters beyond U+FFFF included). Library writers that escape more MUST NOT be used for either: Gson
  escapes U+2028 and U+2029 even with HTML escaping off, Android's `org.json` writes `/` as `\/`, and
  Python escapes non-ASCII unless told `ensure_ascii=False`; writing both by hand is safest. This refuses
  a note holding U+000B, which Word uses for a manual line break; it is a known refusal, because Nostr
  libraries disagree on that note's id.
- **Depth.** The outermost value is at depth 1, and a value at depth 33 is `malformed`. Each JSON text is
  counted on its own (a seal, the rumor inside it and the rumor's content are three texts).
- **Integers only, spelled one way.** Every number is written `-?(0|[1-9][0-9]*)` with absolute value at
  most 2^53 − 1; `-0`, a fraction, an exponent (`1.0`, `1e0`) or a larger value is `malformed`, checked as
  the text is parsed, so no implementation rounds. This covers an event's `created_at` (non-negative) and
  `kind`. Decimal strings in Keykin tags (`["v","1"]`, `["epoch","<number>"]`) use the same spelling and
  are compared as strings.
- **Event shape.** A signed event (a seal, a gift wrap, a Keykin event) has exactly `id`, `pubkey`,
  `created_at`, `kind`, `tags`, `content` and `sig`; a rumor has the same without `sig`. `id` and `pubkey`
  are 64 lowercase hex characters, `sig` 128, `kind` an integer from 0 to 65535, `created_at` a
  non-negative integer, `content` a string, and `tags` an array of arrays of strings. Anything else is
  `malformed`. A receiver recomputes `id` (NIP-01) and refuses a mismatch.
- **A site's event.** An event a site asks to have signed (NIP-07, NIP-46, NIP-55) may leave out `id`,
  `pubkey` and `sig`, and an empty string or `null` there counts as absent; a missing `tags` counts as
  `[]` and a missing `content` as `""`; its other fields follow the shape above. The device refuses a
  `pubkey` other than `g`, drops `id`, `sig` and any extra field (a site's `id` is never trusted), and
  sends co-signers exactly `pubkey` (= `g`), `created_at`, `kind`, `tags`, `content` and `id`. A co-signer
  refuses any other field, recomputes the id (§5.4) and refuses one that differs.
- **JCS** is RFC 8785: keys sorted by UTF-16 code units; a string escapes only `"`, `\\` and U+0000–U+001F
  (as `\b \f \n \r \t`); every other character, U+007F and above included, is written raw. On values that
  passed the rules above this is ES2019 `JSON.stringify` with sorted keys, written by hand rather than
  through an object (a JavaScript object puts `"9"` before `"10"`). Every hash or signature over a body
  that another member checks is over JCS of the parsed value, which is the complete JSON tree with unknown
  fields kept (an implementation that maps bodies to typed records keeps the tree beside them), never over
  the bytes received, with two exceptions fixed by other standards: a lock assertion is checked over the
  `clientData` bytes as the authenticator made them (WebAuthn, §6.1), and an event id is over NIP-01's
  serialization. Wherever Core compares values ("an identical add", "the same `new`", "matches one entry
  of the list"), they are the same when their JCS bytes are equal. An add always carries `lock` (`null` when the device has none); an add without
  it is not a change.
- **A change names one change.** A change's `change` object, and every entry of an approved list (§6.7.2),
  has exactly one of `add`, `remove`, `lock`, `seat`, `paper` or `redeal`, plus `to` (a member key) with a
  `remove` only (§6.4); a key counts as present whatever its value, `null` included. Anything else there
  is not a change: it is refused, it is not "void", and it takes part in no rule of §3 or §6.7 (an
  exception to §11.1's "unknown fields are ignored"; module fields go inside the change they belong to).
- **Encodings in Keykin fields.** In a Keykin body or a Keykin event (not the tags of an event a site asks
  to have signed, which §5.7–5.8 judge): hex is lowercase, with exactly the length the field needs;
  base64url (RFC 4648 §5) uses the URL alphabet only, with no padding (Java's `Base64.getUrlEncoder()`
  pads unless told `withoutPadding()`), spaces or line breaks, a length that is not 1 mod 4, and zero
  unused bits in the last character. A part's `data` (§9.1) is standard base64 (RFC 4648 §4): length 0 mod
  4, at most two `=` and only at the end, and zero unused bits. A seal's or gift wrap's `content` is
  NIP-44's payload, standard base64 with padding, with zero unused bits; the same rumor under two wraps is
  one message, known by its recomputed id (this only removes duplicate wraps; §5.3 and §5.6 still decide
  replays of requests).
- **Saying why.** A device that refuses a site's event under these rules names the cause in its log and to
  the site (for example "contains control character U+000B"), never a bare `malformed`.

A legacy record (§3.4's `cosign` and `frost` tags) is read with the parse rules; its field encodings are
whatever Cosign 0.12 wrote (§11.2).

**Kind 0.** §5.8's test reads a profile written by any Nostr app. A kind 0 event is an event object, so
the rules above apply to it; its *content* is read with the first five rules only (UTF-8, RFC 8259, no key
twice, no lone surrogates or stray control characters, depth), and content that breaks one, or is not an
object, counts as empty; numbers inside it are checked against RFC 8259's grammar only, never converted,
so no form or size makes the parse fail. A field is non-empty when it is a string holding a character
outside this whitespace set (JavaScript's `\s`): U+0009–U+000D, U+0020, U+00A0, U+1680, U+2000–U+200A,
U+2028, U+2029, U+202F, U+205F, U+3000 and U+FEFF. So a sloppy app's valid-looking profile (a repeated
key, a BOM) is held for `W` like a blank one, and a name of invisible characters (U+200B, U+3164) passes,
as a name of `"."` does: a face-value test cannot judge content, and Device policy judges profiles on the
device.

Hostile inputs that every implementation must decide the same way are the shared negative vectors (§14), including U+2028 in a note, a signpost target in uppercase hex, and integer-like keys (`"10"` sorts
before `"9"` in JCS, unlike a JavaScript object's own key order).

## 10. Security properties, and their limits

**What holds.**

- One member signs nothing: not a device (3), not a server (1), not the backup (2), not a helper (3).
- All servers together (3) can never sign, and neither can two colluding operators. Every server a seat
  has ever had holds the same seat value, so in any one state all the servers ever seated are still 3
  distinct points.
- A server can delay or withhold its share and see what it co-signs. It cannot sign, cannot make an
  epoch record or a change, cannot add a member that others believe (live finding #1), cannot read
  messages (decryption answers are useless without a device's own points), and cannot fake a push.
- A joining device trusts only its scan, the group key and the join check typed on the side that showed the code (#17).
- A lock is a biometric-only signature that servers check, not a device's word (#4). A face reset on a
  stolen phone kills its lock.
- **No account change without a lock, two devices with a typed code, or the paper.** A thief holding one
  phone without its lock cannot add a device, report the owner's devices, seat a server or touch the
  paper. They can sign everyday events, and start holds, until the owner reports the phone from a second
  device or with the paper.
- Everyday changes are independent and safe in any order, so the account cannot fork and a device that
  was away catches up by fetching them.
- A stolen paper needs two servers that each waited, with every device and channel told; the owner's
  locked device, or two devices, can stop it.
- The paper is checked when it is made, signed by its own key and pinned; every later redeal adds a
  paper delta that devices check after each apply, so a missing one is caught.
- Servers, the helper and the paper can always be replaced, with no step needing everyone online and
  nothing that can get stuck (§6.7.8). Every replacement and report-lost kills old pieces held by
  honest members and rotates the data and release keys.
- Nonces never touch storage and are hedged, so no restore or snapshot replays one.

**What does not, said plainly.**

- **Kept pieces combine, across states too.** A redeal kills old pieces only in honest hands. Pieces of
  one state that someone kept combine for ever: a removed device plus a server that was dishonest at the
  time, a removed device plus the paper, or the paper plus two servers that kept the same state. And
  because every redeal has a zero constant term, anyone who knows a redeal's `δ` can move pieces across
  it. Every device of that time knows `δ` (its 3 values plus `δ(0) = 0`), as do the three servers
  together, and the paper plus one server. So a stolen paper plus one current server plus one retired
  server from an older state can be the key, with no wait. Prompt replacement and a new paper narrow
  this; nothing in the core ends it. Key families (a module) let followers move to a new master set up
  beforehand, ideally on other servers' operators; the old key stays usable to whoever holds it.
- **Devices of one account may follow different server lists** (different apps, or a list added by
  hand). A server sending the `ask` can then choose which device to ask, and so choose among those
  devices' picks. Each pick is still deterministic on its list, and no seat moves without the person's
  approval.
- **A stolen paper plus one dishonest server reads the account's data**, never signs. Every server holds
  the release seeds that open the paper's items, so with the paper it gets the seeds, and so every data
  key, without a wait. A paper already did for every state after it; since 14.21 it also does for the states before it, because it carries every seed so that an honest recovery loses no data.
- **A paper reaches every state since it was printed**, through its paper items. A stolen paper is
  dangerous until it is replaced, and the app cannot know it was exposed.
- **A lone device has no second checker** of a paper item it dealt itself. It opens the item with its own `paper_eph`, so a bug in its own sealing shows at once, but a fault it shares with the item surfaces only at an optional paper check, or at recovery.
- **A dishonest helper at a redeal** learns `δ`, and with a retired server is the key. The helper is
  opt-in.
- **A retired server that never hears it was replaced** keeps answering everyday rounds at its old
  state, which pairs only with pieces kept from that state (above). It starts no wait and releases
  nothing without first checking its peers, and after 7 days offline it stays passive, so a stolen paper
  can't use it to recover behind the account's back.
- **Forwarding notes and `seated?` answers** tell anyone holding the current backup key (forwarding notes: a current or former one) which
  hosts serve the account. That is addresses, not power.
- **The signpost's device copy uses the base data key**, which never changes, so a removed device or an
  old paper can read today's server endpoints for ever. Servers never act on the signpost, so this leaks
  addresses, not power.
- **One Face ID per dead server**, and no automatic replacement: a standing order would let a thief plus
  one week-dead server seat a server.
- **A server that answers but won't co-sign isn't detected automatically.** Unless it answers `deleted`
  or "unknown account" or gives a confirmed shutdown notice (§6.7.7), it never counts as dead for F1, so
  it keeps its seat until the person moves it (F4), prompted only by §6.7.9's quiet line; one that sends
  refusals, or refuses only recovery, helper or Upkeep rounds, brings no line at all. Signing still works
  through the other servers. While it sits in a seat, a paper recovery relies on the other two servers,
  and one more dead server ends paper-only recovery.
- **App grants on platforms that can't name the caller.** On Linux or Windows, a local program that reads
  an app's stored grant secret can get member-key signatures under that app's domain (§5.9), as local
  software running as the person can already read an extension's storage.
- **Two servers dead and every device lost before replacement** ends paper-only recovery.
- **A lone device without a working lock** (a passcode-only phone, a new fingerprint enrolled, an
  extension, a Mac without Touch ID) needs the paper in hand to add a device, make a paper, re-lock or
  replace a server. That is the price of "no wait instead" (user, 2026-11-03: it stays). Apps quietly suggest a
  second device, which a browser extension on a laptop counts as, and never push.
- **A stolen current device plus any dishonest retired server** from any state since the device joined
  is the key, because the device could work out every `δ` since then from its own values (it keeps
  only the paper's two, and only until they are delivered, but a thief who took the device during that
  time, or extracted it earlier, has them). Replacing a suspect server protects other
  members from it, not a phone stolen later.
- **The change set never compacts** (about 10 KB a year).
- **The public signpost** shows that the account uses Keykin and roughly how many seat or paper changes
  it has had.
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
  is the bar. A desktop app keeps its shares in the OS keychain, which other programs can't read
  silently on macOS; but a local program that can reach the app's native-messaging host can ask it to
  sign for any site the app has a grant for. So the host's manifest lists only Keykin extension IDs in
  `allowed_origins`, the app accepts only a browser-launched host it has checked, and grants are per
  browser, profile and origin. Windows and Linux can't authenticate the caller as well as macOS can.
  Browsers that can't reach a native host (Flatpak or Snap, some managed policies) leave a second
  member if the app joins separately; the app's join screen asks about an existing extension.
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
- **Helper plus one server** signs, by design: the person opted in to that. It signs only the kinds of §5.7
  item 8, and any one device can stop it at once. But the helper's 3 shares plus **any one dishonest
  server's** share are 4 points: the whole key, offline, with no kind limit. So is a stolen helper box
  plus one dishonest server.
- **A lock accepts any enrolled biometric**, a partner's finger included, as the phone itself does.
- **Locks are unattested.** Servers cannot tell a hardware, biometric-only key from a software one, and a
  tampered app can make its own "lock".
- **Browser profiles.** An extension keeps shares a copied profile can carry away unless the browser
  offers prompt-free secure storage (live finding #5). That is 3 points, not the key: better than an nsec
  in the same storage, which is the bar. An extension never has a lock.
- **Until the paper is printed**, the device that made it holds 5 points (§4.3). On a lockless device
  whose person declined a paper, that lasts until a lock is registered or a paper is read back, and every
  lockless device holds it meanwhile: whoever copies any of those browser profiles in that time has the whole key **and** every approval a paper gives, deleting the account
  included, and keeps that paper power until a new paper replaces the backup key.
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
| #2 paper added with any key | papers only at creation or by an approved `paper` change (§6.7), checked, signed and pinned |
| #3 report-lost race | §6.2, §6.4 (lock, two devices with a typed code, or the paper) |
| #8, #9 server archive and ECDH oracle | §2 (no history), §5.5 (devices only, weighted) |
| #12 paper promotes itself | kinds never change; a backup is never a device |
| #13 stranded server, #14 removal in a pending refresh | deliveries (§7.1); no plans or epochs move: a remove travels with its redeal in one list (§6.7.2) |
| #16a/b optional or partial proofs | §5.5 |
| #5 extension shares unencrypted | encrypted where it costs no prompt (§7.3); otherwise 3 points, which beats the bar (§10) |
| #10, #15 | Doors and grants module (a `private-data` scope; revoke tombstones only a human act clears) |
| #11 app data not judged | not closed: Device policy deliberately doesn't judge app data (holding it would nag); only `keykin-` app data is guarded |

## 11. Versions, moving from Cosign 0.12, the rename

### 11.1 Versions

- Core follows semantic versioning. Any wire change bumps the major version, which is `v` in every
  rumor, every epoch record, every change and every push payload.
- Unknown fields have no meaning of their own, but are kept, hashed and compared (§9.5); in a change's
  `change` object they are refused. Unknown message types are refused (`unsupported`). Unknown member kinds are
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
announcement `d` tag `cosign-server`, `cosign:` codes, and Cosign paper QR codes, which they recognise and explain: a
0.12 paper belongs to the 0.12 account, which moves only by import (§11.2). Writers use the `keykin` names. Kind numbers 24301, 24302, 30242, 30243, 10243 and the key-family kinds
1244–1247 stay provisional until upstream assigns them.

## 12. Modules (not part of Core)

Each is a short document of its own, and none may weaken anything above.

- **Account admin**: creating a key (DKG, import), adding and removing devices on screen, a device
  leaving, delete (NIP-62 plus destroying shares and forgetting push addresses), taking data out.
- **Server profile**: the duties as an operator sees them, abuse defaults, the 30-day shutdown notice,
  telling the person calmly after a week that a server is quiet and offering to move its piece (§6.7.6
  F1), signed server lists, any number of them (§6.7.7),
  announcements (kind 30243/10243), the operator notice.
- **Device policy**: the destructive check, Undo from the device's own history, rebasing staged drafts onto
  the newest version, honest quiet notices.
- **Doors and grants**: NIP-07, NIP-46 (per-site signer keys, bunker://, watching), NIP-55, the QRST
  signer-ticket, the same-device door on iPhone, grants and scopes, the iOS push appendix.
- **Backup**: 24 words, recovery contacts, heir. (A paper finds today's servers by the server lists, forwarding notes and the signpost, §6.7.5; the old escape hatch is F3.)
- **Helper**: the opt-in (joins by a `seat` change, §6.7.6 F6).
- **Key families**: family events signed by both keys, NIP-03 timestamps, release and leaked events; child groups. This is the answer to a
  serious leak of the key itself.

## 13. Open items

- **Formal check** of the one-call round (§5.1).
- **Outside reviewer** sign-off on the core.
- **Upkeep** (§6.7) needs its own red-team round and vectors (`vectors/vectors.md`, case 12).
- Repair with mixed-weight helpers relies on `frost-core`'s `repairable` module; its behaviour with a
  helper holding 3 indices must be pinned by vectors.

## 14. Test vectors

The vectors are in `docs/keykin/vectors/` (`vectors.md` describes them; `vectors.json` is generated
by `gen_vectors.py`). Done when the TypeScript and Kotlin implementations both
pass it and a fuzzed parser has run against every message. `vectors/negative.json` holds 300 negative and edge cases (§9.5's reader, JCS, UTF-8, base64, §5.8, §3.4,
membership and more), each agreed by the TypeScript and Kotlin implementations in a differential run. The interop plan is
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

## Changes in draft 8.5

From the re-check of §4.6 (no critical or high): the extension checks the app's membership with a
fresh challenge and its own view before deleting or retiring; the handover runs the full §3.4 checks,
finishes in-flight work first and moves push registration; a `self` approval for self-removal; lock-change
retries after a void; §10 on the desktop app's native-messaging host and browsers that can't reach it.

## Changes in draft 9

**Keykin Upkeep** (§6.7), from the hub's design panel, replaces `refresh.md`. Servers, the helper and
the paper have fixed seats. A replacement is repaired at the same index, so a newcomer never adds
weight. Every seat change and report-lost carries a mandatory redeal that kills honest members' old
pieces and rotates the data and release keys. Members track a set of applied redeals (their state)
instead of epochs, so nothing needs everyone online and nothing gets stuck.

New pieces: `seat`, `paper` and `redeal` changes with approval lists; process-memory dealing;
`need_repair`, `rerepair` and `need_seeds`; paper deltas; the beacon with a fail-closed freshness check;
and a deterministic replacement pick from a signed server list.

Added while writing it in: a site can never get the beacon signed, and a server destroys its share only
after verifying the group-signed seat change that replaced it, never on a beacon alone.

§10's "structure is fixed" limit is gone, replaced by Upkeep's own limits. The §4.6 one-member rule is
kept.

## Changes in draft 10

From red-team round 9 (0 critical, 6 high), with the hub's two decisions:

- **Servers never read the signpost** (the old "beacon"). It is a paper's and a sleeping device's
  signpost only, published at creation, and a site can never get it signed or deleted (H1, H2, M3, M4,
  L3).
- **Release seeds**: every redeal adds one, members keep every seed of their state, and welcomes carry
  them (H3, L4).
- **The backup material is a set of items**, one per redeal, each under its own release seed, so
  concurrent redeals just add up (H4).
- **Any 4 points fill a seat**, including two devices or a device with the paper (H5).
- **A paper missing a piece means a new paper**, never a same-key repair (H6).
- Mediums:
  - `rerepair` only for redeals never addressed to the member (M1);
  - `need_repair` only for a seat's current holder (M2);
  - a removal's stranded redeal is re-dealt, never stepped back past (M5);
  - the list binds its redeal's dealer (M6);
  - a seat holder's welcome is defined, with no data key (M7);
  - §10 states what knowing `δ` allows (M8).
- Lows: signpost ties and lookup by author; one host in two seats voids both; `new: null` empties a seat;
  the paper co-signer checks `replaces`; and a dead peer never slows everyday signing.

## Changes in draft 11

From red-team round 10 (0 critical, 2 high):

- The signpost is a hint: recovery follows the paper's printed servers and the group-signed seat
  changes, and co-signers refuse every signpost delete and check `n` (H1).
- `need_repair` is never answered for the backup seat (H2).
- Step-back is gone: a stranded redeal is replaced by a fresh one and members are repaired forward (M1).
- `rerepair` works for any redeal a current member lacks (M2).
- Servers fetch nothing extra before everyday signing (M7).
- Paper items are verified before applying (M3).
- An unexplained `self` remove prompts a redeal (M4).
- Deliveries go only to the post-change view (M5).
- Paper/redeal races closed (M6).
- Lows: the base item's release seed is named, the helper leaves only by a seat change, seat changes
  for the same host are deduped, the signpost's public footprint is stated, and references are fixed.

## Changes in draft 12

From red-team round 11 (0 critical, 1 high):

- **Finding today's servers** no longer depends on the signpost (H1). The paper app asks the signed
  public list (`seated?`), and retired servers keep one forwarding note: the change that retired them.
  The signpost remains for private servers, with an `n` that only grows, an `h` co-signers check, and
  enforceable delete guards (M1, L1).
- An unexplained `self` remove raises the report-lost card (M2).
- A replaced paper key is removed and refused (M3).
- Stranded redeals get `base` and `abandons` (M4).
- Retired servers check their peers before waits or releases, and stay passive after 7 days offline (M5).
- Devices re-issue missing paper items instead of forcing a reprint (M6).
- §10 states the lone-lockless-device and stolen-device-plus-retired-server limits (M7, L10).
- `upload`, `state_get`, the `rerepair` challenge, and what an incoming holder fetches (M8).
- Lows: the co-signer applies only with the group-signed list; `need_seeds` for servers; `cosig`
  notice-only and stored; one list hash; the approving device enforces once per K; the newest list
  version picks; a 90-day lookup on open; verified bits for redeals applied by delta.

## Changes in draft 13

From red-team round 12 (0 critical, 1 high), all local:

- Devices keep `δ(b1)`, `δ(b2)` and the data-key seed until the current paper's item is verified, so
  re-issue works (H1).
- A `self` remove only for §4.6, countersigned by the app (M1, L4).
- Concurrent seat lists can't put one host in two seats (M2).
- Catch-up messages show a "Report lost" button, and `need_repair` is answered once per key and index
  (M3).
- Devices can use `seated?` and forwarding notes (M4).
- Passive servers are released by a peer, or after a full wait (M5).
- Re-issued items are signed, capped and checked per item (M6).
- A paper may lag some redeals, and devices fill the gap (M7).
- Stranded-redeal edge cases (M8).
- Lows: signposts for later-seated servers, the table rows, the §2 list, `rerepair` and the backup seat,
  delta recipients, and numbering.

## Changes in draft 13.1

From red-team round 13, the first clean round since Upkeep (0 critical, 0 high), its mediums and lows:

- A redeal that travelled with a `remove` is never abandoned, and a device re-deals if no redeal
  excluded a removed member (M1).
- A paper whose base was abandoned is flagged for a new paper (M2).
- F7 fills in the paper's `state` at step 4 (M3).
- Passive servers are released only by a current seat holder (M4).
- A failed `need_repair` doesn't use up a server's one answer (M5).
- Re-issued items carry clear commitments that servers and devices check, so bits set and kept values
  go (M6).
- A `self` remove carries a redeal dealt by the app (M7).
- Lows: §10 wording on what a device knows, one list hash, "remove a device" only, the new messages,
  who deals in F9, `upload_held`, double abandons, dedupe losers removed, and the `seated?` signature.

## Changes in drafts 13.2 to 13.15

Small clarifications from the module reviews, none a new mechanism: the host-signed enrol reply in a
seat's `new` entry, refusing picks fall through, no future-dated kind 5 (13.2); own servers don't hold
grants, opt-in NIP-46 watching, heir storage and the heir wait (13.3); the newest public server list kept,
and `seated?` verified (13.4); what a watching server keeps for each signer key, and the heir record (13.5); a declined or unfinished paper is destroyed, and the passkey page is dropped (13.6); a server's own keys in §2, and peers may fetch forwarding notes (13.7); §5.8's tests made exact, a list with private items isn't empty, co-signing devices refuse rather than prompt, rebased drafts (13.8); modules may publish events (13.9); heir waits named in §1 and §2, Cosign papers explained rather than read (13.10); `account_delete` approved like other changes, and its tombstone (13.11); encodings and rules pinned from the reference implementation's first batch: the approval `expiry` field, the `pair`, `paper`, `recovery` and `release_request` signatures, `ecdh_partial`, `rs`/`dk` as seed hashes, the hedge stream, a list in every change event, lifetime classes, approvers, duplicate-key adds, kind 5 skew, list-hash ordering, and recovery changes co-signed only by the holder (13.12); heir waits in `inbox_get` and §2's table, and heir lookups (13.13); a removed key's holder destroys what it holds under that key (13.14); a `paper` approval of a request that isn't a list, and the delete tombstone keeps its approver's changes (13.15).

## Changes in draft 14

From the user's answers on the Helper and Key families modules (2026-11-03):

- A round the helper coordinates is co-signed only for notes, replies, comments, reactions, reposts, zap
  requests, media posts and relay auth (§5.7 item 8).
- Any one device stops the helper at once with `helper_stop`, no approval; servers keep one flag until the
  helper seat changes (§5.7, §2 item 6, §6.2).
- The helper's entry names its host, and no host holds both the helper seat and a server seat (I6).
- A helper never co-signs for others (§2 table).
- §10 and F10 say plainly what key families do and don't do.
- From the module reviews: `helper_stop` names the helper's key, travels in seat welcomes and is fetched
  before helper rounds; `helper_resume` with an approval; devices never co-sign helper rounds; §10 says a
  helper plus one dishonest server is the key; key-family releases and leaked events are in §5.8.
- An imported 0.12 account may be a child of a new master (§6.8).
- On a device with no lock, a declined paper keeps the backup secret sealed until a lock or a read-back
  paper exists, held by every lockless device meanwhile (§4.3 step 4; the user's answers to Q6 and Q7).

## Changes in draft 14.1

From the red team of every core change since 13.1 (0 critical, 1 high):

- Requests with no co-signer (`account_delete`, `take_out`, notice-channel removal) are checked by every
  receiver against its own view of current devices, and a peer's `deleted` counts only from a current seat
  holder (H1).
- Void adds' keys go into `removed` (M3).
- `helper_stop` names the stopping device; relay auth by the helper only for the account's own relays
  (M2, M4).
- §10 says what a lockless kept backup secret exposes, and a repeated sentence goes (M5).

## Changes in draft 14.2

From the reference implementation's batch 2 (items 18–27), in the new §6.7.10: repair sigmas sealed only
to the index's owner and who may ask, the `rerepair` proof, single-use bound challenges, redeal-first list
co-signing, the `material` field, who may upload, signpost ids delivered to servers, one key one member,
and the co-signer's trial of a change; "one host in two seats" means at once (§6.7.2).

## Changes in draft 14.3

From the red team of 14 to 14.2 (0 critical, 1 high):

- A list is co-signed in **one** request, all or nothing, at the pre-redeal state, and no member applies its
  redeal before every event is signed (H1; replaces 14.2's redeal-first rule).
- Requests with no co-signer skip a silent peer after an hour, are re-sent until answered, and include
  `helper_resume` (M1, M2).
- Challenges are reused only by a retry of the same request (M3).
- The helper's relay sign-in can't be limited by servers; the module says so (M4).
- §10 says a copied kept secret keeps paper power until a new paper (M5).

## Changes in draft 14.4

From the Helper module's fourth red team: a stop always applies and stops the helper seat, whoever holds
it; a resume clears only lower-numbered stops; devices show "Stopped" once a server confirms.

## Changes in draft 14.5

Q7 (hub, on the user's Q6 reasoning): a lockless account's kept backup secret lasts until any device has a
lock or a paper is read back, every lockless device holds a sealed copy meanwhile (carried in welcomes),
and `kept_done` destroys every copy.

## Changes in draft 14.6

From Account admin's fifth red team: a lock counts as registered only once its device has finished joining
(welcome acknowledged); the kept secret always follows the current backup key; `kept_done` names its
trigger and comes only from a current device; a new paper is suggested afterwards.

## Changes in draft 14.7

From the red team of 14.2 to 14.5 (0 critical, 1 high) and Helper's fifth:

- A list's events each get their own nonce commitments and partials, and one nonce pair signs one event,
  ever (§5.2, §6.7.10; H1).
- F7 deals its redeal with the paper change, as one list, and retries the redeal without a new paper (M1).
- A helper seat change clears only the stop counters it names; stop counters are capped (M4).
- Helper rounds are never dated ahead.
- `kept_done` is in the message table.

## Changes in draft 14.8

From the reference implementation's batch 3 (items 28–33): `participant` is the index being repaired, and
repair requests' fields; **a helper checks the helper list against its own view** (independent review 2
reproduced a fourth point without it); `repair_ok` from the owner marks a `need_repair` as succeeded; a
`paper` challenge is used once per list hash; which release seed opens an F7 base (§6.5 step 4); and
"one host in two seats" decided by the changes alone (§6.7.2).

## Changes in draft 14.9

From Helper's sixth red team: helper stops carry an id and are kept as account state that never expires;
a resume (with an approval, checked by every receiver) or a helper seat change (`clears_stops`) clears only
the stop ids it names. The stop counters of 14.4–14.7 are gone. Also: `kept_new` carries a lockless
account's new kept secret after an F7; the delete tombstone keeps the epoch record.

## Changes in draft 14.10

From the red team of 14.5 to 14.8 (0 critical, 1 high): the backup may be a repair helper alongside a
current device under a `paper` approval, so F3 works for a one-device owner with a paper (H1); a
co-signer's hedge includes the event's position in a list (M1); devices keep paper deltas for 30 days
after a redeal, for F7s that straddle it (M2); "one host in two seats" voids only changes approved within
24 hours of each other (M5); a server answering `deleted` or "unknown account" while its peers serve the
account counts as dead for F1 (M6).

## Changes in draft 14.11

From Helper's seventh red team (0 critical, 0 high): cleared stop ids are kept as account state so a
cleared stop never returns; at most 3 stops in force per member; a `paper`-approved resume gets a
challenge from every server.

## Changes in draft 14.12

From the red team of 14.8 to 14.11 (0 critical, 0 high), its mediums: paper deltas are kept past
verification only by the device running an F7, and the "verified" bit is per backup key (M1); `kept_new`
only after F7 step 5, checked against the current backup key (M2); a server answering `deleted` or
"unknown account" for a day brings the F1 card on its own (M3); servers list stop ids in force to devices,
and keep cleared ids a year (M4, L5).

## Changes in draft 14.13

From the reference implementation's batch 5: `stop_relay {stop, by}` carries helper stops between
servers.

## Changes in draft 14.14

From the final seam review across the core and all modules (0 critical, 0 high): per-server `challenges`
for `paper`-approved requests checked by every server (M3); report-lost under a `recovery` approval in
§6.5 and F9 (M4); `deliver` slots, so cumulative reports replace each other (M5); the helper's host bound
in its join (L10); lifetime classes for every message (L13); §11.3 and §12 brought up to date (L14).

## Changes in draft 14.15

From the reference implementation's batch 6 (a differential run over two implementations): §9.5, a strict
JSON profile for bodies and events: fatal UTF-8, no repeated keys, no lone surrogates or stray control
characters, depth 32, integers spelled one way, JCS, a change naming exactly one change, hex and base64,
the event shape and a site's event, §5.8's tag counting, and the kind 0 whitespace set. Five red-team rounds (3, 2, 1 and 1 high, then clean; no critical) are folded in, with the last
round's mediums: how a kind 5 targets a signpost (§6.7.5), and what an empty `content` is (§5.8).

## Changes in draft 14.16

From the reference implementation's batch 6 follow-up (item 46): an add always carries `lock`, `null` when
there is none, as both implementations already require; the "absent `lock` counts as null" line is gone.
`vectors/negative.json` (300 cases) joins the vectors.

## Changes in draft 14.17

Pointers only: a shutdown notice counts for F1 through the server's live answer (Server profile §4.1,
draft 8).

## Changes in draft 14.18

From the reference implementation's item 48 (b): a kind 5's `a` value hits the signpost when it contains
both `g` and a signpost `d`, whatever its kind part or splitting (§6.7.5). Item 48 (a), by the hub's Q10
answer (b): a server that answers but won't co-sign is not detected automatically. It is stated as a limit
in §10, and §6.7.9 adds a quiet Backup line with a button to move it by hand (F4).

## Changes in draft 14.19

For the encrypted-sync spec, in the signing form the reference implementation built (deaab29; its grant model is not built yet): §5.9, member-key
signatures for apps, `SHA-256(utf8(domain) ‖ 0x00 ‖ message)` by the device's own member key, with every
`keykin…` and `cosign…` domain reserved. Domains are granted by app lists with OS-checked
identities; a by-hand grant never covers a listed domain; a per-grant secret is used where the OS can't
check. Never through a door; device keys only. The device API gets `members.devices()` (with F5 flags) and
a durable `members.removed` log that covers every way a key leaves. Every member-key signature in Core and
its modules is now tagged, including the three challenge signatures (`keykin-retire/1`,
`keykin-seated-ask/1`, `keykin-forward-ask/1`). Three red-team rounds (2 high, 1 high, then clean; no critical) are folded in.

## Changes in draft 14.20

From the reference implementation's review 13 (M4) and five red-team rounds (1 critical and 1 high, then 1, 2 and 2 high, then clean):
- **`paper_eph` replaces `paper_ck`.** The dealer sends devices the paper item's ephemeral secret instead
  of a conversation key. A device checks it against the item's `eph`, derives the conversation key itself,
  and checks the item's contents against its own `δ(b1)`, `δ(b2)` and `dk_seed`. A dealer can no longer
  make devices drop their paper values for an item the backup key can't open.
- **Re-issued items** (§6.7.6) get the same treatment through `reissue_eph`, an ordinary delivery. Other devices open and compare them before destroying anything, which closes the same silent loss on the re-issue path (the critical). Servers keep the first item per device, redeal and K for good. Devices check that two servers hold it, and re-issue at most once. `reissue_eph` names its K, a server can't make a device blame anyone on its word alone, and an equivocating re-issuer only delays others' own re-issue by 7 days.
- **A failed check** applies the redeal anyway, keeps the values and re-issues the item. It shows a dismissable line naming the dealer, separate from the paper dot. `paper_eph` is bound to its redeal and item, so a server replaying an old one can't make a device blame an honest dealer; a missing or mismatched one is fetched from peers and never brings the dot.
- **The co-signer** also requires `paper_eph` and `dk_seed` deliveries.

## Changes in draft 14.21

For the vaults spec (vaults.md §12.3), and a core gap it found:
- **The paper now carries every data-key seed** (§4.3, §4.5, §7.2, F11). Before, the base item held only
  the base data key, so after any new paper a paper-only recovery couldn't derive the data key of any
  state, and everything encrypted under the data key was lost. Seed items beside the base now hold every co-signed redeal's seed, and the paper change lists their ids in the clear. The printer fetches any it lacks first. Every device re-issues, as a seed-only item under the paper release seed, every seed it holds, for each new backup key, so abandoned, stranded and late seeds are never lost, and every server and device keeps the paper release seed and passes it on.
- **Every device keeps every seed** for the account's life, abandoned and stranded redeals included, and passes them on.
- **`dataKeys.derive(ids, info)`** gives apps keys derived from a state's data key, never the key itself,
  under a granted domain and only for a real state. Also `current()`, `states()` and `onRotate`.
- **App-list domains can be `open`** to hand grants, per domain. An entry can cover a whole first
  segment (§5.9). When the member acts as a vault app, it signs under the app's domain.
- **§10** states that a stolen paper plus one dishonest server reads the data, as a creation paper always
  allowed.
- Eight red-team rounds (2, 2, 2, 2, 1, 1 and 1 high, then clean; no critical) are folded in. In the end the design is simple: every device sends every seed it holds to the current backup key, the paper carries the printer's copy, and the paper's own release seed is kept while it is current.

## Changes in draft 14.22

A neutrality pass, with no change to what any check verifies:
- **Server lists:** any app maker, operator or community may publish one, and none is special. Apps pin the lists they trust, the person may add one with a warning, and each device picks replacements from its chosen list (§6.7.7). The `ask` names its list. §10 states that devices on different lists give a server a choice among their picks.
- **App lists (§5.9):** open to anyone in the same way. A domain goes only to apps every followed list naming it allows, and a hand-added list can only narrow a pinned one.
- **"Keykin minimum"** (`minimum.md`) states the smallest set of MUSTs for a door, a member device or a
  server.

## Changes in draft 14.23

From the reference implementation's paper recovery over real relays:
- `seated?` and its challenge are answered at the host, which looks through every seat it holds. The
  sealed answer carries `g`, the epoch id, and each current seat server's member key, host key, HTTPS
  endpoint and relays (§6.7.5 route 1).
- A words-only holder checks the signpost's `h` once `seated?` has given it the epoch id (route 3).
- The answer is a list of entries and a hint, trusted only once two servers return matching records; an heir gets no member keys. `W` is a Core constant (§1).

## Changes in draft 14.24

From the reference implementation's red team of joining by showing a code (§4.1): the 6 digits now
protect whichever side showed the code. The side that scanned shows them, and the person types them on
the side that showed the code. In the join-code direction the new device confirms with `join_confirm`
before the inviter adds it. Before, someone who saw a new device's code could answer first and make the
device join their own account. A second offer for the same code stops the join.

## Changes in draft 14.25

App-private data (§4.5): NIP-44 to self stays a shared pool that `private-data` opens. An app that wants isolation keeps its records under `dataKeys.derive` on its own domain, which no door can open. Each OS-identified app owns an identity domain silently, so no binding has to be synced; derivation is only under identity, listed or open domains, and cross-platform sharing takes an app-list entry. The text says where the device API exists (Android, desktop, browsers; not other iOS apps or websites), who else can read the records, how to re-seal, and what to do before leaving. Six red-team rounds (2, 3, 1, 2 and 2 high, then clean; no critical) are folded in; on desktops the isolation is stated as being from sites and other granted apps, not from local software (§10).
