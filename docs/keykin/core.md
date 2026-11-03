# Keykin Core

Draft 13.4 · 2026-11-03 · `draft` `optional` · not built

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
- **Wait**: a delay, 3 days by default (`W`), that servers apply on their own clocks to exactly two
  things: a paper recovery (§6.5) and a held mass deletion (§5.8).
- **Release seeds**: random 32-byte keys held by devices and seated servers, never by helpers or
  backups, that wrap the backup material's items a second time (§7.2). Every redeal adds one.
- **Data key**: a random 32-byte key held whole by devices only, for reading the account's own
  private data. It can read, never sign, and changes with every redeal (`dk(S)`, §4.5).
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
   scanning it back or re-entering it (§4.3);
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
3. every release seed of its state, and the backup material (§7.2);
4. running waits (recoveries and holds) with their notices, and recovery sessions (§6);
5. push addresses and notice channels (§8.1), and the inbox, including deliveries kept until
   acknowledged (§7.1);
6. answered request ids until each expires (§5.6), and its own counters for §5.8.
7. if the person opted in, the account's NIP-46 signer public keys, for watching (below);
8. if the person set up an heir (Backup module), the heir envelope, its own piece of the envelope key and
   the heir's public key;
9. the newest public server list it has verified (Server profile module).

A server MUST NOT keep signed events, list versions, site grants or logs of what it signed. It
co-signs, checks approvals, enforces the two waits and the stateless destructive rule (§5.8), sends
wake-up pushes, and helps with repair (`need_repair`, `rerepair`). That is all.

**Watching for NIP-46 (opt-in).** If the person turns it on for a server (default off), that server
MAY keep a list of the account's NIP-46 signer **public** keys, watch its relays for kind 24133 events
addressed to them, keep each one in the inbox of the device that holds the grant (about 2 minutes,
`ask` class), and push that device. It never holds a signer key or a grant, so it can't read the
requests, only see when a site is talking to the account. This is how a sleeping iPhone answers a
borrowed computer or a desktop site.

| | device | helper | server | backup |
|---|---|---|---|---|
| Coordinate everyday signing | yes | yes | no | only in a recovery session (§6.5) |
| Co-sign for others | yes | yes | yes | no |
| Get decryption answers (§5.5) | yes | no | no | no |
| Approve an account change (§6.2) | with its lock, with a second device, or with the paper | **no** | no | with a device, or in a recovery |
| Cancel a wait | with its lock, or with a second device | **no** | no | no (the holder withdraws its own) |
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
  "change": { "add": { "key": "<member key>", "kind": "device", "lock": { … } | null, "salt": 0 } },
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
  knows, the seats included. If two changes of the epoch ever claim the same index, both adds are void and the new
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
- **I6.** A helper holds exactly the helper seat.
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
3. **Repair.** At the current state (named in every message), for each new index, the inviting device
   (3 shares) and one server (1) run the repair of
   `frost-core`'s `repairable` module with all 4 shares as helpers: each helper share computes its
   Lagrange-weighted deltas, the helpers exchange them (`repair_delta`), and each sums what it received
   into one `sigma`, sealed to the new device (`repair_sigma`). A server MUST take part only for indices
   that a valid change assigns to that new device. No member ever sees the new share.
4. **Welcome.** The inviting device seals to the new device (`welcome`): the epoch record, the set of
   changes, the relays, the state, every release seed of the state, the backup material (every item,
   §7.2), the base data key and every data-key seed (§4.5).
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
wrapped (§7.2). The read-back (step 4) checks every field. It is made at account creation, or by a
`paper` change (§6.7.6 F7), and it is checked on the device that prints it:

1. The device makes the backup key pair.
2. The device and one server repair the backup seat at the current state; every `repair_sigma` is
   sealed to the backup key. The device, which holds the
   backup secret at this moment, opens them, sums them and checks the shares against `P_i`.
3. The device wraps the shares and the data key (§7.2) and signs the inner layer with the backup key.
   The epoch record (at creation) or the `paper` change (later) pins the inner layer's hash, so members
   refuse any other copy. A `paper` change commits only together with its material.
4. The device keeps the backup secret, encrypted at rest (§7.3), until the person has printed or saved
   it **and shown it is readable** by scanning it back or re-entering it (§1.1), then destroys it and
   the shares. Until then that device alone is worth 5 points, the same as an nsec on it; it SHOULD
   prompt to finish the backup.

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
Data names the state hash it was written under; devices keep older keys to read older data, and data
services re-encrypt lazily.

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
     backup material, the base data key and every data-key seed, plus its site grants and its history.
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
- **Retiring an extension.** When an extension that holds a membership finds the app, it first asks
  the app to sign a fresh challenge with the member key it claims and to re-run the share check. An app
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
  no lock until the app registers one by a lock change (§3.2).

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

(`H` is SHA-256; points 33-byte compressed, integers 4-byte big-endian, scalars 32 bytes.)

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
   other co-signers'), is worth at least 4, all at the named state, and the commitments cover it
   exactly (§5.1);
3. the request is fresh and not a replay (§5.6);
4. `event.pubkey` is `g`, and, for a **replaceable or addressable** kind (0, 3, 10000–19999,
   30000–39999), the event's `created_at` is no more than 10 minutes ahead of its own clock: a version
   dated ahead would block every later change until that date. A deletion (kind 5) may not be dated
   ahead either, since under NIP-09 it would delete future versions of its targets. Other kinds may be
   dated ahead, so a person can schedule a post;
5. if the event is **kind 30242 or kind 24302, whatever its tags, or a kind 30078 with the account's
   signpost `d`, or a kind 5 targeting a signpost**, it is account machinery: it MUST be a valid change
   (§3.2, §6.7.2) or a signpost from a device with the right `n` (§6.7.5); a signpost delete is always
   refused; and a device MUST never sign
   one on a site's request (an epoch record is made only at creation);
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
- for any other request (`take_out`, removing a notice channel), `type ‖ id ‖ SHA-256(JCS(body
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
| `[remove, redeal]`: report a `device` lost (§6.4) | `lock`, `pair` or `paper`; or `recovery` |
| A device removes itself (§6.4) | `self` (its own member key's signature) |
| `[seat …, redeal]`: add, swap or remove a server; add the helper (§6.7) | `lock`, `pair` or `paper`; or `recovery` |
| `[paper, redeal]`: a new paper (§6.7.6 F7) | `lock`, `pair` or `paper`; or `recovery` |
| `[redeal]` alone: a stranded redeal's replacement (§6.7.1) | `lock`, `pair` or `paper`; or `recovery` |
| A list no current seat holder co-signed (every server dead, F3) | `pair`, `paper` or `recovery` only |
| Export a child key (§6.8) | `lock`, `pair` or `paper` |
| Remove or replace a notice channel (§8.1) | `lock`, `pair` or `paper` |
| Add a notice channel | any device, no approval (refused during a recovery wait) |

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
  named app's member key over `"keykin-self/1" ‖ g ‖ change hash`. A server co-signs it only while both are
  current devices and they are different keys. The app deals a redeal with it under the same two-key
  approval (`[remove, redeal]`), so a copied extension profile doesn't stay at the live state. In every
  other case a device leaves by an ordinary report-lost (`[remove, redeal]`, §6.2).
- The change goes to every server and every device as a delivery (§7.1). From the moment a member has
  it, servers MUST refuse every round with the removed member, and devices MUST refuse to co-sign with
  it. It is never delayed, and never waits for its redeal.
- **Removal notice.** The remove (or a reseat) is also delivered to the removed member, kept 7 days,
  with one visible push before its push addresses are dropped (§8.1). A member that verifies a
  group-signed change removing it destroys everything it holds for the account.
- **Removal is final.** Nobody is put back; a device removed by mistake joins again.
- **What the redeal does, and doesn't.** Every honest member applies the redeal and destroys its old
  share, so the removed device's pieces no longer combine with any honest member's, and the data and
  release keys rotate. What the removed device itself kept still combines with other pieces kept from
  the same state (§10).

### 6.5 Recovery

A round with no device-class member (I4) happens only in a recovery session.

0. The holder finds the current servers (§6.7.5): it asks the public list, follows the forwarding notes
   from the servers printed on the paper, and reads the signpost. The group-signed seat changes decide.
1. The backup holder picks a random `r`, asks each server for a `challenge`, and sends each a
   `release_request {r}` signed by the backup key over that server's challenge. Servers pass it to their peers as a delivery (§7.1), so a server that was down starts its
   own wait before it acts for the account again.
2. Each server starts a recovery wait (`W`, §6.3), tells every member and channel, and freezes holds. A
   locked device, or two devices together, can cancel it; the holder can withdraw it.
3. When its own wait has passed, a server seals the **release bundle** to the backup key (the holder
   unions the release seeds from all its servers): the current
   release seeds of its state, the epoch record, the set of changes, the backup material and its waited
   statement (`release`). Members serve the material only to members, or in a release after the wait.
4. The holder checks the material's base against the pinned hash and the backup key's signature,
   opens it, adds the paper deltas of exactly the redeals in the servers' current state, and checks
   the sum against `P_b^S` (§6.7.6 F11).
5. For 7 days after its own wait ended (the **recovery session**), each server takes part, in the
   two-call form (§5.1), in rounds of the backup plus two servers: but only for a recovery join (§4.4)
   and changes approved by `recovery` (§6.2): reseats, a new paper and a redeal (§6.7.6 F9). Not
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
  0. a device first verifies the redeal's paper item with its conversation key (§7.2) and records one
     "paper item verified" bit for the redeal;
  1. check `δ(i)·G == Σ_k D_k·i^k` for each of its indices;
  2. add it, and check `s'·G == P_i^{S'}`; a device also rebuilds `C_{S'}` from its own 3 points and `g`
     (§3.4 step 4);
  3. destroy, at once, the old share and `δ(i)`. A device also works out `δ(b1)`, `δ(b2)` (from the
     redeal's full `δ`: its own 3 values plus `δ(0) = 0`) and keeps them with the redeal's data-key seed,
     encrypted at rest, **until the paper item for the current backup key is verified** (§6.7.6), then
     destroys them and the paper conversation key;
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
  <key | null | "void:<id>">}}`. A new server's member entry carries its `enroll` reply, signed by its
  host key and binding its member key, VAPID key and endpoints to it (Server profile module). Co-signers
  and repair helpers verify that reply before co-signing or repairing.
  - A seat's current holder follows the epoch record's holder along valid seat changes, exactly as a
    lock does (§3.2). `new: null` empties the seat (removing a server or the helper without replacing
    it).
  - Two seat changes for one seat with the same `new`, or with the same host under different member keys,
    count as one (the lower change hash's `new` wins; the losing member key goes into `removed`). Otherwise, with different `new`, both are void and
    the seat stays empty until a `void:<id>` reseat. Two seat changes that would put **one host in two
    seats** are both void too.
  - The helper leaves only by `seat helper→null`; a `remove` never names a seat holder.
  - Every key that stops being a seat's current holder, `replaces` or voided `new`, goes into `removed`,
    and gets the removal notice (§6.4).
- **`paper`**: `{"paper": {"key": K, "replaces": <old backup key>, "inner": <hash>, "state": <sorted redeal
  ids in its base>}}`. Its co-signer checks that `replaces` is the current backup key. A co-signed paper
  change puts `replaces` into `removed`. If two paper changes conflict, the lowest change hash wins and the
  loser's key goes into `removed`. `paper` approvals, `challenge` / `release_request` and recovery
  sessions are accepted **only from the current backup key**, and servers end any wait on a replaced key
  at the co-sign.
- **`redeal`**: `{"redeal": {"id": <16 bytes>, "dealer": <device key>, "D": [D1, D2, D3], "paper_to": K,
  "paper_item": <hash>, "dk": <hash>, "rs": <hash>, "base": <sorted ids>, "abandons": [<ids>]}}`,
  carrying the dealer's detached signature. `D0` is
  the identity and is implicit. A `D` that contains the identity, or a `δ` that is all zero, is refused.
  `paper_to` is the backup key that is current **after** the list the redeal is in (in
  `[paper K', redeal]` it is K'). `rs` is the hash of the sealed new release seed, `dk` of the data-key
  seed, and `paper_item` of the new material item (§7.2). In a `[paper, redeal]` list, the new paper's
  base item is wrapped under that redeal's release seed. At creation, a creation release seed wraps the
  base item, and it travels with the other seeds.

**Approval lists.** Changes that belong together are approved together as one **list**: a seat change
and its redeal, a remove and its redeal, a paper change and its redeal.

- The list is a JSON array of changes in which the redeal is a placeholder and a paper change has no
  `inner` and no `state`. Its hash, `SHA-256(JCS(list))`, is the "change hash" everywhere: the lock assertion's `what` is
  `"change" ‖ list hash ‖ epoch id ‖ expiry` (§6.1), and a pair code uses the same hash. The expiry is at
  most 24 hours away and checked by the co-signer.
- In the list, the redeal appears only as `{"redeal": {"dealer": <device key>}}`: it binds **who** deals,
  not what. Only that device may deal it, and it may deal a fresh one after a failure until the approval
  expires.
- A paper change appears without `inner`, because the material doesn't exist yet when the person
  approves (§6.7.6 F7).
- The changes of one list are co-signed together and delivered as one. A `remove` and its redeal never
  travel apart.

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
  | `paper_ck` | devices only | the conversation key for the paper item |
  | `dk_seed` | devices only | the data-key seed |
  | `release_seed` | devices, and current and incoming seat servers (never helpers, never retired holders) | the redeal's release seed |
  | `paper_item` | every server and device | the new material item (§7.2) |

  The dealer sends them with `upload {list, approval, items[]}`, which must carry the approval list and
  its valid approval, or it is refused. Uploads are inert until the co-sign and expire after 7 days. A
  co-signer applies a redeal, and destroys its old share, only once it holds the group-signed list.
- **The co-signer of a redeal:**
  - fetches its live peers first, so it knows of every paper change;
  - checks the approval and the dealer's signature;
  - holds a delta for every member in its post-list view, incoming seat holders included and the backup
    excluded (the backup gets the `paper_item` instead), plus the `paper_item` and the `release_seed`,
    and otherwise answers `missing`;
  - refuses if `paper_to` is not the post-list current backup key, or if the item's hash doesn't match;
  - drops deltas addressed to removed keys.

  A single server may co-sign a list alone.
- **The co-signer of a paper change:**
  - fetches every live peer first;
  - accepts a paper change whose `state` lacks some co-signed redeals it knows: devices re-issue the
    items for those redeals to K (§6.7.6), and F7 step 5 waits for them;
  - checks that `replaces` is the current backup key;
  - receives the base material item in the same request and checks that its hash equals `inner` and
    that it is signed by K.

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
  succeeded**: a repair whose sum fails the share check doesn't count, and the asker names the bad
  helper so the next try uses another. Repair
  helpers refuse a host that already holds another seat in their view, so concurrent seat lists can't
  repair one host into two seats.
- **`rerepair {indices, state, proof}`.** A current member repairs its own existing indices at a named
  state, for any redeal it lacks. The proof is a Schnorr proof of knowledge of its share at an earlier
  state in its own chain, bound to a fresh server challenge. It is allowed only at the indices its seat
  chain or add gives it, never for the backup seat, and never for a removed member. Every device is told,
  with a "Report lost" button ("*Laptop* restored its pieces", §1.1), and so is every answered
  `need_seeds`, since a copy of a member's storage could otherwise catch up unseen.
- **`need_seeds`.** Any current device seals the data-key and release seeds to another current device
  that asks, and the release seeds (only) to a current seat server that asks.
- **An incoming seat holder**, once welcomed, fetches every unacknowledged delivery, for every member,
  from its live peers.
- **`state_get`** asks a member for its state (`state {ids}`). `rerepair`'s challenge is the ordinary
  server `challenge`.
- **What a welcome carries.**
  - A device's welcome (§4.2 step 4) and a handover (§4.6) carry: the state, the base data key and every
    data-key seed, every release seed of the state, and the backup material (every item).
  - A seat holder's welcome carries: the epoch record, the change set, its seat, the state, every release
    seed of the state (servers only) and the backup material. It never carries the data key or data-key
    seeds.

#### 6.7.5 Finding today's servers, and retired servers

A paper must always be able to find today's servers, even after every server printed on it has been
replaced. Three routes, tried in order:

1. **Ask the public list.** The paper app takes the app maker's signed public server list (§6.7.7) and
   asks each listed server `seated? {H(key), challenge, sig}`, where the key is the backup key or, from a
   device, its member key, and `sig` is that key's signature over the server's challenge (a server answers
   only if it verifies). A server that holds a seat for an account where that key is the current backup
   key or a current device answers with a reply sealed to the key, carrying its host signature outside
   the seal, over `SHA-256("keykin-seated/1" ‖ H(key) ‖ challenge ‖ ciphertext)`, so the asker can check
   it. This needs no relays and no published event.
2. **Follow the forwarding notes.** A retired server, after destroying everything else, keeps for the
   account only the group-signed change that retired it and the hashes of the keys allowed to ask for it
   (the backup keys and device keys it knew). It serves that change to a request signed by one of them. That is a forwarding note with no secrets. From
   the printed servers, the paper app walks the notes to today's servers.
3. **The signpost**, for servers the person runs themself that are not on the public list. It is a kind
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
   - Readers take the highest `n` whose decrypted copy matches `h`. (The paper carries the epoch id, so
     the holder can check `h`.)
   - **Guards.** A device MUST NOT sign, on a site's request, a kind 30078 with any of the account's
     signpost `d` values, or a kind 5 targeting one. Co-signers keep the current signpost's event id
     (one hash per backup key). They refuse every kind 5 that targets a signpost by `e` or `a`, from
     anyone, and co-sign a signpost only from a device, with the right `n` and an `h` that matches their
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
- A server that verifies a group-signed change removing it destroys everything for the account except
  its forwarding note.
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

- **F1, one server dies.** A peer has been quiet for 7 days, or sent a 30-day shutdown notice, and a live
  server pushes an `ask` naming a candidate Y.
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
  1. A makes K. One approval covers `[paper {K, replaces}, redeal (paper_to K)]` (without `inner` and
     `state`; it expires in 24 hours).
  2. A and one server repair the backup seat towards K under that approval. A checks the shares, wraps
     the base item and signs it with K. A is worth 5 points for this moment (§4.3).
  3. The person prints or writes the paper and reads it back. The screen says "Keep your old paper until
     this app says the new one is ready."
  4. A sends the paper change with `inner`, the base item and `state` (the state the repair in step 2 was
     done at); the co-signer checks and co-signs. Devices re-issue items only for redeals outside that
     `state`.
  5. After a check against every live server, for conflicting paper changes and for redeals whose items
     went to the old paper, the screen says "You can destroy the old paper", and servers end any wait on
     the old key.

  If A dies before step 4, nothing has changed. If the approval expires, the person approves again and
  starts from step 1 with a new K. There is never a second repair towards the same K.
- **F8, data key and release seeds.** Every redeal moves both on. A bare `[redeal]` exists but is never
  needed by hand.
- **F9, after a paper-only recovery.** `recovery` approvals cover reseats, a new paper (offered, not
  forced) and a redeal. The recovery app's new device deals it, once it has joined (§4.4).
- **F10, the group key leaks.** A new npub (key families, later).
- **F11, paper-only recovery after changes.**
  1. The holder finds the current servers (§6.7.5) and runs §6.5.
  2. After the wait it receives every release seed of the servers' state and the material items.
  3. It sums the base and the paper items of exactly the redeals in that state, leaving stranded ones
     out, and checks the sum against `P_b^S`.

**A device keeps a "paper item verified" bit** for each redeal it applied by delta (§6.7.1). If one not in
the paper's `state` lacks a verified item for the current K, the device **re-issues** it from the paper
values it kept (§6.7.1 step 3: `δ(b1)`, `δ(b2)`, the data-key seed). It seals them to K as a
supplementary item under that redeal's release seed, signs it with its member key, publishes the item's
`δ(b)·G` values in the clear, and delivers it (`paper_reissue`) to the servers. Servers accept items only
for the current K, from current devices, and only when the clear `δ(b)·G` match the redeal's
commitments (`Σ D_k·b^k`); they keep every distinct valid one (at most one per device). Other devices
check the clear values the same way and then set their own bit, so the kept paper values are destroyed.
The holder opens each item and checks it against the clear values and the sum against `P_b^S`. This is not a repair: K learns only what devices
already know. A **new paper** (F7, the quiet dot) is for a paper that is lost or exposed, or when no
current device can re-issue.

#### 6.7.7 Choosing a replacement

- The public server list is signed by the app maker, and apps pin its minimum version. (For now the user
  signs it and the app pins it; co-signers are added once other operators exist.)
- The server that sends the `ask` names a candidate. A device accepts it only if it is the deterministic
  pick `hash(g ‖ dead key ‖ seat ‖ version)` over the **newest list version the device knows** (at least
  the pin), taken from that seat's own slice of the list (the list's servers dealt round-robin to the
  three server seats), never putting two seats on one
  `operator` while another eligible one exists. If that pick refuses the seat or doesn't answer within a
  minute, the device takes the next server in the slice, in list order, and the `ask` names which one.
  It checks for itself that the server is dead (or has sent a host-signed shutdown notice) before it
  shows the card. When there is no other operator, the card says "All your servers are run by X".

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

### 6.8 Exporting keys

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
redeal deliveries of §6.7.3, the backup material, and every `cancel`, `withdraw` and
`release_request`) is a **delivery**. Every server of the account MUST keep each delivery for every member, other servers
included, until that member sends `ack` for it or is removed, and MUST hand it over when asked (§8.2).
A server that was offline MUST fetch its deliveries from its peers before it co-signs, issues a waited
statement or releases anything again, skipping a peer that has not answered for an hour. Changes are
kept for ever (§3.2). Deliveries for a removed member are dropped, except its removal notice, kept 7
days (§6.4); deliveries for the backup (which never fetches) are dropped; `deliver` from a removed
member is refused. Data-key seeds and paper conversation keys go to devices only. Uploads made before a
co-sign are inert and expire after 7 days (§6.7.3).

Deliveries travel **through HTTPS, server inboxes, or live kind 21059 wraps** (which relays do not
store), never as stored kind 1059 copies on relays: anything that carries a share or a key must not
sit in public archives.

### 7.2 The backup material and the release seeds

The backup's shares exist only as **backup material**, a set of items that simply add up:

- the **base item**: the shares at the paper's `state` (made and checked once, §4.3) and the base data
  key, NIP-44 to the backup key and signed by it (pinned by hash in the epoch record at creation, or in
  the `paper` change);
- one **paper item** per later redeal: NIP-44 from an ephemeral key to that redeal's `paper_to`,
  carrying `{δ(b1), δ(b2), data-key seed}`.

Each item is wrapped a second time, with XChaCha20-Poly1305, under **its own redeal's release seed** (the
base item under the release seed made with it). Two redeals at once each add their own item, and the
set is simply the union. Every server and every device keeps every item and every release seed of its
state (so device + paper still works if every server is gone). Members refuse an item whose hash doesn't
match its change (re-issued items: §6.7.6). Helpers and backups never hold release seeds; a recovery receives them only after the
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
| `take_out` / `released` | device → servers / back (children only) | 6.8 |
| `ack` | member → servers | 4.2, 7.1 |
| `notice` | server → members | 6.3, 8.2 |
| `push_register` / `push_unregister` / `notify_register` | device → server | 8.1 |
| `inbox_get` / `inbox` / `inbox_ack` / `deliver` | member ↔ server | 8.2 |
| `delta` / `paper_ck` / `dk_seed` / `release_seed` / `paper_item` | dealer → members (deliveries) | 6.7.3 |
| `stale` / `missing` | co-signer → requester | 6.7.1, 6.7.3 |
| `need_repair` / `rerepair` / `need_seeds` / `state_get` / `state` | member → servers / devices | 6.7.4 |
| `upload` / `upload_held` | dealer → seat holders / seat holder → co-signer | 6.7.3, 6.7.1 |
| `paper_reissue` | device → servers | 6.7.6 |
| `seated?` / `seated` / `forward_get` / `forward` | paper app or device → servers / back | 6.7.5 |
| `part`, `error` | anyone | 9.1 |

The signpost (kind 30078) is the one Keykin event published on relays (§6.7.5). That is the whole of Core. Cosign 0.12 has 55 message types in
`server/core/group.ts`; everything not here belongs to a module or goes.

## 10. Security properties, and their limits

**What holds.**

- One member signs nothing: not a device (3), not a server (1), not the backup (2), not a helper (3).
- All servers together (3) can never sign, and neither can two colluding operators. Every server a seat
  has ever had holds the same seat value, so in any one state all the servers ever seated are still 3
  distinct points.
- A server can delay or withhold its share and see what it co-signs. It cannot sign, cannot make an
  epoch record or a change, cannot add a member that others believe (live finding #1), cannot read
  messages (decryption answers are useless without a device's own points), and cannot fake a push.
- A joining device trusts only its scan, the group key and the check on both screens (#17).
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
  this; only key families end it.
- **A paper reaches every state since it was printed**, through its paper items. A stolen paper is
  dangerous until it is replaced, and the app cannot know it was exposed.
- **A lone device has no second checker** of its own paper item; a mistake surfaces only at an optional
  paper check, or at recovery.
- **A dishonest helper at a redeal** learns `δ`, and with a retired server is the key. The helper is
  opt-in.
- **A retired server that never hears it was replaced** keeps answering everyday rounds at its old
  state, which pairs only with pieces kept from that state (above). It starts no wait and releases
  nothing without first checking its peers, and after 7 days offline it stays passive, so a stolen paper
  can't use it to recover behind the account's back.
- **Forwarding notes and `seated?` answers** tell anyone holding a backup key (current or former) which
  hosts serve the account. That is addresses, not power.
- **The signpost's device copy uses the base data key**, which never changes, so a removed device or an
  old paper can read today's server endpoints for ever. Servers never act on the signpost, so this leaks
  addresses, not power.
- **One Face ID per dead server**, and no automatic replacement: a standing order would let a thief plus
  one week-dead server seat a server.
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

- **Account admin**: creating a key (DKG, import), adding and removing devices on screen, retire, delete
  (NIP-62 plus destroying shares and forgetting push addresses), the take-out bundle, the passkey page on
  servers for reporting a device lost.
- **Server profile**: the duties as an operator sees them, abuse defaults, the 30-day shutdown notice,
  telling the person calmly after a week that a server is quiet and offering to move its piece (§6.7.6
  F1), the signed public server list (§6.7.7),
  announcements (kind 30243/10243), the operator notice.
- **Device policy**: the destructive check, Undo from the device's own history, re-confirming staged
  events (a staged replaceable event older than the newest known is destructive), honest quiet notices.
- **Doors and grants**: NIP-07, NIP-46 (per-site signer keys, bunker://, auth_url), NIP-55, the QRST
  signer-ticket, the same-device door on iPhone, grants and scopes, the iOS push appendix.
- **Backup**: 24 words, recovery contacts, heir. (Finding servers from the paper is the signpost, §6.7.5,
  and the old escape hatch is F3.)
- **Helper**: the opt-in (joins by a `seat` change, §6.7.6 F6).
- **Key families**: claim, accept, release; the challenge window; child groups. This is the answer to a
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
