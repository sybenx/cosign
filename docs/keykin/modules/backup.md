# Keykin module: Backup

Draft 5 · 2026-11-03 · module of [Keykin Core](../core.md) draft 14.15 · not built

The core has one backup: the **paper**, a backup key pair whose shares exist only as wrapped material
(core §4.3, §7.2), recovered with two servers after a 3-day wait (§6.5). This module says how that key is
written down (a QR code, or 24 words), how friends can hold it instead of paper (**recovery contacts**),
and how an heir can take over the account after a long wait. It adds no new way to sign. The core wins any
disagreement, and nothing here may weaken it.

The bar is the core's: an nsec in a password manager. A backup must be easier to keep than an nsec and
harder to steal, and nothing here is ever forced. Most people won't print a paper, and the app only
suggests it quietly.

## 1. The backup set

Every backup key has one **backup set**: whatever holds its secret. The **set id** is the backup public
key. The set can be any of:

- a **paper** (a QR code, 24 words, or both, §2);
- **recovery contacts**: three pieces held by friends, or two friends and one printed piece (§3);
- an **heir's envelope** (§4).

### 1.1 Making a set

The whole set is made at once, by the core's new paper (F7, core §4.3, §6.7.6). Adding or changing friends
or an heir later is also an F7, since no device keeps the backup secret. A new backup key voids the old
set once its `paper` change commits (core §6.7.2), so the F7 card names everything it replaces: "This also
renews your heir and the pieces your 3 friends hold."

1. **Before F7 starts**, the device collects what needs a person in the room: each friend's and the heir's
   holder key (§3), scanned in person. It shows who must be reachable: "Ana, Ben and Carl must open their
   apps before *time*."
2. **F7 steps 1–3** as the core says (make K, repair the backup seat, read back any paper).
3. **Hand out.** Between F7 step 3 and step 4, the device hands every friend its piece (§3) and builds the
   heir record (§4.1). The deadline is **an hour before the F7 approval's expiry**, leaving time for the
   upload and the co-sign. (Declining a *paper* never destroys K while friends or an heir are being
   handed theirs.)
4. **Commit only when the set can recover**: the paper, or two pieces, or one piece plus a printed piece.
   Holders that haven't acknowledged by then are dropped and named on Backup. If no recoverable set is
   reached before the expiry, nothing is sent: the device destroys K (core §4.3 step 4), and the old set
   stays in force.
5. **F7 step 4**: the `paper` change carries two module fields **inside its `paper` object**
   (`change.paper.holders`, `change.paper.heir`, never beside it: core §9.5), which the group signature
   pins (core keeps unknown fields there and hashes them):
   - `holders`: the hashes of the holder keys kept in the set;
   - `heir`: the hash of the heir record, if there is one. The record and each server's piece travel with
     the change as inert uploads (core §6.7.3), and every server accepts a record **only** when it applies
     a co-signed `paper` change naming its hash. So nobody can install or swap an heir outside an F7.

   Both fields are part of the approved list (core §6.7.2).
6. The device destroys K once the change is co-signed, except on a lockless account with no lock and no
   read-back paper, where K becomes the kept secret and goes to every lockless device (core §4.3 step 4,
   `kept_new`).
7. **The commit proof is the co-signed `paper` change itself.** After F7 step 5's check (core §1.1 item 7),
   devices forward it to every holder, and again each time a holder's still-holding note names another set
   (§3), until each holder acknowledges. A holder checks `g`'s signature and `paper.key`.
8. **Holders never delete on a timer.** A holder deletes a set's piece only when it sees a co-signed
   `paper` change that `replaces` that set, the `paper` change **of that same set** (`paper.key` = its
   set id) whose `holders` doesn't list it, or a checked delete proof for the account (Account admin §3).
9. **Any device can renew.** The pinned holder keys and the heir's are kept in the synced device metadata
   (Device policy §1, encrypted under the data key), so a renewal from another device, or after a recovery
   through friends, keeps every holder.

## 2. Writing the backup key down

The backup key's secret is a 32-byte scalar (not 0, less than the curve order `n`). Readers reject any
other value.

- **The QR code** is a bare `kkbak1…` payload in bech32 (not bech32m) without the length limit, as NIP-19,
  printed in upper case so the QR uses its alphanumeric mode. It is never a URI, so a phone's camera
  doesn't hand it to some other app. Only the member app's own scanner reads it. It is a TLV like
  NIP-19's:
  - `0`: the secret;
  - `1`: the group key `g`;
  - `2`: the epoch id;
  - `3`, repeated: one per current server, its 32-byte host key ‖ UTF-8 JSON `{https, relays}`;
  - `4`: the holder-inbox key (§3).

  Unlike NIP-19, lengths here are **2 bytes** big-endian, so a server's relays fit.

  The same TLV without type `0` is the set's **account card**: friends and the heir keep it with their
  copy. A holder pins the card's `g` for good. Servers and relays in later cards are **hints** only, and the
  holder-inbox key changes only with a commit proof (§1.1 step 7).
- **The 24 words** encode the raw scalar with the BIP-39 English word list, but the last 8 bits are the
  first 8 bits of `SHA-256("keykin-backup/1" ‖ secret)`, not BIP-39's checksum. No PBKDF2 is applied.
  - A wallet then rejects the words 255 times in 256, and a Keykin app can say "This looks like a wallet
    seed, not a Keykin backup" for real BIP-39 words.
  - They are printed under "**Keykin backup — not a wallet seed**".
  - The tag string carries the version; another version would use another tag.
- **Cosign 0.12 papers** are recognised and explained: a 0.12 paper belongs to the 0.12 account, which
  moves to Keykin only by import (core §11.2). Cosign 0.12 never had 24 words.
- **Finding servers.**
  - From the **QR code** or an account card, all three of the core's routes work (core §6.7.5).
  - From the **words alone**, only the server lists the recovering app trusts work (`seated?`). An account
    with a server on no such list needs the QR code, or the person adds the list their app used; when the
    person picks words only and has a server outside its app's pinned lists, the app says so once: "Your
    own server isn't on your app's list. Keep the QR code too."
- **Pinning the account.** The QR code and the account card pin `g`. With the words alone, the app takes
  `g` and the epoch id only when **two servers return matching epoch records** and change sets, and it
  shows the npub for the person to confirm, as at joining (core §1.1).

## 3. Recovery contacts

The backup secret can be **split among friends** instead of, or as well as, a paper: **SLIP-39**, one
group, threshold 2 of 3, empty passphrase, iteration exponent 1, the extendable flag set. No friend ever
holds a FROST share. SLIP-39 shares are wallet shares too (a Trezor would import them as a different
wallet, which is harmless), so a printed piece is headed "**Keykin recovery piece — not a wallet**".

- **The holder key.** A friend's app (any app that implements this module) makes a dedicated **holder
  key**, an ordinary secp256k1 key kept like a member key (core §7.3), never the friend's everyday nsec.
  The owner's device **pins** the holder key it scanned in person. Only another in-person scan, or the
  friend's **Move to a new phone**, changes it. Pieces are sealed to the holder key, and everything the
  friend's app signs here is signed by it.
- **Setup**, as part of making the set (§1.1):
  1. The friend's app shows a QR code carrying the holder key and the friend's npub. The person scans it
     in person, before F7 starts.
  2. The device sends the friend their piece and the account card, sealed to the holder key, **live**
     (kind 21059, never stored on relays) or as a QR the friend scans.
  3. The friend's app stores it per set id, encrypted at rest, excluded from cloud backups, shows "You're
     holding a recovery piece for *name* (*npub*)", and acknowledges with a holder-key signature over
     `SHA-256("keykin-piece/1" ‖ g ‖ set id ‖ piece)`.
  4. Optionally one of the three pieces is printed instead, in SLIP-39 words, and read back.
- **The holder inbox.** Devices derive a **holder-inbox key** from the base data key,
  `HKDF-SHA256(base data key, "keykin-holders/1")`, put its public half in the account card, and watch
  for kind 1059 events addressed to it on the card's relays and the epoch record's relays. So holders'
  notes never land where the person's messages go.
- **Staying alive.** A friend's app sends a small **still holding** note, signed by the holder key and
  naming the set id, every 90 days and when it starts. It is a kind 1059 wrap to the holder-inbox key
  with a NIP-40 expiration (it holds no secret).
- **A restore that lost the piece.** The friend's app keeps a non-secret **holding record** (whose piece,
  the set id, the account card) in its backed-up data. An app restored from a backup finds the record but
  no piece or holder key, and sends a **lost** note as a NIP-59 wrap whose seal is signed by the friend's
  npub, which the owner pinned at setup.
  - A device that reads a note answers with a fresh account card sealed to the holder key on the same
    relays, and the commit proof if the note names an older set (§1.1 step 7).
  - The owner's device shows the quiet dot on Backup for a friend who is silent for 100 days ("Ana's app
    hasn't checked in"), who sent a lost note, or who still names an old set ("Ana still has an old
    piece").
  - A friend's app that holds pieces offers **Move to a new phone** by an in-person QR, and warns before it
    is uninstalled where the platform allows.
- **After a server swap**, the quiet dot isn't shown for a friend set: core §6.7.6's re-issue keeps the old
  key complete, so the set needs no renewal.
- **Recovering.**
  1. The person's new device shows a QR code with a fresh key and the npub it is recovering.
  2. Each friend scans it **in person**. Their app says: "Only give this if you can see them." A video
     call is allowed only behind a second warning: "A fake video call can take their account, if they
     have no locked phone." If the friend holds pieces for several people, their app asks which.
  3. The friend's app seals every piece it holds for that account, with its account card, to the scanned
     key, and sends them live or as a QR.
  4. The new device combines two pieces whose SLIP-39 identifiers match, pins the account by the account
     card (§2), and runs the ordinary paper recovery (core §6.5): two servers, the 3-day wait, every device
     and channel told, and any locked device (or two devices) can stop it.
- **Pieces are for recovery.** The app never asks friends to approve anything else. If two pieces were
  combined, the app offers a new set afterwards (core §6.5 step 6), never forcing it.

## 4. An heir

The person can name an **heir**, who can take over the account after a long silence. The heir's app makes
a holder key exactly as a friend's does (§3), and the person scans it in person. At setup the device also
sends the heir the account card, sealed to the holder key. The heir's app sends still-holding notes like a
friend's, and gets fresh cards the same way. The envelope holds the backup secret and the account card, so opening it is followed by
the core's paper recovery, with its 3-day wait.

At setup the app suggests, never forces, a notice channel (core §8.1), since heir notices are what protect
an owner who rarely opens the app.

### 4.1 The envelope

- The device picks a random scalar `r`, and splits it Shamir 2-of-3 over the integers mod `n`, with each
  server's piece at x = the FROST index of its seat. It publishes the commitments `C0 = r·G` and `C1 =
  a1·G` of the line, so every piece can be checked: `r_x·G == C0 + x·C1`.
- It picks an ephemeral key `e`, and takes `z`, the 32-byte x-coordinate of `e·H` for the heir's holder
  key `H` lifted to even y. (Since `z` is an x-coordinate, the heir's `h·E` gives the same `z` whichever
  sign its key has.)
- `K = HKDF-SHA256(ikm = z ‖ r, salt = empty, info = "keykin-heir/1")`, with `r` as 32 bytes big-endian.
  The envelope is ChaCha20-Poly1305 under `K` with a random 12-byte nonce and associated data
  `"keykin-heir/1" ‖ g ‖ H ‖ set id`. The device opens it once itself, to check it.
- The **heir record** is `{set id, H, E = e·G, nonce, envelope, C0, C1, wait days}`, encoded with JCS. Its
  hash is pinned in the `paper` change (§1.1 step 5), and each server's piece is sealed to that server's
  member key. Servers refuse a record whose `wait days` is under 30.
- At the co-sign of a later `paper` change, servers delete the record of the replaced key and end its
  running wait.
- Neither the heir alone, nor any two servers alone, can open the envelope.

### 4.2 Carrying pieces to new servers

A retired server destroys its piece (core §6.7.5), so pieces must follow the seats. It is a standing duty
of the two live current piece holders with the lowest seat indices, retried until done, at every seat
change: they give the incoming server its piece at its seat's x by Shamir repair in the pattern of core
§4.2 step 3 (each sends the other a masked Lagrange-weighted share, both seal their sums to the newcomer),
and send it the heir record from their own storage.

- The newcomer checks the record's hash against the `heir` field of the co-signed `paper` change, and its
  piece against `C0` and `C1`.
- **Every** server holding a piece sends every device `heir_held {set id, x}`, signed by its host key, as a
  delivery: at setup and after each repair. Devices show one quiet line, "Your heir can't inherit until
  you renew your backup", when fewer than two current seats have sent `heir_held` for the current set.

### 4.3 The long wait

1. The heir's app finds the current servers from its account card. A server that holds a heir record
   naming `H` answers `seated?` and `forward_get` signed by `H` (core 13.13, §6.7.5).
2. The heir's app sends `heir_request {set id, request id}`, signed by the holder key over each server's
   challenge. Servers pass it to their peers as a delivery. A record has at most one running heir wait.
3. Each server starts an **heir wait** of the record's days (default **180**), with wait id
   `SHA-256("heir" ‖ H ‖ set id ‖ request id)`. It tells every member, and every notice channel in the
   core's fixed words (§8.1), at the start and every 30 days, and **weekly in the last 30 days**. Devices
   merge copies by wait id. `inbox_get` lists heir waits with the others (core §8.2).
4. **The wait ends** at a server when any current device sends `cancel {wait}`, with or without a lock. A
   lockless cancel is accepted **only** for an heir wait id, never a recovery or a hold. It is a delivery,
   and the device repeats it to every server until each answers.
5. **A device cancels the next time the person visibly uses it**: the app's own screens, or a card they
   answered. It then shows "Your heir asked to take over. Stopped." Silent NIP-07, NIP-46 and NIP-55
   signing never counts, so a tab left open on a dead owner's computer can't keep the heir out. Devices
   SHOULD fetch every server's inbox at least daily, best effort (an extension from its background worker;
   iPhones as background refresh allows); push and the notices cover the rest.
6. Before releasing, a server fetches its deliveries from its peers and runs `changes_get` (core §6.3,
   §6.7.5), and stays passive if the core says so.
7. When its own wait has passed with no cancel, a server seals its piece to the heir's holder key, signed
   by its host key. The heir fetches the record with `heir_get`, signed by the holder key, checks each
   piece against `C0` and `C1`, combines two, and opens the envelope.
8. When pieces are released, every device shows that the backup key is now with the heir, and Backup
   shows the dot for a new set.

After a cancel, servers refuse a new `heir_request` from that heir for **30 days**.

### 4.4 Approvals

| Change | Approval |
|---|---|
| Set up or change an heir | a new set (F7, §1.1) |
| Remove the heir | **any current device**, no approval: it only takes power away. It is a delivery, `heir_remove {set id}`, which every server checks as core §3.2 does for requests with no co-signer; every device and notice channel is told, naming the device ("*Laptop* removed your heir"). It is final: servers delete the record and their piece, refuse any `heir_request` for it and end a running wait. A mistaken removal means a new set |
| Cancel an heir wait | any current device (§4.3) |

### 4.5 Messages

| `type` | From → to | `cls` |
|---|---|---|
| `heir_request {set id, request id}` | heir → servers | `member` |
| `heir_get` | heir → servers | `member` |
| `heir_held {set id, x}` | server → devices (delivery) | `member` |
| `heir_remove {set id}` | device → servers (delivery) | `member` |

## 5. When every server is gone

Core F3 covers it: with a device and the paper (or two devices), the app moves all three seats to new
servers. The app offers it calmly, after 7 days with every server unreachable from 2 or more networks
(core §6.7.9). Heir pieces don't survive this; the quiet line of §4.2 shows until the backup is renewed.

## 6. What the app shows

- One quiet suggestion at setup ("Write down a backup, or ask two friends to hold it"), and the quiet dot
  on Backup after a report-lost or a server swap (core §6.7.9; not for friend sets, §3). Never a banner,
  never a gate.
- A plain comparison, on request:

  | Case | An nsec in a password manager | Keykin, no backup | Keykin with paper or friends |
  |---|---|---|---|
  | Phone stolen, locked | safe while the manager is locked | safe; report it from another device if you have one | the same |
  | Password manager breached | the key is gone | not affected | not affected |
  | A server hacked | — | can't sign | can't sign |
  | The app maker shuts down | the key is in the manager | any Keykin app keeps working | the same |
  | Every device lost | the key is in the manager | **the account is lost**: worse than an nsec | recover in 3 days, if two servers answer and two friends still hold their pieces |

## 7. Limits, said plainly

- **Two friends** hold the backup key between them. One dishonest friend who fools a second one, or an
  outsider who fools two on a faked video call, plus two servers' waits that nobody cancels, take the
  account. In-person hand-over is the protection.
- **Two friends plus any current device** make a `paper` approval: full control at once, with no wait.
- **Renewing a friend set** needs the friends' apps reachable before the approval expires; a friend who
  isn't is dropped from the new set.
- **Old pieces aren't worthless.** Servers refuse their key, but kept pieces still combine with old
  pieces a dishonest server kept (core §10).
- **An heir plus two dishonest servers** skip the heir's wait. Today one operator runs every server.
- **An heir who opened the envelope** holds the backup key for good: with any current device that is
  full control, until a new set is made.
- **An owner who only signs in the background** (through NIP-46 or a tab left open) and misses every heir
  notice for 180 days can lose the account to the heir; a lockless owner then can't stop the recovery
  that follows. A notice channel is the protection.
- **A dishonest retired server** kept its old heir piece; with one current piece it rebuilds `r`, which
  still needs the heir's holder key.
- **A server holding a heir record** tells the heir which servers serve the account, as it would the
  backup key (core §10).
- **A removed device keeps the holder-inbox key** (it comes from the base data key, which never rotates),
  so it can read friends' still-holding and lost notes, and so learn who the friends are.
- **24 words in the wrong place** (a photo, a cloud note) are as dangerous as the paper.
- **Words alone** can't find servers that are on no list the recovering app trusts.
- With no paper, no friends and every device lost, the account is gone. That is the likeliest loss, and
  there an nsec in a password manager does better.

## Changes

- **Draft 5**, from its fourth red team (0 critical, 0 high), its mediums and lows:
  - a restored friend's app sends a lost note signed by the friend's npub, and silence shows after 100
    days (M1);
  - newcomers check the heir record against the pinned hash (M2);
  - every server accepts the record when applying the change, and every holder sends `heir_held` (M3);
  - module fields are part of the approved list (M4, core 14);
  - pinned holder keys synced among devices (M5);
  - cards pin `g`, later servers are hints (M6);
  - deletion only on the piece's own set's change (M7);
  - the heir checks in, and forwarding notes answer the heir key (M8, core 14);
  - `heir_accept` and the even-y clause cut; the hand-out deadline's margin (cuts, L8).
- **Draft 4**, from its third red team (0 critical, 3 high):
  - the heir record's hash is pinned in the `paper` change and accepted only at its co-sign (H1);
  - the co-signed `paper` change is the commit proof, forwarded until acknowledged, and holders never
    delete on a timer (H2, L1);
  - the heir gets an account card, and servers holding its record answer its lookups (H3, core 13.13).

  The mediums and lows:
  - heir removal is final, no undo (M1, L7);
  - the commit proof follows F7 step 5 (M2);
  - holder keys collected before F7, the approval's expiry as deadline, no post-swap dot for friend sets
    (M3);
  - a holder-inbox key for notes, and fresh cards in reply (M4);
  - `"alive"` rounds and `heir_alive` cut: a device cancels on the next visible use (M5);
  - a suggested notice channel and weekly notices near the end (M6);
  - `holders` in the `paper` change (M7);
  - `heir_held` from newcomers (M8);
  - the published holder binding cut (M9);
  - core 13.13 lists heir waits in `inbox_get` and footnotes §2's table (L2, L3);
  - best-effort daily checks (L4);
  - SLIP-39 parameters and printed label (L5);
  - a 30-day floor on the wait (L6);
  - envelope encodings (L8);
  - lost notes and several accounts per friend (L9).
- **Draft 3**, from its second red team (0 critical, 4 high): signed holder keys, read-back before commit,
  "final note" cut, and its mediums and lows.
- **Draft 2**, from its first red team (0 critical, 5 high): one backup set, heir pieces following the
  seats, in-person hand-over, servers in the QR code, and its mediums and lows.
- Draft 1.
