# Keykin module: Backup

Draft 3 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.10 · not built

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

- **The whole set is made at once**, by the core's new paper (F7, core §4.3). Adding or changing friends
  or an heir later is also an F7, since no device keeps the backup secret.
- **A new backup key voids the old set.** Once the new `paper` change commits, servers refuse the old key
  (core §6.7.2). So the F7 card names everything it replaces: "This also renews your heir and the pieces
  your 3 friends hold." The app remakes all of it, never only the paper.
- **Holders first, then the change.** The device hands every holder its copy and collects the read-backs
  **before** it sends the `paper` change for co-signing (core §4.3 steps 2–3):
  - the paper is scanned back or retyped;
  - each friend's app acknowledges its piece (§3);
  - two servers acknowledge the heir record (§4; the repair of §4.2 covers the third).
- **It commits only when the set can recover**: the paper, or two pieces, or one piece plus a printed
  piece, with any heir record acknowledged. Holders still missing are dropped from the set and named on
  Backup. If that isn't reached within 24 hours, nothing is sent: the device destroys the new secret
  (core §4.3 step 4), and the old set stays in force.
- After the commit, the device sends every holder a **set committed** note signed by the new backup key,
  then destroys the secret. Holders delete older pieces for the account only on that note; a piece whose
  set never committed is deleted after 30 days.

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
  - `3`, repeated: one per current server, its host key, HTTPS endpoint and relays.

  The same TLV without type `0` is the set's **account card**: friends and the heir keep it with their
  copy.
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
  - From the **words alone**, only the public list works (`seated?`). An account with a server that isn't
    on the list needs the QR code; when the person picks words only and has such a server, the app says
    so once: "Your own server isn't on the public list. Keep the QR code too."
- **Pinning the account.** The QR code and the account card pin `g`. With the words alone, the app takes
  `g` and the epoch id only when **two servers return matching epoch records** and change sets, and it
  shows the npub for the person to confirm, as at joining (core §1.1).

## 3. Recovery contacts

The backup secret can be **split among friends** instead of, or as well as, a paper: **SLIP-39**, one
group, threshold 2 of 3, empty passphrase. SLIP-39's own word list and digest share tell pieces apart from
any wallet seed and catch a bad piece. No friend ever holds a FROST share.

- **The holder key.** A friend's app (any app that implements this module) makes a dedicated **holder
  key**, an ordinary secp256k1 key kept like a member key (core §7.3), never the friend's everyday nsec. It
  binds it once to the friend's npub with one event: kind 30078, `d = "keykin-holder"`, content the holder
  public key. A Keykin device never signs that event on a site's request (the `keykin-` guard, Doors and
  grants §2). Pieces are sealed to the holder key, and everything the friend's app signs here is signed by
  it.
- **Setup**, as part of making the set (§1):
  1. The friend's app shows a QR code carrying the holder key and npub. The person scans it **in person**.
  2. The device sends the friend their piece and the account card, sealed to the holder key, **live**
     (kind 21059, never stored on relays) or as a QR the friend scans.
  3. The friend's app stores it per set id, encrypted at rest, excluded from cloud backups, shows "You're
     holding a recovery piece for *name* (*npub*)", and acknowledges with a holder-key signature over
     `SHA-256("keykin-piece/1" ‖ g ‖ set id ‖ piece)`.
  4. Optionally one of the three pieces is printed instead, in SLIP-39 words, and read back.
- **Staying alive.** A friend's app sends a small **still holding** note, signed by the holder key and
  naming the set id, every 90 days and when it starts after a restore. It goes to the owner's account as a
  NIP-59 wrap to `g` (it holds no secret). The owner's device shows the quiet dot on Backup when a friend
  has been silent for 6 months: "Ana's app hasn't checked in. Ask her to open it, or choose someone else."
  A friend's app that holds pieces offers **Move to a new phone** by an in-person QR, and warns before it
  is uninstalled where the platform allows.
- **Recovering.**
  1. The person's new device shows a QR code with a fresh key.
  2. Each friend scans it **in person**. Their app says: "Only give this if you can see them." A video
     call is allowed only behind a second warning: "A fake video call can take their account, if they
     have no locked phone."
  3. The friend's app seals every piece it holds for that account, with its account card, to the scanned
     key, and sends them live or as a QR.
  4. The new device combines two pieces whose SLIP-39 identifiers match, pins the account by the account
     card (§2), and runs the ordinary paper recovery (core §6.5): two servers, the 3-day wait, every device
     and channel told, and any locked device (or two devices) can stop it.
- **Pieces are for recovery.** The app never asks friends to approve anything else. If two pieces were
  combined, the app offers a new set afterwards (core §6.5 step 6), never forcing it.

## 4. An heir

The person can name an **heir**, who can take over the account after a long silence. The heir uses a
holder key bound to their npub, exactly as a friend does (§3). At setup the heir's app shows a QR code with
it, the person scans it in person, and the heir's app signs `heir_accept {g, holder key}` with it. The
envelope holds the backup secret and the account card, so opening it is followed by the core's paper
recovery, with its 3-day wait.

### 4.1 The envelope

- The device picks a random scalar `r`, and splits it Shamir 2-of-3 over the integers mod `n`, with each
  server's piece at x = the FROST index of its seat. It publishes the commitments `C0 = r·G` and `C1 =
  a1·G` of the line, so every piece can be checked: `r_x·G == C0 + x·C1`.
- It picks an ephemeral key `e`, and takes `z`, the 32-byte x-coordinate of `e·H` for the heir's holder
  key `H` (lifted to even y).
- `K = HKDF-SHA256(ikm = z ‖ r, salt = empty, info = "keykin-heir/1")`, and the envelope is
  ChaCha20-Poly1305 under `K` with a random 12-byte nonce and associated data `"keykin-heir/1" ‖ g ‖ H ‖
  set id`. The device opens it once itself, to check it, before going on.
- The **heir record** `{set id, H, E = e·G, nonce, envelope, C0, C1, wait days}`, signed by the backup key,
  and each server's piece, sealed to that server's member key, go to every server as a **delivery** (core
  §7.1). A server accepts a record only for the account's current backup key. At the co-sign of a `paper`
  change, servers delete the record of the replaced key and end its running wait.
- Neither the heir alone, nor any two servers alone, can open the envelope.

### 4.2 Carrying pieces to new servers

A retired server destroys its piece (core §6.7.5), so pieces must follow the seats. It is a standing duty
of the two live current piece holders with the lowest seat indices, retried until done, at every seat
change: they give the incoming server its piece at its seat's x by Shamir repair in the pattern of core
§4.2 step 3 (each sends the other a masked Lagrange-weighted share, both seal their sums to the newcomer),
and send it the heir record from their own storage. The newcomer checks the result against `C0` and `C1`.
If fewer than two holders are live, every device shows one quiet line: "Your heir can't inherit until you
renew your backup."

### 4.3 The long wait

1. The heir's app sends `heir_request {set id, request id}`, signed by the holder key over each server's
   challenge. Servers pass it to their peers as a delivery. A record has at most one running heir wait.
2. Each server starts an **heir wait** of the record's days (default **180**), with wait id
   `SHA-256("heir" ‖ H ‖ set id ‖ request id)`. It tells every member, and every notice channel in the
   core's fixed words (§8.1), at the start and every 30 days. Devices merge copies by wait id.
3. **The wait ends** at a server when:
   - any current device sends `cancel {wait}`, with or without a lock. A lockless cancel is accepted
     **only** for an heir wait id, never a recovery or a hold. It is a delivery, and the device repeats it
     to every server until each answers;
   - or that server co-signs a round marked `"alive": true` by a current device. A device marks a round
     alive only when the person started it: from the app's own screens, from a NIP-07 or NIP-55 request
     of an app in use, or from a card the person answered. Background NIP-46 answers, helper rounds,
     scheduled posts and push wakes are never marked;
   - or it receives `heir_alive {wait, at}`, signed by the host key of a peer that ended its wait by a
     round. A server that ends its wait by a round **delivers** this to its peers (core §7.1).
4. **Devices check daily.** Every device that coordinates rounds fetches every server's inbox at least
   once a day, an extension from its background worker. If it finds an heir wait, it shows "Your heir
   asked to take over. Stopped." the next time the person uses it, and sends the cancel then.
5. Before releasing, a server fetches its deliveries from its peers and runs `changes_get` (core §6.3,
   §6.7.5), and stays passive if the core says so.
6. When its own wait has passed with no cancel, a server seals its piece to the heir's holder key, signed
   by its host key. The heir fetches the record with `heir_get`, signed by the holder key, checks each
   piece against `C0` and `C1`, combines two, and opens the envelope.
7. When pieces are released, every device shows that the backup key is now with the heir, and Backup
   shows the dot for a new set.

After a cancel, servers refuse a new `heir_request` from that heir for **30 days**. The heir's app says
how the wait ended ("their laptop signed on 12 May"), so a family can switch a device off.

### 4.4 Approvals

| Change | Approval |
|---|---|
| Set up or change an heir | a new set (F7, §1) |
| Remove the heir | **any current device**, no approval: it only takes power away. It is a delivery; every device and notice channel is told, naming the device ("*Laptop* removed your heir"), and servers keep the record 7 days so any device can undo it |
| Cancel an heir wait | any current device (§4.3) |

## 5. When every server is gone

Core F3 covers it: with a device and the paper (or two devices), the app moves all three seats to new
servers. The app offers it calmly, after 7 days with every server unreachable from 2 or more networks
(core §6.7.9). Heir pieces don't survive this; the quiet line of §4.2 shows until the backup is renewed.

## 6. What the app shows

- One quiet suggestion at setup ("Write down a backup, or ask two friends to hold it"), and the quiet dot
  on Backup after a report-lost or a server swap (core §6.7.9). Never a banner, never a gate.
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
- **Old pieces aren't worthless.** Servers refuse their key, but kept pieces still combine with old
  pieces a dishonest server kept (core §10).
- **An heir plus two dishonest servers** skip the heir's wait. Today one operator runs every server.
- **An heir who opened the envelope** holds the backup key for good: with any current device that is
  full control, until a new set is made.
- **A dishonest server** can send a false `heir_alive` and so delay an heir, never hurry one.
- **A device of theirs that someone keeps using** keeps the heir out. The heir's app says which device.
- **A dishonest retired server** kept its old heir piece; with one current piece it rebuilds `r`, which
  still needs the heir's holder key.
- **24 words in the wrong place** (a photo, a cloud note) are as dangerous as the paper.
- **Words alone** can't find servers that aren't on the public list.
- With no paper, no friends and every device lost, the account is gone. That is the likeliest loss, and
  there an nsec in a password manager does better.

## Changes

- **Draft 3**, from its second red team (0 critical, 4 high):
  - only rounds the person started stop the heir, and a server that sees one tells its peers; devices
    check daily (H1, M1);
  - friends' apps check in, and move to new phones in person (H2);
  - holders are read back before the `paper` change, it commits only when the set can recover, and
    holders keep pieces per set until a signed commit note (H3);
  - holder keys for friends and heirs (H4, M7).

  The mediums and lows:
  - "final note" cut (M2);
  - heir removal is told everywhere and can be undone for 7 days (M3);
  - friends and the heir keep the account card (M4, L3);
  - repairing holders send the record, as a standing duty (M5);
  - set id is the backup key, records are signed by it and end with it (M6);
  - an opened envelope is shown everywhere (M8);
  - in person by default, video behind a warning (M9);
  - core 13.10 names the heir wait in §1 and §2 (L1);
  - two servers' acknowledgements (L2);
  - QR encoding details (L4);
  - the comparison table (L5);
  - Cosign 0.12 papers (L6, core 13.10).
- **Draft 2**, from its first red team (0 critical, 5 high): one backup set, heir pieces following the
  seats, signing ending the heir wait, in-person hand-over, servers in the QR code, and its mediums and
  lows.
- Draft 1.
