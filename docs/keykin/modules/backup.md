# Keykin module: Backup

Draft 2 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.5 · not built

The core has one backup: the **paper**, a backup key pair whose shares exist only as wrapped material
(core §4.3, §7.2), recovered with two servers after a 3-day wait (§6.5). This module says how that key is
written down (a QR code, or 24 words), how friends can hold it instead of paper (**recovery contacts**),
and how an heir can inherit the account, or post a last note, after a long wait. It adds no new way to
sign. The core wins any disagreement, and nothing here may weaken it.

The bar is the core's: an nsec in a password manager. A backup must be easier to keep than an nsec and
harder to steal, and nothing here is ever forced. Most people won't print a paper, and the app only
suggests it quietly.

## 1. The backup set

Every backup key has one **backup set**: whatever holds its secret. That can be any of:

- a **paper** (a QR code, 24 words, or both, §2);
- **recovery contacts**: three pieces held by friends, or two friends and one printed piece (§3);
- an **heir's "take over" envelope** (§4).

- **The whole set is made at once**, by the core's new paper (F7, core §4.3). Adding or changing friends
  or a "take over" heir later is also an F7, since no device keeps the backup secret.
- **A new backup key voids the old set.** Once the new `paper` change commits, servers refuse the old key
  (core §6.7.2). So the F7 card names everything it replaces: "This also renews your heir and the pieces
  your 3 friends hold." The app then remakes all of it, never only the paper.
- **The read-back covers every holder** (core §1.1, §4.3 step 4). The device destroys the secret only
  after:
  - the paper has been scanned back or retyped;
  - each friend's app has acknowledged its piece (§3);
  - every current server has acknowledged the heir record (§4).

  Until then the device alone is worth 5 points (core §4.3). It keeps a quiet dot on Backup. Each missing
  holder can be retried, or dropped from the set.

## 2. Writing the backup key down

The backup key's secret is a 32-byte scalar (not 0, less than the curve order `n`).

- **The QR code** is a bare `kkbak1…` payload, bech32 without the length limit (as NIP-19), never a URI,
  so a phone's camera doesn't hand it to some other app. Only the member app's own scanner reads it. It
  is a TLV like NIP-19's:
  - `0`: the secret;
  - `1`: the group key `g`;
  - `2`: the epoch id;
  - `3`, repeated: one per current server, its host key, HTTPS endpoint and relays.

  Readers also accept the old `cosign:` form.
- **The 24 words** encode the raw scalar with the BIP-39 English word list, but the last 8 bits are the
  first 8 bits of `SHA-256("keykin-backup/1" ‖ secret)`, not BIP-39's checksum. No PBKDF2 is applied.
  - A wallet then rejects the words 255 times in 256, and a Keykin app can say "This looks like a wallet
    seed, not a Keykin backup" for real BIP-39 words.
  - They are printed under "**Keykin backup — not a wallet seed**".
  - The tag string carries the version; another version would use another tag.
- **Finding servers.**
  - From the **QR code**, all three of the core's routes work (core §6.7.5).
  - From the **words alone**, only the public list works (`seated?`). An account with a server that isn't
    on the list needs the QR code; when the person picks words only and has such a server, the app says
    so once: "Your own server isn't on the public list. Keep the QR code too."
- **Pinning the account.** The QR code pins `g`. With the words alone, the app takes `g` and the epoch id
  only when **two servers return matching epoch records** and change sets, and it shows the npub for the
  person to confirm, as at joining (core §1.1).

## 3. Recovery contacts

The backup secret can be **split among friends** instead of, or as well as, a paper: **SLIP-39**, one
group, threshold 2 of 3, empty passphrase. SLIP-39's own word list and digest share tell pieces apart from
any wallet seed and catch a bad piece. No friend ever holds a FROST share.

- **Setup**, as part of making the set (§1):
  1. Each friend opens a Keykin app (any app that implements this module) and shows a QR code carrying
     their npub. The person scans it in person, or on a video call.
  2. The device sends each friend their piece, sealed to that npub, **live** (kind 21059, never stored
     on relays) or as a QR the friend scans.
  3. The friend's app stores it encrypted at rest, excluded from cloud backups, shows "You're holding a
     recovery piece for *name* (*npub*)", and acknowledges by signing `SHA-256("keykin-piece/1" ‖ g ‖
     piece)` with the friend's key.
  4. Optionally one of the three pieces is printed instead, in SLIP-39 words, and read back.
- **Recovering.**
  1. The person's new device shows a QR code with a fresh key.
  2. Each friend scans it **in person or on a video call**. Their app says: "Only give this if you can see
     them."
  3. The friend's app seals the piece to the scanned key and sends it live, or shows it as a QR.
  4. The new device combines two pieces, checks that the backup public key is recognised by `seated?`
     (§2), and runs the ordinary paper recovery (core §6.5): two servers, the 3-day wait, every device and
     channel told, and any locked device (or two devices) can stop it.
- **Pieces are for recovery.** The app never asks friends to approve anything else. If two pieces were
  combined, the app offers a new set afterwards (core §6.5 step 6), never forcing it.

## 4. An heir

The person can name an **heir**, who can act after a long silence. The heir confirms their own npub at
setup: the heir's app shows a QR code and signs `heir_accept {g, heir key}`, which the person's device
checks. The person chooses what the heir may do:

- **"Final note"**: the envelope holds events the account signed at setup, a note the person wrote and
  optionally a request to vanish (NIP-62, with the lock or a hold, core §5.8). Opening it can only publish
  those. It holds no backup secret, so it isn't part of the backup set and survives new papers.
- **"Take over"**: the envelope holds the backup secret. It is part of the backup set (§1), and opening it
  is followed by the core's paper recovery, with its 3-day wait.

### 4.1 The envelope

- The device picks a random scalar `r`, and splits it Shamir 2-of-3 over the integers mod `n`, with each
  server's piece at x = the FROST index of its seat. It publishes the commitments `C0 = r·G` and `C1 =
  a1·G` of the line, so every piece can be checked: `r_x·G == C0 + x·C1`.
- It picks an ephemeral key `e`, and takes `z`, the 32-byte x-coordinate of `e·H` for the heir key `H`.
- `K = HKDF-SHA256(ikm = z ‖ r, salt = empty, info = "keykin-heir/1")`, and the envelope is
  ChaCha20-Poly1305 under `K` with a random 12-byte nonce and associated data `"keykin-heir/1" ‖ g ‖ H ‖
  set id ‖ mode`.
- The **heir record** `{set id, mode, H, E = e·G, nonce, envelope, C0, C1, wait days}` and each server's
  piece, sealed to that server's member key, go to every server as a **delivery** (core §7.1). Each
  server acknowledges it. Incoming seat holders fetch it like any delivery.
- Neither the heir alone, nor any two servers alone, can open the envelope.

### 4.2 Carrying pieces to new servers

A retired server destroys its piece (core §6.7.5), so pieces must follow the seats. At every seat change,
two live current piece holders give the incoming server its piece at its seat's x, by Shamir repair in
the pattern of core §4.2 step 3: each sends the other a masked Lagrange-weighted share, both seal their
sums to the newcomer, and the newcomer checks the result against `C0` and `C1`. If fewer than two holders
are live, every device shows one quiet line: "Your heir can't inherit until you renew your backup."

### 4.3 The long wait

1. The heir sends `heir_request {set id, request id}`, signed by the heir key over each server's
   challenge. Servers pass it to their peers as a delivery.
2. Each server starts an **heir wait** of the record's days (default **180**), with wait id
   `SHA-256("heir" ‖ H ‖ set id ‖ request id)`. It tells every member, and every notice channel in the
   core's fixed words (§8.1), at the start and every 30 days. Devices merge copies by wait id.
3. **The wait ends** at a server when:
   - any current device sends `cancel {wait}`, with or without a lock. A lockless cancel is accepted
     **only** for an heir wait id, never a recovery or a hold. It is a delivery, and the device repeats it
     to every server until each answers;
   - or that server co-signs any round **coordinated by a current device** (helper rounds don't count), so
     a person who signs anything is alive;
   - or a device opens and finds the heir wait in its inbox: it cancels at once and shows "Your heir asked
     to take over. Stopped."
4. Before releasing, a server fetches its deliveries from its peers and runs `changes_get` (core §6.3,
   §6.7.5), and stays passive if the core says so.
5. When its own wait has passed with no cancel, a server seals its piece to the heir key, signed by its
   host key. The heir fetches the record with `heir_get`, signed by the heir key, checks each piece
   against `C0` and `C1`, combines two, and opens the envelope.

After a cancel, servers refuse a new `heir_request` from that heir for **30 days**.

### 4.4 Approvals

| Change | Approval |
|---|---|
| Set up or change an heir | a new set (F7) for "take over"; for "final note", `lock`, `pair` or `paper` |
| Remove the heir | **any current device**, no approval: it only takes power away. It is a delivery, and servers delete the record and their piece |
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
  | Every device lost | the key is in the manager | **the account is lost**: worse than an nsec | recover in 3 days, if two servers answer |

## 7. Limits, said plainly

- **Two friends** hold the backup key between them. One dishonest friend who fools a second one, plus
  two servers' waits that nobody cancels, take the account. In-person hand-over is the protection.
- **Two friends plus any current device** make a `paper` approval: full control at once, with no wait.
- **Old pieces aren't worthless.** Servers refuse their key, but kept pieces still combine with old
  pieces a dishonest server kept (core §10).
- **An heir plus two dishonest servers** skip the heir's wait. Today one operator runs every server.
- **A dishonest retired server** kept its old heir piece; with one current piece it rebuilds `r`, which
  still needs the heir's key.
- **A "take over" heir who opens the envelope** still faces the 3-day recovery, which a lockless owner
  can't cancel. The heir wait ending at any signing is what protects that owner.
- **24 words in the wrong place** (a photo, a cloud note) are as dangerous as the paper.
- **Words alone** can't find servers that aren't on the public list.
- With no paper, no friends and every device lost, the account is gone. That is the likeliest loss, and
  there an nsec in a password manager does better.

## Changes

- **Draft 2**, from its first red team (0 critical, 5 high):
  - one backup set per key, renewed together, with every holder read back (H1);
  - heir pieces follow the seats by repair, with commitments (H2);
  - any signing round by a device, or opening the app, ends an heir wait (H3);
  - no phrase: pieces are handed over only in person or on a video call (H4);
  - the QR code carries every server's endpoints and relays (H5).

  The mediums and lows:
  - a Keykin checksum on the words (M1);
  - heir wait id, deliveries, lockless cancel only for heir waits, the approval table (M2);
  - "final note" holds signed events, not the key (M3);
  - a 30-day cooldown, and any device removes the heir (M4);
  - SLIP-39, live delivery, acknowledgements (M5);
  - plainer limits (M6);
  - two servers' epoch records and the npub for words only (M7);
  - pieces only for recovery (M8);
  - a bare QR payload (M9);
  - "offers" a new set (L1);
  - an honest comparison (L2);
  - the heir cryptography (L3).
- Draft 1.
