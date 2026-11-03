# Keykin module: Account admin

Draft 2 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.11 · not built

This module covers the account's life on screen: creating it (fresh, or by importing an nsec), adding and
removing devices, a device leaving, deleting the account, and taking things out. It adds no power to any
member. The core wins any disagreement, and nothing here may weaken it.

The bar is the core's: an nsec in a password manager. Creating an account must take less effort than
making an nsec and saving it, and nothing here is ever forced.

## 1. Creating an account

If the machine has the desktop member app, an extension creates the account in the app (core §4.6), so
the machine never needs a handover.

Every secret the device makes here (polynomials, keys, seeds) is hedged as core §5.2 does: `SHA-256(OS
randomness ‖ a fresh per-purpose counter ‖ what it is for)`.

### 1.1 Fresh (DKG)

1. **Pick servers.** The device takes the signed public list (Server profile §4) and, by default, makes
   three deterministic picks for a new account (one per seat slice, `hash(device's new member key ‖ seat ‖
   version)`, never two seats on one operator while another exists). This is a default, not a rule servers
   check: the person may add a server of their own instead of one pick. It asks each to `create`.
   - A server answers under its new-account limits (Server profile §3). When the per-IP limit is reached
     (people behind a mobile carrier share IPs), it asks for proof of work instead of refusing.
   - Its answer carries a **throwaway DKG key**, signed by its host key, which it destroys when the DKG
     ends. DKG traffic is sealed to it, never to the long-lived host key (Server profile §4).
   - A refusing or silent pick falls through as in Server profile §4.
2. **Run the DKG.** The device and the three servers run FROST's distributed key generation (`frost-core`
   `keys::dkg`, the ciphersuite of core §5.1), threshold 4, with one participant per index. The indices are
   fixed: the device's 1, 2, 3; the backup seat's 5, 6, run by the device; the servers' 4, 7, 8 (core
   §3.1).
   - The device relays every message. After round 1, each server returns the hash of every round-1
     package it received; the device continues only if they all match its own. So a server can't show
     different commitments to different participants.
   - Every participant checks its round-2 packages. Any failure aborts. The device restarts at most three
     times, each time with a new key and without the server it can't rule out; a server that aborts is
     dropped for this creation.
   - The group key is brought to even y as `frost-secp256k1-tr` does, for every share and the commitment.
   - A server that took part in a DKG that never reached its epoch record drops everything for it after
     one hour.
3. **Enrol, wrap, and sign the epoch record.** Now that `g` exists, the device asks each server
   `enroll {g}` for its enrol reply (Server profile §4). It makes the backup key pair and wraps the
   backup seat's shares as the base item (core §4.3, §7.2), with the creation release seed (core §6.7.2).
   Then it builds the epoch record (core §3.1, `origin: dkg`, `role: master`): `g`, the summed commitment,
   the members (the device with its lock if it has one; the servers with their enrol replies; the backup
   key), the seats, the relays (the servers' relays plus the app's defaults) and the base item's pin. The
   device and one server sign it, and the device sends it to each server sealed, as its welcome.
4. **Live only when adopted.** The account goes live (the npub is shown, anything is published) only after
   every server has adopted the epoch record first-hand (core §3.4) and stored its seat keys (Server
   profile §4). Otherwise it starts again from step 1.
5. **The backup.** The device asks once, quietly: "Write down a backup now? If you lose this phone, it gets
   your account back." — **Write it down**, **Add another device instead**, or **Not now**.
   - **Write it down** makes the backup set (Backup module §1), with its read-back.
   - **Add another device instead**: while the device still holds the backup secret, it can approve adding
     a device with it (a `paper` approval, core §6.2). This is the way out for a device with no lock.
   - **Not now** destroys the backup secret and the backup seat's shares at once (core §4.3 step 4). On a
     device with **no lock**, it first says once: "Without a lock or a backup, this account can't add a
     device or replace a server later. Add a phone with Face ID, or write down a backup." The person may
     still choose Not now.
   - If the flow is left unfinished, the device destroys the secret after 24 hours and says: "No backup
     yet. If you wrote one down, scan it in Backup to check it."
6. **The signpost** is published (core §6.7.5), and the device registers push with each server (core §8.1).

The person sees one screen with a spinner ("Making your account…", a few seconds), then the backup
question, then the npub (core §1.1). No seed words, no server choices unless they ask.

### 1.2 Import (an existing nsec)

For someone who already has an nsec, and for moving a Cosign 0.12 account (core §11.2):

1. The person pastes or scans the nsec on a Keykin device. The device clears the clipboard and shows the
   npub it belongs to for the person to confirm.
2. **Already a Keykin account?** The device looks on relays for any Keykin event signed by that key (a
   signpost or grant event). If it finds one: "This key is already a Keykin account. Sign in to it
   instead." Importing it again would make a second account for one npub.
3. The device picks and enrols servers as in §1.1 steps 1 and 3 (`g` is the nsec's public key), then
   deals: if the key's point has odd y, it negates the nsec (the npub is the same), then makes a random
   polynomial `f` of degree 3 with `f(0) = nsec`, with shares for its own three indices, the backup seat's
   two and each server's one, each server's share sealed to its member key. The epoch record has `origin:
   import`.
4. Steps 3–6 of §1.1 follow.
5. The device wipes the nsec and `f` from memory. Once a Keykin backup exists (or the person has a second
   device), it says plainly: **"Your old key still works wherever it is saved. Delete it from your password
   manager and any app that has it."** Until then it says: "Keep your old key until you've made a Keykin
   backup." It shows where the key came from if it knows (the 0.12 app, a paste), and a **Done** button.
6. For a 0.12 account, the device then asks each 0.12 server to `forget`, and offers to wipe the 0.12
   apps' copies (core §11.2).

An imported key was whole, so it is "ever whole" (core §10): anyone who copied the nsec before still has
it. The Key families module is the answer if that copy may have leaked. `origin` is the creating device's
word; servers can't check it.

## 2. The devices screen

One list, in plain words:

- each **device** with its name, whether it has a lock ("Face ID", "no lock"), its model, and when this
  device last saw it sign. A device silent for 90 days gets a quiet "Report lost?" offer;
- each **server**, with its operator ("Run by X", or "unknown" for an off-list server whose operator list
  doesn't name it, Server profile §4), and "your own" for `own`;
- the **helper**, if any (Helper module), and whether there is a **backup** (Backup module).

**Names.** A device names **itself**: it suggests its model at join, and the person can rename it later on
that device. Names are kept in an account-signed kind 30078 event, with `d` made as Doors and grants does
for grant events (`"keykin-labels:" ‖` an HMAC under the base data key), encrypted under
`HKDF-SHA256(dk(S), "keykin-labels/1")`, with each name signed by the named device's own member key.
Devices show only names signed by the device they name, so a stolen device can't rename the others to
trick the owner into reporting the wrong one. The `keykin-` guard (Doors and grants §2) keeps sites away.

### 2.1 Adding a device

The person picks **Add a device** on a member, or opens the app on the new device and picks **I already
have an account**. Either side shows a code (core §4.1). Then:

1. The new device shows a 6-digit number; the person types it on the old device (core §4.1).
2. The old device asks for its approval: its lock; or, with no lock, the person picks **Use another
   device** (a `pair`) or **Scan my paper** (core §6.2).

A lone device with no lock and no paper can't add a device (core §6.2, no wait path). The app says so in
one line when it happens.

### 2.2 Reporting a device lost

**Report lost** on any device (core §6.4): one confirmation naming the device, then the approval (a lock,
a second device, or the paper). It takes effect at once. The app then shows the quiet dot on Backup
(core §6.7.9).

Without any other device and without a lock, the person uses the paper; with every device lost, a paper
recovery (core §6.5) can remove the stolen one. An owner with one device is pointed once at **Also tell me
by email** (§5), so a thief's holds and recoveries at least reach them.

*The passkey page on servers that earlier notes mention is dropped:* core §6.1 doesn't count a passkey as
a lock, and a server-hosted approval page could be phished.

### 2.3 Leaving: a device the person is giving away

**Remove this device** asks **another current device** to report it lost (core §6.4), so the redeal that
kills its pieces is dealt by a device that stays; the other device shows the request and its approval
card. It is refused on the account's only device (core §6.4: a report needs another device or the paper).
When what is left would have no lock and no paper, the app warns once first. On success the leaving
device destroys everything for the account and says so.

An extension retiring in favour of the machine's desktop app uses the core's `self` remove instead (core
§4.6), with no question asked.

## 3. Deleting the account

**Delete my account** is in the account settings, never on a main screen. It is two separate acts.

1. **Erase my posts** (optional, offered first): a request to vanish (NIP-62, kind 62, `["relay",
   "ALL_RELAYS"]`), Held like any vanish (core §5.8): the lock, or a 3-day hold. It erases posts on relays
   that honour it and leaves the key alone, so a person can erase their posts and keep their npub.
2. **Destroy my key**: the card says "This destroys every piece of your key. Your npub can never be used
   again. This can't be undone." It is an approved request, `account_delete {id}`, with a lock, a second
   device (`pair`) or the paper (core §6.2), encoded as core §6.1's generic request. There is no hold path:
   a thief with an unlocked lockless phone can't destroy the key.
   - The device sends it to every server, as a delivery.
   - A server that verifies the approval destroys everything for the account (its share, seeds, material,
     waits, push addresses, notice channels, heir record), keeps only `SHA-256(g)` and the approved
     request (core §2), and answers every later request for `g` with `deleted` and that request, which
     devices check. It never seats or creates `g` again.
   - Every device that verifies it destroys everything for the account. Friends and the heir get one
     notice ("*Name* deleted their account"), and their apps drop their pieces.

After a delete, a paper can no longer be used with any honest server. Pieces a dishonest member kept
still combine as core §10 says.

## 4. Taking things out

- **Your data.** "Download your posts and lists" writes a file of the signed events in the device's
  verified history (Device policy §1), as a JSON array of Nostr events. It holds no secrets and needs no
  approval.
- **A child key** (core §6.8, Key families module) can be exported as an nsec with `take_out` and an
  approval. The app shows what that means ("Anyone with this text can use *name* for ever").
- **The account key itself is never exported** (core §6.8). The app says so if asked: "Keykin never puts
  your key in one place. To move to another app, sign in to it with Keykin."

## 5. Notice channels

In settings, **Also tell me by email** adds a notice channel (core §8.1) at each server that supports it.
Any device may add one; removing or replacing one needs an approval (a lock, two devices, or the paper),
and the old channel is told. The channel only ever gets the core's fixed words.

## 6. Limits, said plainly

- **An imported key is only as safe as every old copy.** Keykin can't delete the nsec from a password
  manager, a 0.12 app or a screenshot.
- **"Not now" on a device with no lock** leaves an account that can sign but can never add a device, make
  a paper or replace a server. When its last server dies, it stops.
- **"Not now" means no backup.** If that device is lost and no other exists, the account is lost (Backup
  module §6).
- **A thief with a device's lock, or a second device, or the paper, can destroy the key.** That is the
  same approval that takes the account over anyway.
- **The DKG's device runs five participants**, so until the backup flow ends that device alone holds 5
  points, as core §4.3 says.
- **A rushing server** can abort after seeing the device's round 1 and so bias `g` slightly across
  restarts, which is harmless for Schnorr; restarts are capped.
- **A device wiped without being removed** stays a member until reported, and servers keep its
  deliveries.

## Changes

- **Draft 2**, from its first red team (0 critical, 4 high):
  - destroying the key is its own approved request, with no hold path (H1, H2; core 13.11);
  - erasing posts is a separate vanish, Held as before (H2);
  - "Add another device instead" while the backup secret is held, and warnings before leaving an account
    with no lock and no paper (H3);
  - a buildable DKG: throwaway server keys, relayed and cross-checked round 1, fixed indices, even y,
    live only when every server adopted (H4, M1).

  The mediums and lows:
  - another device deals a leaving device's redeal (M2);
  - the clipboard is cleared, and old keys are kept until a Keykin backup exists (M3);
  - import enrols first and fixes even y (M4);
  - a second import of the same key is caught where possible (M5);
  - devices name only themselves (M6);
  - a server proves `deleted` with the approved request, kept by core §2 (M7, core 13.11);
  - proof of work instead of a per-IP refusal (M8);
  - what a delete does to a paper (M9);
  - references, the pick as a default, hedged secrets, capped restarts, unfinished DKGs dropped, silent
    devices, the labels `d`, piece holders told, `origin` unchecked, unknown operators, creating in the
    desktop app (L1 to L11).
- Draft 1.
