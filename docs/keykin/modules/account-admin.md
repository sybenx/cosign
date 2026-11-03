# Keykin module: Account admin

Draft 1 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.6 · not built

This module covers the account's life on screen: creating it (fresh, or by importing an nsec), adding and
removing devices, a device leaving, deleting the account, and taking things out. It adds no power to any
member. The core wins any disagreement, and nothing here may weaken it.

The bar is the core's: an nsec in a password manager. Creating an account must take less effort than
making an nsec and saving it, and nothing here is ever forced.

## 1. Creating an account

### 1.1 Fresh (DKG)

1. **Pick servers.** The device takes the signed public list (Server profile §4) and makes the three
   deterministic picks for a new account (one per seat slice, `hash(device's new member key ‖ seat ‖
   version)`, never two seats on one operator while another exists). It asks each to `create`. A server
   answers under its new-account limits (Server profile §3), may ask for proof of work, and signs its
   DKG messages with its host key. A refusing or silent pick falls through as in Server profile §4. The
   person may add a server of their own instead of one pick.
2. **Run the DKG.** The device and the three servers run FROST's distributed key generation (`frost-core`
   `keys::dkg`, the ciphersuite of core §5.1), threshold 4, with one participant per index: the device runs
   five participants (its three indices and the backup seat's two), and each server one. Round-2 packages
   travel sealed (core §9.1). Every participant checks its packages; any failure aborts, and the device
   starts again with another server in place of the one it can't rule out. Servers contribute randomness,
   so a weak random number generator on the device alone doesn't make a weak key.
3. **Enrol, wrap, and sign the epoch record.** Now that `g` exists, the device asks each server
   `enroll {g}` for its enrol reply (Server profile §4). It makes the backup key pair and wraps the
   backup seat's shares as the base item (core §4.3, §7.2). Then it builds the epoch record (core §3.1,
   `origin: dkg`, `role: master`): `g`, the summed commitment, the members (the device with its lock if
   it has one; the servers with their enrol replies; the backup key), the seats, the relays (the
   servers' relays plus the app's defaults) and the base item's pin. The device and one server sign it, and the device sends it to each server sealed, as
   its welcome, with the creation release seed (core §6.7.3). Each server adopts it first-hand (core §3.4)
   and stores its seat keys as for a seat change (Server profile §4).
4. **The backup.** The device asks once, quietly: "Write down a backup now? If you lose this phone, it gets your account back." —
   **Write it down** or **Not now**.
   - **Write it down** makes the backup set (Backup module §1), with the read-back.
   - **Not now** destroys the backup secret and the backup seat's shares at once. The account has no paper
     until the person makes one (core F7), which the quiet dot on Backup suggests. So the device never
     keeps 5 points longer than the backup flow takes.
   - If the flow is left unfinished, the device destroys the secret after 24 hours and says: "No backup
     yet. If you wrote one down, scan it in Backup to check it."
5. **The signpost** is published (core §6.7.5), and the device registers push with each server (core §8.1).

The person sees one screen with a spinner ("Making your account…", a few seconds), then the backup
question, then the npub (core §1.1). No seed words, no server choices unless they ask.

### 1.2 Import (an existing nsec)

For someone who already has an nsec, and for moving a Cosign 0.12 account (core §11.2):

1. The person pastes or scans the nsec on a Keykin device. The device shows the npub it belongs to for
   the person to confirm.
2. The device deals: a random polynomial `f` of degree 3 with `f(0) = nsec`, shares for its own three
   indices, the backup seat's two and each server's one, each server's share sealed to it. Servers are
   picked and enrolled as in §1.1 step 1. The epoch record has `origin: import`.
3. Steps 3–5 of §1.1 follow.
4. The device wipes the nsec and `f` from memory, and says plainly: **"Your old key still works wherever
   it is saved. Delete it from your password manager and any app that has it."** It shows where it came
   from if it knows (the 0.12 app, a paste), and a **Done** button for when it's deleted.
5. For a 0.12 account, the device then asks each 0.12 server to `forget`, and offers to wipe the 0.12
   apps' copies (core §11.2).

An imported key was whole, so it is "ever whole" (core §10): anyone who copied the nsec before still has
it. The Key families module is the answer if that copy may have leaked.

## 2. The devices screen

One list, in plain words:

- each **device** with the name the person gave it, whether it has a lock ("Face ID", "no lock"), and when
  this device last saw it sign;
- each **server**, with its operator ("Run by X"), and "your own" for `own`;
- the **helper**, if any (Helper module), and whether there is a **backup** (Backup module).

Device names are kept in an account-signed kind 30078 event, `d = "keykin-labels"`, encrypted under
`HKDF-SHA256(dk(S), "keykin-labels/1")`, and sent in every welcome. The `keykin-` guard (Doors and grants
§2) keeps sites away from it.

### 2.1 Adding a device

The person picks **Add a device** on a member, or opens the app on the new device and picks **I already
have an account**. Either side shows a code (core §4.1). Then:

1. The new device shows a 6-digit number; the person types it on the old device (core §4.1).
2. The old device asks for its approval: its lock; or, with no lock, the person picks **Use another
   device** (a `pair`) or **Scan my paper** (core §6.2).
3. The new device asks for a name ("Laptop"), suggesting the device model.

A lone device with no lock can't add a device by itself: it needs a second device's typed code or the
paper. The app says so in one line when it happens.

### 2.2 Reporting a device lost

**Report lost** on any device (core §6.4): one confirmation naming the device, then the approval (a lock,
a second device, or the paper). It takes effect at once. The app then shows the quiet dot on Backup
(core §6.7.9).

Without any other device and without a lock, the person uses the paper; with every device lost, a paper
recovery (core §6.5) can remove the stolen one.

*The passkey page on servers that earlier notes mention is dropped:* core §6.1 doesn't count a passkey as
a lock, and a report needs a lock, two devices or the paper.

### 2.3 Leaving: a device the person is giving away

**Remove this device** is a report-lost of the device itself, with the same approval. It is refused on
the account's only device, because the account would have no device left (core I4). On success the device
destroys everything for the account (core §6.4) and says so.

An extension retiring in favour of the machine's desktop app uses the core's `self` remove instead (core
§4.6), with no question asked.

## 3. Deleting the account

**Delete my account** is in the account settings, never on a main screen.

1. The card says: "This asks every relay to erase your posts, and destroys every piece of your key. Your
   npub can never be used again. This can't be undone."
2. The device signs a request to vanish (NIP-62, kind 62) with `["relay", "ALL_RELAYS"]`. It is Held
   (core §5.8): the device's lock, or a 3-day hold the person starts, which every device is told about and
   can stop.
3. The device publishes it to the account's relays and its known write relays, then sends
   `account_delete {event}` to every server, as a delivery.
4. A server that verifies the kind 62 under `g`, with `ALL_RELAYS`, co-signed by the core's rules,
   destroys everything for the account (its share, seeds, material, waits, push addresses, notice channels,
   heir record), keeps only `SHA-256(g)` and the event, and answers every later request for `g` with
   `deleted`. It never seats or creates `g` again.
5. Every device that verifies the event destroys everything for the account. A paper becomes worthless;
   a recovery attempt is told `deleted`.

So deleting needs the same as vanishing, which it is: a lock or a waited hold. Retired servers that are
offline keep their forwarding notes, which hold no secrets.

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
- **"Not now" means no backup.** If that device is lost and no other exists, the account is lost (Backup
  module §6).
- **A thief with the device's lock, or a 3-day hold nobody stops, can delete the account.** That is no
  worse than vanishing, which an nsec does at once.
- **The DKG's device runs five participants**, so until the backup flow ends that device alone holds 5
  points, as core §4.3 says.

## Changes

- Draft 1.
