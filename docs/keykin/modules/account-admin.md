# Keykin module: Account admin

Draft 8 · 2026-11-03 · module of [Keykin Core](../core.md) draft 14.14 · not built

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

1. **Pick servers.** The device takes its chosen signed server list (Server profile §4, core §6.7.7) and, by default, makes
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
   - The device relays every message (`dkg_1`, `dkg_2`, sealed to each server's throwaway key), so every
     participant sees the same round 1.
   - Every participant checks its round-2 packages. Any failure aborts. A server that aborts is dropped
     for this creation; for a disputed round-2 package, both servers in it are dropped. The device
     restarts at most three times in all; each restart makes new picks, since the device's member key is
     new.
   - Every participant destroys its round-1 and round-2 secret packages when the DKG ends.
   - A server accepts DKG messages only from the device that sent `create`, and refuses, at the welcome,
     a provisional seat for which it holds no share of its own, so an outsider's `create` can't leave a
     "live" account with no server shares.
   - The group key is brought to even y as `frost-secp256k1-tr` does, for every share and the commitment.
   - A server that took part in a DKG that never reached its epoch record drops everything for it after
     one hour.
3. **Enrol, wrap, and sign the epoch record.** Now that `g` exists, the device asks each server
   `enroll {g}` for its enrol reply (Server profile §4). It makes the backup key pair and wraps the
   backup seat's shares as the base item (core §4.3, §7.2), with the creation release seed (core §6.7.2).
   Then it builds the epoch record (core §3.1, `origin: dkg`, `role: master`): `g`, the summed commitment,
   the members (the device with its lock if it has one; the servers with their enrol replies; the backup
   key), the seats, the relays (the servers' relays plus the app's defaults) and the base item's pin. The
   device signs it alone with its own 3 points and the backup seat's 2 (no co-signer knows the account
   yet), and sends it to each server sealed, as its welcome. Each server checks the enrol replies in it,
   as a co-signer would.
4. **Live only when adopted.** The account goes live (the npub is shown, anything is published) only after
   every server has adopted the epoch record first-hand (core §3.4) and stored its seat keys (Server
   profile §4). Until then each server holds the account **provisionally**. As soon as every server has
   adopted, the device signs the signpost (core §6.7.5) and delivers its event id and the epoch id to every
   server (core §6.7.10), together with an explicit `confirm {epoch}`, and only after every server
   acknowledges does it publish the signpost; that `confirm` **confirms** the account (a server confirms only the epoch record it adopted), and it registers push (core §8.1), all before the backup question. A server
   that hasn't seen the confirmation within an hour asks its peers first (`confirm_status {epoch}` →
   `{confirmed}`),
   and drops the provisional
   account only if none has seen it, keeping no record. A provisional account never counts for `refused:
   exists`, and a newer group-signed epoch record for the same `g` replaces it. A seat answering "unknown
   account" before the account is live restarts the creation; after, the core's dead check applies (F1). Dropping keeps no record, so a failed attempt never bars a retry of the same imported npub and no message can
   wipe a live account. Restarts count towards the three of step 2; after the third, the app says
   "Couldn't reach enough servers. Try again later." 
5. **The backup.** The device asks once, quietly: "Write down a backup now? If you lose this phone, it gets
   your account back." — **Write it down**, **Add another device instead**, or **Not now**.
   - **Write it down**, during creation, makes a **paper** of **this** backup key (no new key or `paper`
     change: the epoch record already pins it), with the read-back; then the secret is destroyed, with no
     new-paper suggestion. Later, from a kept secret, Write it down runs as an F7, so the paper is of a
     fresh key. Friends' pieces and an heir
     always go through a new set (F7, Backup module §1.1), which the kept secret may approve as a paper
     would.
   - **Add another device instead**: while the device still holds the backup secret, it can approve adding
     a device with it (a `paper` approval, core §6.2). This is the way out for a device with no lock.
   - **A kept secret** approves whatever a paper would (adding a device, registering a lock, replacing a
     server, deleting the account), retried freely until the change is co-signed. It is destroyed once any
     device has a lock or a paper has been read back.
   - **Not now**, on a device with a lock, destroys the backup secret and the backup seat's shares at once
     (core §4.3 step 4).
   - **Not now**, on a device with **no lock** (every browser extension), keeps them sealed (core §7.3)
     until any device of the account has a lock or a paper has been read back. Every lockless device that
     joins meanwhile gets a sealed copy in its welcome, so losing one never traps the other; all copies are
     destroyed together (`kept_done`, core §4.3 step 4; re-sent to any device that joined in the day before,
     so a copy can't outlive it). After an F7 on such an account, `kept_new` gives every lockless device the
     new key's secret. Meanwhile the quiet dot on Backup suggests, once, "Add your phone to keep your account safe if
     this browser is lost." No banner, no push.
   - If the flow is left unfinished, the device treats it as Not now after 24 hours and says: "No backup
     yet. If you wrote one down, scan it in Backup to check it."
The person sees one screen with a spinner ("Making your account…", a few seconds), then the backup
question, then the npub (core §1.1). No seed words, no server choices unless they ask.

### 1.2 Import (an existing nsec)

For someone who already has an nsec, and for moving a Cosign 0.12 account (core §11.2):

1. The person pastes or scans the nsec on a Keykin device. The device clears the clipboard and shows the
   npub it belongs to for the person to confirm.
2. **Already a Keykin account?** The device looks on relays for any Keykin event signed by that key (a
   signpost or grant event). If it finds one: "This key is already a Keykin account. Sign in to it
   instead." with **Import anyway**, for someone who lost that account and has only the nsec. A server
   that already serves this `g` refuses the new epoch record when it arrives (`refused: exists`; never in
   answer to an unauthenticated enrol, which would tell anyone which servers serve an npub), and the device
   picks another. With one operator today, every listed server may already hold the old account; then
   the app says plainly: "Your old account's servers still hold it. Recover it with its paper, or delete
   it from a device you still have. Otherwise you can keep using your nsec as before; Keykin can host it
   only on a server you run." A server that answers `deleted` for this `g` is skipped the same way.
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
that device. Names are kept in one account-signed kind 30078 event **per device**, with `d` made as Doors and grants
does for grant events (`"keykin-labels:" ‖` an HMAC of the member key under the base data key), encrypted under
`HKDF-SHA256(dk(S), "keykin-labels/1")`, with each name signed by the named device's own member key.
Devices show only names signed by the device they name, always with the model next to the name, and
flag two devices with the same name, so a stolen device can't pass itself off as another to trick the
owner into reporting the wrong one. The `keykin-` guard (Doors and grants §2) keeps sites away.

### 2.1 Adding a device

The person picks **Add a device** on a member, or opens the app on the new device and picks **I already
have an account**. Either side shows a code (core §4.1). Then:

1. The new device shows a 6-digit number; the person types it on the old device (core §4.1).
2. The old device asks for its approval: its lock; or, with no lock, the person picks **Use another
   device** (a `pair`), **Scan my paper**, or, on a lockless device that kept its backup, **Use the backup
   this browser kept** (core §6.2).

A lone device with no lock, no paper and no kept backup can't add a device (core §6.2, no wait path). The
app says so in one line when it happens.

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

**Delete my account** is in the account settings, never on a main screen. It is two separate acts. If the
account is a key family's master, it first says "This also ends your key families" and offers to warn
the children's followers (Key families module §7).

1. **Erase my posts** (optional, offered first): a request to vanish (NIP-62, kind 62, `["relay",
   "ALL_RELAYS"]`), Held like any vanish (core §5.8): the lock, or a 3-day hold. It erases everything the
   account published on relays that honour it, the profile, follows and lists included, and leaves the
   key alone, so a person can erase their posts and keep their npub. Afterwards the device republishes the
   signpost and its grant and labels events.
2. **Destroy my key**: the card says "This destroys every piece of your key on your servers. They will
   never serve this npub again. This can't be undone." For an imported key it adds: "Old copies of your
   nsec still work."
   It is an approved request, `account_delete {id}`, with a lock, a second device (`pair`) or the paper
   (core §6.2), encoded as core §6.1's generic request (for `paper`, the backup signs `{"what":
   hex(what), "challenge"}`, core 13.15). There is no hold path: a thief with an unlocked lockless phone
   can't destroy the key, unless that phone still keeps its backup secret (§1.1 step 5), which approves
   as a paper would. If the person chose Erase my posts, the delete's approval is asked for only
   after the vanish is signed, and the device republishes the signed vanish to every relay it knows first.
   - For a `paper` approval the device first gets a fresh challenge from every server and has the backup
     sign for each, so every server can check it itself.
   - The device sends it to every server, as a delivery, and keeps everything until **two** servers have
     answered `deleted` (or, after 7 days, every server that answers has, and at least one did; meanwhile it
     shows "Deleting…");
     it sends the friends', heir's and helper's notice first (the helper destroys its shares on it), and only then destroys the account, keeping only the request, the first
     `deleted` it received and the servers' endpoints, and sending until each answers.
   - A server accepts it with an approval it checks itself (fresh, with its own challenge for `paper`, every
     approver a current device in its own view, core §3.2), or with a host-signed `deleted` from a peer that
     is a current seat holder, carrying the request, **and only if the carried request's approval checks
     in its own view**: fully for `lock` and `pair`; for `paper`, both signatures and that the backup key is
     current, and its own challenge's signature when the request carries one per server (as it does when
     the device asked every server for a challenge). A peer's word alone never deletes anything. It then destroys everything for the
     account (its share, seeds, material, waits, push addresses, notice channels, heir record), keeps only
     `SHA-256(g)`, the epoch record, the approved request and the changes that prove its approval (core §2), and
     answers every later request for `g` with a host-signed `deleted` and those, which devices check. It
     never seats or creates `g` again. Servers that never held the account aren't bound by it.
   - Every device that verifies it destroys everything for the account. Friends and the heir get one
     notice ("*Name* deleted their account") carrying a host-signed `deleted` with the request and the
     changes that prove its approval; their apps check those against the account card's `g` and epoch id
     and only then drop their pieces (Backup module §1.1 step 8).

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

## 6. Messages

This module's messages, sealed as core §9.1, with the core's lifetime classes (§5.6):

| `type` | From → to | `cls` |
|---|---|---|
| `create` / `create_ok {dkg_key, host_sig}` (`host_sig` over `SHA-256("keykin-dkg-key/1" ‖ dkg_key)`) | device → server / back | `ask` |
| `dkg_1 {index, max}` → `{package}`; `dkg_2 {round1: [[i, package]…], dkg_keys: {i: key}}` → `{packages: [[j, package \| {sealed, from}]…]}` (sealed NIP-44 to the other server's DKG key); `dkg_3 {round1, round2}` → `{g, points}`; `dkg_abort {culprit}` | device ↔ server (relayed) | `ask` |
| `confirm {epoch}` / `confirm_status {epoch}` → `{confirmed}` | device → servers / server → peers | `member` / `ask` |
| `refused: exists` | server → device (an `error`) | — |
| `account_delete {id, approval}` / `deleted {request, changes, host_sig}` (`host_sig` over `SHA-256("keykin-deleted/1" ‖ g ‖ JCS(request))`) | device → servers, server → server / back | `member` |

## 7. Limits, said plainly

- **An imported key is only as safe as every old copy.** Keykin can't delete the nsec from a password
  manager, a 0.12 app or a screenshot.
- **"Not now" on a device with no lock** leaves every lockless device worth 5 points until any device has
  a lock or a paper is read back: whoever copies one of those browser profiles has the whole key, as with
  an nsec kept in it, and keeps paper power until a new paper replaces the backup key.
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

- **Draft 8**, from its sixth red team (0 critical, 0 high), its mediums and lows:
  - `kept_new` after an F7 on a lockless account (M1, core 14.9);
  - a delete's 7-day fallback needs at least one `deleted` (M2);
  - confirmations name the epoch id (M3);
  - the tombstone keeps the epoch record (M4, core 14.9);
  - "unknown account" before and after going live (M5);
  - no new-paper suggestion at creation; later papers from a kept secret are F7s (M6);
  - "signs" then "publishes", `kept_done` re-sent to recent joiners, the helper told of a delete, `deleted`
    only to authenticated requests (lows).
- **Draft 7**, from its fifth red team (0 critical, 1 high):
  - the kept secret survives until a locked device has finished joining (H1, core 14.6).

  The mediums and lows:
  - servers ask peers before dropping a provisional account, and unknown seats count as dead (M1);
  - an F7 on a lockless account keeps the new key's secret (M2, core 14.6);
  - a new paper suggested after `kept_done` (M3, core 14.6);
  - the signpost published after confirmation, provisional accounts and `exists`, Import anyway wording,
    the epoch id in delete proofs, `kept_done` senders, deletes with one live server, notice order
    (L1 to L8).
- **Draft 6** (Q7): the kept secret lasts until a lock or a read-back paper exists, and every lockless
  device holds a copy meanwhile (core 14.5).
- **Draft 5**, from its fourth red team (0 critical, 1 high):
  - `create_abort` is gone: servers hold a new account provisionally until the device confirms it, and
    drop it after an hour, so no message can wipe a live account (H1).

  The mediums and lows:
  - a delete destroys the device's copy only after two servers accept, with a challenge from each for
    `paper` (M1);
  - friends and the heir check the delete proof before dropping pieces (M2);
  - "a second device has joined" means its welcome was acknowledged (M3, core 14.2);
  - from the creation key, a paper only; friends and heirs through F7 (M4);
  - Import anyway when every server holds the old account (M5);
  - alignment with core 14.1, and smaller wording (lows).
- **Draft 4**, from its third red team (0 critical, 2 high):
  - a handover carries the kept backup secret, and the app may use it for its first lock (H1, core 14);
  - a failed creation is undone by `create_abort`, which leaves no record (H2).

  The mediums and lows:
  - the kept secret approves whatever a paper would, and ends when a lock is registered (M1, L1);
  - `refused: exists` only when the epoch record arrives (M2);
  - the delete tombstone keeps what proves its approval (M3, core 14);
  - "Write it down" from a kept secret (M4);
  - a third approval choice when adding a device, the delete approval after the vanish, the vanish
    republished, restarts counted, signpost and push before the backup question, the destroy card
    wording, names shown with models, the sender keeps only the request (L2 to L10).
- **Draft 3** (and the user's answer on lockless "Not now": keep the secret sealed until a second device
  or a paper, core 14), from its second red team (0 critical, 1 high):
  - lockless devices lead with **Add your phone now**, and Not now says plainly what it costs (H1; the
    alternative, keeping the secret on a lockless device, is open for the user).

  The mediums and lows:
  - the creation secret approves one add from that screen only (M1);
  - a `paper` approval of `account_delete`, late copies by a peer's `deleted` (M2, core 13.15);
  - the tombstone keeps the approver's changes (M3, core 13.15);
  - destroy waits for a chosen erase (M4);
  - honest wording for imported keys and other servers (M5);
  - **Import anyway**, and `refused: exists` (M6);
  - the module's messages (M7);
  - the device signs the epoch record alone, no round-1 cross-check, orphans deleted, restarts capped and
    worded, secret packages destroyed, labels per device, what a vanish erases, delete resent until
    answered (L1 to L8).
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
