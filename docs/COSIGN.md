# Cosign — Specification

Version 0.2-draft
Applies to: a user's own devices and one or more servers that together hold a Nostr
key that none of them holds alone

Key words MUST, MUST NOT, SHOULD, MAY are normative.

> **Working title.** "Cosign" is the name of the prototype app this was worked out
> on; the spec may get a name of its own.
>
> **Relation to other specs.** [QRST](https://github.com/sybenx/qr-secret-transfer/blob/main/QR_SECRET_TRANSFER.md)
> moves things between devices: it is how a site is connected and how a device
> joins. [NKM](https://github.com/sybenx/nostr-key-management/blob/main/NOSTR_KEY_MANAGEMENT.md) keeps storage and
> backup for clients that hold an nsec. This document replaces NKM 9.2 §7 (both of
> its threshold modes) with one model, and carries over what §7 got right: the
> two-tier revocation of §7.9, the rule that a server destroys its old piece, the
> epoch records of §7.4, and threshold ECDH (§7.6a).

---

## 0. Design principle

**No device, site or server holds the user's key, and nobody has to run a server.**

- The key is split into pieces of different **weight**, and signing takes **4 points**.
  Each of the user's devices is worth **3**, each server **1**, the paper backup **2**.
- So the everyday pair is **the device the user is on plus any one server**, and **two of
  the user's devices** sign with no server at all. **All the servers together (3) can
  never sign**, and neither can one device alone (3).
- There are **several servers run by different people** — typically three — and the
  device asks them at once; the first to answer signs. No server is central, and any one
  of them may be down. Servers may be public, a friend's, or the user's own.
- Sites and apps that only ask for signatures never hold a piece. They are connected
  by scanning a code and removed with one tap.
- Being a member is meant to be a feature of the Nostr apps people already use, not an
  extra app (§4.1).
- A lost device is removed instantly and its piece is made worthless. **The npub never
  changes.**
- Anything more — more devices, a paper backup, a server of one's own — is optional and
  only adds robustness. Nothing in this document may require the user to add one.

The baseline this improves on is one device holding the whole nsec. Where a choice is
no worse than that baseline, this document takes it without ceremony.

## 1. Overview

```
 site ──▶ the device you're on (3) ──┬──▶ server A (1) ─┐
                                     ├──▶ server B (1) ─┼─ first answer: 3 + 1 = 4, signed
                                     └──▶ server C (1) ─┘
          destructive: the device asks you first (Undo after)
 optional:  more devices (3 each) · paper backup (2) · a server of your own (1)
```

| Piece | Weight | Job |
|---|---|---|
| Each device (extension, phone, iPad…) | 3 | Coordinates its own signing. Judges what's destructive and asks the user. Connects and removes sites. |
| Each server (typically three, ideally different operators) | 1 | Always on. Adds the missing point. Keeps list history for Undo, enforces waits, wakes devices. |
| Paper backup (optional) | 2 | Opens the current backup piece, which lives gift-wrapped on relays (§8). |

| Together | Points | Signs? |
|---|---|---|
| A device + any one server | 4 | yes — the everyday pair |
| Two devices | 6 | yes — no server involved |
| All three servers | 3 | **never** |
| One device alone | 3 | no |
| Paper + two servers | 4 | yes, **after a wait** — recovery when every device is lost |
| Paper + a device | 5 | yes |

What the user does:

- **Connect a site**: through the extension, or scan its code with a device (§6).
- **Everyday**: nothing. Routine events sign in well under a second.
- **Destructive**: the device asks; approve or refuse. Undo afterwards (§5.4).
- **Add a device**: scan a code (§7.1).
- **Lose a device**: report it; it is blocked at once (§7.2).
- **Lose every device**: the paper backup plus two servers, after a wait (§8).

## 2. Definitions

- **Group key** — the user's Nostr key. Its public half is the npub. Never assembled.
- **Share** — a FROST share: a point `f(i)` on the group's polynomial at a unique
  index `i`. Each share is worth one **point**.
- **Piece** — everything one member holds: a device's piece is 3 shares, a server's 1,
  the paper backup's 2.
- **Member** — anything holding a piece: a server or a device. Each member has a stable
  **enrollment keypair** `E` (servers: `S`) that authenticates it (NKM §7.1).
- **Operator** — whoever runs a member. The user is the operator of their own devices
  and of any server they run themselves.
- **Epoch** — one version of the set of pieces. A refresh (§7.3) starts a new epoch; a
  piece from an old epoch does not combine with one from a new epoch.
- **Coordinator** — the member that runs a signing or decryption round and finishes
  it.
- **Site** — any web page or app that asks for signatures. Holds a **grant**, never a
  piece.
- **Grant** — a site's access: its own key, its origin or package name, an optional
  expiry, and the member that admitted it.
- **Backup key** — a keypair printed on paper. It opens the backup piece (§8). It is not
  itself a piece.
- **Wait** — a delay with notices to every member, cancellable by any one of them
  (§7.4). Its length `W` is **3 days**.

## 3. Parameters

- **Scheme**: FROST per RFC 9591, secp256k1 with BIP-340 (Taproot) challenge, as
  `frost-secp256k1-tr`. Odd-y group keys are handled as NKM §7.4. Final signatures are
  plain BIP-340.
- **Threshold**: `t = 4`.
- **Weights**: each device holds **3** shares, each server **1**, the paper backup **2**.
  A member with several shares is simply several FROST participant identifiers on one
  machine; no new cryptography is involved. A typical group — two devices, three
  servers, paper — is 11 shares.
- **At least two servers, from the start.** An account is created with two or more
  servers (at launch, three), so the paper (2) plus two servers can always recover it
  (§8.3). The paper is always worth 2.
- **Indices**: every share has a **unique** index. There are no replicas.
- **Changing the threshold or weights** of an existing group keeps the same key. Either:
  - **redistribute** (preferred): enough current holders each split their own
    Lagrange-weighted part under the new threshold and send each new share its
    portion, sealed; the new holders add them up. No one ever holds the whole key. The
    reference library (ZF `frost-secp256k1-tr`) has no built-in for this, but it needs
    only scalar arithmetic on top of it; or
  - **rebuild and re-split** on one trusted device, which deals the new shares and wipes
    the key — the same exposure as importing an nsec (§3, "Creating the key"). A client
    MUST tell the servers, and so every device, before it rebuilds or shows the key
    (*announce before showing*); the escape hatch of §8.4 is the one exception.
  Groups made under 0.1 (threshold 2) were test keys only and may simply be recreated.
- **A server holds exactly one share.** No server may hold more, whoever runs it.
- **Servers SHOULD have different operators.** Clients prefer three servers from three
  operators. When fewer operators exist, a client fills the remaining places from one
  operator's servers and says so plainly in setup and settings. *(Planned, not yet
  specified: swapping them out automatically by refresh as other operators appear;
  today a device adds a server by hand, §9.5.)* A public server, a friend's and the
  user's own make three; the user may run any number of devices.
  - **What it costs:** one operator's servers together are at most 3 points and can
    never sign. Its exposure is that operator plus a stolen paper backup: 2 + 2 = 4
    points, with the wait (§7.4) in that operator's hands — the same as two colluding
    operators. Accepted at launch, and shown to the user.
  - **Why it is better than one server:** a server losing its data, or vanishing, no
    longer strands an account that has one device and no paper backup; that device and
    another server still make 4.
- **Creating the key**: a new identity SHOULD be created by distributed key generation
  between the user's first device — a phone, or just as well a browser extension — and
  its servers, so no one sees it whole. An existing nsec is split
  by the device that holds it (as dealer), which then wipes it (NKM §7.5 steps 4–5).
- **Epoch record**: as NKM §7.4 (kind 30242, `d = "frost"`, encrypted under the group
  secret), with `members: [{index, E.pub|S.pub, kind: server|device|backup, label,
  operator, shares: [indices]}]` and the commitments to the current polynomial. Signed
  by the group key, which needs 4 points.
- **Nonces**: generated fresh per round. A member MUST NOT reuse a nonce, and MUST NOT
  persist nonces where a restore or a second copy could replay them.

## 4. Members

### 4.1 Devices

A device is any app holding a piece on hardware the user owns: the phone app, a desktop
app, a browser extension (§6.3), an iPad app. Every device holds 3 shares and all are
equal in what they can do; the user's **main device** is only where approvals go when no
device is in the loop (§5.1).

**No phone is required.** Any one device plus servers is a complete setup: a browser
extension and public servers can create an account together (§3) with no code to
scan, sign everything, and show approvals in the extension. On an iPhone, Safari's
extension plus a server is the whole of Cosign. Wherever "the phone" appears below, read
"the user's main device". A client with only one device SHOULD prompt early to add a
second device or print the paper backup (§8), since losing that one device otherwise
leaves only the servers' 3 points.

**Built into the apps people already use.** Membership SHOULD be a feature of ordinary
Nostr clients — the feed, search and notifications app the user opens every day — not
a separate signer app that sits idle. An app that is opened often is an app that is
awake to co-sign, and its own posts need no hop to another app. A standalone signer app
is the fallback for people whose client does not include it yet. Implementations SHOULD
share a reference library (§4.3) so that adding membership to a client is a dependency,
not a re-implementation.

**Several such apps on one device.** Where the platform lets apps share a signer
(Android, through NIP-55), the apps on a device SHOULD share the one member already
there rather than each holding a piece. Where it does not (iOS), each app MAY join as a
member of its own, listed by app and device ("*Primal* on *iPhone*") *(not built)*. Two such apps on
one device hold 6 points and can sign together without any server; as with §5.5, that is
no worse than today's one app holding the nsec, and reporting the device lost (§7.2)
removes both.

### 4.2 Servers

A server is an always-on member reachable over relays. It needs no public address: it
connects out to relays like any client. HTTPS is an optional fast path.

A server MAY host pieces for many users (§9). For each user it holds exactly one share,
that
user's grants, the archive of their lists (§5.4), and pending sealed messages for their
offline members.

### 4.3 The member library

*Planned, not yet specified.* The intent, to make §4.1 concrete: a **member library**
that holds everything a member needs and nothing of any app's interface:

- the group record, shares, nonces and their storage hooks (§3);
- coordinating and joining rounds, including hedging across servers (§5.1);
- the destructive check against its own archive (§5.2, §5.3);
- the doors: NIP-07 and NIP-55 handlers, NIP-46 for the signer keys it holds, and both
  halves of `signer-ticket` (§6);
- repair, refresh, removal, waits and the paper backup (§7, §8);
- server discovery (§9.5).

It ships in **Kotlin** (for Android apps) and **TypeScript** (for browser extensions,
web apps and servers), sharing test vectors. An app supplies only storage, the device
lock and its screens, so that Amethyst, Primal and other clients can become members with
a dependency, not a rewrite.

### 4.4 The member list

The member list lives in the epoch record. Every member keeps a copy and subscribes to
`#p = E.pub` for sealed messages addressed to it.

## 5. Signing

### 5.1 Who signs

**The device coordinates.** A device is in every signature — the servers together have
only 3 points — so the device that receives a request (from a site through §6.3, or its
own app) runs the round: its own 3 shares plus one more point.

1. **Another of the user's devices, if one is known to be awake** (it holds a live relay
   connection): 3 + 3 = 6, and **no server sees the event at all**.
2. **Otherwise, a server**: 3 + 1 = 4. The device asks its most reliable server first and,
   if no answer comes within a short hedge delay (reference: 300 ms), the others at
   once; it completes with the first valid share and cancels the rest. It MAY ask all
   of them at once. A server the user runs counts as one of their own devices for
   privacy and is preferred.

Each request to a server is an independent round with its own fresh coordinator
nonces. The coordinator discards the nonces of every round it cancels. Every nonce is
still used once, and a share from a round that never completes reveals nothing.

Hedging trades a little privacy for speed: every server asked sees the event. A device
SHOULD remember which servers answer fastest and ask those first, so most events are seen
by one server only. This MUST NOT add waiting: a device or server that is not known to
be awake is not tried first.

- **Presence.** A device announces "awake" to the user's other devices when it connects
  and at a slow interval while connected (reference: 60 s), and "asleep" when it can.
  These go only between the user's own devices, never to a server, and there are no
  standing pings. A device whose last announcement is stale is treated as asleep. If a
  device believed awake does not answer within a short timeout (reference: 1 s), the
  servers are asked instead.
- **History still reaches the archive.** Devices that sign without a server MUST send
  each signed event of an archived kind (§5.4) to the servers and to the other members
  afterwards, so the archive, the change history, Undo and later destructive checks
  stay current. It is already signed, so this is history only; a public server learns
  it no sooner than it would from relays.

**When no member device is in the loop** — a NIP-46 site used from a browser with no
extension (§6.1) — the request reaches the holders of that site's signer key, which are
the user's devices and servers the user runs. A server the user runs MAY coordinate,
asking a device for its 3 points (woken by push, §10); a server run by anyone else
never coordinates.

- **Asking.** A device putting a request to the user MUST say so ("asking") when it is
  not the coordinator, and the coordinator then waits for it (reference: up to 60 s).
- **Last one left.** When the only device that can be asked is asleep, the coordinator
  pushes to it (§10) and waits (reference: 15 s) before returning an error to the site.
- **A decline is final.** When the user declines, the round ends. The coordinator MUST
  NOT go on to ask anyone else.

### 5.2 What every co-signer checks

Before giving its shares, every member taking part MUST check, for the full unsigned
event (never a bare digest — it hashes the event itself, per NIP-01):

- the requesting site holds a live grant (§6.2), or the requester is a member;
- the event is not destructive (§5.3), or carries a valid approval;
- the round's nonces have not been seen before;
- the site's request is not a replay: members MUST drop a site request they have already
  answered (by id) and one whose `created_at` is too old (reference: 30 s). Relays
  replay recent ephemeral requests to a new subscription, so a member restarting could
  otherwise re-sign, say, an old follow list.

**The device is the gate.** Since a device is in every signature, the destructive check
that counts is the device's own, against its own copy of the archive, and it asks the
user itself (§5.3). Servers MAY check too and refuse, but because any one server's point
is enough, a server's check is a second opinion, not the gate. So the event never
depends on which server happened to answer first.

A device's copy holds the latest version of each list **taken only from events with a
valid signature under the group key** — from the servers' notices and from its own
relay subscription. So a server can withhold a version but cannot invent one. A device
that missed the newest version judges against an older one; that is accepted.

### 5.3 Destructive events

An event is destructive by **what it does**, not by its kind, judged against the
version it replaces. The reference policy:

| Event | Held when |
|---|---|
| Request to vanish (kind 62) | always |
| Deletion (kind 5) | it targets a list kept in the archive, or 5 or more events |
| Profile (kind 0) | 2 or more filled fields are emptied, or it is emptied entirely |
| Follow list, mutes, bookmarks, sets… | emptied (from 3 or more items), or 10 or more items **and** 20% or more removed |
| Relay lists | 2 or more relays **and** half or more removed |
| Any event dated in the future | more than 10 minutes ahead of the network's time |

A replaceable event, or a deletion by address, dated in the future is **refused**, not
held: a version dated ahead would block every later change until that date.

A held event is shown on the device that is signing (or, when no device is in the loop,
the user's main device) in plain words — "Remove 412 of your 430 follows" — and signed
only once the user approves there, confirmed with the device's lock. The device that
approves MUST be a member device and MUST NOT be the site that asked.

Implementations MAY tighten this policy. They MUST NOT make holding the default for
ordinary events: routine signing is silent.

### 5.4 Archive and Undo

Each server, and each device, keeps the recent versions of the user's replaceable lists (profile, follows,
mutes, relays, bookmarks, sets; reference: the last 25 per list). Every change shows in
every device's history in plain words, with **Undo**, which republishes the archived
version (a routine signature).

### 5.5 Without any server *(not built)*

Two member devices (6 points) MAY sign together without any server, using the same
checks (§5.2) against whatever archive they have. This keeps the user signing while every
server is down. Two of the user's own devices are not bound by any server's policy; that
is accepted, as it is strictly better than one device holding the key.

- **Epochs.** A device-only round carries the epoch. A device refuses any round below the
  newest epoch it has seen, and after coming online fetches the latest epoch record
  before taking part in any device-only round, so a device removed while it was offline
  (§7.2) cannot sign with one that missed the news.

### 5.6 Decryption

NIP-04 and NIP-44 conversation keys and NIP-59 unwrapping need ECDH with the group key,
done in one round as NKM §7.6a: the members taking part return Lagrange-weighted
partials `λ_i·s_i·P` for shares worth 4 points between them (a device's 3 and a
server's 1); the coordinator adds them. The coordinator learns the shared
secret; the others learn only `P`.

**Who gets a partial.** Servers give decryption partials only to active member
devices — never to the backup key, and never to a removed member.

**A server operated by anyone but the user MUST NOT coordinate a decryption.** It gives
its partial and never finishes one. With a device coordinating (§5.1) this is the
normal case. For NIP-46 sites this follows from §6.1: such a
server never holds their signer key, so it never sees their requests at all.

## 6. Sites and apps

### 6.1 Connecting

- **By code (primary).** The site shows a QRST code for the published profile
  [`signer-ticket`](https://github.com/sybenx/qr-secret-transfer/pull/14) (QRST §5.2
  shape: `{pubkey, signer, relays, t, expires}`). The user scans it with a member
  device and taps **Connect**. The device tells the holders of the signer key about the
  ticket; the site redeems it as a NIP-46 `connect` secret and keeps a key of its own,
  which is its grant. QRST check level `none` is allowed for a camera scan or a verified
  App Link; `compare` for a pasted link, the `qrst:` handoff or any custom scheme. How
  the code reaches an app is §6.4.
- **By nostrconnect (fallback).** A `nostrconnect://` code is scanned the same way and
  ends in the same kind of grant, removed the same way. Ordinary NIP-46 sites send each
  request once; members SHOULD answer twice and move the site onto relays known to work.
  Such sites stay less reliable than QRST ones: they cannot re-send, and some client
  libraries' relay connections go stale after a few idle minutes until the page is
  reloaded (non-normative, seen with nostr-tools).

  NIP-46 is unchanged; this document only decides which of the user's pieces answers
  it. A NIP-46 site encrypts its requests to a **signer key** — a mailbox address, not
  the user's key, and unable to sign anything. Whoever holds it can read those requests,
  DM text included. So:

  - The signer key for each site is copied to **every member device and to any server
    the user runs themselves**, and **never to a server run by anyone else**. Whichever
    holder is awake answers, and gets the rest of a signature as usual (§5.1): a
    device adds one server's point, a server the user runs asks a device for its 3.
  - With only the phone holding it, NIP-46 sites work while the phone is awake or can be
    woken by push (§10).
  - The first time a NIP-46 site asks to encrypt or decrypt, the phone asks once: **"Let
    *site* read and send your DMs?"** The answer is part of the grant.

### 6.2 Grants

A grant holds the site's key, its origin (or Android package name), when it was made,
and an optional expiry. Members refuse every request from a key without a live grant.

- **Remove**: from the phone, any member device, or any server's web page. Immediate.
- **Expiry**: by default a grant **never expires while it is used, and expires after 90
  days unused** — the pattern of OAuth refresh tokens with an inactivity limit. The user
  MAY instead pick a fixed 30, 60 or 90 days, or never. When a grant expires the site is
  asked to reconnect.
- **One entry per site, each connection inside it.** Grants with the same origin are
  grouped under one site, whichever door they came through (§6.3). Inside, each grant is
  listed by where it lives — "Chrome on *Work PC*", "*Laptop* extension", "*Phone*" —
  with when it was last used. The user can **sign out one connection** (the work
  computer) or **sign the whole site out everywhere** (a site misbehaving). Both are
  immediate.
- A grant gives the site nothing to keep: removing it leaves the site holding a key that
  no member will answer.

### 6.3 Doors sites already use

Sites MUST NOT need to change to work with this. A conforming device SHOULD offer the
doors that already exist:

- **Android: NIP-55.** The phone app is a NIP-55 signer. An app's request reaches the
  phone app directly (Android starts it to answer), and the phone app is the
  coordinator of §5.1. Each app is a grant.
- **Desktop: NIP-07.** A browser extension is a member device. A site calls
  `window.nostr`; the extension is the coordinator of §5.1. Each website is a grant
  of its own, merged with any other grant for the same origin (§6.2).
- **Everything else: NIP-46** via §6.1.

### 6.4 Open to any app

The doors are a protocol, not a product. No app, website or host is required:

- **The code.** A site's QR is the `https` form of QRST §11.2 on **any bounce host**
  (QRST §11.2a) — the site's own, or a neutral one. Its fragment carries the
  `signer-ticket` parameters and MAY carry `nc`, a `nostrconnect:` fallback (the
  profile's "`nc` fallback"). A bounce host only explains itself to someone with no
  member app; `cosign.aaro.cc` is one such host and is never required.
- **Handing the code to an app.** On the same device the site hands the code over
  either by the neutral `qrst:` handoff (QRST §11.2c), which **any member app may
  claim**, or by a verified `https` App Link to one app it knows.
- **No host needed.** An installed member app MUST work with no bounce host reachable:
  scanning the code with the app, or receiving it by `qrst:`, involves no request to the
  host. Every parameter is in the fragment.
- **Same-phone shortcut.** A site MAY skip its own "Sign in as …?" only when it handed
  the code over by a verified `https` App Link to one specific app. Through `qrst:` or
  any custom scheme, which any app can claim, the site MUST ask before redeeming (the
  profile's "Same-phone sign-in").

## 7. Devices

### 7.1 Adding a device

The new device shows a code; a member device (usually the phone) scans it.

1. Members holding 4 points between them (usually the vouching device's 3 and one
   server's 1, or two devices) compute the new device's 3 shares at fresh indices by
   repair: each computes its Lagrange-weighted contributions, blinded so that no one
   learns another's shares, and seals them to the new device's `E.pub`. The new device
   adds them and checks each result against the commitments. **No member, and no
   server, ever sees the new piece.**
2. The new device is **instant** when two member devices vouch for it, or when one
   vouches **and the user confirms with that device's own lock** (biometric or
   passcode). A server never counts as vouching: it cannot tell who is asking.
3. When only one member device vouches without its lock, adding it is a **wait**
   (§7.4).

Whoever adds a device holds 6 points afterwards: their own device and the new one. So one
device vouching instantly must cost a thief at least what today's baseline costs —
unlocking the phone that holds the nsec. That is what the device lock is for: the
device MUST ask for it at the moment of vouching, even when the device is already
unlocked.

**Today the lock is a claim the device makes.** Servers take the device's word that it
asked. *Planned:* a hardware-bound user-verification key — an Android Keystore P-256 key
that needs user authentication, or a WebAuthn credential with user verification — whose
signature the servers check. A device without one will then count as vouching without
its lock, so the wait applies.

### 7.2 Removing a device ("report lost")

From any member device, **confirmed with that device's own lock** (biometric or
passcode) at that moment (or from a server's web page with a passkey, *not built*):

1. **Instant block.** Every member MUST refuse rounds with the removed `E.pub` from
   that moment, so a stolen device (3) can no longer find its fourth point.
   Reporting a device removes every member on it (every app, §4.1). This is the whole
   of removal for a device that was merely retired.
2. **Refresh** (§7.3), so the removed device's piece no longer combines with anything.
3. **Notice to every member, the removed one included** — "*Phone* was removed from
   *Laptop*."

**Removal is final.** A device removed by mistake is added again (§7.1) by a remaining
device or with the paper backup.

### 7.3 Refresh

A refresh moves every remaining member to a new epoch with the same group key:

- At least one device and one server each deal a random polynomial of degree 3 with zero
  constant term and send each remaining share its delta, sealed to its member's `E.pub`,
  with commitments. Each member adds its
  deltas and checks the result against the new commitment.
- Members that are offline receive their deltas when next online: they wait sealed on
  the servers and on relays (kind 1059, NIP-40 expiration 30 days). A member offline
  longer than that is re-added (§7.1).
- **Every member MUST destroy its old-epoch piece** once the new one verifies — with no
  snapshot, backup, version history or log line that keeps it (NKM §7.9). Some hosts
  keep history that cannot be turned off: Cloudflare's SQLite-backed Durable Objects
  keep 30 days of point-in-time recovery. A piece MUST NOT be stored there in a form
  that history could bring back.
- The backup piece is renewed as part of every refresh (§8.2).

Refresh runs after every removal, after the backup is used, and MAY run on a schedule.

### 7.4 Waits

A wait applies to:

- adding a device vouched for by only one member device (§7.1);
- using the paper backup without a surviving device (§8.3);
- taking the account out with the servers' shares, and removing the servers' pieces
  (§7.6).

During a wait, every server MUST notify every member (push, the members' own screens,
and the server's web page), and **any one member device can cancel**, confirmed with its
lock. Cancel is the only action during a wait. Signing goes on as usual
throughout; the wait only delays trusting the newcomer. **Every server enforces it** by
refusing to take part before the wait ends, so it holds unless the operators of two
servers collude — or are one operator (§3).

Nothing else waits. Signing, approvals, connecting and removing sites, and reporting a
device lost are never delayed.

### 7.5 Replacing the phone

- **Upgrading, old phone in hand**: the old phone vouches and the user unlocks it;
  instant.
- **Phone lost**: report it from another device or a server's web page (§7.2), then
  add the new phone (§7.1). With two other devices vouching, instant; with one, a wait.

### 7.6 Taking the account out, and removing the servers' pieces

Both are **guarded**, like reporting a device lost: each needs the lock of a live
member device, every device is told and woken, and a waiting one can be cancelled by any
device with its lock (§7.4).

- **Take out** gives the user their whole key back, as an nsec.
  - **With servers:** after the wait (§7.4), each server seals its share to the device
    that asked; the device adds them to its own and rebuilds the key.
  - **With the paper backup:** the device already holds enough (5 points), so there is
    no wait, but it MUST first be heard by a server, which answers `noted` for that
    request and tells every device, before the device shows the key (*announce before
    showing*). The escape hatch (§8.4) is the one exception.
- **Remove the servers' pieces** ("forget"): a server stops signing and decrypting for
  the account at once, and deletes its pieces for real after the wait — the files on a
  Node server, the KV entry and every row on the Worker.

## 8. Backup and recovery

### 8.1 The paper backup

The user prints a **backup key** once, as a QR. The backup member has its own 2 share
indices in the member list, but **nobody online holds its piece**. Printing a new paper
runs a refresh (§7.3) that drops the old backup's indices, so the old paper is
worthless.

*Planned, not yet specified:* the paper also as 24 BIP-39 words of the backup secret,
labelled as a Cosign backup and not a NIP-06 or wallet seed; restoring from the words
alone by asking known servers' host keys, with a request signed by the backup key over
a server's nonce (`backup_find`); and a warning when every server is private or
unannounced.

### 8.2 Keeping the backup piece current

At setup and after every refresh, members holding 4 points between them compute the
backup's 2 shares by repair (§7.1 step 1). Each gift-wraps **only its own
contributions** to the backup key and stores them widely: on several relays as kind 1059
**with no expiration**, on every server, and on every member device. No member can
open them, and no member ever sees the backup piece.

Each wrapped contribution carries its epoch. Old epochs are harmless — they do not
combine with current pieces — so it does not matter if a relay keeps them.

### 8.3 Using the backup

Scan the paper. Fetch the newest epoch's contributions from any source, add them, and
check against that epoch's commitments. The paper is now worth 2 points:

- with any surviving device (5): sign, refresh, and add new devices;
- with two servers (4): the same, **after a wait** (§7.4) that both enforce, since a
  stolen paper plus two servers would otherwise be enough;
- with one server (3): nothing.

A refresh follows every use of the backup.

### 8.4 When no server answers: the escape hatch

If **no server has answered for 7 days**, a device plus the paper backup (5 points), or
two devices (6), MAY rebuild the key on one device, after the device's lock and a plain
warning: the whole key will then sit on that device, as an nsec does today. From there
the user can keep using it as an nsec, or split it again with new servers (§3, "rebuild
and re-split"). This is the one case where a client rebuilds the key without first
telling the servers (§3, *announce before showing*), because none are answering.

### 8.5 What survives what

| Lost | Still signing | Getting back to normal |
|---|---|---|
| A device | any other device + a server | report it; add the new device |
| A server | nothing changes: the other servers answer | add another server |
| Every server | nothing (device-only signing, §5.5, is not built) | after 7 days, the escape hatch (§8.4) |
| Every device | paper + two servers, after a wait | add new devices |
| Everything but the paper | nothing | — (the key is gone) |

There is no way to change a Nostr key. A thief who gathers 4 points of the same epoch —
for example a device plus one cooperating server — holds the identity for good.
Everything here is about never letting that happen: block and refresh quickly, and keep
pieces in different places.

## 9. Servers

### 9.1 Personal and public

A server is just a member that is always on. Anyone can run one.

- **Personal**: the user's own (a home box, a VPS, a Worker).
- **Public**: run by someone else for many users. An operator MAY accept anyone, or only
  people it invites; how invitations work is up to the operator.

**A server belongs beside a relay, or inside one** (non-normative). A relay is already
always on, already speaks Nostr to the user's devices, and already has an operator and
often an invite list. A server MAY therefore be a relay itself, accepting only its
users' member traffic and the requests addressed to them, so devices reach it by adding
it to the group's relays and it needs no outbound connections. Since NIP-46 sites are
answered by the user's own devices (§6.1), not by a server run by someone else, such a
server never has to dial out to a site's relays. This is the shape of a free-tier
Cloudflare Worker (a hibernating Durable Object), a container beside any relay, or a
feature of relay software. Implementations SHOULD keep the member logic in a library
with no I/O, so each of these is a thin host around the same core.

### 9.2 What a public server sees

It sees every event it co-signs (it must, to check it), the site grants, the archive,
and the counterparties of decryptions (peer pubkeys, never the plaintext, §5.6). It
holds one share per user, worth one point: it signs nothing alone, and all of a user's
servers together (3) still sign nothing.

A public server MUST NOT coordinate a decryption, MUST NOT hold a NIP-46 signer key
(§6.1), and MUST destroy old pieces on refresh. Until per-site signer keys exist, a
public server that still holds a NIP-46 signer key MUST refuse NIP-46 `nip04_*` and
`nip44_*` encrypt and decrypt requests: NIP-46 sites can sign through it, but not
read or send DMs.

**What strangers can make it reach.** Accounts, sites and new devices name relays and
push addresses, and on an open server anyone can create an account. A public server MUST
NOT connect to private, loopback, carrier-grade NAT (tailnet) or cloud-metadata
addresses because a stranger named them, and SHOULD resolve and check each address at
every connect, not once. It SHOULD cap what one stranger can use: accounts held, new
accounts per hour, messages per account per minute, relays per account and relay
connections overall. It SHOULD let go of an account a stranger started enrolling and
never finished (reference: after a day), and MAY cap how many unfinished enrollments it
holds.

**A server MUST NOT delete a finished account's share for inactivity.** Its share may be
all that stands between a user with one device and losing the account, and every server
of an account may share one operator and one setting. A finished account's share goes
only through the guarded actions of §7.6. Push MUST be `https://` to hosts the operator allows, without
following redirects.

### 9.3 Several servers

A group has several servers, typically three, each holding one share, each with its own
copy of the archive, and ideally each run by a **different operator** (§3). Any one of
them answering is enough (§5.1), so a server being down, slow or gone changes nothing
the user can see, and no server is central. Clients SHOULD keep a list of servers known
to be reliable and suggest three from different operators at setup, filling from one
operator's servers only when no others exist, and saying so (§3). The user may replace
any of them with their own.

### 9.4 Load (non-normative)

Measured on the prototype (Node, pure-JS curve arithmetic): about 5 ms per co-signature,
17–22 ms to coordinate and finish one. Per user, a few KB of state and an archive bounded
at a few MB for very large lists. Liveness checks SHOULD be on demand, not periodic
pings; one relay subscription can serve every user on a server. A server for many users
is far lighter than a relay that stores their events.

### 9.5 Finding servers

The list of servers lives on Nostr, not on one website.

- **A server announces itself** with an addressable event, kind 30243, `d =
  "cosign-server"`, signed by the server's **host key** (its stable identity across all
  the users it serves). Content: `{"relays": [...], "https": "<url>" | null, "enroll":
  "open" | "invite", "version": "<string>"}`. Tags: `["p", <operator pubkey>, "",
  "operator"]`, and optionally `["nip05", "name@domain"]`.
- **An operator lists its servers** with a replaceable event, kind 10243, signed by the
  operator, with one `["p", <server host key>]` per server. A server counts as an
  operator's **only when both name each other**.
- **Clients ship a seed list** `[{pubkey, relays, operator}]` so a fresh install works,
  merged with announcements found on the user's relays and on the seed relays.
- **Picking servers:** one ping round trip per candidate at setup, then a rolling record
  of answer times and failures from real signing (§5.1). Three servers, preferring
  **three distinct operator pubkeys**; when fewer operators exist, the rest come from
  one operator's servers, shown as such (§3). A server the user runs
  is preferred and counts as one of their own devices. Settings show each server's
  operator by name.
- **Adding a server** to an existing account: a device and an existing server make
  the new server's share by repair (§7.1 step 1), started by the user (**Add a
  server**). *(Planned, not yet specified: swapping a dead or slow server out
  automatically by refresh, §7.3.)*

**Limit.** Operators are pubkeys, so one person with two npubs can pose as two
operators. Everyday signing stays safe — all three servers are still 3 points — but such a
person running two of a group's servers, plus a stolen paper backup, would have 4 points
with the wait (§7.4) in their own hands, and their two servers could fail together. That
is the same exposure as two servers openly from one operator (§3). Seed lists and the
operator names shown in settings are the defence: clients SHOULD seed only operators
known to be distinct people.

## 10. Notifications

- **Approvals** for destructive events are asked on the device that is signing; when no
  device is in the loop, on the user's main device (and any member device that asks to
  receive them).
- **Notices** go to every member: a device added or removed, a wait started or ended,
  the backup used.
- Push is content-free: a server sends only "wake up" through UnifiedPush (for example
  ntfy) or the platform's push service; the message itself travels sealed over relays.
  Without push, a device sees its messages when it next connects.

## 11. Nostr binding

- Live rounds (sign requests, partials, ECDH partials, approvals) travel as **ephemeral
  gift wraps, kind 21059** (QRST 1.6 §11.4), re-sent until answered; a repeated request
  gets the same answer, never a second partial.
- Messages that must wait for an offline member (refresh deltas, new pieces, notices)
  travel as **kind 1059 with NIP-40 expiration 30 days**.
- Backup contributions travel as **kind 1059 with no expiration** (§8.2).
- Sites speak their own door (§6.3); nothing here is visible to them.
- **Size.** NIP-44 caps a plaintext at 64 KB, and members carry full events (§5.2): a
  follow list of 1,500 is about 110 KB. Member messages larger than a part (reference:
  24 KB) are split into numbered parts and reassembled on arrival.

Message names, carried over from NKM §7.17 where they exist; numbers are provisional and
will be assigned before 1.0:

| Name | Direction |
|---|---|
| SIGN_REQUEST / SIGN_PARTIAL | coordinator ↔ co-signer |
| ECDH_REQUEST / ECDH_PARTIAL | coordinator ↔ member |
| HOLD / APPROVAL | server → device; device → members |
| REPAIR_CONTRIBUTION | member → new device or backup key |
| REFRESH_DELTA / SHARE_ACK | dealer → member; member → dealer |
| REMOVE | member → members |
| WAIT_NOTICE / WAIT_CANCEL | server → members; member → server |
| EPOCH_FINALIZED | initiator → members |

## 12. Security properties

- **One piece signs nothing.** Not a device (3), not a server (1), not the paper (2).
- **The servers can never sign without the user.** All of them together are 3 points;
  two operators colluding are 2. A device is in every signature, and the device is the
  gate for destructive events (§5.2).
- **A breached server** learns what the user signs through it, nothing more.
- **A site holds no piece.** Removing its grant ends it.
- **A lost device** is blocked at once and worthless after the refresh.
- **Two of the user's own devices** can sign without any server and its policy.
  Accepted (§5.5, not built).
- **Decryption partials** go only to active member devices, never to the paper key or a
  removed member (§5.6).
- **The device lock is a claim** the device makes today; servers cannot check it until
  the hardware-bound key of §7.1 is built.
- **A stolen unlocked device plus one cooperating server** is 4 points: the same as the
  everyday pair, and at the accepted baseline. Reporting the device lost blocks it at
  every honest server.
- **A stolen paper** needs a surviving device, or two servers and a wait that every
  member is told about.
- **One operator running two or more of a group's servers** — openly, or posing as two
  with two npubs — plus a stolen paper backup is 4 points, with the wait in that
  operator's hands (§3, §9.5). At launch every public server has one operator.
- **The identity is permanent.** 4 points of one epoch in a thief's hands cannot be
  undone.

## 13. Open questions

1. **Kind numbers** and a name for this specification.

## Status

**Beta.** Signing uses an audited FROST library (ZF `frost-secp256k1-tr`); the protocol
around it — key creation, repair, refresh, recovery, the doors — has not had an outside
review.

0.2-draft, 2026-10-24. 0.1 (2026-10-23) used equal pieces with threshold 2 and one
server plus the phone as the everyday pair; 0.2 moves to weighted pieces (devices 3,
servers 1, paper 2, threshold 4), several servers ideally run by different operators,
and the device as coordinator and gate. After two outside reviews (2026-10-24): removal
is final (no contest), the paper is always weight 2 with at least two servers, decryption
partials go only to active devices, and the 7-day escape hatch (§8.4) is added.

The reference implementation is [sybenx/cosign](https://github.com/sybenx/cosign): a
server, an Android app and a browser extension, with FROST from ZF
`frost-secp256k1-tr` 2.2. As of Cosign 0.11 (2026-10-24) it has:
- weighted groups, and Create account by distributed key generation;
- refresh after a device is reported lost;
- the paper backup with its 3-day wait;
- server announcements (§9.5) and open or invite enrollment;
- "asking", the final decline, chunking, replay protection, the destructive policy and
  Undo.
- in 0.11.1: several keys on one phone; the three-party repair (§7.1), so a phone
  restored from a 2-share paper with two servers grows a device's 3; moving an existing
  nsec out of a web app into the phone in one scan (§3, "Creating the key").

**Not built yet:** per-site NIP-46 signer keys held only by the user's devices (§6.1).
Until they are, the server holds a NIP-46 signer key for nostrconnect sites, and a
public server refuses their encrypt and decrypt requests (§9.2). Also not built: the DM
prompt, device-only signing (§5.5), the passkey page for reporting a device (§7.2),
per-app members on iOS (§4.1), and the hardware-bound lock (§7.1). Planned and not yet specified:
the 24-word paper (§8.1), automatic server swaps (§3, §9.5) and the member library
(§4.3). Feature freeze since 2026-10-24: nothing new is added to this document until real
use calls for it. Exactly which parts of §5.1 and
§7 the server and app follow is tracked in the repository, not here.

The browser extension (2026-10-24) runs the same library: a
weighted key made there signs with the browser plus any one server and not with servers
alone, and Touch ID works for approvals in Chrome. Sign-in also works in desktop
Firefox, whose build keeps the extension's background awake during sign-in (Firefox
otherwise suspends it mid-scan). **Create account** works (§4.1): a name, then the
browser and up to three servers make a key by distributed key generation, using
servers that announce themselves (§9.5); syb.lol is the first. The extension follows refreshes after
a device is reported lost (§7.2–7.3), tested with the Android app as the reporting device. With Cosign 0.11.0, same-phone sign-in on Android (§6.4) returns to the browser
without a tap. Safari is not yet checked on a real device.
