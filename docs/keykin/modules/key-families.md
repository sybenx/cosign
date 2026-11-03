# Keykin module: Key families

Draft 5 · 2026-11-03 · module of [Keykin Core](../core.md) draft 14.6 · not built · off the 1.0 path

A **key family** links a **master** key to a **child** key in public, so other people's clients can show
them as one person and, if the child's key leaks, offer to move followers to the master. It is the core's
answer to a leak of a key itself (core §6.7.6 F10, §10). This module covers the family event, the
timestamped window, releases, leaks, and the onboarding choices. It is meant to become its own NIP, next
to the upstream key-migration discussion (NIP-41). The core wins any disagreement, and nothing here may
weaken it.

The bar is the core's: an nsec in a password manager. An nsec that leaks is lost for good, and its
followers with it. Families can't undo a leak, but they let followers move to you. That beats the bar
only when the family was set up **before** anyone copied the key, so the app suggests it early, quietly.

## 1. Events

All are ordinary, **regular** (never replaceable) Nostr events. Kind numbers are provisional, like the
core's (core §11.3).

| Event | Kind | Signed by | Content and tags |
|---|---|---|---|
| **accept** | 1247 | the child | `["p", master]` |
| **family** | 1244 | the master | `["p", child]`; content: the child's accept event, as JSON |
| **release** | 1245 | the master | `["e", <family id>]` |
| **leaked** | 1246 | the master | `["e", <family id>]`; content: a short note for followers |

- The family carries **both keys' signatures** in one event: the master's on the family, and the child's
  on the embedded accept, which is an ordinary Nostr event any signer can make (a Keykin child account
  co-signs it like any event; core §5.4 needs no bare hash). Neither key can later erase or replace the
  other's part. Clients ignore kind 5 aimed at any of these kinds or at their proofs.
- **The accept must name this family's master** (`p` = the family's author), and a release counts only
  from that family's master.
- **No child becomes a master.** A family whose master is already the child in an **earlier-anchored**
  family is ignored. A master may later become a child (that is "Protect this key", even after making app
  passwords), so compared by anchor height, never by settled status.
- Every event has exactly one `p` tag, and a leaked event counts only from the family's master.

### 1.1 The timestamp

Every family, release and leaked event has a NIP-03 OpenTimestamps proof, published by the **master** as
kind 1040.

- The proof's digest MUST equal the event's id; the 1040's `e` tag alone proves nothing.
- **Anchored height** is the earliest Bitcoin block height among all valid, **complete** proofs for that
  id. A pending calendar-only proof counts for nothing.
- Block headers are checked by proof of work from a checkpoint pinned in the app, or taken from at least
  two independent sources.
- The app submits to at least two independent calendars, upgrades the proof when the block arrives (a few
  hours later), then publishes the 1040.
- Windows are counted in blocks: **2016 blocks** (about 14 days), so every viewer agrees.

### 1.2 Where events live

The master publishes families, proofs, releases and leaked events to its own and the child's write
relays, and to the **index relays**: the replicating set the upstream key-migration NIP names, or until
then a set of at least five independently run relays pinned in the app. The master's app republishes
them there from time to time. Clients query at least two index relays and keep proofs they have verified;
never only the child's relay list, which a thief holding the child key could rewrite.

## 2. Settling, as a procedure

For a child `C`, a client takes every family naming `C` with a valid proof, and every release of them,
and:

1. **Sorts** the families by anchored height, then by event id.
2. **Blocks.** A family anchored within 2016 blocks of another family for `C` **from a different master** is
   in **dispute** with it. Two families from the same master (a retry, two devices) are one: the earliest
   counts. Released families still block: releasing never helps in a dispute.
3. **Dead pairs.** Once a (master, child) pair has any anchored release, every family for that pair is
   dead for good, so an old accept can't be replayed.
4. **The first family decides.** Take the earliest family that is not dead. If it is in a dispute, `C` is
   **disputed for good**: no later family can settle it. Otherwise, once it was anchored at least 2016 +
   144 blocks ago (a day's grace for late proofs), it is settled, and every later family for `C` is
   ignored.
5. **Late reveals.** If this client saw a family before it saw an earlier-anchored one for `C` (by more
   than a day; "saw" means a full check of at least two index relays), the two are a **dispute** for this
   client, never a win for the earlier one. Families from the same master, and a family released before
   the other was anchored, are exempt. This local rule
   can only downgrade, never make a family win. A client that keeps no history counts as a new viewer.
6. Otherwise the family is **pending**, and shows no badge.

These rules get test vectors with the module (`vectors/`).

**A dispute** shows both keys plainly and stays shown for good. The viewer decides from their own
signals: whom their own follows follow, their contacts, and a NIP-05 they had already verified for the
child before the dispute (its client had checked the child's `nip05` and that domain's `nostr.json` now
also names the master). Nothing else counts, and the child's current profile never does.

## 3. What a client shows

- The checks: every family naming the child from at least two index relays, their releases, two
  signature checks and a proof check for each. A settled family shows the child with a small "part of
  *master's name*" badge, and the master's profile lists its children.
- **A leaked event** on a settled family that isn't disputed tells followers the child's key is no longer
  safe, and a client that understands families offers each follower one tap: "Follow *master* instead of
  *child*?" The leaked event needs its own proof first, so the offer comes a few hours later. In a
  dispute, the offer needs the viewer's own signals above. It never swaps follows by itself.
- Older clients just see two ordinary npubs.

## 4. Keykin devices

- A Keykin device never signs accept, family, release or leaked events on a site's request (Doors and
  grants §2), and never a kind 5 aimed at any of them.
- **All four kinds are Held**, by devices and by servers (core §5.8): the key's lock, or a 3-day hold every
  device is told about. So a stolen phone with no lock can't quietly accept a thief's master. On a key with
  no lock, a family or a leaked warning therefore waits 3 days.
- A Keykin app watches the index relays for families naming the person's own keys and shows any it didn't
  make: "Someone claimed your key *child* for *master*. Make your own claim now, from a device you trust;
  if theirs was first, it will show as disputed." Before importing a key as a child, the app looks for any
  family already naming it that the person didn't make, and if it finds one says plainly: "This key was
  already claimed by someone else; it has leaked. Your claim will show as disputed."
- **Before signing a new family**, the app looks for an existing one for that child by any of the person's
  masters and reuses it, so a retry or a second device never starts a dispute with itself.
- Proofs (kind 1040) for family events are never signed or published on a site's request either. 

## 5. Child keys

- **Any account may be a family's child**, master or child by `role`. `role` (core §6.8) decides only
  export. So "Protect this key" is also offered later, from settings.
- **An imported child**: an existing nsec brought into Keykin as its own account (core §6.8 lets it be
  `role: child`, `origin: import`), alongside a new master. A Cosign 0.12 account may be imported this
  way.
- **App passwords** are plain keys the device generates for one app, always children of the account's
  master (with "Protect this key", the new master): it signs the family (with the new
  key's accept) before handing the key over as an nsec, then wipes its copy. The master's app keeps the
  list, so §4 watches them. They have no special role. The master's profile lists each one publicly, and
  that app posts as "part of *name*".

## 6. Onboarding: two choices

For someone who already has an nsec, the app offers both, plainly (Account admin §1.2):

- **"Bring my key"**: import the nsec as the account. Quickest. "Protect this key" stays available later.
- **"New account that protects my key"**: a fresh master by DKG (never whole), and the existing nsec
  imported as a child. The app signs the family, then anchors it, which takes a few hours. The person
  keeps posting as the npub everyone knows. The card says plainly:
  - "If someone copied your old key before today, or copies it in the next two weeks, they can hold a
    claim that makes yours disputed. We can't know."
  - "Once this has settled (about two weeks), a later leak can't take it over, and your followers can move
    to the new account."
  - What it costs: two accounts, so two backups, and a Face ID per dead server for each. When there are
    other server operators, the master uses different ones.

The app suggests the second once, quietly, never as a gate.

## 7. Changing master, and deleting one

- To change master: release the old family, wait until the release is anchored, then make the new family
  after the old one's window has passed (2016 blocks from its anchor), or it is a dispute for good. In
  between, the child is unprotected; that gap is the price of a change.
- Deleting a master's account (Account admin §3) warns first: "This also ends your key families."
- Deleting a master's account erases its families from relays that honour the vanish; clients keep the
  proofs they have already verified.

## 8. Limits, said plainly

- **A compromised master loses the whole family.** Its releases and leaked events are the family.
- **Families mean "your followers can move to you", not "the leak is fixed".** The leaked key still signs
  as the child, and older clients still show the attacker's posts as the child's.
- **A silent leak from before your family existed** leaves a dispute at best: a thief who held the key
  first can anchor a claim first. Viewers who saw yours first see a dispute; new viewers see the earlier
  claim win.
- **A dispute is for good.** Neither side can clear it.
- **A thief who held the key during the two weeks** before your family settled can keep a claim back and
  reveal it later, turning your settled family into a dispute for good. Nothing under these rules stops
  that; the onboarding card says so.
- **Events stay on relays only while someone republishes them**, which is the master's app.
- **Kind numbers are provisional.** They must be pinned before 1.0 (core §11.3), or 1.0 devices wouldn't
  guard the final kinds.
- **Disputes rarely resolve themselves.** New masters are quiet keys, and most people have no NIP-05
  domain.
- **The master shares the child's devices and often its servers**, so the core's worst leftover cases
  (core §10) can reach both keys.
- **Clients that can't check NIP-03** show every family as pending.

## Changes

- **Draft 5**, from its fourth red team (0 critical, 1 high):
  - a master may later become a child, so "Protect this key" works after app passwords; chains compared by
    anchor height (H1).

  The mediums and lows:
  - the held-back claim during the window stated (M1);
  - same-master and released families exempt from late reveals, "saw" defined (M2);
  - an existing family reused before signing a new one (M3);
  - kind numbers to pin before 1.0 (M4, core 14.6);
  - one `p` tag, leaked only from the master, proofs guarded, watcher and import wording, the gap when
    changing master, a warning on deleting a master, republishing (lows).
- **Draft 4**, from its third red team (0 critical, 3 high):
  - a dispute on the first family lasts for good (H1);
  - all four family kinds are Held and guarded from sites, in core 14.2 too (H2);
  - the late-reveal rule applies whenever this client saw the later family first (H3).

  The mediums and lows:
  - the accept names its master, releases only from the master (M1);
  - one master's duplicate families are one (M2);
  - a day's grace before settling, complete proofs only (M3, lows);
  - no chains, earliest wins (M4);
  - app passwords belong to the master (M5);
  - the NIP-05 signal spelled out, the import warning, changing master, deleting a master, clients without
    history (lows).
- **Draft 3**, from its second red team (1 critical, 4 high):
  - NIP-05 only from what the viewer had verified before, never the current profile; a late-revealed
    earlier family is a dispute, never a win; the app looks for earlier claims before importing (C1, H2);
  - the child's consent is an embedded accept event any signer can make (H1);
  - a written settling procedure, with released families still blocking (H3);
  - the one-tap move on any settled, undisputed family's leaked event (H4);
  - releases and leaked events held by servers too (M1, core 14);
  - dead pairs after a release (M2);
  - the NIP-03 check pinned: digest, earliest proof, headers, calendars, 2016 blocks (M3);
  - index relays and proofs published by the master (M4);
  - any account may be a child; `role` only governs export (M5);
  - no chains, no kind 5 at families, app-password steps, timing of leaked warnings, honest wording (lows).
- **Draft 2**, from its first red team (3 critical, 8 high) and the user's answers: NIP-03 timestamps, one
  family event, earliest anchored wins, no app role.
- Draft 1.
