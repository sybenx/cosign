# Keykin module: Key families

Draft 3 · 2026-11-03 · module of [Keykin Core](../core.md) draft 14.2 · not built · off the 1.0 path

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
- A key that is a child in a settled or pending family is never a master, and a master is never a child,
  so no chains.

### 1.1 The timestamp

Every family, release and leaked event has a NIP-03 OpenTimestamps proof, published by the **master** as
kind 1040.

- The proof's digest MUST equal the event's id; the 1040's `e` tag alone proves nothing.
- **Anchored height** is the earliest Bitcoin block height among all valid proofs for that id.
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
2. **Blocks.** A family anchored within 2016 blocks of another family for `C` is in **dispute** with it.
   Released families still block: releasing never helps in a dispute.
3. **Dead pairs.** Once a (master, child) pair has any anchored release, every family for that pair is
   dead for good, so an old accept can't be replayed.
4. **Settled.** The earliest family that is in no dispute, is not dead, and was anchored at least 2016
   blocks ago is settled. Later families for `C`, anchored more than 2016 blocks after it, are ignored.
5. **Late reveals.** A family anchored earlier than the settled one but first seen by this client more
   than 2016 blocks after the settled one settled is a **dispute** for this client, never a win. (This
   local rule can only downgrade a family, never make one win.)
6. Otherwise the family is **pending**, and shows no badge.

These rules get test vectors with the module (`vectors/`).

**A dispute** shows both keys plainly and stays shown for good. The viewer decides from their own
signals: whom their own follows follow, their contacts, and a NIP-05 they had already verified for the
child before the dispute. Nothing else counts, and the child's current profile never does.

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

- A Keykin device signs accept, family, release and leaked events, and kind 5, never on a site's request
  (like the `keykin-` guard, Doors and grants §2), and never a kind 5 aimed at any of them.
- A family is one Confirm card on each key's device. **Release and leaked events are Held** (Device
  policy §2), and servers hold them too (core §5.8): the master's lock, or a 3-day hold every device is
  told about. On a master with no lock, a leaked warning therefore waits 3 days.
- A Keykin app watches the index relays for families naming the person's own keys and shows any it didn't
  make: "Someone claimed your key *child* for *master*." Before importing a key as a child, the app looks
  for any family already naming it, and if it finds one says plainly: "This key was already claimed by
  someone else; it has leaked."

## 5. Child keys

- **Any account may be a family's child**, master or child by `role`. `role` (core §6.8) decides only
  export. So "Protect this key" is also offered later, from settings.
- **An imported child**: an existing nsec brought into Keykin as its own account (core §6.8 lets it be
  `role: child`, `origin: import`), alongside a new master. A Cosign 0.12 account may be imported this
  way.
- **App passwords** are plain keys the device generates for one app: it signs the family (with the new
  key's accept) before handing the key over as an nsec, then wipes its copy. The master's app keeps the
  list, so §4 watches them. They have no special role. The master's profile lists each one publicly, and
  that app posts as "part of *name*".

## 6. Onboarding: two choices

For someone who already has an nsec, the app offers both, plainly (Account admin §1.2):

- **"Bring my key"**: import the nsec as the account. Quickest. "Protect this key" stays available later.
- **"New account that protects my key"**: a fresh master by DKG (never whole), and the existing nsec
  imported as a child. The app signs the family, then anchors it, which takes a few hours. The person
  keeps posting as the npub everyone knows. The card says plainly:
  - "If someone copied your old key before today, they may already hold an earlier claim. We can't know."
  - "Once this has settled (about two weeks), a later leak can't take it over, and your followers can move
    to the new account."
  - What it costs: two accounts, so two backups, and a Face ID per dead server for each. When there are
    other server operators, the master uses different ones.

The app suggests the second once, quietly, never as a gate.

## 7. Limits, said plainly

- **A compromised master loses the whole family.** Its releases and leaked events are the family.
- **Families mean "your followers can move to you", not "the leak is fixed".** The leaked key still signs
  as the child, and older clients still show the attacker's posts as the child's.
- **A silent leak from before your family existed** leaves a dispute at best: a thief who held the key
  first can anchor a claim first. Viewers who saw yours settle first see a dispute; new viewers see the
  earlier claim win.
- **Disputes rarely resolve themselves.** New masters are quiet keys, and most people have no NIP-05
  domain.
- **The master shares the child's devices and often its servers**, so the core's worst leftover cases
  (core §10) can reach both keys.
- **Clients that can't check NIP-03** show every family as pending.

## Changes

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
