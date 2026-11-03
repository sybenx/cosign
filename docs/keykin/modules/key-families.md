# Keykin module: Key families

Draft 2 · 2026-11-03 · module of [Keykin Core](../core.md) draft 14 · not built · off the 1.0 path

A **key family** links a **master** key to a **child** key in public, so other people's clients can show
them as one person and, if the child's key leaks, offer to move followers to the master. It is the core's
answer to a leak of a key itself (core §6.7.6 F10, §10). This module covers the family event, the
timestamped window, releases, leaks, and the two onboarding choices. It is meant to become its own NIP,
next to the upstream key-migration discussion (NIP-41). The core wins any disagreement, and nothing here
may weaken it.

The bar is the core's: an nsec in a password manager. An nsec that leaks is lost for good, and its
followers with it. Families can't undo a leak, but they let followers move to you. That beats the bar
only when the family was set up **before** the leak, so the app suggests it early, quietly.

## 1. Events

All are ordinary, **regular** (never replaceable) Nostr events, each with a NIP-03 OpenTimestamps proof
(kind 1040) anchoring it in Bitcoin. Kind numbers are provisional, like the core's (core §11.3).

| Event | Kind | Signed by | Content and tags |
|---|---|---|---|
| **family** | 1244 | the master | `["p", child]`; `["child_sig", <BIP-340 by the child over SHA-256("keykin-family/1" ‖ master ‖ child ‖ created_at)>]` |
| **release** | 1245 | the master | `["e", <family id>]` |
| **leaked** | 1246 | the master | `["e", <family id>]`; content: a short note for followers |

- A family carries **both keys' signatures** in one event, so neither key can later erase or replace the
  other's part. Deletions (kind 5) of these kinds are ignored by clients.
- **Anchored time** is the Bitcoin block time of the event's NIP-03 proof. Clients use only that, never
  `created_at` and never when they first saw it.
- Events are published to the master's and the child's write relays and to a set of well-known index
  relays the client knows. Clients look in all three, never only in the child's relay list, which a thief
  holding the child key could rewrite.

## 2. Settling

- **A family is settled** when it has been anchored for 14 days and no other family for the same child is
  anchored within 14 days of it, before or after.
- **The earliest anchored family wins.** A later family for the same child, anchored more than 14 days
  after a settled one, is ignored automatically: nobody has to watch relays or object. So a thief who
  steals a child key after its family settled can do nothing with families.
- **Two families anchored within 14 days of each other** are a **dispute**. Clients show both keys
  plainly and fall back to the viewer's own signals: whom the viewer's own follows follow, the viewer's
  contacts, and NIP-05. Nothing from outside the viewer's follows counts.
- A family with no NIP-03 proof yet, or anchored less than 14 days ago, shows as "pending", never with a
  badge.
- **A release** ends a family as soon as it is anchored. Afterwards the child may join a new family, which
  settles by the same rules.

## 3. What a client shows

- One relay query for family events naming the child, two signature checks and one NIP-03 check. A
  settled family shows the child with a small "part of *master's name*" badge, and the master's profile
  lists its children.
- **A leaked event** on a settled family tells followers the child's key is no longer safe. A client that
  understands families offers each follower one tap, "Follow *master* instead of *child*?", **only** when
  a signal a thief can't forge agrees: the child's NIP-05 domain lists the master, or the viewer's own
  follows already follow the master. It never swaps follows by itself.
- Older clients just see two ordinary npubs.

## 4. Keykin devices

- A Keykin device signs family, release and leaked events, and kind 5 targeting them, **only for the
  person**, never on a site's request (like the `keykin-` guard, Doors and grants §2).
- A family is one Confirm card on each key's device. **Release and leaked events are Held** (Device
  policy §2): the master's lock, or a 3-day hold every device is told about.
- A Keykin app watches for families naming the person's own keys and shows any it didn't make: "Someone
  claimed your key *child* for *master*." It can't stop a family, but the person can answer with their own
  before it settles.

## 5. Child keys

- **An imported child**: an existing nsec brought into Keykin as a child group (core §6.8: `role: child`,
  `origin: import`), alongside a new master. A Cosign 0.12 account may be imported this way too.
- **App passwords** are plain keys the device generates for one app that needs its own key, handed to it
  as an nsec, and joined to the master by an ordinary family. They have no special role.

## 6. Onboarding: two choices

For someone who already has an nsec, the app offers both, plainly (Account admin §1.2):

- **"Bring my key"**: import the nsec as the master. Quickest. If the old nsec ever leaks, nothing can move
  followers.
- **"New account that protects my key"**: a fresh master by DKG (never whole), and the existing nsec
  imported as a child group. The app signs and anchors the family at once. The person keeps posting as the
  npub everyone knows. Once the family has settled, a leak of the old nsec can't change it, and followers
  can move to the master. The card says what it costs: two accounts, so two backups, and a Face ID per
  dead server for each. The app prefers different server operators for the master.

The app suggests the second once, quietly, never as a gate.

## 7. Limits, said plainly

- **A compromised master loses the whole family.** Its releases and leaked notes are the family.
- **Families mean "your followers can move to you", not "the leak is fixed".** The leaked key still signs
  as the child, and older clients still show the attacker's posts as the child's.
- **A silent leak from before your family existed can't be undone.** A thief who held the child key first
  can anchor a family of their own first, and it wins.
- **Disputes rarely resolve themselves.** New masters are quiet keys; the child's NIP-05 domain is often
  the only signal a thief can't forge.
- **The master shares the child's devices and often its servers**, so the core's worst leftover cases
  (core §10) can reach both keys.
- **Clients that can't check NIP-03** show every family as pending.

## Changes

- **Draft 2**, from its first red team (3 critical, 8 high) and the user's answers:
  - the window counts from a NIP-03 Bitcoin timestamp, not from when a client first sees it (C2; the user
    reversed "first seen");
  - one family event carrying both keys' signatures, regular and undeletable; the earliest anchored
    family wins, and two within 14 days are a dispute; no contests, no watching (C1, H1, H2, H3);
  - no app role; app passwords are plain keys (C3, H5);
  - the one-tap move only with a signal a thief can't forge, and claims on your keys shown (C3);
  - relays to ask named (H4);
  - the guard covers deletions; a leaked event with its own kind, Held (H6);
  - imported 0.12 accounts may be children (H7, core 14);
  - plain limits on shared devices and servers (H8, core 14 wording);
  - releases immediate, disputes stated honestly, the cost of two accounts on the card (mediums).
- Draft 1.
