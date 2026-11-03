# Keykin module: Key families

Draft 1 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.13 · not built · off the 1.0 path

A **key family** links a **master** key to **child** keys in public, so other people's clients can show
them as one person and, if a child's key leaks, move followers to the master. It is the core's answer to a
serious leak of a key itself (core §6.7.6 F10, §10). This module covers claims, accepts, releases and
contests, the challenge window, child groups inside Keykin, and the two onboarding choices. It is meant
to become its own NIP, staying close to the upstream key-migration discussion (NIP-41, nostr-protocol/nips
PRs 2137 and 2139). The core wins any disagreement, and nothing here may weaken it.

The bar is the core's: an nsec in a password manager. An nsec that leaks is lost for good, and its
followers with it. Families can't undo a leak, but they let followers move to you. That beats the bar
only when the master was set up **before** the leak, so the app suggests it early, quietly.

## 1. Events

All are ordinary Nostr events on relays. Kind numbers are provisional, like the core's (core §11.3).

| Event | Kind | Signed by | Content and tags |
|---|---|---|---|
| **claim** | 30244, `d` = child pubkey (hex) | the master | `["p", child]`; `["status", "active" \| "released"]`; optional `["role", "app"]` |
| **accept** | 30245, `d` = master pubkey (hex) | the child | `["p", master]`; `["e", <claim event id>]`, committing to the master's key and that claim |
| **contest** | 30246, `d` = claim address (`30244:<master>:<child>`) | the child, the claiming master, or an already settled master of that child | `["a", <claim address>]`, optional reason text |

- A claim with no accept has no state. Clients show nothing for it.
- A **release** is the master republishing its claim with `status: released`.
- A NIP-03 timestamp (OpenTimestamps) MAY be attached to any of them, and SHOULD be to claims and
  accepts.

## 2. The challenge window

- **A family is settled** 14 days after a client first saw both the claim and the accept, with no contest
  from someone entitled to contest. It counts from when the client saw them, **never from `created_at`**,
  because backdating is the named attack.
- A client that has a NIP-03 proof older than 14 days for both may treat them as settled at once.
- Until settled, a client shows "pending", never the badge.
- A release settles the same way: 14 days after first seen, unless the child contests it.

**Contests.**

- Only the child, the claiming master, or a master already settled for that child may contest.
- A contest inside the window turns the claim into a **dispute**. Clients then show both keys plainly
  and fall back to the viewer's own signals: whom the viewer's own follows follow, the viewer's contacts,
  and NIP-05. Nothing from outside the viewer's follows counts.
- **Once a family has settled, contests from the child are ignored.** A leaked child key can then do
  nothing to the family. This is why an early master is the real protection.
- A new claim on a settled child by a different master is contested by the settled master, and fails.
- **App children** (`role: app`) have no contest rights at all.

## 3. What a client shows (Tier 1)

- One relay query for the claim and the accept, and two signature checks. A settled family shows the
  child with a small "part of *master's name*" badge, and the master's profile lists its children.
- When a settled child's key is known to be leaked, the master publishes a note saying so. A client that
  understands families offers each follower one tap: "Follow *master* instead of *child*?" It never swaps
  follows by itself.
- Older clients just see two ordinary npubs.

## 4. Child groups in Keykin

A child can be a Keykin account of its own: a group whose first epoch record says `role: child` (core
§3.1, §6.8), created like any account (Account admin §1) on the same devices and servers.

- **App passwords.** A fresh child group with `role: app` in its claim, made for one app that needs its
  own key. It can be exported as an nsec to that app (core §6.8, in Core 1.x), with an approval. It has
  no contest rights, so a leaked app key can never fight the family.
- **An imported child**: an existing nsec brought in as a child group (`origin: import`, `role: child`)
  rather than as the master. In later Core versions only such children may be exported (core §6.8).
- A Keykin device signs claims, accepts, releases and contests **only for the person**, never on a site's
  request: like the `keykin-` guard (Doors and grants §2), a device refuses kinds 30244–30246 from any
  site.
- **Releases are Held** (Device policy §2): the master's lock, or a 3-day hold every device is told about.
  A claim or an accept made in the app is one Confirm card.

## 5. Onboarding: two choices

For someone who already has an nsec, the app offers both, plainly (Account admin §1.2):

- **"Bring my key"**: import the nsec as the master (Account admin §1.2). Quickest. If the old nsec ever
  leaks, nothing can move followers.
- **"New account that protects my key"**: a fresh master by DKG (never whole), and the existing nsec
  imported as a child group. The app signs the claim and the accept at once. The person keeps posting as
  the npub everyone knows. After 14 days the family is settled, and from then on a leak of the old nsec
  can't contest it: followers can move to the master.

The app suggests the second once, quietly, never as a gate.

## 6. Limits, said plainly

- **A compromised master loses the whole family.** Its claims and releases are the family.
- **Families mean "your followers can move to you", not "the leak is fixed".** The leaked key still signs
  as the child, and older clients still show the attacker's posts as the child's.
- **A leak before the master settles** leaves a dispute that only the viewer's own social signals decide.
- **A client's 14 days** start when that client first sees the events, so a new client sees "pending" for
  a while unless NIP-03 proofs exist.
- **Deferred:** contest and dispute screens, vouch lists, a Tier 2 check, and server watch lists.

## Changes

- Draft 1.
