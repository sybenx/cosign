# Keykin module: Device policy

Draft 1 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.1 · not built

The device is the real gate on what the account signs (core §5.7, §5.8). This module says how a device
judges an event before it signs or co-signs it, how Undo works from the device's own history, how drafts
staged offline are re-checked, and what a person is told about background signing. It can only make a
device **stricter** than the core. Nothing here loosens a core rule, and the core wins any disagreement.

The bar is the core's: an nsec in a password manager. Routine signing stays silent and instant; a
policy that nags fails the bar.

## 1. What the device keeps

- **Its own history**: every event it signed or saw signed for the account (from its own rounds and from
  the account's relays), with the newest version of each replaceable and addressable event. It is kept
  on the device, encrypted at rest under the data key (core §4.5), and never sent to servers.
- **List versions**: the last 25 versions of each list (kind 0, 3, 10000–19999, 30000–39999), so Undo
  can put one back.
- Devices of the same account MAY sync this history through a data service under the data key. Nothing
  in the core depends on it.

## 2. Judging an event

Before signing or co-signing, a device compares the event with the newest version it knows of the same
replaceable or addressable event. An event is **destructive** when it:

| Event | Destructive when |
|---|---|
| Request to vanish (kind 62) | always |
| Deletion (kind 5) | 5 or more targets, any target that is a list or the profile, or a burst (more than 5 targets in 10 minutes) |
| Profile (kind 0) | 2 or more filled fields emptied, or emptied entirely |
| Follows, mutes, bookmarks, sets (kind 3, 10000–10030, 30000–30030) | emptied from 3 or more items, or 10 or more items **and** 20% or more removed |
| Relay list (kind 10002) | 2 or more relays **and** half or more removed |
| App data (kind 30078) | an existing value replaced by an empty one, or shrunk by more than 80% (not the account's signpost, which the core guards) |
| A replaceable or addressable event staged offline | older than the newest version now known (it would roll the list back) |

A destructive event is **held**: the device shows it in plain words ("Remove 412 of your 430 follows")
and signs only when the person approves there with the device's lock, or, on a device without a lock,
through the core's hold (a 3-day wait, core §5.8). Approval is on the device that is signing, never on
the site that asked.

**A single deletion** (kind 5 with one target that is not a list or the profile) is not held. The device
waits **10 seconds** with an Undo button, then signs it as usual. Reference numbers in this table are
defaults; implementations MAY make them stricter, never looser than the core's §5.8 set.

## 3. Undo

- **A list or the profile**: Undo signs the earlier version from the device's own history again, with a
  fresh `created_at`. It is an ordinary event, so it needs no approval.
- **A post or reaction**: Nostr can't undelete. "Post again" signs a new event with the same content; the
  person sees that it is new.
- **Everything a site did**: "Undo everything *site* did since it connected" gives back the lists from
  before the site connected, and offers one batched deletion for the rest. The batched deletion is held
  like any mass deletion.
- Undo uses only the device's own history. It never asks a server for a copy, so a server can't plant
  content for Undo to sign (live finding #8).

## 4. Drafts staged offline

A draft written offline keeps the time it was written (core §5.6). When the device is online again, it
re-runs §2 before signing:

- a replaceable or addressable draft older than the newest version now known is **destructive** and is
  held;
- a draft that was held before going offline is shown again, with its plain-words reason, before it is
  signed. An earlier approval does not carry over.

## 5. What the person is told

- **Background signing** shows an honest, quiet notice where the platform requires one (an iPhone
  notification extension must show something): "Signed a note for *Primal* · Undo". It never pretends
  nothing happened, and it never alarms.
- **Held events** show the plain-words reason and two buttons: approve (lock) or decline. A decline is
  final for that request (the site gets a refusal).
- **Several held events from one site** in a minute are shown as one card.
- **Duplicate alerts** from several servers about the same wait are merged by wait id (core §8.2).

## 6. What this module does not do

- It never asks a server to judge an event; servers keep only the core's stateless rule.
- It never stores the account's history on a server.
- It never holds an ordinary event by default. Routine signing is silent.

## 7. Limits, said plainly

- **A thief holding the device is the person** as far as the policy knows. Without a lock, it can
  overwrite lists in small steps that are not destructive by the table, until the owner reports the
  device. Mass deletions, vanishing and emptying wait 3 days (core §10).
- **A device that missed the newest version** judges against an older one, and may let a change through
  that it would otherwise hold.
- **The thresholds are guesses** that real use will tune.

## Changes

- Draft 1.
