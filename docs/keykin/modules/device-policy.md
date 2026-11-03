# Keykin module: Device policy

Draft 2 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.2 · not built

The device is the real gate on what the account signs (core §5.7, §5.8). This module says how a device
judges an event before it signs or co-signs it, how Undo works from the device's own history, how drafts
staged offline are re-checked, and what a person is told. It can only make a device **stricter** than the
core, and the core wins any disagreement.

The bar is the core's: an nsec in a password manager. Routine signing stays silent and instant. Anything
that nags fails the bar, so this module uses three levels and saves the heavy one for what servers also
hold:

| Level | What the person sees | Used for |
|---|---|---|
| **Silent** | nothing, or a quiet notice | ordinary events |
| **Confirm** | one card on the signing device; one tap (no lock needed) | changes a device judges risky but servers don't hold |
| **Held** | the core's approval (lock, two devices or the paper) or its 3-day hold | exactly the core §5.8 set: vanishing, mass deletions, emptied profile or lists |

## 1. What the device keeps

- **Its own history:** every event signed for the account that it signed itself or fetched, **only if
  `pubkey == g` and the signature verifies**, kept with the newest version of each replaceable and
  addressable event. Entries from a sync service are checked the same way. An entry that fails is
  dropped, never shown, and never used for Undo or judging (live finding #8).
- **List versions:** for each list and the profile, the last 25 versions, **plus the version from just
  before each site's session started**, kept for as long as that site's grant exists and 90 days after.
  A site's many small edits can't push the pre-site version out of reach.
- History is encrypted at rest under the data key (core §4.5) and never sent to Keykin servers. Devices
  MAY sync it through a data service, which stores it encrypted.

## 2. Judging an event

Kinds, explicitly:

| Group | Kinds |
|---|---|
| Profile | 0 |
| Relay lists | 10002, 10050 |
| Follow and mute lists | 3, 10000 |
| Other lists and sets (NIP-51) | 10001, 10003–10030 except 10002, 30000–30009 |
| Wallets (NIP-60) | 17375, 37375 |
| Everything else | not judged by this table (articles 30023, marketplace kinds, app data 30078 and the rest are ordinary events) |

"Items" are the tags other than `d`.

**Baselines.** A change from a site is judged against that site's **baseline**: the version from just
before the site's session started, or the largest version of the last 24 hours, whichever has more
items. Many small cuts therefore add up, and a site can't strip a list step by step. A change the person
makes in the member app itself is judged against the current version.

| Event | Level |
|---|---|
| Anything in core §5.8 (vanishing; a deletion of 5 or more targets or a burst; an emptied profile or list; a relay list with no relays) | **Held** |
| A deletion (kind 5) with exactly one `e` target that is a known ordinary event of the account in history | Silent, after the **10-second Undo** (§3) |
| A deletion with 2–4 targets, or any `a` target, or a target the device can't find in its history | **Confirm** |
| Profile: 2 or more filled fields emptied; or `lud16`, `lud06` or `nip05` changed by a site | **Confirm** |
| Follow, mute and other lists: 3 or more items removed, or 20% or more, against the baseline | **Confirm** |
| Relay lists: any relay removed by a site, or half or more removed against the baseline | **Confirm** |
| Wallets: any change by a site | **Confirm** |
| An Undo that removes items against the current version | judged like any change (§3) |

**Bursts** are counted per account, from every deletion the device knows of, not only its own.

**Confirm** shows one card on the device that is signing, in plain words ("Remove 3 of your 430
follows?"), with Allow and Decline. No lock is needed, because servers would co-sign it anyway. A thief
holding the device can tap Allow; that is no worse than an nsec, which is the bar.

**Held** shows the same card with the approval the core needs. On a device with no lock, the person
chooses **Wait 3 days** themself; a hold is never started by a site, and never on its own. The card says
the change happens on *date* unless they stop it. A site gets at most one pending hold.

**Servers have the last word on the §5.8 set.** If a server answers that an event needs an approval or a
hold, the device shows the Held card. It never retries the event unchanged.

**Co-signing for another device.** A device asked to co-sign (not the coordinator) never prompts anyone,
because nobody may be looking at it. It applies this table. If its verdict is Confirm or Held and the
request carries no matching approval (the coordinator's lock assertion or a recorded Confirm with that
event id), it refuses with `needs-confirm`. The coordinator then shows the card on its own screen, or
asks a server instead. A stricter co-signer simply refuses.

## 3. Undo

- **Undo is judged.** It signs an earlier version from history as a new event, with a fresh `created_at`.
  It goes through §2 against the current version like any change:
  - restoring a bigger list is silent;
  - restoring a smaller one is Confirm;
  - restoring an empty one is Held (core §5.8), and the card says so.
- **A post or reaction can't be undeleted** on Nostr. "Post again" signs a new event with the same
  content from verified history, and says it is new.
- **The 10-second wait on a single deletion** fails closed. If the app is killed or backgrounded before
  the 10 seconds pass, nothing is signed, and it is asked again on the next open.
- **Everything a site did:** "Undo everything *site* did since it connected" puts back each list's
  pre-site version (judged as above) and offers one deletion for the rest. That deletion is held like any
  mass deletion.

## 4. Held events and lists that keep changing

While a change to a list is held, that list is **frozen on this device**. Further edits to it from sites
or the person are queued, not signed. When the hold completes or is cancelled, the device rebases the
queued edits on top of the result and judges them again. So a held change can't be lost to a later edit,
and nobody waits twice.

## 5. Drafts staged offline

When the device is online again:

1. it fetches the newest version of each list a draft touches;
2. it rebases each replaceable draft onto that version (applying the draft's own additions and removals);
3. it judges the result by §2.

A draft identical to what is already published is dropped silently. A draft that was held or confirmed
before going offline is judged again; an earlier answer does not carry over.

## 6. What the person is told

- **Background signing** shows an honest, quiet notice where the platform needs one: "Signed a note for
  *Primal* · Delete". The button offers a deletion, because a signed note can't be unsigned.
- **Cards** list every event separately with its reason. When one site asks several things at once, the
  destructive ones come first and each needs its own answer.
- **Declines.** After 3 declined requests from one site in an hour, that site's further requests of the
  same kind are declined without asking for an hour. The site gets `declined`.
- **Holds started on another device** show on every device, with the plain-words reason the starting
  device puts in the hold (`hold {event, reason}`) and a Stop button (a lock, or two devices, core §6.3).
- **Duplicate alerts** from several servers about one wait are merged by wait id (core §8.2).

## 7. What this module does not do

- It never asks a server to judge an event; servers keep only the core's stateless rule.
- It never stores the account's history on a Keykin server.
- It never holds an ordinary event, and it never starts a hold for a site.
- It doesn't judge app data (kind 30078). Ordinary apps write it constantly, so holding it would nag (live
  finding #11). Only the core's guards on `keykin-` app data apply.
- Grants and private-data reads (live findings #10 and #15) are the Doors and grants module's.

## 8. Limits, said plainly

- **A thief holding the device is the person.** It can Allow every Confirm card and overwrite lists in
  steps, until the owner reports the device. Only the core §5.8 set waits 3 days.
- **A device that missed the newest version** judges against an older one.
- **The thresholds are guesses** that real use will tune.

## Changes

- Draft 2, from its red team (0 critical, 7 high):
  - per-site baselines (DP-1);
  - single deletions only for known `e` targets, and no future-dated deletions (DP-2, with core 13.2);
  - Undo judged (DP-3);
  - history signature-checked (DP-4);
  - holds started only by the person, one per site (DP-5);
  - three levels, with Held only for the core set (DP-6);
  - frozen lists with rebasing (DP-7);
  - an explicit kind table, superset of the core (DP-8, DP-9);
  - unknown and 2–4-target deletions (DP-10, DP-11);
  - co-signing devices (DP-12);
  - holds shown everywhere (DP-13);
  - decline limits and per-event cards (DP-14);
  - pinned pre-site versions (DP-15);
  - payment fields (DP-16);
  - rebased drafts (DP-17);
  - app data not judged (DP-18);
  - a "Delete" button (DP-19);
  - wording (DP-20, DP-21);
  - fail-closed Undo (DP-22).
