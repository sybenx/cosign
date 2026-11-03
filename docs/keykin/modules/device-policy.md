# Keykin module: Device policy

Draft 3 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.4 · not built

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
| **Held** | the core's §5.8 answer: a lock assertion, or a 3-day hold the person starts | exactly the core §5.8 set: vanishing, mass deletions, emptied profile or lists |

## 1. What the device keeps

- **Its own history:** every event signed for the account that it signed itself or fetched, **only if
  `pubkey == g` and the signature verifies**, kept with the newest version of each replaceable and
  addressable event. Entries from a sync service are checked the same way. An entry that fails is
  dropped, never shown, and never used for Undo or judging (live finding #8).
- **List versions:** for each list and the profile, the last 25 versions, **plus the version from just
  before each site's session started**, kept for as long as that site's grant exists and 90 days after.
  A site's many small edits can't push the pre-site version out of reach.
- History, and its metadata (which site made a version, when), is encrypted at rest with an AEAD under a
  key derived from the data key and bound to `g`, and never sent to Keykin servers. Devices
  MAY sync it through a data service, which stores it encrypted.

## 2. Judging an event

Kinds, explicitly:

| Group | Kinds |
|---|---|
| Profile | 0 |
| Relay lists | 10002, 10050 |
| Follow and mute lists | 3, 10000 |
| Other lists and sets (NIP-51) | 10001, 10003–10030 except 10002, 30000–30030 |
| Wallets and payments (NIP-60/61) | 17375, 37375, 7375, 7376, 10019 |
| Everything else | not judged by this table (articles 30023, marketplace kinds, app data 30078 and the rest are ordinary events) |

"Items" are the tags other than `d`.

**Baselines.** For each list, the device counts the items **a site itself** has removed since its grant
was made, adding up across all of that site's changes. The person's own removals in the member app, and
other sites', never count against it. A site's change is judged by that running total, so many small cuts
add up and a site can't strip a list step by step. The count resets only when the person approves a
Confirm card for that site and list. A change the person makes in the member app is judged against the
current version.

| Event | Level |
|---|---|
| Anything in core §5.8 (vanishing; a deletion of 5 or more targets or a burst; an emptied profile or list; a relay list with no relays) | **Held** |
| A deletion (kind 5) with exactly one `e` target that is a known ordinary event of the account in history, not of a judged kind | Silent, after the **10-second Undo** (§3) |
| A deletion with 2–4 targets, or any `a` target, or a target the device can't find in its history, or **any target of a judged kind** (a list, the profile, a wallet or token event) | **Confirm** |
| A NIP-60 roll-over: a site with the `wallet` scope deletes token events (7375) and publishes their replacement token event within 60 seconds | Silent (an ordinary spend) |
| Profile: 2 or more filled fields emptied; or `lud16`, `lud06` or `nip05` changed by a site | **Confirm** |
| Follow, mute and other lists: 3 or more items removed, or 20% or more, against the baseline | **Confirm** |
| Relay lists: any relay removed by a site, or half or more removed against the baseline | **Confirm** |
| Wallets and payments: any other change by a site, including a changed payment pubkey in 10019 | **Confirm** |
| Relay lists: a relay switched from write to read only | counts as a removal |
| Profile: `name`, `picture` or `about` replaced (not emptied) | Silent; `nip05`, `lud16`, `lud06` changed by a site: **Confirm** (above) |
| An Undo that removes items against the current version | judged like any change (§3) |

**Bursts** use the core's numbers (more than 5 deletion targets in 10 minutes), counted per account from
every deletion the device knows of.

**Confirm** shows one card on the device that is signing, in plain words ("Remove 3 of your 430
follows?"), with Allow and Decline. No lock is needed, because servers would co-sign it anyway. A thief
holding the device can tap Allow; that is no worse than an nsec, which is the bar.

**Held** shows the same card with the core §5.8 answer: the device's lock, or, on a device with no lock,
**Wait 3 days**, which the person chooses themself. A site's request can lead to a hold only by the person
choosing it on this card; it never starts one itself. The card says the change happens on *date* unless
they stop it. There is at most one pending hold per site. The person can always **Withdraw** their own
hold (core §6.3), even on a device without a lock.

**Servers have the last word on the §5.8 set.** If a server answers that an event needs an approval or a
hold, the device shows the Held card. It never retries the event unchanged.

**Co-signing for another device.** A device asked to co-sign (not the coordinator) never prompts anyone,
because nobody may be looking at it. It applies this table:

- for a **Held** verdict, it co-signs only with the coordinator's lock assertion over `"sign" ‖ event id`,
  or the hold's waited statements from two servers (core §6.3);
- for a **Confirm** verdict, the coordinator's recorded Confirm (a detached signature by its member key
  over the event id) is enough;
- otherwise it refuses with `needs-confirm` or `needs-approval`.

The coordinator MUST show the card on its own screen before asking any other co-signer for that event. It
never drops a co-signer's refusal by going to a server instead. A helper co-signing applies the same rules.

## 3. Undo

- **Undo is judged.** It signs an earlier version from history as a new event, with a fresh `created_at`,
  and goes through §2 against the current version like any change. Additions are never destructive, so
  restoring a bigger list is silent; restoring a smaller one is Confirm; restoring an empty one is Held
  (core §5.8).
- **A post or reaction can't be undeleted** on Nostr. "Post again" signs a new event with the same
  content from verified history, and says it is new.
- **The 10-second wait on a single deletion** fails closed. If the app is killed or backgrounded before
  the 10 seconds pass, nothing is signed, and it is asked again on the next open.
- **Everything a site did:** "Undo everything *site* did since it connected" reverses only that site's own
  changes: it re-adds the items the site removed and removes the items it added, on top of the current
  lists, so other people's and other sites' edits stay. It then offers to delete the site's own events,
  judged as any deletion (Confirm for 2–4, Held for 5 or more).

## 4. Held events and lists that keep changing

While a change to a list is held, that list is **frozen on every device**: the hold is delivered to every
device (core §8), and each one refuses edits to that list until the hold completes or ends. The person's
own edits in the member app are queued and rebased on top of the result afterwards, then judged again.
Site requests for that list are **not** queued: they are refused with `try-later`, and the site asks
again. So a held change can't be lost to a later edit, and nothing is signed days later without the
person seeing it.

## 5. Drafts staged offline

When the device is online again:

1. it fetches the newest version of each list a draft touches, from at least two relays and its own
   history, and shows a Confirm card if they disagree;
2. it rebases each replaceable draft onto that version, applying the draft's own additions and removals,
   with a **fresh `created_at`**;
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
- **Holds started on another device** show on every device. The hold carries the event itself, and each
  device checks it against the wait id (`SHA-256("hold" ‖ event id)`, core §6.3) and writes its **own**
  plain-words reason from the event, never one supplied by the starting device. Each shows a Stop button
  (a lock, or two devices, core §6.3).
- **Background notices** collapse per site ("Signed 4 notes for *Primal*").
- **Duplicate alerts** from several servers about one wait are merged by wait id (core §8.2).

## 7. What this module does not do

- It never asks a server to judge an event; servers keep only the core's stateless rule.
- It never stores the account's history on a Keykin server.
- It never holds an ordinary event, and a site never starts a hold.
- It doesn't judge app data (kind 30078). Ordinary apps write it constantly, so holding it would nag (live
  finding #11). Only the core's guards on `keykin-` app data apply.
- Grants and private-data reads (live findings #10 and #15) are the Doors and grants module's.

## 8. Limits, said plainly

- **A thief holding the device is the person.** It can Allow every Confirm card and overwrite lists in
  steps, until the owner reports the device. Only the core §5.8 set waits 3 days.
- **A device that missed the newest version** judges against an older one.
- **The thresholds are guesses** that real use will tune.

## Changes

- **Draft 3**, from its second red team (0 critical, 3 high):
  - a Held verdict needs a lock or waited statements at a co-signer; a recorded Confirm counts only for
    Confirm (DP2-1);
  - each device writes its own hold reason from the event (DP2-2);
  - token, nutzap and judged-kind deletions (DP2-3).

  The mediums and lows:
  - baselines count only the site's own removals;
  - holds freeze the list everywhere, and site requests aren't queued;
  - fresh `created_at` on rebases;
  - Held means the core's lock or hold;
  - Undo reverses only the site's own changes;
  - cards come before other co-signers;
  - 10019 payment targets;
  - NIP-60 roll-overs stay silent;
  - Withdraw on a lockless device;
  - the core's burst numbers;
  - sets 30010–30030 and relay markers;
  - history metadata encrypted;
  - wording.

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
