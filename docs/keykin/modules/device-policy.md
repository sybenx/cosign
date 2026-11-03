# Keykin module: Device policy

Draft 4 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.7 · not built

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
| **Held** | the core's §5.8 answer: a lock assertion, or a 3-day hold the person starts | the core §5.8 set, plus deleting a whole list or the profile |

## 1. What the device keeps

- **Its own history:** every event signed for the account that it signed itself or fetched, **only if
  `pubkey == g` and the signature verifies**, kept with the newest version of each replaceable and
  addressable event. Entries from a sync service are checked the same way. An entry that fails is
  dropped, never shown, and never used for Undo or judging (live finding #8).
- **List versions:** for each list and the profile, the last 25 versions, **plus the version from just
  before each site's session started**, kept for as long as that site's grant exists and 90 days after.
  A site's many small edits can't push the pre-site version out of reach.
- **Metadata** (which site made a version, pre-site versions, removal counts) is kept as entries each
  **signed by the writing device's member key**, with a per-writer sequence number. A device accepts an
  entry only from a key that is a current device, and never one with a lower sequence number than it has
  seen from that writer. So a removed device or the sync service can't forge it or roll it back.
- History and metadata are encrypted at rest with an AEAD under a key derived from the data key and bound
  to `g`, and never sent to Keykin servers. Devices MAY sync them through a data service, which stores
  them encrypted.

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

"Items" are the tags other than `d`. When several rows match, **the strictest wins**.

**A site's removals.** For each list, the device counts a site's **net removals**: the items in the
reference version that are missing now and that this site removed. The reference is the newer of the
pre-site version (§1) and the version from 7 days ago. So many small cuts add up within a week, a
reconnect doesn't reset anything, and ordinary unfollows spread over weeks never bring up a card. The
count also resets when the person approves a Confirm card for that site and list. The person's own edits
in the member app, and other sites', never count against a site.

| Event | Level |
|---|---|
| Anything in core §5.8 (vanishing; a deletion of 5 or more targets or a burst; an emptied profile or list; a relay list with no relays) | **Held** |
| A deletion (kind 5) of a judged kind's **current** version: an `a` target naming a list, set or profile, or an `e` target that is its newest version | **Held** (it wipes the list as surely as emptying it) |
| A deletion with exactly one `e` target that is a known ordinary event of the account in history, not of a judged kind, within the site's daily budget | Silent, after the **10-second Undo** (§3) |
| A site's 21st and later single deletion in a day (reference) | **Confirm** |
| A deletion with 2–4 targets, or an `a` target, or a target the device can't find in its history, or any other target of a judged kind (an older version, a wallet or token event) | **Confirm** |
| A NIP-60 spend: a site with the `wallet` scope publishes a token event (7375) whose `del` tags name spent tokens, then deletes exactly those tokens | Silent (an ordinary spend); the wallet defers and batches these deletions so they stay under the burst limit, which is harmless because the `del` tags already supersede them |
| New token (7375) and history (7376) events by a site with the `wallet` scope | Silent |
| Wallet and mint settings (17375, 37375) changed, or the payment pubkey or mints in 10019 changed, by a site | **Confirm** |
| Profile: 2 or more filled fields emptied (a whitespace-only value counts as empty); or `lud16`, `lud06` or `nip05` changed by a site | **Confirm** |
| Profile: `name`, `picture` or `about` replaced (not emptied) | Silent |
| Follow, mute and other lists: a site's net removals reach **10 items, or 20%** of the reference | **Confirm** |
| Relay lists: any relay removed by a site, or switched from write to read only | **Confirm** |
| An Undo that removes items against the current version | judged like any change (§3) |

**Bursts** use the core's numbers (more than 5 deletion targets in 10 minutes), counted per account from
every deletion the device knows of.

**Confirm** shows one card on the device that is signing, in plain words ("Remove 12 of your 430
follows?"), with Allow and Decline. No lock is needed, because servers would co-sign it anyway. A thief
holding the device can tap Allow; that is no worse than an nsec, which is the bar.

**Held** shows the same card with the core §5.8 answer: the device's lock, or, on a device with no lock,
**Wait 3 days**, which the person chooses themself. A site's request can lead to a hold only by the person
choosing it on this card; it never starts one itself. The card says the change happens on *date* unless
they stop it. There is at most one pending hold per site. The person can always **Withdraw** their own
hold (core §6.3), even on a device without a lock.

**When a server asks for an approval.** The device runs the core's stateless §5.8 checks itself before
signing, so it already knows which events need one.

- For a **kind 5**, the server's burst count is something the device can't see, so the device trusts it
  and shows the Held card.
- For **anything else** the device's own §5.8 check passes, the device never shows a Held card because a
  server asked. It tries the event with the next server instead, and stops using a server that keeps
  doing this (Server profile §5: replaced through F4).
- It never retries the same event unchanged at a server that refused it.

**Co-signing for another device.** A device asked to co-sign (not the coordinator) never prompts anyone,
because nobody may be looking at it. It enforces only **Held**: for an event this table rates Held, it
co-signs only with the coordinator's lock assertion over `"sign" ‖ event id`, or the hold's waited
statements from two servers (core §6.3), and otherwise refuses with `needs-approval`. Confirm is the
coordinator's own job, because any coordinator could claim a Confirm. The coordinator MUST show its card
before asking any other co-signer for that event, and never drops a co-signer's refusal by going to a
server instead. A helper co-signing applies the same rule; it has no screen and never shows a card.

## 3. Undo

- **Undo is judged.** It signs an earlier version from history as a new event, with a fresh `created_at`,
  and goes through §2 against the current version like any change. Additions are never destructive, so
  restoring a bigger list is silent; restoring a smaller one is Confirm; restoring an empty one is Held
  (core §5.8).
- **A post or reaction can't be undeleted** on Nostr. "Post again" signs a new event with the same
  content from verified history, and says it is new.
- **The 10-second wait on a single deletion.** The device signs it 10 seconds after the request if Undo
  wasn't tapped and the app is still running. When the request arrived in the background (a NIP-46 site
  waking a phone), the device shows a notification with Undo for those 10 seconds instead of a card. If
  the app is killed first, nothing is signed, and it is asked again on the next open.
- **Everything a site did:** "Undo everything *site* did since it connected" reverses only that site's own
  changes: it re-adds the items the site removed and removes the items it added, on top of the current
  lists, so other people's and other sites' edits stay. It then offers to delete the site's own events,
  judged as any deletion (Confirm for 2–4, Held for 5 or more).

## 4. Held events and lists that keep changing

- A held event is signed **unchanged** once its wait has passed (core §5.8: the hold is on its event id).
- If a newer version of the same list exists by then, the held event is **dropped**, and the person is
  told ("Your held change to *Follows* was dropped, because the list changed since"). So a hold can never
  overwrite a later edit days afterwards.
- While a hold for a list is pending, the device that started it refuses site requests for that list
  with `try-later`. Other devices and the person's own edits carry on as normal.

## 5. Drafts staged offline

A replaceable draft is stored with the version it was based on. When the device is online again:

1. it fetches the newest version of each list a draft touches, from at least two relays and its own
   history, and takes the newest valid one;
2. it rebases each replaceable draft onto that version, applying the draft's own additions and removals
   against its stored base, with a **fresh `created_at`**;
3. it judges the result by §2.

A draft identical to what is already published is dropped silently. A draft that was confirmed before
going offline is judged again; an earlier answer does not carry over. A draft that was **held** is not
rebased: §4 applies to it.

## 6. What the person is told

- **Background signing** shows an honest, quiet notice where the platform needs one: "Signed a note for
  *Primal* · Delete". The button offers a deletion, because a signed note can't be unsigned.
- **Cards** list every event separately with its reason. When one site asks several things at once, the
  destructive ones come first and each needs its own answer.
- **Declines.** After 3 declined requests from one site in an hour, that site's further requests of the
  same kind are declined without asking for an hour. The site gets `declined`.
- **Holds started on another device** show on every device that gets the wait notice. Each device fetches
  the held event, checks it against the wait id (`SHA-256("hold" ‖ event id)`, core §6.3) and writes its
  **own** plain-words reason from the event, never one supplied by the starting device. Each shows a Stop
  button (a lock, or two devices, core §6.3).
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
  steps, until the owner reports the device. Only the Held set waits 3 days.
- **Single deletions are silent** up to a site's daily budget, so a site can quietly delete 20 posts a
  day before a card appears.
- **A device that missed the newest version** judges against an older one.
- **The thresholds are guesses** that real use will tune.

## Changes

- **Draft 4**, from its third red team (0 critical, 2 high):
  - the device runs the §5.8 checks itself, and trusts a server's demand only for kind 5 bursts (DP3-1);
  - deleting a whole list or the profile is Held (DP3-2).

  The mediums and lows:
  - held events signed unchanged, or dropped if the list changed (DP3-3);
  - lists aren't frozen everywhere; only the holding device refuses site requests (DP3-4);
  - net removals over 7 days, Confirm at 10 items or 20% (DP3-5);
  - NIP-60 spends follow the `del` tags, and token events are silent (DP3-6);
  - co-signers enforce only Held (DP3-7);
  - a notification with Undo for background single deletions (DP3-8);
  - a daily budget of single deletions per site (DP3-9);
  - signed, sequenced metadata (DP3-10);
  - the strictest row wins; newest valid version on rebase; whitespace counts as empty; relay rows
    merged; helpers have no screen; drafts keep their base (DP3-11 to DP3-15).

- **Draft 3**, from its second red team (0 critical, 3 high):
  - a Held verdict needs a lock or waited statements at a co-signer; a recorded Confirm counts only for
    Confirm (DP2-1);
  - each device writes its own hold reason from the event (DP2-2);
  - token, nutzap and judged-kind deletions (DP2-3);
  - and its mediums and lows.

- Draft 2, from its red team (0 critical, 7 high): per-site baselines, known single deletions, judged
  Undo, signature-checked history, person-started holds, three levels, an explicit kind table, co-signing
  devices, and the rest (DP-1 to DP-22).
