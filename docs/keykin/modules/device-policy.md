# Keykin module: Device policy

Draft 11 · 2026-11-03 · module of [Keykin Core](../core.md) draft 14.10 · not built

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
| **Held** | the core's §5.8 answer: a lock assertion, or a 3-day hold the person starts | exactly the core §5.8 set |

## 1. What the device keeps

- **Its own history:** every event signed for the account that it signed itself or fetched, **only if
  `pubkey == g` and the signature verifies**, kept with the newest version of each replaceable and
  addressable event. Entries from a sync service are checked the same way. An entry that fails is
  dropped, never shown, and never used for Undo or judging (live finding #8).
- **List versions:** for each list and the profile, the last 25 versions, **plus the version from just
  before each site's session started**, kept for as long as that site's grant exists and 90 days after.
  A site's many small edits can't push the pre-site version out of reach.
- **A removal log** for each site and list: every item that site removed, with when, kept while the grant
  exists and 90 days after. Counting comes from this log, never from the kept versions, so a site can't
  push its removals out of reach with no-op edits.
- **Metadata**: which **grant** `(by, id)` each event was signed for (never the self-claimed site name),
  which grant made each list version, the pre-site and last-approved versions, the removal logs,
  deletion counts, and the hashes of ciphertexts the device encrypted and for which grant or for the member
  app (Doors and grants §1). Entries are kept while their grant exists and 90 days after; an encrypt
  record, and the record of which grant an event was signed for, are kept as long as that event is
  **current**: for a replaceable or addressable event, until a newer version replaces it; for a regular
  event, until it is deleted, or while its grant lasts for notes, reactions and reposts. Zap requests,
  relay sign-ins and upload tokens are never recorded, and encrypt records for messages are kept 90 days.
  Snapshots are split at 48 KB, with `d = "keykin-meta:" ‖ hex(HMAC-SHA256(HKDF(base data key,
  "keykin-meta-d/1"), member key ‖ month ‖ part))`, distinct from grant events. A closed month's snapshot is
  dropped once all its entries are. Each device publishes it
  as **one cumulative snapshot per month**, signed by its member key, with a sequence number **per writer
  and month**; a higher number replaces that writer's earlier snapshot for the same month, and only the
  current month changes. It publishes only changed parts, at most once every 10 minutes (through the data service, or else as an
  encrypted account-signed kind 30078 with a `keykin-` `d`, as Doors and grants does for grants), and
  fetches the others' snapshots, for at most 3 seconds, before a judgement that depends on them; if they
  don't arrive, it judges with what it has. A device accepts a snapshot only from a key that is a current device,
  and never one with a lower number than it has seen from that writer **for that month**. So a removed device or the sync service can't forge it or roll
  it back, and out-of-order sync loses nothing.
- **A device leaving by its own choice** (Remove this device, or a `self` remove, core §4.6) first merges
  its metadata into the snapshot of the device that takes over or approves (if there is one), and only
  then sends the remove. Only a report-lost drops a device's metadata.
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
| Other lists and sets (NIP-51 and similar), listed exactly | 10001, 10003, 10004, 10005, 10006, 10007, 10009, 10012, 10013, 10015, 10020, 10030, 10063, 10101, 10102; sets 30000, 30002, 30003, 30004, 30005, 30006, 30007, 30008, 30015, 30030, 39089 |
| Wallets and payments (NIP-60/61) | 17375, 37375, 7375, 7376, 7374, 10019 |
| Others' content | articles (30023, 30040, 30041), classifieds (30402, 30403), stalls and products (30017, 30018), calendar events (31922, 31923), wiki pages (30818): judged only by the "another's content" row below |
| Everything else | ordinary events (app data 30078, drafts 30024 and 31234, and the rest) |

The **judged kinds** are the profile, list, set and wallet groups above; "others' content" has its own row.

**Items.** An item is a tag's name plus its first value, and whether it is public or private, with relay URLs normalised (lowercase host, no
trailing slash). Relay hints, petnames and other later values don't count, and `d`, `title`,
`description`, `image`, `alt` and `client` tags are not items. A list's **private items** (NIP-51
content encrypted to the account's own key) are items too. The self conversation key is the same for
every such list, so the device gets it with one `ecdh` round for the account's own key (core §5.5), keeps
it **in memory only** for at most 10 minutes (as Doors and grants does), and decrypts old and new versions
locally. New content that is empty, or that doesn't decrypt to a NIP-51 tag array, removes every private
item. If the self key can't be had, the change is Confirm. Kind 3's legacy relay JSON is not private
content.

**Public items stay public.** An item that leaves the public tags counts as removed, even if it reappears
in the private content, because other people's clients read only the public tags. Kinds whose spec has no
private items (3, 10002, 10050, 10019, 10063) are judged by their public tags alone. (Moving private items
into the public tags counts as removing them from the private part; that is intended.)

**Expiring lists.** A device never signs, for a site, a judged **replaceable or addressable** kind with a
NIP-40 `expiration` tag: relays would drop the list a moment later. It answers `declined:`. (Wallet quote
events, 7374, carry an expiry by spec and are fine.)

When several rows match, **the strictest wins**, except where a row says otherwise; no row ever wins over
the core §5.8 row.

**Deletions.** The core §5.8 row uses the core's count, of `e` and `a` tags. This module's own rows count
**distinct events**: an `e` and an `a` naming the same event are one target. Before judging a deletion,
the device fetches each target it doesn't have from the account's relays, by id, and judges it by what it
is. A target signed by another key is ignored (relays ignore it too), never shown on a card. An `a`
target counts as the site's own only if every version the device knows at that address was signed for
that grant.

**A site's removals.** For each list, the device counts a site's **net removals**: the items in the
reference version that are missing now and that this site removed. The reference is the newer of the
pre-site version (§1), the version from 7 days ago, and the version the person last approved on a
Confirm card for that site and list. So many small cuts add up within a week, a reconnect doesn't reset
anything, and ordinary unfollows spread over weeks never bring up a card. The person's own edits
in the member app, and other sites', never count against a site.

| Event | Level |
|---|---|
| Anything in core §5.8 (vanishing; a deletion of 5 or more targets or a burst; an emptied profile or list; a relay list with no relays) | **Held** |
| A site deleting a list, set or the profile: an `a` target naming its current version, or an `e` target that is the newest version the device knows of, or newer | **Confirm** (Undo restores it, as for an emptied list) |
| A site leaving a list or set with **no items**, public or private, in a new version of a list that had items, or removing **every** item of a reference that had at least one (a new, empty named set is not a removal; for the profile, only the profile rows and core §5.8 apply) | **Confirm** |
| A site replacing **another's content** (the group above) with a version that is **blank** (no content and no tags but `d`), under a quarter of the **size** (content bytes plus tag values) of the reference, adds an `expiration` or moves one earlier. The reference is the newest version at that address **not signed for this grant**, fetched from relays for at most 3 seconds (without one, only the blank and expiry tests apply); anything not recorded as this grant's counts as another's. **Whenever** a site replaces a version it didn't sign, silently or not, the device keeps that version as the reference, while the grant lasts and 90 days after, and judges the site's later versions against it | **Confirm**; Undo restores the reference. Ordinary edits stay silent; same-size junk is silent but undoable |
| A deletion of one ordinary event of the account (not of a judged kind), that the site signed itself, within its daily budget | Silent, after the **10-second Undo** (§3) |
| A deletion of one ordinary event another site or the member app signed, or not recorded as this grant's | **Confirm** |
| A site's 21st and later single deletion in a day, counted across all devices from the synced metadata (reference) | **Confirm** |
| A deletion with 2–4 targets, or a target still not found after the lookup, or any other target of a judged kind (an older version of a list) | **Confirm** |
| A site's judged-kind or others'-content event dated more than a minute ahead | declined (so Undo and rebased drafts never lose to it at relays) |
| A **wallet deletion**: every target is a token, history or quote event (7375, 7376, 7374), from a site with the `wallet` scope | Silent with at most 3 targets, while the site has made at most 3 such deletions in 10 minutes and the account's burst count, this deletion included, stays at 3 or below, leaving room for ordinary deletions; **anything else gets a quiet `try-later:`**, never a card, even when servers or a co-signing device refuse, and nothing is signed (a newer token event already supersedes them; the device doesn't check its `del` list). This row wins over the stricter rows of this table; it never signs what core §5.8 would hold |
| New token, history and quote events (7375, 7376, 7374) by a site with the `wallet` scope | Silent |
| Wallet and mint settings (17375, 37375) changed, or the payment pubkey or mints in 10019 changed, by a site | **Confirm** |
| Profile: 2 or more filled fields emptied by a site within 7 days, counted like list removals (a whitespace-only value, or a removed key, counts as empty); or `lud16`, `lud06` or `nip05` changed by a site | **Confirm** |
| Profile: `name`, `picture` or `about` replaced (not emptied) | Silent |
| Follow, mute and other lists: a site's net removals, public and private, reach **10 items, or 20% of the reference and at least 5 items** | **Confirm** |
| Relay lists: any relay removed by a site, or switched from write to read only | **Confirm** |
| An Undo that removes items against the current version | judged like any change (§3) |

**Bursts** use the core's numbers (more than 5 deletion targets in 10 minutes), counted as the core
counts them: only targets deleted without an approval, per account, from every deletion the device knows
of, wallet deletions included. So heavy wallet use can make a burst Held, which §8 says.

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

- When a server demands an approval the device's own check doesn't explain, the device tries the next
  server. It shows the Held card only when its own check (its burst count included) says so, or when
  **two servers** demand it for the same event. (Servers count bursts per server, and the core already
  accepts that spreading gives about three times as much, so this costs no security.)
- If no other server is reachable, or the others have refused too without two demanding an approval, the
  device answers the site `try-later:`, signs nothing and shows no card.
- A server that keeps demanding approvals no other server does is replaced through F4 (Server profile
  §5).
- It never retries the same event unchanged at a server that refused it.

**Co-signing for another device.** A device asked to co-sign (not the coordinator) never prompts anyone,
because nobody may be looking at it. It enforces only **Held**: for an event this table rates Held, it
co-signs only with the coordinator's lock assertion over `"sign" ‖ event id`, or the hold's waited
statements from two servers, carried in the `sign` request as `"waited": [<statement>, <statement>]` and
checked as core §6.3 does: `kind` is `hold`, each signature verifies, the two come from two distinct host
keys that each hold a current seat, the wait id is `SHA-256("hold" ‖ event id)`, `end − start ≥ W`, and
`end` is within 7 days. Otherwise it refuses with the error code `needs-approval` (core §9.1's `error`).
Confirm is the coordinator's own job, because any coordinator could claim a Confirm. The coordinator MUST
show its card before asking any other co-signer for that event, and never drops a co-signer's refusal by
going to a server instead: on `needs-approval` it shows its own Held card. A helper never co-signs (core §5.7).

## 3. Undo

- **Undo is judged.** It signs an earlier version from history as a new event, with a fresh `created_at`
  later than any deletion it undoes and than the newest version it replaces (if that is dated ahead, the
  device waits until its time has passed, since a co-signer refuses events dated more than 10 minutes
  ahead; a waiting Undo is kept in the outbox, so it survives the app being killed),
  and goes through §2 against the current version like any change. Additions are never destructive, so
  restoring a bigger list is silent; restoring a smaller one is Confirm; restoring an empty one is Held
  (core §5.8).
- **A post or reaction can't be undeleted** on Nostr. "Post again" signs a new event with the same
  content from verified history, and says it is new.
- **The 10-second wait on a single deletion.** The device signs it 10 seconds after the request if Undo
  wasn't tapped and the app is still running. When the request arrived in the background (a NIP-46 site
  waking a phone), the device shows a notification with Undo for those 10 seconds instead of a card. If
  the app is killed first, nothing is signed and nothing is asked later; the site may ask again.
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
- **Errors to sites** use the Doors and grants codes, `try-later:` included.

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
- **A new set with only a `d` tag** is held by core §5.8 whatever this module says.
- **Kept references live on the device that judged.** Undo of another app's blanked article works from
  that device.
- **Junk in every profile field.** A site may replace `name`, `picture` and `about` with junk silently,
  since replacing them is ordinary; Undo restores them.
- **The 7-day window rolls.** A patient site can cut a list by under 10 items, or under 20%, each week, and
  so shrink 430 follows to a handful over a year without a card. Undo everything *site* did still
  reverses it.
- **Co-signing devices** use only the core's test, so they can't tell a site's deletion of a list from the
  person's.
- **Heavy wallet use** counts towards the burst, so deleting posts right after many wallet spends can be
  Held.
- **A reported device's metadata is dropped**, so Undo for what happened on a stolen phone has no
  pre-site reference; its grants are revoked anyway (Doors and grants §2).
- **The thresholds are guesses** that real use will tune.

## Changes

- **Draft 11**, from its tenth red team (0 critical, 1 high):
  - whenever a site replaces a version it didn't sign, that version is kept as the reference, so a silent
    edit first can't erase the original (DP10-1).

  The mediums and lows:
  - a 3-second cap on fetching the reference (DP10-2);
  - fewer records, changed parts only, every 10 minutes (DP10-3);
  - a distinct, monthly snapshot `d` (DP10-4);
  - a site's events dated more than a minute ahead declined; Undo dated after them (DP10-5);
  - "judged kinds" defined, others' content its own group, wallet refusals by devices, the site's own old
    notes, a waiting Undo kept, missing kinds (lows).
- **Draft 10**, from its ninth red team (0 critical, 3 high):
  - another's content is judged against the newest version this grant didn't sign, fetched first, and
    kept while the grant lasts (DP9-1, DP9-2);
  - the covered kinds are listed exactly, without app data or drafts (DP9-3).

  The mediums and lows:
  - "blank", "size" and expiry moved earlier defined (DP9-4);
  - wallet deletions never Held, even when servers demand it (DP9-5);
  - note records capped at 90 days, snapshots split at 48 KB with an HMAC `d` (DP9-6);
  - new `d`-only sets stated (DP9-7);
  - Undo waits for a deletion dated ahead; kept references and private-to-public stated (lows).
- **Draft 9**, from its eighth red team (0 critical, 1 high):
  - a site blanking, shrinking or expiring another app's article or other addressable event gets a Confirm
    card, and the replaced version is kept for Undo (DP8-1).

  The mediums and lows:
  - signed-for records kept while the event is current, with "current" defined (DP8-2);
  - a new empty set is no removal (DP8-3);
  - wallet deletions at most 3 targets; Undo dated after the deletion; public or private in an item's
    identity; a 3-second snapshot fetch and where snapshots live; removed profile keys; junk fields stated
    (lows).
- **Draft 8**, from its seventh red team (0 critical, 1 high):
  - an item that leaves the public tags counts as removed, and kinds with no private items are judged
    publicly (DP7-1).

  The mediums and lows:
  - the expiry rule only for replaceable and addressable kinds (DP7-2);
  - wallet deletions leave room in the burst (DP7-3);
  - deleting a list is Confirm, and Held is exactly the core set (DP7-4);
  - snapshot numbers per month (DP7-5);
  - the member app's encrypt records, kept while current (DP7-6);
  - a first item added to an empty list is no removal (DP7-7);
  - the rolling window stated (DP7-8);
  - 10013, the profile counted over 7 days, a missing self key, fetching before judging, closed months,
    co-signers (lows).
- **Draft 7**, from its sixth red team (0 critical, 3 high):
  - no NIP-40 `expiration` on judged kinds for a site (DP6-1);
  - a wallet deletion that can't be silent gets a quiet `try-later:`, never a card (DP6-2);
  - list kinds listed exactly, so articles and products are ordinary (DP6-3, Doors aligned).

  The mediums and lows:
  - the profile judged only by its rows and the core (DP6-4);
  - one in-memory self conversation key decrypts every version (DP6-5, and the plaintext store dropped);
  - sequence numbers per writer and month (DP6-6);
  - encrypt records in the metadata (DP6-7);
  - a list emptied by a new version is Confirm; only deleting it is Held (DP6-8);
  - merge only when there is a device to merge into, and budgets per site (lows).
- **Draft 6**, from its fifth red team (0 critical, 2 high):
  - removing every item of a small list is Confirm (DP5-1);
  - a per-site removal log, so no-op edits can't reset the count (DP5-2).

  The mediums and lows:
  - private items from known plaintext, at most one decryption per new version (DP5-3);
  - wallet deletions capped per request, counted in the burst, never over core §5.8 (DP5-4);
  - leaving a list empty by any route is Held (DP5-5);
  - monthly, pruned, batched metadata snapshots (DP5-6);
  - a device leaving by choice merges its metadata first (DP5-7);
  - the core row's tag count, full `waited` checks, `needs-approval` defined, the newest version or newer,
    `a` targets, grants rather than names, `try-later:` with no second server, no stale questions, other
    keys' targets ignored (DP5-8 to DP5-17; the Doors `lists` scope aligned, DP5-14).

- **Draft 5**, from its fourth red team (0 critical, 4 high):
  - private list items are items, so emptying or re-encrypting the content counts (DP4-1);
  - core 13.8: a list with private content isn't "emptied" (DP4-2);
  - wallet deletions are Silent within a small count, then quietly `try-later:` (DP4-3);
  - 20% only from 5 items (DP4-4).

  The mediums and lows:
  - every kind tries another server first; Held needs the device's own check or two servers (DP4-5);
  - core 13.8: §5.8's tests made exact (DP4-6);
  - items are name and first value, with normalised URLs (DP4-7);
  - unknown targets are looked up (DP4-8);
  - distinct events, and only the site's own events silently (DP4-9, DP4-10);
  - one cumulative signed snapshot per writer (DP4-11);
  - a `waited` field (DP4-12);
  - the burst counted as the core counts it (DP4-13);
  - `try-later:` in Doors (DP4-14);
  - a last-approved reference (DP4-15);
  - core 13.8 wording for co-signers and drafts (DP4-16, DP4-17);
  - the kind table (DP4-18, DP4-19);
  - limits stated (DP4-20); the daily budget counted across devices (DP4-21).

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
