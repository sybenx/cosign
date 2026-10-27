# Servers keep no history — proposal, first draft

> **Status after an independent red team (`~/igloo/cosign-no-history-redteam.md`): this cannot
> be built as written** — five critical, eleven high. The direction is fine and the author's
> decision stands; §4, §5 and §9 each specified a mechanism that does not exist and priced it at
> zero. **Two of the findings change the premise the decision was made on**, so they are at the
> top of this file rather than buried in a revision, and the author should see them before any
> more work is done here. Both verified in the code by me, not taken on trust.
>
> **1. Deleting the archive removes the gate that forces a device into a destructive signing.**
> This is a security regression, not a weaker check. `assess` guards *both* of its hold branches
> with `if (prev)` (`policy.ts:112-117`), so with no version to compare against it returns a
> **positive** verdict — `{change: 'Follow list: 0 items'}` — not silence. And the hold is the
> only thing that keeps the other server out of the round:
> `partners((hold ? devices() : [...devices(), ...others()]))` (`group.ts:519`). So no `prev`
> means no hold, no hold means the two servers are eligible partners, and **two servers alone
> sign a follow-list wipe with the phone asleep and never asked.** Today that is impossible,
> because a wipe always holds and a hold always needs a device. §4's `unjudged` does not weaken
> the second opinion; it removes the first one. The device fails the same way at the same moment
> (`core/Policy.kt:70` returns null when `prev == null`), so the two checks fail open together
> and are not independent.
>
> **2. The account's write-relay list lives in the archive.** `ourWriteRelays()` is
> `archive.latest('10002')` (`group.ts:952`) and it feeds `publishOut` (`:956`) — every event a
> server originates. Delete the archive and a server publishes only to the group's own
> coordination relays, so Undo, deletions and restores stop reaching the relays the account
> actually uses. It is also circular with §4: the server needs the relay list to know which
> relays to read the relay list from. An attacker's cheapest first move is one relay-list
> rewrite.
>
> Neither of those was in the cost/benefit the decision was taken on. Both are fixable, and
> neither fix is free: the first needs the hold gate decoupled from `prev` (a verdict of
> "could not tell" that behaves like a hold for participant choice, which is a change to how
> rounds are formed), and the second needs the write-relay list kept somewhere that is not the
> archive — which is a small store of exactly the kind this document is deleting.
>
> The other three criticals, in short: §5's device log is append-only with no reader, no cap, no
> dedupe and **no `ours` check** (`Phone.kt:1546`, `:1931`, `:401` are its only three
> references), so promoting it to the account's history re-points finding #8 rather than retiring
> it, and §3's sentence that the `ours` validator has nothing left to validate is **wrong** —
> three new unvalidated inputs appear. §9's addition of kind 30078 and the wallet kinds to
> `ARCHIVED` would make `undoSite` publish an **empty** app-data record and an **empty** wallet
> record, because `ARCHIVED` is a switch on six behaviours and the restore path signs
> `content: before?.content ?? ''` (`group.ts:921`); it needs a `JUDGED` set separate from
> `ARCHIVED`. And `assess`'s comparison reads **tags**, while both those kinds keep their state
> in ciphertext `content` with no tags, so the judgement it would make is `removed === 0` for
> ever: no holds bought at all.
>
> Also, against §2's table: `S.changes` is history by any reading — persisted, synced between
> servers, and rendered on the server's own page — so §10's proposed sentence for COSIGN §5.4
> would be false on arrival. And `~/igloo/cosign-no-history-carry.md` holds four more items that
> arrived from the DM spec while this was under review, including a direct contradiction: this
> §5 leans on `logged`, whose `prev` comes from a server, while the DM spec's §5.5 forbids taking
> that version from a server for exactly the finding-#8 reason. The DM spec is the correct one.

**Status: proposal, for review. Nothing here is built.** Written as specification text so it can
be attacked. It is not part of [COSIGN.md](COSIGN.md) until it has been reviewed and the author
agrees; §10 lists what it would change there.

## 1. What this is, and why

Today a Cosign server keeps three stores of the account's past (§2). This proposal deletes all
three. Devices keep their own, and Undo comes from a device.

**The reason, stated as narrowly as the author did:** server-side history buys one rare case — a
user with a single device and no paper backup who loses that device and wants an erased list
back — and it costs an archive that has to be synced between servers, judged for authenticity,
and defended. It is a cost/benefit call about this one case, not a principle about what the
system owes people who skip precautions. The author's words were that a general rule "sounds
like a general rule but it's not. it just overcomplicates our setup for such a minor gain".

What it buys, besides simplicity: **live finding #8 stops existing.** That finding was "a server
takes another server's word for the archive and the history", and 0.12.5 fixed it by requiring
every entry to be the account's own signed event (`archive.ts:41`, the `ours` validator at
`group.ts:72`). With no archive there is nothing to forge into and nothing for Undo to sign
from. Retiring an attack surface is better than guarding it.

**An earlier version of this proposal had devices seal copies of the important lists to the paper
backup.** That is dropped. It helped only the same rare case, and it would have put the
account's social graph on relays under a key a paper thief holds — changing what the paper is
worth. The paper stays what it is.

## 2. What a server keeps today, exactly

Three stores, and they are not the same thing. A proposal to delete them has to say what each
one does, because two of them are load-bearing for features the user can see.

| Store | Host file | What is in it | What it is for |
|---|---|---|---|
| **Archive** | `archive.json` | the newest 25 versions of each list kind in `ARCHIVED` (`policy.ts:13-25`: profile, follows, mutes, pins, relays, bookmarks, communities, relay lists, interests, emoji, sets) | the erase check compares a new version with the one it replaces (`assess(ev, archive.latest(keyOf(ev)))`); versions **dated ahead** are found and shown to devices (`future()`); a list can be put back by signing an old version again |
| **History** | `history.jsonl` | every event signed, and for whom, with the version it replaced (`history.ts`, `Entry`) | Undo, including "remove everything this site signed" (`bySite`); the site summary; the `logged` message to devices |
| **Saved** | `saved.jsonl` | copies of events the account deleted | "Post again", because Nostr cannot take a deletion back (`repost`, `savedCopy`) |

A server also keeps `S.changes` — the newest 60 changes as a list for the devices' screen
(`addChange`, `group.ts`) — which is a notification feed and not history, and is unaffected.

## 3. What is deleted

> **A server MUST NOT keep the archive, the history or the saved copies.** No `archive.json`, no
> `history.jsonl`, no `saved.jsonl`. The `logged` and `saved` messages between servers go, and so
> do `archive_forget` and the archive's half of `sync`.

What goes with them, stated so nobody is surprised later:

- **The server cannot put a list back.** Restoring a follow list is a device's job (§5).
- **The server cannot find a version dated in the future.** §7.
- **The server's erase check gets weaker.** §4, which is the heart of this.
- **"Post again" is a device's.** §5.
- **Live finding #8 is retired**, and the `ours` validator it added has nothing left to validate.

## 4. The erase check, without an archive

This is the part to attack. `assess(ev, prev)` (`policy.ts`) needs `prev` — the version this one
replaces — to say "this would drop 23 of your 30 follows". Today `prev` comes from the archive.

> **A server MUST judge a replacement against the current version it can read from relays at the
> moment it is asked, and MUST NOT sign a destructive change on its own judgement when it could
> not read one.** Its three answers are **fine**, **this looks destructive**, and **I could not
> tell**, and the third is reported, not enforced.

> **The device's own check is the one that counts.** A device already judges every event against
> the latest version it has seen signed (`group.ts:663`), and the user's approval of a
> destructive change is asked there. A server's check is a second opinion, and after this change
> it is a weaker one.

**Why it is weaker, in the words a user would need.** A stored archive held versions the server
*watched being signed*. A relay query returns what relays will serve *now*, which anyone can
influence: withhold the current version and the replacement looks like a first write; serve a
stale version and a destructive change looks tame; let the query time out and the server has no
opinion at all. None of that is exotic — a relay being slow is the ordinary case.

**What the server does when it cannot tell** is the decision this spec exists to make, and the
options are not equal:

- *Refuse to sign* — then a relay outage stops the account posting, and anyone who can slow a
  relay can stop it. Unacceptable.
- *Sign anyway, silently* — then the second opinion is skippable by whoever makes relays slow,
  which is worse than not having it, because the interface says a check happened.
- **Sign, and say it could not tell** — the server answers the device with `unjudged` alongside
  its signature share, the device records it, and a destructive change that was never judged by
  any server is shown as such in the account's own history on the device. This is the one this
  proposal takes.

> **A server MUST NOT hold a signing round open waiting for relays.** The query is bounded
> (reference: 2 s) and a timeout is `unjudged`, not a refusal.

## 5. Undo, and Post again, from a device

> **A device MUST keep its own log of what was signed and for whom, and Undo MUST be served from
> it.** The device that asks for an Undo uses its own log; where the signature was made does not
> matter.

**Half of this is already built, and the half that is not is the browser.** Android appends every
`logged` entry to a file of its own (`Phone.kt:1931`, `signedLog`), cleared when the account is
removed (`:401`). The extension does not handle `logged` at all — there is no equivalent anywhere
in `extension/src` — so a browser-only account would keep nothing, and this proposal MUST NOT
ship before the extension keeps a log too.

**The case the author accepted losing:** Undo asked from a device that never saw the event. Today
any server can answer it; after this, only a device that holds it can. Two devices that were both
online have both logs; a device that was away does not, and asking it shows nothing rather than
something wrong. A one-device account that loses the device loses the log with it — the rare case
§1 priced.

> **"Post again" MUST keep the deleted event on the device that asked for the deletion**, for as
> long as that device chooses, and a server MUST NOT keep a copy beyond §6's window.

## 6. The deletion hold stays, because a hold is not history

> **The ten-second window before a deletion goes out stays on the servers**, and the copy a
> server holds for it MUST live only in memory and only until the window closes or the deletion
> is cancelled.

A hold is a decision not yet taken; history is a decision kept. The window is what makes a
deletion cancellable at all, and it is the one place a server still touches the event — for
seconds, never written down.

> **Waits stay on the servers, unchanged** (COSIGN §7.1, §8.2): the recovery wait, the add wait,
> the contest window. They are enforced by the party a thief cannot skip, which is the whole
> reason they are there, and they keep no history — a guard is a timer and a decision.

## 7. A version dated in the future

Today a server finds a list version dated years ahead, shows it to the devices, and removes it by
id with one tap (`archive.future()`, `removeFuture`). That is only possible because the server
kept it.

> **Finding a version dated ahead becomes a device's job**, from what it reads on relays, and a
> client MUST offer the same one-tap removal from there.

This is a real loss and worth naming: the server noticed passively, as events went by. A device
notices when it next looks. A list dated 2099 that nobody looks at blocks every change to that
list on every relay that took it, and after this change it blocks it silently for longer.

## 8. Deleting what servers hold now

> **On the release that takes this up, a server MUST delete its archive, history and saved copies
> at startup**, with the files removed rather than emptied, and MUST say so once in its activity
> so the operator sees it happen.

Two things the author should decide before it ships, because deletion is not reversible:

1. **Whether devices are offered the server's history first.** A server could send its log to the
   devices once, before deleting, so an account that has been running keeps what it already has.
   That is a one-release migration path and it costs a message; without it, every existing
   account's Undo history is gone on upgrade.
2. **Whether the servers' copies of the lists are offered too.** Same shape: one message, then
   deleted.

I recommend both, and that the deletion happen on the release *after* the one that adds the
device-side log, so no account is left with neither. Shipping both in one release is the case
where a device that is offline during the upgrade window keeps nothing.

## 9. What this does not do

- **It does not protect anything the archive was protecting.** The erase check gets weaker (§4),
  and the compensation is that the device's check was always the one that mattered.
- **It does not reach what a server already kept.** A server that kept copies outside the
  protocol keeps them; deletion by the software is not a promise about the operator (COSIGN §5.4).
- **It does not help the one-device, no-paper case.** That case is what was priced and declined.
- **It does not judge app data or wallets.** Which is the next item, and it belongs here:

> **The kinds the erase check judges are too few, and that is independent of where the versions
> come from.** `ARCHIVED` (`policy.ts:13-25`) holds the social lists and nothing else. Kind 30078
> **app data** is named in `KIND_NAMES` (`:36`) and is not judged — live finding #11 — and
> NIP-60's **wallet** kinds are not there either, so a wallet rewrite is judged by nobody today,
> whatever permission the caller holds. Adding both to the judged set is cheap and protects
> against every caller rather than only a granted site, which is why the DM spec routes its
> decision 5(c) here. It is specified in this document because the check's mechanism is being
> rewritten in §4 anyway, and doing it twice would be worse.

## 10. What this would change in COSIGN.md

- **§5.4**: a server keeps no history of what it signed. The sentence about what a server could
  keep anyway stays, because it is about the operator and not the software.
- **§5.2, §5.3**: the erase check's three answers, including `unjudged`, and that a server never
  holds a round open for a relay.
- **§9 (Undo)**: served from a device's own log; what an Undo cannot reach.
- **§3**: the archive leaves the group record's neighbourhood entirely.
- **§12**: finding #8's class is retired rather than fixed.

## 11. Still open

1. **The migration of §8** — mine to recommend, the author's to decide. Two releases or one.
2. **What `unjudged` looks like to a person.** It must not become a banner on every post, and it
   must not be invisible. My instinct is that it belongs in the account's own history on the
   device, next to the change, and nowhere else.
3. **Whether a device should query relays itself** when a server says `unjudged`, before showing
   a destructive change for approval. It makes the check stronger and the approval slower.
4. **What replaces the `future()` sweep** (§7) in a client that is not opened for weeks.
