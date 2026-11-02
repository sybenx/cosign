# Servers keep no history — proposal, first draft

> **Status, 2026-11-01: buildable, and simpler than both the red team and I thought.** The
> review (`~/igloo/cosign-no-history-redteam.md`) said this could not be built, and its first
> critical was that deleting the archive removes the gate that forces a device into a destructive
> signing. **That finding is wrong, and so was my repetition of it.** The author asked the
> obvious question — *why not keep it on devices? the server requires the device to sign anyway*
> — and the code says yes:
>
> - **A server can never partner with another server.** `const enough = (m) => new Set([...myIdxs,
>   ...sharesOf(m)]).size >= S.group.threshold` (`group.ts:518`) filters the candidate list before
>   the hold is consulted. A server holds 1 share; two make 2 against a threshold of 4. So "two
>   servers sign a follow-list wipe with the phone asleep" cannot happen, with or without an
>   archive, and the hold's devices-only restriction is redundant for a server-coordinated round.
> - **A device judges for itself and does not take the server's word for it.**
>   `val hold = msg["hold"] as? String ?: Policy.hold(ev, lists.latest(Policy.keyOf(ev)))`
>   (`Phone.kt:2047`). A server that sends no hold does not suppress the prompt: the device
>   computes one from its own copy of the lists. The gate was never the server's to lose.
>
> What the review got right, at its real size: with nothing kept, the server's **second opinion**
> degrades from "this would remove 412 of your 430 follows" to "looks fine" — the loss of a second
> opinion, not of the gate, and exactly what was traded away on purpose. And one finding stands
> and is load-bearing: **the account's write-relay list lives in the archive**
> (`ourWriteRelays()` is `archive.latest('10002')`, `group.ts:967`, feeding every event a server
> publishes). That is one current event, not a history, and a server keeps it.
>
> So the shape is: **a server keeps your relay list and nothing else.** No archive of versions, no
> per-site log, no copies of deleted events. §4's three answers and §8's migration are rewritten
> against that, and the two real losses — spotting a list dated in the future, and Undo per site
> on a device that was not there — are §7 and §5.

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

## 3. What is deleted, and the one thing kept

> **A server MUST NOT keep the archive, the history or the saved copies.** No `archive.json`, no
> `history.jsonl`, no `saved.jsonl`. The `logged` and `saved` messages between servers go, and so
> do `archive_forget` and the archive's half of `sync`.

> **A server MUST keep the account's current relay list** (kind 10002), and nothing else of the
> account's events. Not as history: one current version, replaced when a newer one is signed.

That last rule is not a compromise, it is a dependency. `ourWriteRelays()` is
`archive.latest('10002')` (`group.ts:967`) and it feeds `publishOut` — every event a server
originates. Without it a server publishes only to the group's own coordination relays, so Undo,
deletions and restores stop reaching the relays the account actually uses. It is also circular
with §4: a server would need the relay list to know which relays to read the relay list from.

What goes with the rest, stated so nobody is surprised later:

- **The server cannot put a list back.** Restoring is a device's job (§5).
- **The server cannot find a version dated in the future.** §7.
- **The server's second opinion gets weaker**, and that is the trade (§4).
- **"Post again" is a device's.** §5.
- **Live finding #8 is retired** — a server taking another server's word for an archive — because
  there is no archive to take a word about. The `ours` validator it added still guards the relay
  list, which is the one thing left to validate.

## 4. The check, without an archive

**The device is the gate, and always was.** This is the part the first draft got wrong, in the
direction of giving a server too much credit.

> **A device MUST judge every event it signs against its own copy of the list it replaces, and
> MUST ask the user before signing something destructive.** It already does: `holdFor(ev)` is
> `Policy.hold(ev, lists.latest(...))` (`Phone.kt`), and a device asked to co-sign computes the
> hold from its own copy when the coordinator offers none (`Phone.kt:2047`). Every signature needs
> a device's 3 points of 4, so there is no signature a device is not party to.

> **A server's check is a second opinion, and after this change a weaker one.** It MAY compare a
> replacement against what relays will serve at that moment, and MUST NOT hold a round open
> waiting for them (reference: 2 s, a timeout is no opinion). Its answers are **fine**, **this
> looks destructive**, and **I could not tell**, and the third is reported, never enforced.

> **A server MUST NOT treat "I have nothing to compare against" as "fine".** `assess` guards both
> of its hold branches with `if (prev)` (`policy.ts:112`), so today a missing previous version
> produces a *positive* verdict — "Follow list: 0 items", filed as a routine change. That is the
> one code change this section needs: no comparison means no opinion, said as `unjudged`, and a
> client records that a change was never judged by any server.

**Why this is safe, written out, because the first draft claimed the opposite.** Two things hold
it up, both checked in the code rather than reasoned about:

- **A server can never partner with another server.** `enough` (`group.ts:518`) keeps a candidate
  only if the coordinator's shares plus the candidate's reach the threshold. A server has 1 of a
  needed 4, so another server never qualifies — before any hold is considered. A server's round
  is always with a device.
- **A device does not take the server's word.** When the server sends no hold, the device computes
  one itself. So a server with no archive, a server that stays quiet, and a server that lies by
  omission all produce the same outcome: the device asks.

What is genuinely lost is the server's *words* — "Remove 412 of your 430 follows" came from a
server that had watched the old version arrive. A device that has the list says the same thing. A
device that does not have it says nothing, and that was already true before this change.

## 5. Undo, and Post again, from a device

> **A device MUST keep its own log of what was signed and for whom, and Undo MUST be served from
> it.** The device that asks for an Undo uses its own log; where the signature was made does not
> matter.

**This is now the only part with real work in it, and half of it is already built.** Android appends every
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

- **It does not protect anything the archive was protecting.** The server's second opinion gets
  weaker (§4). It is not a compensation but a fact that the device's check was always the one
  that mattered, and it is unchanged.
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

1. **The migration of §8** — two releases or one. Mine to recommend, the author's to decide, and
   the recommendation is two: the release that adds the device-side log, then the release that
   deletes. Shipping both at once leaves any device that was offline during the upgrade with
   nothing.
2. **What `unjudged` looks like to a person.** It must not become a banner on every post and must
   not be invisible. My instinct: in the account's own history on the device, beside the change,
   and nowhere else.
3. **The extension keeps no log at all.** Android appends every `logged` entry to its own file
   (`Phone.kt:1931`); there is no equivalent anywhere in `extension/src`. This must not ship for
   the extension before that exists, or a browser-only account keeps nothing.
4. **What replaces the `future()` sweep** (§7) in a client that is not opened for weeks.
5. **The judged kinds are still too few**, and that is independent of where the versions come
   from. `ARCHIVED` (`policy.ts:13-25`) holds the social lists and nothing else: kind 30078 app
   data is named in `KIND_NAMES` and not judged — live finding #11 — and NIP-60's wallet kinds are
   not there at all, so a wallet rewrite is judged by nobody, whatever permission the caller holds.
   Adding both is cheap and protects against every caller rather than only a granted site, which
   is why the DM spec routes its decision 5(c) here. One caveat found while writing §4: `assess`
   compares **tags**, and both those kinds keep their state in encrypted `content`, so what a
   check can say is "this changed", never "this was emptied".
