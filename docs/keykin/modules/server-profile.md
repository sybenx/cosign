# Keykin module: Server profile

Draft 1 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.1 · not built

This module covers running a Keykin server and being listed as one: the duties as an operator sees them,
abuse defaults, how a server announces itself, the signed public list, shutting down, and the notice an
operator gives its users. It adds no power to a server. Wherever this module and the core disagree, the
core wins, and nothing here may weaken it. The bar is the core's: an nsec in a password manager.

## 1. What a server is for

A server holds one share per account, co-signs, enforces the two waits (paper recovery and held mass
deletions), sends wake-up pushes, and helps fill seats. Core §2 lists everything it may keep. It never
keeps signed events, list history, grants or logs of what it signed.

**What an operator can and cannot do** (this is also the basis of the operator notice, §6):

- It can **delay or refuse** its share. The account then signs with another server; with every server
  refusing, the account waits for Upkeep (core §6.7.6 F1–F3).
- It can **see** the events it co-signs, when each device is woken and by which push gateway, and the
  hosts in the account's seat changes.
- It can **never sign** alone, never read messages (decryption answers need a device's own points), never
  add a member, and never move a seat.

## 2. Duties, in the operator's words

A conforming server:

1. holds exactly one share per account and keeps only what core §2 lists;
2. co-signs by core §5 and checks every approval by core §6.2 before co-signing an account change;
3. applies redeals before co-signing an Upkeep change, and fetches from its peers as core §6.7 says;
4. runs the two waits on its own clock, tells every member and every notice channel, and honours cancels;
5. sends Web Push with its own VAPID key (core §8) and keeps the short inbox;
6. never reaches private or metadata addresses because a member or stranger named them (core §9.3);
7. destroys everything for an account when it verifies the change that retired it, keeping only the
   forwarding note (core §6.7.5);
8. answers `seated?` and `forward_get` (core §6.7.5);
9. never deletes a finished account's share for inactivity. A share goes only by a seat change.

## 3. Abuse defaults (reference numbers)

These are defaults an operator may tighten. None of them may refuse a request the core requires the
server to answer for a current member.

| Limit | Default |
|---|---|
| New accounts per source IP per day | 10 |
| Unfinished enrolments held | 1,000; dropped after 24 hours |
| Member messages per account per minute | 120 |
| Request size | 512 KB |
| Inbox per account | 512 items or 4 MB (deliveries and wait notices never dropped) |
| Pushes per address per hour | 60 (wait notices always sent) |
| `deliver` per sender and recipient | 32 waiting |
| `seated?` per source IP per minute | 30 |
| Re-issued paper items | one per device per redeal (core §6.7.6) |

An open server MAY require proof of work (NIP-13) on enrolment.

## 4. Announcing a server, and the signed public list

- **Announcement.** A server publishes a kind 30243 event, `d = "keykin-server"` (readers also accept
  `cosign-server`), signed by its **host key**. Its content is `{"relays": [...], "https": "<url>" | null,
  "vapid": "<P-256 key>", "enroll": "open" | "invite", "version": "<string>"}`, with tags
  `["p", <operator pubkey>, "", "operator"]` and optionally `["nip05", "<name@domain>"]`.
- **Operator list.** The operator publishes a kind 10243 event listing its servers' host keys with
  `["p", <host key>]`. A server belongs to an operator only when both name each other.
- **The signed public list** is what apps use to pick servers (core §6.7.7) and what a paper uses to
  find today's servers (core §6.7.5).
  - It is a JSON document `{"version": <integer>, "servers": [ {host, operator, https, relays}, … ]}`,
    signed by the app maker's list key (for now, the user's).
  - Apps ship a pinned minimum version and fetch newer ones from the app maker's site and from relays
    (kind 30078, `d = "keykin-server-list"`, by the list key).
  - A newer version is accepted only if it is signed by the same key and has a higher `version`.
  - Adding a server needs its announcement, its operator's list naming it, and a working `seated?`
    endpoint.
  - The list never decides anything an account has already decided. It only proposes candidates (core
    §6.7.7) and answers lookups.

## 5. Shutting down, moving and going quiet

- **Planned shutdown.** An operator announces it at least **30 days** ahead with a `notice` to every
  account it serves ("This server will close on <date>"). Each account's app then offers to move that
  seat (core §6.7.6 F1), and the person approves it with one Face ID. Until the date the server keeps
  answering normally.
- **Moving hardware.** A server that moves to new hardware keeps its host key and share, so its accounts
  see nothing. Moving the share in any other way breaks core §7.3 (no copies kept), so an operator that
  can't move the share intact shuts down instead.
- **Going quiet.** A server that has been unreachable for 7 days is offered for replacement by its peers
  (core §6.7.6 F1). The app tells the person once, calmly ("Your server at home has been quiet for a
  week"), and offers to move its piece. It never swaps a server without the person.
- **Coming back.** A server that was offline for more than 7 days is passive until a current peer
  confirms its seat (core §6.7.5).

## 6. The operator notice (template)

Every listed server publishes this on its HTTPS page or in its announcement, in plain words:

> This server holds one small piece of your account's key. It cannot sign anything on its own, read your
> messages, or move your account. It can see the posts it helps sign and when your devices are woken. It
> can refuse to help or slow down, and then your app uses another server. If we are legally made to, the
> most we can do is stop helping and hand over the push addresses we hold. We keep no history of what you
> sign. If we ever close, we will tell your app 30 days ahead so it can move your piece.

## 7. Limits, said plainly

- **One operator today.** Every listed server is run by one person, so "a different operator" means
  nothing yet. The app says "All your servers are run by X" (core §6.7.7).
- **Operators are pubkeys.** One person with two npubs can pose as two operators. The list's signer is
  the defence: it lists only operators it knows to be distinct.
- **A server can be compelled** to stop helping and to hand over push addresses (personal data under
  GDPR). It cannot be compelled to sign.

## Changes

- Draft 1.
