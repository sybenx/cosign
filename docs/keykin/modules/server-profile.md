# Keykin module: Server profile

Draft 2 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.2 · not built

This module covers running a Keykin server and being listed as one: the duties as an operator sees them,
abuse defaults, how a server enrols and announces itself, the signed public list, shutting down and
moving, and the notice an operator gives its users. It adds no power to a server. Wherever this module
and the core disagree, the core wins, and nothing here may weaken it. The bar is the core's: an nsec in a
password manager.

## 1. What a server is for, and what it sees

A server holds one share per account, co-signs, enforces the two waits (paper recovery and held mass
deletions), sends wake-up pushes, and helps fill seats. Core §2 lists everything it may keep.

**It can:**

- delay or refuse its share. The account signs with another server. A server that keeps answering but
  refuses is replaced like a dead one, by the person (§5).
- see the events it co-signs, including who the person exchanges messages with (peer keys, never the
  text); the account's membership; when devices are woken and through which gateway; the IP addresses
  devices connect from; and any notice-channel email or webhook it was given.
- if compelled or dishonest, also: ignore cancels, drop notices, log events from then on, or keep an old
  share it should have destroyed. Core §10 states what that allows with other kept pieces.

**It can never:** sign alone, read messages (decryption answers need a device's own points), add a
member, or move a seat.

## 2. Duties

A conforming server, for every account it serves:

1. holds exactly one share and keeps only what core §2 lists (at most one public server list, the
   newest it has verified);
2. co-signs by core §5, applies the stateless destructive rule and holds (§5.8), and keeps answered
   request ids across restarts (§5.6);
3. checks every approval by core §6.2 before co-signing an account change, and only from the current
   backup key where the core says so;
4. applies redeals before co-signing an Upkeep change, fetches from its peers as core §6.7 says before
   any wait, release or Upkeep co-sign, and follows the repair rules (§6.7.4: never for the backup seat;
   one successful `need_repair` answer per key and index; no host in two seats);
5. runs the two waits on its own clock, tells every member and every notice channel, and honours cancels;
6. stays passive after more than 7 days offline until a current peer confirms its seat (§6.7.5);
7. sends Web Push with its own VAPID key and keeps the short inbox (core §8);
8. never reaches private or metadata addresses because a member or stranger named them (core §9.3);
9. guards the signpost (§6.7.5) and never seals a master group's share to anyone (§6.8);
10. answers `seated?` and `forward_get` (§6.7.5), and destroys everything for an account when it verifies
    the change that retired it, keeping only the forwarding note;
11. never deletes a finished account's share for inactivity. A share goes only by a seat change, an
    account delete (Account admin module), or a 0.12 `forget`.

## 3. Abuse defaults

These are defaults an operator may tighten, with one rule above all: **no limit may refuse a request
the core requires a server to answer.** Limits are counted **per sender key, after the sender is verified
as a current member** (or as the account's backup key, or as a peer server), never before. And these are
never counted at all:

- `cancel` and `withdraw`;
- changes (`change`, `changes_get`), `upload` and `upload_held`;
- inbox fetches (`inbox_get`, `inbox_ack`);
- `challenge` and `release_request` from the current backup key;
- `forward_get` and `seated?` from a key the server can verify.

| Limit | Default |
|---|---|
| New accounts per source IP per day (strangers only) | 10 |
| Account creations waiting to finish (strangers only) | 1,000; dropped after 7 days |
| Member messages per sender key per minute (counted ones) | 120 |
| Message size, after reassembly | 512 KB |
| Inbox per account | 512 items or 4 MB (deliveries and wait notices never dropped) |
| Pushes per address per hour | 60 (wait notices always sent) |
| `deliver` per sender and recipient | 32 waiting |
| Unverified `seated?` per source IP per minute | 30 (clients retry with backoff) |
| Re-issued paper items | one per device per redeal (core §6.7.6) |

"Account creations waiting to finish" means only a new account's creation by a stranger. **A seat in an
existing account is never an unfinished enrolment**: a server seated by an approved seat change keeps it
until it is repaired, however long that takes. An open server MAY ask strangers for proof of work
(NIP-13) when they create an account, never for a seat.

## 4. Enrolling, announcing, and the signed public list

- **Enrol reply.** When a device asks a server to take a seat, the server answers `enroll {account:
  H(g), member_key, vapid, https, relays}`, signed by its **host key**. The seat change's `new` entry
  carries this signed reply. Co-signers and repair helpers verify it against the host key before
  co-signing or repairing (core §6.7.2). So nobody between the device and the server can swap in their
  own member key.
- **Announcement.** A server publishes a kind 30243 event, `d = "keykin-server"` (readers also accept
  `cosign-server`), signed by its host key. Its content is `{"relays": [...], "https": "<url>" | null,
  "vapid": "<P-256 key>", "enroll": "open" | "invite", "version": "<the Keykin Core major version it
  speaks>"}`. Its tags are `["p", <operator pubkey>, "", "operator"]` and optionally
  `["nip05", "<name@domain>"]`.
- **Operator list.** The operator publishes a kind 10243 event listing its servers' host keys with
  `["p", <host key>]`. A server belongs to an operator only when both name each other.
- **Which endpoints win.** For an account, the seat's member entry (from its signed enrol reply) wins.
  The announcement is used to find a server and for new accounts. The public list is used only to pick
  candidates. A server that changes its VAPID key or endpoints sends `notice {enroll: <new signed
  reply>}` to every account it serves, and devices update the member entry they keep. The seat doesn't
  change, and papers find it through `seated?`.
- **The signed public list** is what apps pick replacement servers from (core §6.7.7), and what a paper
  uses to find today's servers (§6.7.5).
  - It is a JSON document `{"version": <integer>, "issued": <unix>, "key_next": <optional next list
    key>, "servers": [ {host, operator, https, relays}, … ]}`, with `servers` sorted by host key.
  - It is signed with BIP-340 by the list key over `SHA-256("keykin-list/1" ‖ JCS(document))`.
  - Apps ship a pinned minimum version and fetch newer ones from the app maker's site and from relays
    (kind 30078, `d = "keykin-server-list"`, by the list key).
  - A newer version is accepted only if it is signed by the current list key (or by `key_next` named in
    a version signed by the current key) and has a higher `version`, at most 1,000 above the newest known.
  - **Only open servers are listed**: `enroll: open`, HTTPS required, a working `seated?`, and a
    published operator list naming them.
  - A listed server MUST accept any seat for which it receives an approved seat change, whatever its
    other limits. A server that stops doing so is removed from the list.
  - The list never decides anything an account has already decided. It only proposes candidates and
    answers lookups.
- **A refusing or dead pick.** If the deterministic pick (core §6.7.7) refuses the seat or doesn't answer
  `enroll` within a minute, the device takes the next server in that seat's slice, in list order,
  skipping refused ones, and the `ask` names which one it took.

## 5. Shutting down, moving, and going quiet

- **Planned shutdown.** An operator announces it at least **30 days** ahead with a structured notice,
  `notice {shutdown: <unix>, host}`, signed by the host key, to every account it serves and to its peers.
  - Devices treat a host-signed shutdown notice as "dead" for the seat-replacement card (core §6.7.6
    F1). The app shows the card calmly, then a quiet dot on Backup until the seat has moved.
  - An operator that runs several of one account's servers MUST stagger their shutdowns at least 30 days
    apart, or keep the closing servers in a **move-only mode** past the date. In move-only mode a server
    still co-signs seat changes and repairs for its seat, and nothing else, until that seat has moved.
    So a person who ignores the cards is never locked out by a closure.
  - After closing, a server keeps its forwarding notes for at least a year.
- **Moving hardware.** A server may move to new hardware only as a **live transfer** that keeps its host
  key, every member key, its shares, replay ids, running waits, deliveries and counters, and destroys the
  old copy. It is never a restore from a backup, which could revive destroyed shares (core §7.3). If the
  endpoints change, it sends the `notice {enroll}` above. An operator that can't move this way shuts down
  instead.
- **Going quiet.** A server that has been unreachable for 7 days is offered for replacement by its peers
  (core §6.7.6 F1).
  - The app tells the person once, calmly ("Your server at home has been quiet for a week"), offers to
    move its piece, and keeps a quiet dot until the seat has moved.
  - Moving it takes one Face ID, or a second device, or the paper.
  - The app never swaps a server without the person.
- **A server that refuses but answers** is replaced the same way. The person can choose a server outside
  the list (their own, a friend's) with two devices or the paper.

## 6. The operator notice (template)

Every listed server publishes this on its HTTPS page and links it from its announcement:

> This server holds one small piece of your account's key. It cannot sign anything on its own, read your
> messages, or move your account. It can see the posts it helps sign, who you message (not what you
> say), which devices your account has, when they are woken, the addresses they connect from, and any
> email you give it for alerts. It can refuse to help, or slow down, and then your app uses another
> server. If we were forced to, we could also stop passing on your alerts or keep records from then on.
> We could never sign as you. We keep no history of what you sign. If we close, we will tell your app 30
> days ahead so it can move your piece.

## 7. Limits, said plainly

- **One operator today.** Every listed server is run by one person, so "a different operator" means
  nothing yet. The app says "All your servers are run by X" (core §6.7.7).
- **Operators are pubkeys.** One person with two npubs can pose as two operators. The list's signer is
  the defence: it lists only operators it knows to be distinct.
- **The list signer** chooses which servers are candidates. By publishing versions it can steer which
  server a given account's next pick lands on. It can never move a seat without the person's approval.
- **A compelled server** can do everything in §1's "if compelled" list. It cannot sign.

## Changes

- Draft 2, from its red team (0 critical, 4 high):
  - limits count per verified sender and never block cancels or recovery (H1);
  - listed servers must accept seats, and a refusing pick falls through (H2);
  - host-signed enrol replies (H3);
  - staggered or move-only shutdowns (H4);
  - the full duties (M1);
  - enrolments versus seats (M2);
  - structured shutdown notices (M3);
  - the list's format, order and key rotation (M4, M6);
  - one newest list kept (M5);
  - an honest notice (M7);
  - refusing servers (M8);
  - live hardware moves (M9);
  - quiet dots until moved (M10);
  - which endpoints win (M11);
  - lows.
