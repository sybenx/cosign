# Keykin module: Server profile

Draft 3 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.4 · not built

This module covers running a Keykin server and being listed as one: the duties as an operator sees them,
abuse defaults, how a server enrols and announces itself, the signed public list, closing and moving,
and the notice an operator gives its users. It adds no power to a server. Wherever this module and the
core disagree, the core wins, and nothing here may weaken it. The bar is the core's: an nsec in a password
manager.

## 1. What a server is for, and what it sees

A server holds one share per account, co-signs, enforces the core's waits, sends wake-up pushes, and helps
fill seats. Core §2 lists everything it may keep.

**It can:**

- delay or refuse its share. The account signs with another server, and the person can replace a server
  that keeps refusing (§5).
- see the events it co-signs, including who the person exchanges messages with (peer keys, never the
  text); the account's membership; when devices are woken and through which gateway; the IP addresses
  devices connect from; any notice-channel email or webhook; and, if watching is on (core §2), when sites
  talk to the account.
- if compelled or dishonest: ignore cancels, drop notices, log events from then on, or keep an old share
  it should have destroyed. Core §10 states what that allows together with other kept pieces.

**It can never** sign on its own, read messages (decryption answers need a device's own points), add a
member, or move a seat.

## 2. Duties

A conforming server, for every account it serves:

1. holds exactly one share and keeps only what core §2 lists;
2. co-signs by core §5, including the stateless destructive rule and holds (§5.8); keeps answered request
   ids across restarts (§5.6); and answers `ecdh` only from a current device (§5.5);
3. checks every approval by core §6.2 before co-signing an account change, and accepts backup-key
   requests only from the current backup key;
4. follows Upkeep (§6.7):
   - applies redeals before an Upkeep co-sign, and fetches from its peers before any wait, release or
     Upkeep co-sign;
   - repair rules: never for the backup seat, one successful `need_repair` answer per key and index, no
     host in two seats;
   - recovery sessions only for the changes the core allows, and releases only after its own wait;
5. runs the core's waits on its own clock, tells every member and every notice channel, and honours
   cancels;
6. stays passive after more than 7 days offline until a current peer confirms its seat, or a full wait
   lifts it (§6.7.5);
7. sends Web Push with its own VAPID key and keeps the inbox, including deliveries until they are
   acknowledged (core §7.1, §8);
8. never reaches private or metadata addresses because a member or a stranger named them (core §9.3);
9. guards the signpost (§6.7.5), and never seals a master group's share to anyone (§6.8);
10. answers verified `seated?` and `forward_get` requests (§6.7.5). When it verifies the change that
    retired it, it destroys everything for the account except the forwarding note, which it keeps for as
    long as it runs;
11. never deletes a finished account's share for inactivity. A share goes only by a seat change, by an
    account delete (Account admin module), or by a 0.12 `forget`.

## 3. Abuse defaults

These are defaults an operator may tighten, with one rule above all: **no limit may refuse a request the
core requires a server to answer.**

- **Unverifiable junk** (undecryptable wraps, unknown accounts, malformed messages) MAY be limited per
  source IP before anything is verified.
- **Everything else** is counted per sender key, only after the sender is verified as a current member,
  the account's backup key, or a peer server.
- These are **never counted**:
  - `cancel` and `withdraw`;
  - `change`, `changes_get`, `upload` and `upload_held`;
  - `inbox_get` and `inbox_ack`;
  - `challenge` and `release_request` from the current backup key;
  - verified `forward_get` and `seated?`.

| Limit | Default |
|---|---|
| New accounts per source IP per day | 10 |
| New accounts per hour, server-wide | 1,000 (proof of work MAY be asked) |
| Counted member messages per sender key per minute | 120 |
| Message size, after reassembly | 512 KB |
| Inbox per account | 512 items or 4 MB (deliveries and wait notices never dropped) |
| Pushes per address per hour | 60 (wait notices always sent) |
| `deliver` per sender and recipient | 32 waiting |
| Unverifiable junk per source IP per minute | 30 |
| Re-issued paper items | one per device per redeal (core §6.7.6) |

**A seat is never an account creation.** A server keeps nothing for a seat until a group-signed seat change
naming its enrol reply arrives. That can't be faked without the account's 4 points, so seats need no proof
of work and no creation limit. An account creation (a new account's key generation) is the only thing the
creation limits and proof of work apply to.

## 4. Enrolling, announcing, and the signed public list

- **Stateless enrol.** A server's member key for an account is derived, never stored before a seat exists:
  `member_sk = HKDF-SHA256(ikm = host secret, info = "keykin-member/1" ‖ g)`. A device asks
  `enroll {g}`, and the server answers with `enroll_reply`:

  ```jsonc
  { "g": "<group key>", "member_key": "<derived>", "vapid": "<P-256 key>", "https": "<url>",
    "relays": [ … ], "operator": "<operator pubkey>", "issued": <unix> }
  ```

  It is signed with BIP-340 by the **host key** over `SHA-256("keykin-enroll/1" ‖ JCS(reply))`.
  - The seat change's `new` entry carries this signed reply. Co-signers and repair helpers verify it
    against the host key (core §6.7.2).
  - **A server that signed an enrol reply for `g` MUST accept a valid, approved seat change that carries
    it**, whenever it arrives, and fill the seat. It re-derives the same member key, so it needs no
    pending state.
- **A seat's member key and VAPID key never change in place.** To rotate them, the server is moved to a
  new seat holder by a seat change (core §6.7.2). Endpoint changes are announced (below) and sent as a
  `notice {endpoints}` signed by the host key. Devices use these only as extra routes. They never change
  the group-signed member entry, its relays, or what the signpost `h` covers.
- **Announcement.** A server publishes a kind 30243 event, `d = "keykin-server"` (readers also accept
  `cosign-server`), signed by its host key. Its content is `{"relays": [...], "https": "<url>" | null,
  "enroll": "open" | "invite", "versions": [<Keykin Core major versions it speaks>]}`, with tags
  `["p", <operator pubkey>, "", "operator"]` and optionally `["nip05", "<name@domain>"]`. `invite` means
  new accounts need an invite code from the operator. Seats never do.
- **Operator list.** The operator publishes a kind 10243 event listing its servers' host keys with
  `["p", <host key>]`. A server belongs to an operator only when both name each other.
- **The signed public list** is what apps pick replacement servers from (core §6.7.7), and what a paper
  uses to find today's servers (§6.7.5).
  - It is a kind 30078 event with `d = "keykin-server-list"`, published by the list key, an ordinary Nostr
    key that is pinned in the app. Its content is `{"version": <integer>, "issued": <unix>, "key_next":
    <optional next list key>, "servers": [ {host, operator, https, relays, versions}, … ]}`, with
    `servers` sorted by host key. The event's own signature is the list's signature.
  - Apps fetch newer versions from the app maker's site and from relays. A newer version is accepted only
    if it is signed by the pinned key (or by a `key_next` that a version signed by the pinned key named,
    which then becomes the pin) and has a higher `version`. A device never accepts a version lower than
    the newest it has seen, so it can't be rolled back.
  - **Only open servers are listed**: `enroll: open`, HTTPS, a working verified `seated?`, an operator
    list naming them, and support for the current Core major version. A listed server that refuses a seat
    for which it signed an enrol reply is removed from the list.
  - Servers keep only the newest list they have verified (core §2).
  - The list never decides anything an account has already decided. It only proposes candidates and
    answers lookups.
- **Picking, and falling through.** The server that sends the `ask` names the list version. If the device
  doesn't have that version, it fetches it before deciding, and it never decides on a version older than
  its newest.
  - The device asks the deterministic pick (core §6.7.7) for an enrol reply. If the pick answers with a
    **host-signed refusal**, or doesn't answer within a minute, the device moves to the next server in
    that seat's slice, in list order, skipping servers that have sent a shutdown notice.
  - When the slice is used up, it continues through the whole list in order, still never putting two
    seats on one operator while another eligible one exists.
  - The device shows the card for the server it got an enrol reply from.
- **`seated?` is verified.** The request carries a signature by the key it asks about, over the server's
  challenge. A server answers only if that signature verifies, so seeing a member key on relays isn't
  enough to learn which servers serve it.

## 5. Closing, moving, and going quiet

- **Planned closing.** An operator announces it at least **30 days** ahead with `notice {shutdown: <unix>,
  seq: <n>, host}`, signed by the host key, to every account it serves and to its peers. A later notice
  with a higher `seq` can move the date or cancel it.
  - Devices treat a host-signed shutdown notice as "dead" for the seat-replacement card (core §6.7.6 F1):
    the card calmly, then a quiet dot on Backup until the seat has moved.
  - A **closing** server refuses only new accounts, new seats and new waits. It keeps co-signing,
    answering recoveries already running, cancels, catch-up and seat moves.
  - An operator that runs several of one account's servers MUST stagger their closing dates at least 30
    days apart. A server whose accounts haven't all moved their seats by the date stays in closing mode
    until they have. So nobody is locked out by a closure.
- **Moving hardware.** A server may move to new hardware only as a **live transfer**: it keeps its host key
  (and so every derived member key), its shares, replay ids, running waits, deliveries and counters, and
  destroys the old copy. It is never a restore from a backup, which could bring back destroyed shares (core
  §7.3). If its endpoints change, it sends `notice {endpoints}`. An operator that can't move this way
  closes instead.
- **Going quiet, or refusing.** A server that has been unreachable for 7 days, or that answers but keeps
  refusing to co-sign, can be replaced by the person through F1/F4 (core §6.7.6).
  - The app tells the person once, calmly ("Your server at home has been quiet for a week"), offers to
    move its piece, and keeps a quiet dot until the seat has moved.
  - The move is one approval (a lock, two devices, or the paper).
  - The person may also choose a server outside the list, with the same approval.
  - The app never swaps a server without the person.

## 6. The operator notice (template)

Every listed server publishes this on its HTTPS page and links it from its announcement:

> This server holds one small piece of your account's key. It cannot sign anything on its own, read your
> messages, or move your account. It can see the posts it helps sign, who you message (not what you say),
> which devices your account has, when they are woken, the addresses they connect from, and any email you
> give it for alerts. It can refuse to help, or slow down, and then your app uses another server. If we
> were forced to, or acted in bad faith, we could also stop passing on your alerts, ignore a request to
> stop a recovery, or keep records and old pieces from then on. Together with other stolen pieces, for
> example your paper, that could help someone take your account. Today the same person runs all the
> listed servers. We keep no history of what you sign. If we close, we will tell your app 30 days ahead so
> it can move your piece.

## 7. Limits, said plainly

- **One operator today.** Every listed server is run by one person, so "a different operator" means
  nothing yet. The app says "All your servers are run by X" (core §6.7.7).
- **Operators are pubkeys.** One person with two npubs can pose as two operators. The list's signer is the
  defence: it lists only operators it knows to be distinct.
- **The list signer** chooses which servers are candidates. By publishing versions, it can steer which
  server a given account's next pick lands on. Someone who steals the list key can do the same, and can
  name a `key_next` of their own. It can never move a seat without the person's approval. A list signed
  by several keys is future work.
- **A compelled server** can do everything in §1's "if compelled" list. It cannot sign on its own.

## Changes

- **Draft 3**, from its second red team (0 critical, 3 high):
  - member entries never change in place; endpoint notices are only hints (H1);
  - closing mode keeps everything running except new accounts, seats and waits (H2);
  - stateless derived member keys, so seats aren't account creations (H3).

  The mediums and lows:
  - the enrol reply's encoding;
  - the list kept in core §2;
  - fetching the asked version, with no rollback;
  - key pinning and rotation;
  - the list signed as a Nostr event;
  - fall-through only on signed refusals, with an end;
  - no special approval for servers off the list;
  - refusing servers replaced through F4;
  - verified `seated?`;
  - an honest notice;
  - complete duties;
  - per-IP limits for junk;
  - shutdown sequence numbers;
  - forwarding notes kept;
  - a version list;
  - `invite` defined.
- **Draft 2**, from its first red team (0 critical, 4 high).
