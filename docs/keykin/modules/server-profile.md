# Keykin module: Server profile

Draft 7 · 2026-11-03 · module of [Keykin Core](../core.md) draft 14.8 · not built

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
- if the person turned them on: hold the heir's envelope piece (Backup module) and the NIP-46 signer
  public keys it watches (core §2).

**It can never** sign on its own, read messages (decryption answers need a device's own points), add a
member, or move a seat.

## 2. Duties

A conforming server, for every account it serves:

1. holds exactly one share and keeps only what core §2 lists;
2. co-signs by core §5, including the stateless destructive rule and holds (§5.8); keeps answered request
   ids across restarts (§5.6); and answers `ecdh` only from a current device (§5.5);
3. checks every approval by core §6.2 before co-signing an account change, and accepts backup-key
   requests only from the current backup key. For a seat change it also checks the `new` entry's enrol
   reply (host signature, and its age at this co-sign, §4) and the I2 and I7 host rules, and refuses with
   the rule's name (`refused: I2`, `refused: I6`, `refused: I7`) and the conflicting change's id, or
   `refused: replaced` when the seat's `replaces` is no longer its current holder;
4. follows Upkeep (§6.7):
   - applies redeals before an Upkeep co-sign, and fetches from its peers before any wait, release or
     Upkeep co-sign;
   - repair rules: never for the backup seat, one successful `need_repair` answer per key and index, no
     host in two seats;
   - recovery sessions only for the changes the core allows, and releases only after its own wait;
5. runs the core's waits on its own clock, tells every member and every notice channel, and honours
   cancels;
6. stays passive after more than 7 days offline until a live peer that is itself a current seat holder
   confirms its seat. Only if **no peer is live** does a paper holder's `release_request` lift it, once
   the server has run its full wait and found no change removing it at any peer or device it can reach
   (core §6.7.5);
7. sends Web Push with its own VAPID key and keeps the inbox, including deliveries until they are
   acknowledged (core §7.1, §8);
8. never reaches private or metadata addresses because a member or a stranger named them (core §9.3);
9. guards the signpost (§6.7.5), and never seals a master group's share to anyone (§6.8);
10. answers verified `seated?` and `forward_get` requests (§6.7.5), addressed to its **host key** or over
    HTTPS, never to a member key. Everything per seat (share, stored keys, retirement, forwarding note)
    is kept **per member key**, not per account, since one host can hold an old and a new seat for the
    same account. When it verifies the change that retired a member key, it destroys everything for that
    key, its stored member and VAPID keys included, except the forwarding note, which it keeps for as
    long as it runs. It serves that note to the account's backup and device keys, and to the account's
    other seat servers by their host keys. If a dedupe (core §6.7.2) makes the loser a key on this same
    host, it first opens the loser key's pending deliveries, then moves the share, which has the same
    value, to the winner's key, and only then destroys the loser key. Devices that apply the dedupe
    re-register push with the winner key's VAPID key;
11. never deletes a finished account's share for inactivity. A share goes only by a seat change, by an
    account delete (Account admin module), or by a 0.12 `forget`.

## 3. Abuse defaults

These are defaults an operator may tighten, with one rule above all: **no limit may refuse a request the
core requires a server to answer.**

- **Unverifiable junk** (undecryptable wraps, unknown accounts, malformed messages) MAY be limited before
  anything is verified: per source IP for direct HTTPS, and by a decryption budget per relay connection
  for messages that arrive through relays, whose IP is the relay's. Under a flood, the server asks for
  proof of work (NIP-13) on relay-delivered requests instead of refusing them, so one flood through a
  shared relay can't block anyone else on it.
- **Requests from keys that aren't members yet** have their own buckets, never the junk bucket, and are
  limited only per HTTPS source IP or by proof of work over relays, **never per account**, since `g` is
  public and anyone could empty a victim's bucket:
  - `enroll {g}`;
  - an incoming holder's uploads and welcome (§4);
  - `changes_get` from a removed key (core §3.2);
  - the `challenge` before a `seated?` or `forward_get`, and the `challenge` a paper asks of a server
    being seated in F3.
- **Everything else** is counted per sender key, only after the sender is verified as a current member,
  the account's backup key, or a peer server. This replaces core §9.3's per-account reference figure on
  purpose: counting per key means a thief's device can't use up the owner's allowance.
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

**A seat is never an account creation.** Before a group-signed seat change naming its enrol reply arrives,
a server keeps for that reply only the inert uploads of §4. A seat change can't be faked without
the account's 4 points, so seats need no proof of work and no creation limit. An account creation (a new account's key generation) is the only thing the
creation limits and proof of work apply to. At creation, a server's member keys also come from its enrol
reply, stored and aged as in §4; the epoch record naming the reply stands in for the seat change (Account
admin §1.1).

## 4. Enrolling, announcing, and the signed public list

- **Stateless enrol, with keys that can be destroyed.** A server keeps a rotating **enrol secret**: a
  new random one each calendar month, named by an id. A device asks `enroll {g}`, and the server picks a
  fresh 16-byte `nonce` and answers with `enroll_reply`:

  ```jsonc
  { "g": "<group key>", "secret_id": "<enrol secret id>", "nonce": "<16 bytes hex>",
    "member_key": "<derived>", "vapid": "<derived P-256 key>", "https": "<url>",
    "relays": [ … ], "operator": "<operator pubkey>", "issued": <unix> }
  ```

  - `member_sk = HKDF-SHA256(salt = empty, ikm = enrol secret (32 bytes), info = "keykin-member/1" ‖ g
    (32-byte x-only) ‖ nonce (16 bytes) ‖ c, L = 32)`, with `c` a counter byte starting at 0, raised
    until the output is a valid secp256k1 scalar (not 0, below the order). The member key is its x-only
    public key, used as BIP-340 does (even y). The VAPID key is the same with `"keykin-vapid/1"` and the
    P-256 order. So each reply, and so each seat, gets fresh keys, and the same host can be seated again
    later (core I7). A test vector is to be added to `vectors/`.
  - The reply is signed with BIP-340 by the **host key** over `SHA-256("keykin-enroll/1" ‖ JCS(reply))`.
    The seat change's `new` entry carries it.
  - **The reply's age is checked once, when the change is approved.** A reply is **unexpired** while it
    is at most **30 days** past `issued` and not more than 10 minutes ahead. The device fetches the reply,
    checks it, and only then shows the card and asks the person to approve. The co-signer refuses a reply
    that isn't unexpired at its co-sign. For a list no seat holder co-signs
    (F3), the device makes the same check at approval. Repair helpers and the server itself check only the
    host signature, so a group-signed seat change never becomes unfillable because time passed.
  - **A server MUST accept a valid, group-signed seat change carrying one of its replies**, closing or
    not, and fill the seat. It derives the keys from the named enrol secret and **stores them per member
    key** at the first verified upload (below) or seat change naming the reply, so it needs the enrol
    secret only until then. On retirement (duty 10) it deletes them, and if the upload expires with no
    seat change, it deletes them then.
  - An enrol secret is destroyed **13 months** after it was made. After that, logged traffic to a seat
    that has since retired can't be opened again, even if the host is later compromised. A seat change
    that arrives with no stored keys after its secret is gone (a server offline for a year) is the one
    case it can't fill: it answers with a host-signed `refused: expired`, and the device replaces the seat
    again (F1/F4). That refusal never delists the server.
  - The host secret and enrol secrets are **never in a backup** (core §7.3). Only a live transfer (§5)
    copies them.
- **Incoming holders before the seat change.** Core §6.7.3 has the dealer upload deliveries to incoming
  holders before the co-sign. A server accepts an `upload` naming one of its own unexpired replies only
  if it carries the epoch record and the change set, which it verifies from `g`, with an approval that
  checks (core §6.2). Uploads count only when they come over HTTPS or sealed by the account's members,
  never from an unauthenticated relay message. It keeps the **newest upload per dealer and approval** (a retry replaces the
  last, unless the last was already vouched for with `upload_held`, which is never dropped), inert, for 7
  days or until the seat change arrives, and counts as a live post-change holder for `upload_held` (core
  §6.7.1). It keeps at most 8 such uploads per `g` (safe, since a real account needs few) and asks for
  proof of work past a server-wide byte budget. At a hard server-wide cap it refuses **new enrol requests**
  with a host-signed refusal, so picks fall through before anyone approves, and keeps accepting uploads for
  replies it has already issued. A co-signer that counted an incoming server's upload as one of the two
  holders sends that server the co-signed list, so the vouched upload never expires.
- **A seat's member key and VAPID key never change in place.** To rotate them, the server is moved to a
  new seat by a seat change with a fresh enrol reply (core §6.7.2). Endpoint changes are announced
  (below) and sent as a `notice {endpoints}` signed by the host key, to the account's members and to the
  server's peers. Readers also resolve a host key's current endpoints from its kind 30243 announcement.
  These are only extra routes. Peers apply core §9.3 to them. They never change the group-signed member
  entry, its relays, or what the signpost `h` covers.
- **Announcement.** A server publishes a kind 30243 event, `d = "keykin-server"` (readers also accept
  `cosign-server`), signed by its host key. Its content is `{"relays": [...], "https": "<url>" | null,
  "enroll": "open" | "invite", "versions": [<Keykin Core major versions it speaks>], "pow": <optional
  NIP-13 difficulty>}`, with tags
  `["p", <operator pubkey>, "", "operator"]` and optionally `["nip05", "<name@domain>"]`. `invite` means
  new accounts need an invite code from the operator. Seats never do.
- **Operator list.** The operator publishes a kind 10243 event listing its servers' host keys with
  `["p", <host key>]`. A server belongs to an operator only when both name each other.
- **The signed public list** is what apps pick replacement servers from (core §6.7.7), and what a paper
  uses to find today's servers (§6.7.5).
  - It is a kind 30078 event with `d = "keykin-server-list"`, published by the list key, an ordinary Nostr
    key that is pinned in the app. Its content is `{"version": <integer>, "issued": <unix>, "key_next":
    <optional next list key>, "servers": [ {host, operator, https, relays, versions, closing}, … ]}`,
    with `servers` sorted by host key and `version` below 2^53. The event's own signature is the list's signature.
  - The list key is pinned in the app **and in each server's configuration**, so servers verify the list
    the same way.
  - Apps fetch newer versions from the app maker's site and from relays. A newer version is accepted only
    if it is signed by the pinned key (or by a `key_next` that a version signed by the pinned key named,
    which then becomes the pin) and has a higher `version`. A device never accepts a version lower than
    the newest it has seen **from that key**, so the list can't be rolled back. If the list key is stolen,
    an app update (and server configuration) re-pins, and the floor starts again for the new key; nothing
    else can.
  - **Listed servers** are `enroll: open`, HTTPS, with a working verified `seated?`, an operator list
    naming them, and support for the current Core major version. A **closing** server stays listed with
    `closing: true` until it ends: it is left out before the list is dealt into seat slices, so picks
    skip it, and lookups still ask it. A listed server that refuses a
    seat for which it signed an enrol reply is removed from the list.
  - Servers keep only the newest list they have verified (core §2).
  - The list never decides anything an account has already decided. It only proposes candidates and
    answers lookups.
- **Picking, and falling through.** The server that sends the `ask` names the list version and its
  candidate (core §6.7.7). If the device doesn't have that version, it tries to fetch it for a minute, then
  decides on the newest version it has. It never decides on a version older than its newest, and accepts
  the candidate only if it is the pick, or a later one reached by the fall-through below; when the `ask`
  names another, the device uses its own pick. The pick is
  `int(SHA-256(g ‖ dead key ‖ seat index (4 bytes) ‖ version (8 bytes)), big-endian) mod` the slice's
  length, all integers big-endian. Slices: the open servers, in list order, dealt round-robin to the three
  server seats sorted by index.
  - Before picking, the device runs `changes_get` against every server. It stops if the dead key is no
    longer that seat's holder (another device already replaced it), and skips any host that holds a seat,
    or is the helper's host, in that view (core I2, I6, I7), and never picks a server of the helper's
    stated operator.
  - The device asks the pick for an enrol reply. It moves to the next server in that seat's slice, in
    list order, if the pick answers with a **host-signed refusal**, doesn't answer within a minute, or
    answers, over HTTPS or sealed by its own key, with a reply the device can't use (a bad signature, the
    wrong `g`, more than 30 days old with a day's slack, or a member key that isn't fresh by core I7).
    Unauthenticated relay replies are ignored, never counted as refusals. The device doesn't check the
    "ahead" bound; the co-signer does, on its own clock.
  - If a co-signer refuses citing I2, I6 or I7, the device fetches the named conflicting change. If it is a
    change replacing the **same key in the same seat** (another device's F1), the device stops: that
    change is the replacement. Otherwise it falls through only if the change exists and checks, and uses
    another co-signer if it doesn't.
  - When the slice is used up, it continues through the whole list in order, still never putting two
    seats on one operator while another eligible one exists. When the whole list is used up, the seat
    stays where it is and the device says: "No replacement server is available. You can add your own."
  - The device shows the card for the server it got an enrol reply from. If the reply is more than 7 days
    old when the person opens the card, it fetches a fresh one first.
  - A host-signed `refused: expired` counts like a shutdown notice for the F1 card.
  - **Off-list servers.** The `operator` in an off-list server's reply counts only if that operator's
    kind 10243 list names the host. Otherwise the operator is "unknown", which never counts as different
    from another for the two-seats rule or the "All your servers are run by X" line.
- **Proof of work.** A server that may ask for it says so in its announcement (`"pow": <NIP-13
  difficulty>`), and answers an HTTPS request that needs it with `error {pow: <difficulty>}`. Over relays,
  where it can't ask before decrypting, senders attach proof of work at the announced difficulty; under a
  flood, relay messages without it may be dropped unread, which is why devices repeat cancels and also use
  HTTPS (core §6.3, §9.2).
- **`seated?` is verified.** The request carries a signature by the key it asks about, over the server's
  challenge. A server answers only if that signature verifies, so seeing a member key on relays isn't
  enough to learn which servers serve it.

## 5. Closing, moving, and going quiet

- **Planned closing.** An operator announces it at least **30 days** ahead with `notice {shutdown: <unix>,
  seq: <n>, host}`, signed by the host key, to every account it serves, to every notice channel (in the
  core's fixed words, with the date) and to its peers. A later notice with a higher `seq` can move the
  date or cancel it. An operator adds a new host to the list before closing one.
  - Devices treat a host-signed shutdown notice as "dead" for the seat-replacement card (core §6.7.6 F1):
    the card calmly, then a quiet dot on Backup until the seat has moved.
  - A **closing** server refuses only **new accounts and new enrol replies**, with a host-signed refusal.
    It keeps everything else: co-signing, recovery waits, holds and heir waits (new and running),
    cancels, catch-up, seat changes carrying its replies (§4), and seat moves away. A person with
    only the paper can always recover through a closing server.
  - An operator that runs several of one account's servers MUST stagger their closing dates at least 30
    days apart.
  - A closing server stays in closing mode for at least **12 months** after its date. After that it may
    end, and to any account still on it, it is a dead server, replaced through F1. Dormant accounts that
    nobody opens for that year lose that server, as with any server that dies.
- **Moving hardware.** A server may move to new hardware only as a **live transfer**, in this order:
  1. the old copy stops answering for every account;
  2. everything is copied: everything core §2 lists, plus the host key, enrol secrets and stored seat
     keys;
  3. the new copy starts;
  4. the old copy is destroyed.

  The two copies never answer at the same time, so cancels and waits can't split between them. It is
  never a restore from a backup, which could bring back destroyed shares (core §7.3). Core §7.3's rule
  applies to servers too: shares, seat keys and enrol secrets sit only as ciphertext in anything with
  history (snapshots, replicas), with the key kept outside it, so deleting the key destroys them. If its endpoints
  change, it sends `notice {endpoints}` (§4). An operator that can't move this way closes instead.
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
> which devices your account has, when they are woken, the IP addresses they connect from, and any email
> you give it for alerts. If you turn them on, it also keeps your heir's sealed piece and watches for
> sites that talk to your account. It can refuse to help, or slow down, and then your app uses another
> server. If we were forced to, or acted in bad faith, we could also stop passing on your alerts, ignore
> a request to stop a recovery, or keep records and old pieces from then on.
>
> Today the same person runs all the listed servers and signs the list your app picks servers from. So
> that person together with your paper, or with a stolen device whose pieces can be copied out, could take
> your account with no wait. We keep no history of what you sign. If we close, we will tell your app 30
> days ahead, and keep running for at least a year after that date so your piece can move.

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
- **Forwarding notes end with the server.** Once a closed server is finally switched off, a paper that
  printed it can't follow its note. The public list and the signpost still work.
- **Logged traffic** to a seat that has retired can be opened by a host compromised within 13 months of
  the enrol reply (§4); after that, it can't. While the seat is current, a compromised host opens
  everything anyway.
- **A closed server is gone after its year.** An account nobody opened in that time has a dead seat,
  which the next device to open replaces. If the **only operator winds down**, that is all three seats,
  and a paper alone can then never recover the account.

## Changes

- **Draft 7**, from its sixth red team (0 critical, 0 high), its mediums and lows:
  - two devices replacing the same server stop at the first, and `refused: replaced` (M1);
  - at the hard cap, new enrol requests are refused before approval (M2);
  - vouched uploads get the co-signed list (M3);
  - only authenticated replies count as refusals (M4);
  - closing servers honour all their replies, proof of work on the wire, I6 and the helper's host, the
    pick to the byte, `refused: expired` brings the card, stale cards refetch, no device "ahead" check,
    push after a dedupe, the F3 challenge bucket (L1 to L9).
- **Draft 6**, from its fifth red team (0 critical, 1 high):
  - any reply the device can't use counts as a refusal, and the device checks the reply before the card
    (H1).

  The mediums and lows:
  - a vouched upload is never dropped (M1);
  - core 13.14: a retired server destroys what belongs to that seat's key (M2);
  - the pick's bytes, closing servers left out before slicing, the device's own pick (M3);
  - proof of work on the wire (M4);
  - two devices replacing the same key stop at one (M5);
  - keys dropped with expired uploads, caps per `g` and server-wide (M6);
  - a single operator winding down, said plainly (M7);
  - "unexpired" defined, `refused: expired` only without stored keys, dedupe order, the logged-traffic
    limit, a `closing` field, a bound on `version`, one upload rule, peers by host key (lows).
- **Draft 5**, from its fourth red team (0 critical, 2 high):
  - an enrol reply's age is checked once, at approval; afterwards only its signature, and keys are stored
    at the first upload, so a signed seat change never becomes unfillable (H1);
  - no per-account limit on `enroll` or lookups, since `g` is public (H2).

  The mediums and lows:
  - per-seat state kept per member key, and dedupe losers on one host (M1);
  - lookups go to the host key; peers may fetch forwarding notes (M2);
  - closing servers stay listed for lookups (M3);
  - a version floor per list key, and no jump cap (M4, L8);
  - the device checks I2 and I7 itself (M5);
  - newest upload per dealer, and a byte budget with proof of work (M6);
  - at least 12 months of closing, notice channels told, an end to the fall-through (M7);
  - no per-wrap-key limit (L1);
  - the key derivation to the byte (L2);
  - future-dated replies refused (L3);
  - the full copy list, and destruction on servers (L4, L5);
  - the `ask` names its candidate (L6);
  - core §2 lists a server's own keys (L7, core 13.7);
  - creation-time servers (L9, Account admin §1.1).
- **Draft 4**, from its third red team (1 critical, 3 high):
  - a closing server refuses only new accounts and new enrol replies, so a paper can always recover (C1);
  - member and VAPID keys come from a monthly enrol secret and a nonce, are stored per seat and deleted at
    retirement, and are never backed up (H1, M7);
  - a host can be seated again with fresh keys; the pick skips seated hosts and falls through on I2 and
    I7 refusals (H2);
  - incoming holders accept verified, capped uploads before the seat change (H3).

  The mediums and lows:
  - enrol replies expire after 30 days, and are honoured while closing (M1);
  - separate buckets for not-yet-members, relay junk limited per wrap key (M2);
  - an ordered hardware move, and endpoint notices to peers (M3);
  - servers pin the list key, version jumps are capped, an unfetchable version doesn't stall (M4);
  - duty 6 quotes the core (M5);
  - a plainer operator notice (M6);
  - shutdown-notice skipping dropped (L1);
  - unverified operators count as unknown (L2);
  - forwarding notes end with the server (L3);
  - the enrol-reply and I2/I7 checks in duty 3 (L4);
  - per-key counting stated (L5).
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
