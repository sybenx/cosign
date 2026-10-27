# An app key of its own — proposal, second draft

**Status: proposal, for review. Nothing here is built.** Written as specification text so it
can be attacked. It is not part of [COSIGN.md](COSIGN.md) until it has been reviewed and the
author agrees; §12 lists what it would change there, §13 what it costs the other two
proposals in flight.

This draft answers an independent red team of the first one
(`~/igloo/cosign-app-keys-redteam.md`, verdict: *build it with changes — substantial ones*;
two critical findings, five high). It was right, and three of its findings I checked against
the code myself before believing them.

**What changed, and the first one matters most:**

- **"It rotates" was overclaimed, and the claim is now gone.** The account's key is permanent
  by design, the label is public, so every epoch's key — including epochs that do not exist
  yet — is a deterministic function of a permanent secret. Anyone who ever holds the key
  **whole** owns every namespace in every epoch, past and future, for ever, locally, with
  nothing to notice. This mechanism compartmentalises against **apps and sites**; it is not
  forward secrecy against the key's own holders, and §4 now refuses to serve an account whose
  key was ever whole.
- **The `created_at` cut-off did not work.** A removed device writes now and *dates* the write
  before the boundary; on a replaceable event the newest date wins, so its forgery beat every
  genuine pack. Replaced by a **signed epoch-boundary checkpoint** (§7), which also removes
  the need for a timestamp devices do not have.
- **"No server change" was false.** Every ECDH round is refused unless it names a live grant
  (`server/core/group.ts:716`, verified), so as written the app key was reachable *through* a
  grant and died *with* one — the opposite of what §9 claimed. §9 now states the one small
  server change it needs.
- **A granted site can already make a device compute `x(ns,e)`** by naming the label point as
  the peer of a `nip04`/`nip44` decrypt, and NIP-04 uses that value *verbatim* as its AES key.
  The first draft's confidentiality rested on an HKDF salt differing, by luck. §5 makes that a
  requirement and adds the check that closes it.
- **The derived value is never verified.** `ecdhCombine` rejects only the identity point
  (`server/frost.ts:159`, verified), so one dishonest partner can make a device derive a key
  **nobody** holds and encrypt under it — silent, permanent data loss. §6 requires a check
  before anything is written.
- The label's bytes are pinned exactly, with test vectors, because three platforms will
  implement it (§3); the first-party rule closes three holes the reviewer found in today's code
  (§4); and §11 says plainly that this is the one access in Cosign a user cannot revoke.

**And one change after the review, from a challenge to this draft rather than to the first.**
Refusing the derive call for any account whose key was ever whole — which is what I wrote
first — **protects nothing and costs the whole point of the mechanism.** Somebody holding the
key already decrypts everything the account encrypts to itself and signs as the account; they
do not need the call, and denying it to the *account* only takes away the compartmentalisation
against apps and sites, which is the thing Marble needs. The refusal is gone.

What replaces it is better than either: **the namespace salt is a members-only secret.** `s`
alone does not derive an app key — the label needs `S`, and `S` is never published, never sent
to a server and never put in the epoch record. So the nsec that existed before an import, held
by whoever held it, cannot construct the label point at all, and an imported account gets a
real guarantee rather than a disclaimer. Two further consequences fall out: a server can no
longer recognise which namespace is being derived, so §8's blinding stops being necessary, and
the thing a client must never claim is now precise — protection fails against someone who held
**both** `s` and `S`, not against anyone who ever touched the key.

---

## 1. What an app key is, and what it is not

An **app key** is a secret derived from the account's key by a **threshold round**, belonging
to a **namespace** (`marble/notes/v1`) and a **committed epoch**, reachable only through a
**first-party call on a device**.

**What it gives you:** an app's data is closed to every site and app the user has merely
connected, including those with full message access, and closed to a device that has been
removed from the account. The namespace's own signing key signs its records on the device, in
a millisecond, with no FROST round and no link to the user's npub.

**What it does not give you, stated here because the first draft implied otherwise:** it is
**not forward secrecy**. The account's key is permanent (COSIGN.md §3; a refresh moves shares
and keeps the key), and the label is public, so `x(ns,e)` is a fixed function of a permanent
secret. Anybody who holds the key whole — by importing an nsec, by taking the account out
(§7.6), by the escape hatch (§8.4), by rebuilding to re-split (§3) — can compute every
namespace's every epoch, for ever, offline, and nothing in the account will ever show it. A
refresh does not help, and neither does re-splitting: §4 is the only answer, and it is a
refusal rather than a repair.

It is not a share of the account's key, carries no points, and signing with it is not signing
as the user.

## 2. The label point

For a namespace `ns`, an epoch `e` and the account's **namespace salt** `S` (§4.4), the label
point `P(ns,e)` is the label's bytes mapped onto secp256k1 by try-and-increment.

- **`P` MUST be obtained by hashing to the curve, never as `h·G` for a hash `h`.** If the
  discrete log of `P` were known then `s·P = h·(s·G)`, computable by anyone holding the
  account's **public** key — which is everyone. That one substitution turns the mechanism into
  a public value.
- Try-and-increment is adequate here: `P` is a fixed public point, nothing depends on the map
  being constant-time or uniform, and the reviewer confirmed `Point.fromHex('02' ‖ x)` is the
  even-y lift the construction assumes (`server/frost.ts:154`).

## 3. The bytes, exactly

Three platforms will implement this — TypeScript, Kotlin, Rust — and an encoding that differs
between them derives different keys and writes into **disjoint invisible data sets**. So the
bytes are pinned, with no room for a judgement call:

```
label      = "cosign-app-key:v1" ‖ 0x00 ‖ S ‖ 0x00 ‖ ns ‖ 0x00 ‖ epoch_be4
             S         32 bytes, the account's namespace salt (§4.4)
             ns        the namespace's name, ASCII, no trailing 0x00 of its own
             epoch_be4 the committed epoch as a 4-byte big-endian unsigned integer
point_hash = SHA-256("cosign-app-key-point:v1" ‖ 0x00 ‖ label ‖ i_u8)
             i_u8      a single byte, 0, 1, 2, …, and an implementation MUST stop at 255
P(ns,e)    = the first i whose 02 ‖ point_hash is a point on secp256k1
x(ns,e)    = the x-coordinate of s · P(ns,e), 32 bytes
K(ns,e)    = HKDF-Extract(SHA-256, salt = "cosign-app-key:v1", ikm = x(ns,e))
```

- The epoch is a **number**, never its decimal spelling: `"7"` and `"07"` would be two keys
  and two data sets. 4 bytes big-endian, and that is the whole of it.
- A conforming implementation MUST ship **test vectors**: for a fixed `S`, `ns` and epochs
  0, 1, 7 and 255, the chosen `i`, `P`'s x-coordinate, and `K`'s first 8 bytes. Two platforms
  that disagree on any of them are not interoperable, and the failure is silent.

## 4. Who may ask, and which accounts may be asked

### 4.1 The first-party rule

> **A device MUST answer a derive call only for a caller it has identified itself, by a
> platform mechanism, against a list compiled into that device's own build.** Never for a
> site or app holding a grant, and the call MUST NOT exist over NIP-46.

- **Android.** The device MUST take the calling UID from the binder and resolve it to a
  package name **and the digest of the signing certificate of that package**, and match both.
  Three things in today's code have to change first, which the reviewer found:
  - identity MUST NOT come from `activity.callingActivity?.packageName`
    (`Nip55Request.kt:70`): an Activity's caller is forwardable with
    `FLAG_ACTIVITY_FORWARD_RESULT`, so a third-party app can present itself as Marble. The
    binder's calling UID is the only identity that cannot be handed on.
  - a caller-supplied `callbackUrl` origin MUST NOT share an identity namespace with package
    names (`Nip55Request.kt:66`), and `http://localhost` MUST NOT be first-party for anything
    (`:148`).
  - no certificate check exists anywhere today (`Nip55Provider` uses `callingPackage` alone).
    A build that has not got one MUST NOT answer a derive call at all. Note that pinning a
    digest breaks on Play App Signing rotation: the list holds the signing-certificate
    digests the publisher controls, and rotating one is a release of the device software.
- **The browser extension.** Only its own extension pages, or an **exact** HTTPS origin on the
  compiled list: scheme, host and port all matching, no wildcard, no subdomain, and `http://`
  never (`background.ts:727` accepts it today for ordinary sites, which is fine there and not
  here). The page MUST be top-level: the manifest's `all_frames: false` happens to prevent
  framing today, and an implementation MUST write that down and set
  `frame-ancestors 'none'` rather than rely on it.
- **A desktop host.** First-party *only* when the host can prove the caller is a page it
  loaded from its own bundle, over a scheme no remote content can occupy, **checked at call
  time and not by a label**. "A webview is not the host" does not settle it, because in Tauri
  the app *is* a webview.

  The Mac app has answered this for itself (`~/igloo/marble-desktop-first-party.md`): **yes,
  after four changes it is making** — check the calling webview's URL is exactly its own
  bundled signer page rather than trusting the label; add navigation guards to the bundled
  webviews and set `frame-src`/`frame-ancestors 'none'` explicitly; add an ACL manifest so the
  derive command is reachable from the signer page alone instead of from every local page; and
  close an event side door by which another bundled page could speak to the signer directly.
  Its remote webview already cannot reach a custom command, cannot become local, and shares no
  storage or process with the signer.

  Two things from that answer belong here rather than there. **A label is not an identity**: a
  host MUST check the caller's URL at the moment of the call, because a label survives a
  navigation and the guarantee does not. And **the derived key stays in the host**: a page gets
  an encrypt or a decrypt, never `K` (§4.3), which for that app is a change to its vault and
  needs its own review before code.
- **NIP-46.** Never. A server cannot tell one app from another, and one signer key is shared
  by every site that connects by code (§6.1).

No user approval is asked for and none would help: the honest question is "is this really
Marble?", which a signature answers and a person cannot.

### 4.2 Accounts whose key was once whole

An earlier draft refused the derive call for these outright. That was wrong. Whoever holds the
account's key already reads everything it encrypts to itself and signs as it; the call gives
them nothing, and refusing it to the account removes only the protection from apps and sites
that the mechanism exists for.

What stands in their way instead is §4.4: **`s` alone is not enough.** The label needs the
account's namespace salt, which is a members-only secret. So:

- **an nsec that existed before the account was imported** — the commonest ever-whole case —
  cannot construct the label point, and therefore cannot derive any namespace, however long it
  is kept;
- **anyone who held the key whole *and* the salt** derives everything, for ever, offline, and
  no later refresh or re-split changes it. That is a member device that was taken out, or a
  take-out, or the escape hatch (§8.4) performed by a member.

> **A client MUST NOT claim protection against a holder of both the key and the salt**, and
> **MUST treat the existence of such a holder as unknown unless it knows otherwise.**

Knowing otherwise is rare and specific: the client watched the account created by distributed
key generation, no member has been removed since, no take-out or escape hatch has run, and no
paper has left the user's hands. Nothing records most of that. A durable "a whole copy may
exist" flag (progressive-accounts §4.3) answers the first part and nothing answers the rest,
so **the default is the unknown**, and what a client says to the namespace, and to the user if
it says anything at all, is that a namespace is closed to apps, sites and removed devices —
not that it is closed to whoever has held the key.

This is not pedantry. The one account this is being built for was imported from an existing
nsec, and whether a member device of it has ever been taken out is not written down anywhere.
A client that assumed the good case would be wrong about that account today.

At progressive-accounts' whole-key stages (§3.1, §3.2 there) the device holds both by
construction, so nothing here protects anything from that device: the derive call still works
and the claims are empty until the account is split.

### 4.3 What the caller gets

The caller gets what the operation needs — a decrypted pack, a signature — and **never `x` or
`K`**. A first-party caller that *is* the host holds them by construction; one that is a
separate process MUST be handed derived material for the operation it asked for.

### 4.4 The namespace salt is a members-only secret

`S` is 32 random bytes, generated once when the account is created, and it is **secret**:

> **`S` MUST NOT be published, MUST NOT be sent to a server, and MUST NOT be put in the epoch
> record** (which COSIGN.md §3 encrypts under the group secret — readable by anyone holding the
> key, which is precisely who must not have it). It is held by the account's **member devices**
> and nowhere else.

- **A new device gets it with its shares**, sealed to it on the path that already seals its
  sigmas (§7.1). A device that has shares but not `S` can sign and read messages; it simply
  cannot take part in a namespace until it has it.
- **A server never needs it.** A server computes `λ·s·P` for a point the device names; it
  never constructs the label. So it also never learns which namespace is being derived, which
  is the privacy §8 used to need blinding for.
- Without a salt at all, a rebuild-and-re-split restarts the epoch counter at 0 with the same
  key, so the new incarnation's epochs 0…k would have **byte-identical** app keys and addresses
  to the old one's. With it, whoever re-splits may deal a fresh `S` and leave every old
  namespace behind (§4.5).
- **The paper backup carries `S`** (the author's decision, 2026-10-27). So a paper restore
  brings a namespace's data back with the account, rather than leaving the account alive and
  the data unreadable for ever. It is written into the paper's code beside the backup key, and
  it means plainly: **a paper holder who also holds a copy of the whole key — an old nsec, say —
  derives every namespace for ever.** The paper is already worth 2 points and a stolen paper
  plus a whole-key copy was already the end of the account (COSIGN.md §12); what this adds is
  that it is also the end of the namespaces. Said here so that nobody has to work it out.

### 4.5 Abandoning a namespace

A deliberate break — after a compromise, or after an XSS on a first-party origin — is a **new
salt**, dealt like any other member-record change, with the namespace's data re-encrypted or
left behind as the namespace decides. It is the only way to make old app keys worthless, and
it is a user-visible, deliberate act. Nothing automatic does it.

## 5. `x` is never a key

> **`x(ns,e)` MUST NOT be used as a key, MUST NOT be returned to any caller, and MUST be put
> through HKDF-Extract with the salt of §3, which MUST differ from every NIP-44 salt.**

This is not tidiness. A granted site can already make a device compute `s·P(ns,e)` today, by
naming the label point's x-coordinate as the peer of `nip44.decrypt` or `nip04.decrypt` —
nothing checks the peer (`background.ts:149`). For NIP-44 the site gets a decryption under
`HKDF(x, "nip44-v2")` and learns nothing about `K`. **For NIP-04 the shared x is the AES-CBC
key verbatim** (`background.ts:165`, `group.ts:797`), so a granted site has an
encrypt-and-decrypt oracle under exactly `x(ns,e)`. The first draft was safe by luck.

So, in addition:

> **A device MUST refuse a `nip04_*` or `nip44_*` request from any grant whose peer is a label
> point of a namespace it knows.** The check is a handful of point comparisons against the
> namespaces in its build, over the epochs it has seen.

## 6. Checking what came back

> **Before anything is written under a fresh `K`, a device MUST confirm it derived the value
> others derive.**

`ecdhCombine` rejects only the identity point (`server/frost.ts:159`, verified): no partial is
verified, unlike signing, which has `verifyPartial` and a final check. One dishonest partner
returning `(λᵢsᵢ + δ)·P` makes the device derive a key **nobody** holds, encrypt a flush under
it and publish — unreadable by every device including itself, for ever, with no error anywhere.
Today the same bad partial costs one visible MAC failure; under this mechanism it costs the
data.

Either check is enough and neither needs new cryptography:

- **a known plaintext**: `HMAC(K, "kid")` against the newest pack the device can already read
  in that namespace and epoch; or
- **two disjoint partner sets**: derive twice, through different members, and require the same
  value. The first time a namespace is used in an epoch there is nothing to compare against, so
  this is the one that must work then.

## 7. Epoch boundaries, by checkpoint and not by clock

The first draft asked readers to reject an old epoch's record dated after that epoch ended. It
does not work: a removed device holds the old epoch's keys, computes every address, writes
*now* and **dates** the write just under the boundary. On a replaceable event the newest date
wins, so relays serve the forgery and every honest reader accepts it — signature valid,
cut-off passed. Every record last written in the previous epoch becomes the removed device's to
rewrite, and a deleted one its to resurrect. It also needed `epochAt`, which **devices do not
have**: it is server state only (`group.ts:1401`, `:1464`), never sent to a device, and absent
from the extension and the Android library (verified).

Instead:

> **On its first write in a new epoch, a device MUST publish an epoch-boundary checkpoint under
> `sk(ns,e)`: the previous epoch's number, and for each of that epoch's records its address, its
> hash and its own sequence number as of the boundary. A reader MUST accept a record of a
> retired epoch only if it matches that checkpoint, and MUST ignore `created_at` in the
> decision.**

- It closes the forgery: the removed device cannot alter a hash list signed under a key it
  cannot derive.
- It removes the dependence on a timestamp devices do not have, and on §7.7's gossiped commit
  moment having an agreed time at all.
- It tells a new device how far back to walk, which §11.3 otherwise leaves open.
- It makes the tag key's rotation unnecessary (§8), and it keeps **honest offline work**: a
  laptop that was away writes records of the old epoch, and they are judged by the checkpoint
  rather than thrown away for being late — which the clock rule did silently.

Marble already writes a checkpoint per flush, so this is a field or two, not a mechanism.

Two more rules, both about not deriving from an epoch that is not real yet:

- **Only a committed epoch.** A device MUST NOT derive for a pending epoch (§7.7's two-phase
  refresh): a pending epoch may be dropped, and records written under a key from an epoch that
  never happened are readable by nobody afterwards.
- **A failed round is not a new epoch.** When no member answers, a device MUST say so and stop,
  not fall back to another epoch's key and not drop the write. The round failing and the epoch
  moving look identical today (`group.ts:795`), and a server outage must not become silent
  write loss.

## 8. What the namespace gets, and what a server sees

From `K = K(ns,e)`, HKDF-Expand with SHA-256, asking for 48 bytes where a scalar is wanted and
reducing mod *n* (rejecting 0):

| | info | what it is |
|---|---|---|
| content key | `"content"` | 32 bytes, the NIP-44 v2 key for this epoch's records |
| tag key | `"tag"` | 32 bytes, for the addresses of this epoch |
| signing key | `"sign"` | a secp256k1 secret: each device derives the same one and signs locally |
| any other | the namespace's own | as it needs |

`pk(ns,e)` is how the records are found, so **nothing is published as a pointer** — every
device that can derive the key knows the address, and a relay sees an unfamiliar pubkey. A
namespace MAY keep one tag key across epochs now that §7 does the work the rotation was for;
rotating it costs each reader a walk back and buys only that a removed device cannot enumerate
addresses it already knows.

**A server sees the round, and with a secret salt (§4.4) it cannot tell what the point is for**
— it is one more peer it has never seen. That was the whole purpose of the blinding the first
draft recommended, so blinding is no longer needed. A device **MAY** still blind — pick random
`r` in `[2, n-2]`, ask about `r·P`, lift the x-only answer and multiply by `r⁻¹`; both lifts
give the same x-coordinate, so x-only suffices, and `r` MUST come from the system's randomness
and MUST NOT be fixed for tests — but it should know the cost: the account's ECDH caches are
keyed on the peer, so every blinded derive is a fresh round, and a peer that never recurs on a
regular cadence is itself a pattern. Blinding is worth it only if `S` may have leaked, which is
the case where §4.5 applies instead.

## 9. The server change this needs

The first draft claimed none. In fact every round is refused unless it names a live grant
(`group.ts:716`): `if (!liveGrant(msg.grant)) return respond({ ok: false, reason: 'revoked: …' })`.
So as written the app key would be reachable through a grant and would die with one — and if a
device borrowed its own grant, the namespace would appear in the user's list of connected apps,
where **Remove** would silently break it, and where 90 days unused expires it.

> **The smallest change: a server MUST accept a derive round from a device that names the
> **device's own member key** as its grant, without a site lookup, and MUST NOT create or show a
> grant for it.** Everything else about the round is unchanged, including that only a device may
> ask (§5.6 and the fix released in 0.12.6).

A server still cannot tell an app key from a message being read, which is why the first-party
rule has to live on the device.

## 10. Two devices, no server

Two devices reach the threshold between them (6 points of 4), so a namespace can be derived
with no server at all by the device-to-device round of §5.5 — the same path, the same rules,
and §6's two-disjoint-sets check is not available there with only two devices, so the
known-plaintext check is the one that must work.

## 11. What it does not protect against

1. **Anybody who held the key whole *and* the namespace salt** (§1, §4.2, §4.4). Every
   namespace, every epoch, for ever, offline, undetectable, and no refresh or re-split reaches
   them. The key alone is not enough — an nsec from before an import cannot construct the label
   — but a member device that was taken out had both. This is the ceiling on everything else
   here.
2. **A breached device in the current epoch.** It derives everything the namespace has and
   signs what it likes. Removing it rotates the epoch; it keeps what it already took.
3. **A removed device's past.** Every key it derived, it keeps: it reads those epochs' records
   for ever, wherever it kept them, and §7 stops it only from writing convincingly.
4. **A stolen device plus one cooperating member.** 3 points and 1 is the threshold, as it is
   for signing (COSIGN.md §12's accepted baseline).
5. **An XSS on a first-party origin.** It is first-party as far as the browser and this rule are
   concerned. The response is §4.5's new salt, and nothing automatic notices.
6. **Servers keeping history.** What a server kept, it keeps (§5.4). The records are not the
   account's events and never pass through a server, so a server sees only derive rounds — but
   the namespace also gets no backup from the servers, which a namespace used to storing things
   under the npub may not expect.
7. **Relays.** An unfamiliar pubkey's records, their number, size, timing and source address.
   A relay that correlates two identities by address and time will.
8. **Per-relay allow-lists.** A namespace that needs its `pk(ns,e)` allow-listed to get past
   spam filtering hands that relay's operator a dated map from each epoch's key to the account
   that asked — the link §8 otherwise does not publish.
9. **The platform's answer to "who is calling".** On a rooted phone, or with a replaced
   extension, that answer is worth what the device is worth, which is case 2.
10. **This access cannot be revoked.** Every other access in Cosign can be taken back from a
    device: a site's grant, an app's, a server's share. A first-party caller's is in the build.
    The user cannot withdraw it except by removing the device or abandoning the namespace
    (§4.5), and nothing in the interface will offer to.

## 12. What this would change in COSIGN.md

- **§5.6**: a second use for the decryption round, with §2's hash-to-curve requirement, §3's
  encoding, §5's "`x` is never a key" and the refusal of a grant-driven ECDH against a label
  point, §6's check on what came back, and §8's optional blinding.
- **§6.2**: an app key is not a grant, no grant reaches one, and §9's reserved
  own-device grant exists and is never shown as a connected app.
- **§6.3, §6.4**: §4.1's first-party rule per door, including that NIP-46 has no such call.
- **§7.3, §7.7**: that a refresh rotates every namespace's keys, that only a committed epoch is
  derived from, and that the boundary is a checkpoint and not a clock (§7).
- **§3**: the namespace salt in the epoch record (§4.4).
- **§12**: the properties of §11, especially 1 and 10.

## 13. Conflicts with the other two proposals

Both live on the branch `claude/progressive-accounts` and are not on `main`, which is why the
reviewer could not check these citations.

- **progressive-accounts.** At its §3.1 and §3.2 the key is whole on one device, so §4.2
  refuses the derive call outright there. The first draft said a namespace must not be told
  rotation protects it "until the account is split"; that was wrong, and the reviewer was right:
  splitting never restores it. Once a key has been whole anywhere, for that account, it is over.
- **user-verification.** No conflict. The derive call is not in the granting class and needs no
  assertion; if §11's open question about asking for the lock is ever answered yes, it becomes
  an `approve`-shaped action and belongs in that document's table.
- **The archive.** A namespace's records are not the account's events, so the destructive policy
  never judges them and nothing holds a mass overwrite for approval. That is the intent and
  also the trade: only the namespace's own checkpoints stand between a compromised first-party
  caller and all of it.

## 14. Still open, and who answers each

1. **Where the first-party list lives** — mine. Compiled in (as §4.1 says) means a release to
   add a caller and no attack surface; in the signed member record means faster and a new thing
   for a compromised device to write. I would keep it compiled in while there is one caller.
2. ~~Whether the Tauri host can be first-party~~ — **answered: yes**, after the four changes
   in §4.1, which that app is making. What remains open there is its own: where the derived key
   lives inside the app, which is a vault change and needs its own review.
3. ~~Whether the paper carries `S`~~ — **answered: it does** (§4.4), with the consequence
   stated there: a paper plus a whole-key copy opens every namespace for ever.
4. **Whether `S` can be added to an existing account without a refresh** — mine, and the answer
   is **yes**: `S` is not key material and nothing in the maths depends on it, so it is dealt to
   the current member devices and acknowledged, with no epoch change and no new shares. The one
   rule is that a namespace MUST NOT start until every member device has it, or devices derive
   into two disjoint invisible data sets (§3's failure, by another route).
5. **Whether to ask for the device's lock** on a derive, once a day rather than once a sync —
   open, and it belongs in the user-verification document if the answer is yes.
