# An app key of its own — proposal, fifth draft

**Status: proposal, for review. Nothing here is built.** Written as specification text so it
can be attacked. It is not part of [COSIGN.md](COSIGN.md) until it has been reviewed and the
author agrees; §12 lists what it would change there, §13 what it costs the other two
proposals in flight.

This draft answers **three** independent red teams. The first went at the whole proposal
(`~/igloo/cosign-app-keys-redteam.md`: *build it with changes — substantial ones*, two critical,
five high). The second went only at the secret salt that answered the first
(`~/igloo/cosign-app-keys-salt-redteam.md`: *a good idea this draft spends three times over*,
three critical). The third was asked to attack the two mechanisms the previous draft introduced to answer the
first two (`~/igloo/cosign-app-keys-pass3.md`: *build it with changes — but §6 and §7 are not
designs yet, and nothing that writes should be built until they are*, four critical, six high).
All three were right, and the claims of theirs that mattered most I checked against the code
before believing them.

**What the fourth review changed, and it is the whole of §7.** A fourth red team went at §7
alone (`~/igloo/cosign-checkpoint-redteam.md`: *§7 still is not a design that can be built*, five
critical) and found that a member device can **pre-derive every future epoch's key**, so "the
current epoch's key, the one no removed device has" — which §7 and §11 both rested on — did not
exist. I verified it in the code rather than taking it on trust. §7 is now its fifth design and
its first that is meant to be built: **an epoch seed** minted at the boundary, so an epoch's key
cannot exist before the epoch does, and a **backward key chain** so a device that joins later can
still read the history. The author chose that path; §7 writes it out, §7.5 says what it does not
fix, and it has not been reviewed yet.

**What the third review changed, in order of how badly I had it wrong:**

1. **§6's check could not be performed at the moment it required one, in any account shape
   Cosign produces** — and "neither check needs new cryptography" was the false claim holding
   it up. The deriving device is in *every* possible partner set, so the two sets are never
   disjoint; with one answering partner there is no check at all; and two partners under one
   operator — which COSIGN.md §3 permits by name — agree on the same wrong value. Worse, a
   partner that has also held the key whole can make the device derive **a key the attacker
   chose and knows**, not merely one nobody holds. §6 now requires a **proof per partial**.
2. **§7 was one paragraph doing the work of a protocol, and it failed in the ordinary case.**
   It named no writer, so two honest devices silently deleted each other's history; its chain
   was signed under keys a *removed* device still holds, so that device owned every epoch below
   the one it lost; and it might never be written at all, with the gap falling exactly in the
   window after a removal. §7 is now a protocol: one writer, union not replacement, the chain
   anchored at the top, an address with the epoch in it, and three stated reader cases.
3. **§5's refusal could not be implemented as scoped.** It was bounded to "epochs it has seen"
   while a salt-holder can build *future* epochs' label points; it was written about grants
   while the member-to-member round has no grant at all; and it needed repeating at five
   chokepoints. Replaced by one rule that collapses the class: **a device in a namespace
   refuses `nip04_*` from a grant outright.**
4. **§9's server change was wider than its purpose.** "Accept a round that names the device's
   own member key" is not "accept app-key rounds" — a server cannot tell them apart — it is
   *accept any ECDH for any peer, with no grant, no record and nothing removable*: the
   capability 0.12.6 removed. Replaced by a reserved internal grant, which keeps the
   revoked-app check load-bearing.
5. §3 defined `point_hash` twice, incompatibly, in the section whose whole purpose is that it
   cannot be (§3); §12 still told the implementer blinding was optional (§12); blinding's
   arithmetic had a parity trap that produces garbage with no error (§8); and the commit half
   of COSIGN.md §7.7, which §7 leaned on, **is not implemented in any client** (§7.3).

**What the second review changed, in order of how badly I had it wrong:**

1. **Blinding is mandatory, not optional.** I had removed it *because* of the salt. Backwards:
   the salt hides how to construct the label point; the round puts that point on the wire, where
   a key-holder who sees it once computes the app key at home. §8.
2. **The one place I told implementers to publish the salt is gone.** §12 still said to put it
   in the group record, which §4.4 forbids in the same breath — and my reason for forbidding it
   was wrong too. §4.4, §12.
3. **Nothing committed to the salt**, so the join path could be handed a chosen one by a relay.
   There is now a commitment in the member record, which also makes "every device has the same
   one" checkable. §4.4, §4.4.1.
4. The salt's own permanence is a standing weakness rather than a footnote — it never rotates,
   it is the most copied secret in the account, and a leak of it cannot be noticed (§11.2); the
   paper's four consequences are spelled out (§4.4); §4.5 admits it is a sketch; and the
   "dealt and acknowledged" of §14.4 needed an acknowledgement that does not exist yet.

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
  (`server/frost.ts:161`, verified), so one dishonest partner can make a device derive a key
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

What replaces it: **the namespace salt is a members-only secret.** `s` alone does not derive an
app key — the label needs `S` as well, and `S` is never published, never sent to a server and
never put in the group record. So the bytes of an nsec from before an import do not reach the
notes by themselves.

**What that is worth, said carefully** (a second review spent most of its length on this, and
it was right to): it raises the cost and narrows who can, and it is not a guarantee. `S` never
rotates while being the most widely copied secret in the account — every device, every paper —
a leak of it is undetectable by construction, and the machine that generated it was holding the
whole key at the time, which is usually the machine an nsec leaks from. So §4.2's rule stands
unchanged: a client says a namespace is closed to apps, sites and removed devices, and does not
say it is closed to whoever has held the key.

---

## 1. What an app key is, and what it is not

An **app key** is a secret derived from the account's key by a **threshold round**, belonging
to a **namespace** (`marble/notes/v1`) and a **committed epoch**, reachable only through a
**first-party call on a device**.

**What it gives you:** an app's data is closed to every site and app the user has merely
connected, including those with full message access, and closed to a device that has been removed
from the account. The second half of that claim was **false in the third and fourth drafts** and
is true only because of §7.1: the epoch used to live in a public label, so a member device could
run one ordinary round per epoch and keep the whole future, and being removed later took away
nothing. An epoch's key now depends on a seed minted at the boundary, so it does not exist before
the epoch does. What a removed device keeps is what it already read, which is §11.4. The namespace's own signing key signs its records on the device, in
a millisecond, with no FROST round and no link to the user's npub.

**What it does not give you, stated here because the first draft implied otherwise:** it is
**not forward secrecy**. The account's key is permanent (COSIGN.md §3; a refresh moves shares
and keeps the key), and the label is public, so `x(ns,e)` is a fixed function of a permanent
secret. Anybody who holds the key whole — by importing an nsec, by taking the account out
(COSIGN.md §7.6), by the escape hatch (COSIGN.md §8.4), by rebuilding to re-split (COSIGN.md §3) — can compute every
namespace's every epoch, for ever, offline, and nothing in the account will ever show it. A
refresh does not help, and neither does re-splitting: §4 is the only answer, and it is a
refusal rather than a repair.

It is not a share of the account's key, carries no points, and signing with it is not signing
as the user.

## 2. The label point

For a namespace `ns`, an epoch `e` and the account's **namespace salt** `S` (§4.4), the label
point `P(ns,e)` is §3's `msg` mapped onto secp256k1 by try-and-increment, keyed by `S`.

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
msg        = "cosign-app-key:v1" ‖ 0x00 ‖ ns ‖ 0x00 ‖ epoch_be4 ‖ 0x00 ‖ E_e ‖ i_u8
             ns        the namespace's name, ASCII, no trailing 0x00 of its own
             epoch_be4 the committed epoch as a 4-byte big-endian unsigned integer
             E_e       the epoch's seed: the group record's `epoch.id`, 16 bytes (§7.1).
                       Without it every epoch's key is a function of values a member device
                       already has, so it derives the whole future in advance; with it an
                       epoch's key does not exist before the epoch does.
             i_u8      a single byte, 0, 1, 2, …
point_hash = HMAC-SHA-256(key = S, message = msg)
             S         32 bytes, the account's namespace salt (§4.4), used as the HMAC key
                       and never as part of the message
P(ns,e)    = the first i whose 0x02 ‖ point_hash is a point on secp256k1
x(ns,e)    = the x-coordinate of s · P(ns,e), 32 bytes
K(ns,e)    = HKDF-Extract(hash = SHA-256, ikm = x(ns,e), salt = "cosign-app-key:v1")
```

- **That is the only definition.** The third draft gave two — a plain `SHA-256` over a `label`
  that contained `S`, and a bullet four lines later saying to use HMAC with `S` as the key
  instead — neither marked normative and the HMAC form's message never written out. Two
  implementations reading that draft could have derived different keys, which is the exact
  failure this section exists to prevent. The word `label` is gone with it: what §5 and the rest
  call the **label point** is `P(ns,e)`, and what MUST NOT be logged is `msg`, `point_hash` and
  `S`.
- The epoch is a **number**, never its decimal spelling: `"7"` and `"07"` would be two keys
  and two data sets. 4 bytes big-endian, and that is the whole of it.
- **HKDF-Extract's arguments are in that order and the order matters.** @noble's
  `extract(hash, ikm, salt)` takes the salt third (`~/marble/extension/src/background.ts:151`)
  while RFC 5869 writes it second; an implementation that passes `x` as the salt and the string
  as the ikm derives a different `K` and nothing fails. The `K` vector below is what catches it,
  which is the reason to keep that vector.
- **An implementation MUST fail the derive at `i = 255`** — surface a named error, never fall
  back to another `i`, another epoch or an unsalted hash. The probability is about `2⁻²⁵⁵`; the
  point is that no implementation invents a different answer.
- A conforming implementation MUST ship **test vectors**: for a **published test salt** and a
  published test seed per epoch (never real ones), a fixed `ns` and epochs 0, 1, 7 and 255 — the
  chosen `i`, `P`'s x-coordinate,
  `K`'s first 8 bytes, and `pk(ns,e)`. Two platforms that disagree on any of them are not
  interoperable and the failure is silent. There is a precedent to copy rather than invent:
  `server/test/policy-vectors.ts` writes
  `android/cosign/src/test/resources/policy.json`, which `PolicyVectorsTest.kt` reads from the
  classpath, and `FrostVectorsTest.kt:56 ecdhPartialsMatchTheServer` already does the same for
  `frost.json`.
- `S` MUST come from a cryptographic random source, and **`S`, `msg` and `point_hash` MUST NOT
  be logged**: a key-holder who has seen one label point on the wire has an offline oracle for
  guessing a weak salt. This codebase has the habit to guard against —
  `android/.../Phone.kt:1484` logs an entire join code in debuggable builds, with a comment
  explaining why — so the rule is written here to keep a debug path from growing that prints a
  salt.

## 4. Who may ask, and which accounts may be asked

### 4.1 The first-party rule

> **A device MUST answer a derive call only for a caller it has identified itself, by a
> platform mechanism, against a list compiled into that device's own build.** Never for a
> site or app holding a grant, and the call MUST NOT exist over NIP-46.

- **Android, and only through the ContentProvider.** `Nip55Provider.query` runs inside a binder
  transaction, so `Binder.getCallingUid()` is the caller's; the device MUST resolve it with
  `getPackagesForUid` and check the digest with
  `PackageManager.hasSigningCertificate(pkg, digest, CERT_INPUT_SHA256)`, which honours Play App
  Signing rotation history. That is about three lines. Today the file uses `callingPackage` alone
  (`Nip55Provider.kt:25`), and **a build without a certificate check MUST NOT answer a derive
  call at all**.
  - **The derive call MUST be absent from the `nostrsigner:` Activity path**, in those words.
    `Nip55Request` is an Activity: there is no binder transaction, so `Binder.getCallingUid()`
    returns the signer's own uid, and all it has is
    `activity.callingActivity?.packageName ?: activity.callingPackage` (`Nip55Request.kt:70`) —
    both forwardable with `FLAG_ACTIVITY_FORWARD_RESULT` and both null when the caller used
    `startActivity`. The rule cannot be satisfied there by any means, so the answer is not a list
    of fixes but the absence of the call. (The other two faults on that path are still worth
    fixing for their own sake: a caller-supplied `callbackUrl` origin MUST NOT share an identity
    namespace with package names, `Nip55Request.kt:67`, and `http://localhost` MUST NOT be
    first-party for anything, `:148`.)
  - **The derive call needs its own account selector, its own gate, and failure modes the caller
    can tell apart.** The provider today picks the account by package and gates everything by the
    grant — `accounts.forApp(pkg)` and `val grant = phone.appGrant(pkg) ?: return null` (`:26`,
    `:28`), with `grant.dm` gating the crypt methods (`:37`) — so a derive with no grant (§9) is
    refused by the existing door before it starts and has no way to say which account it means.
    It should use the `current` pubkey the caller already passes (`:22`, `:29`). And the
    provider's only way to refuse is `return null` (`:25`, `:28`, `:37`, and the blanket `catch`
    at `:43-45`), which by NIP-55 convention means *open the signer's Activity* — so a derive
    that failed because the servers were unreachable would send Marble to a door that must refuse
    it, and the user would get a signer screen that does nothing.
  - **Say what the user sees when a digest rotates.** Pinning breaks on re-signing: the list holds
    the signing-certificate digests the publisher controls, rotating one is a release of the
    device software, and in between the user's notes are unreadable on that phone. A client MUST
    name the app it did not recognise rather than show an empty namespace.
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
  by every site that connects by code (COSIGN.md §6.1).

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
  take-out, or the escape hatch (COSIGN.md §8.4) performed by a member.

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

> **`S` MUST NOT appear in any event the account signs, MUST NOT be sent to a server, and
> MUST NOT be put in the group record.** It is held by the account's **member devices** and
> nowhere else.

The group record is the wrong place for two reasons, and not the one an earlier draft gave. Its
content is encrypted under a random group secret that **every member holds**, removed ones
included until the next refresh (NIP-XX.md, kind 30242) — so it is not readable by a bare
key-holder, and it *is* readable by exactly the members `S` is meant to outlive. And it is a
published replaceable event: putting `S` there once could never be taken back.

> **An account that exists already gets `S` without a refresh, and a namespace MUST stay off
> until every member device has acknowledged it** (§14.4, decided). `S` is not key material and
> nothing in the maths depends on it, so it is dealt to the current member devices with no epoch
> change and no new shares — but a device that has not got it cannot read or write the namespace,
> and two devices with different salts write into disjoint invisible data sets, which is §3's
> failure reached by another road. So the gate is the acknowledgement, not the dealing, and a
> client MUST be able to say which device is still waiting. An account whose devices are rarely
> all online at once is the ordinary case, not the hard one, so "waiting for your other device"
> is a state the app has to wear without looking broken.

> **The account's member record MUST carry a commitment to `S`:
> `SHA-256("cosign-salt-commit:v1" ‖ S)`.** A hash reveals nothing and pays three times over:
> a device that is handed a salt checks it against the commitment, so nothing can inject one
> (§4.4.1); two devices that disagree find out instead of writing into disjoint data sets; and
> §14.4's "every device has it" becomes a thing a client can check rather than hope.

> **`S` MUST be stored at the root of a device's own state, never inside the group or
> membership record it keeps.** `group.members` is server-authored: it arrives in the `members`
> message (`toDevices({ type: 'members', members: publicMembers(), epoch })`, `group.ts:1152`,
> `:1170`, `:1207`, `:1338`, `:1359`, `:1473`) and Android replaces it outright
> (`Phone.kt:1460-1461`), so a salt kept there would be a salt a server could overwrite. The
> extension merges that list instead and deliberately keeps the share points it already knows
> (`device.ts:220-225`), which is why the rule is written about where the salt lives rather than
> about how any one platform merges.

### 4.4.1 Getting it to a new device

> **A secret MUST be dealt only to a member the dealing device has first-hand evidence of, and
> never to one it knows only from a server's list.** A device takes its member list wholesale
> from whatever a server sends: `onMembers` guards only that the list contains this phone and
> that the epoch is not older (`Phone.kt:1455-1462`), and the extension, which is better, keeps
> the share points it already knows but still takes the **member set** from the list
> (`device.ts:213-226`). So "deal `S` to every member device" means "deal `S` to whoever a
> server wrote in", and live finding #1 — only partly fixed in 0.12.6 — is exactly a server
> writing one in. First-hand evidence means the device took part in that member's repair, or has
> verified a signature or a proven partial from that member's indices, which an injected member
> can never produce.



The channel exists: the vouching device seals its sigmas to the newcomer over NIP-44
(`Phone.kt:1451`, and the extension's member code), and `S` travels with them. But **nothing on
that path authenticates the sender**: `onJoinPiece` records who sent a sigma and never checks
it (`Phone.kt:1514`), and the extension does not keep the sender at all. The sigmas survive
that because each one is checked against the group's commitments and the server re-checks the
resulting share points (`group.ts:1143`); **`S` has nothing to check against**, so a relay that
sees the newcomer's key in its own subscription filter could hand it a salt of its choosing —
and an attacker who also held the old whole key would then have *chosen* the salt, which ends
the guarantee without ever learning the real one.

The commitment above is what closes that, and it is the reason it is a MUST rather than a nice
idea: a newcomer takes a salt only when it hashes to the commitment in the record it was
given.

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
  brings a namespace's data back with the account, rather than leaving the account alive and the
  data unreadable for ever. It goes in the paper's code beside the backup key — 64 more hex
  characters, which that QR takes without trouble, and no server ever sees it, because the
  paper's code is made on the device and only its public key is sent (verified). Four things
  follow, and all four should be said out loud rather than discovered:
  - **A paper holder who also holds a copy of the whole key derives every namespace for ever.**
    A stolen paper plus a whole-key copy was already the end of the account (COSIGN.md §12);
    this makes it the end of the namespaces too.
  - **Paper plus two servers reaches the namespaces with no wait in the way.** Recovering the
    *account* that way is guarded by §7.4's wait; reading `S` off a QR is not a protocol step
    and nothing delays it.
  - **Every paper printed before this exists has no salt**, so restoring from one brings the
    account back and leaves the namespace silent. A client MUST say that plainly rather than
    show an empty namespace.
  - **A new salt (§4.5) silently invalidates every paper in existence** for the namespace, and
    §8.1's planned 24-word form becomes about 48 words with a second secret in it.

### 4.5 Abandoning a namespace

A deliberate break — after a compromise, or after an XSS on a first-party origin — is a **new
salt** with a new commitment, dealt to every member device. It is the only way to make old app
keys worthless, and it is a user-visible, deliberate act that nothing automatic does.

**This is a sketch, not a mechanism, and the spec should not pretend otherwise.** What it does
not yet say: who re-encrypts the existing data and reads it meanwhile; that old data stays
readable under the old salt for ever, so a re-salt protects what comes next and nothing else;
that it invalidates every paper (§4.4); and that it severs §7's chain, because an epoch's
boundary checkpoint is signed under a key derived through the salt, so **after a re-salt every
retired epoch becomes unverifiable** and its records can only be taken on trust or abandoned.
A namespace that wants re-salting to be usable has to design that, and until it does, §4.5 is
the lever you pull when the alternative is worse.

## 5. `x` is never a key, and NIP-04 is closed to grants

> **`x(ns,e)` MUST NOT be used as a key, MUST NOT be returned to any caller, and MUST be put
> through HKDF-Extract with the salt of §3, which MUST differ from every NIP-44 salt.**

This is not tidiness. A granted site can already make a device compute `s·P(ns,e)` today, by
naming the label point's x-coordinate as the peer of `nip44.decrypt` or `nip04.decrypt` —
nothing checks the peer (`background.ts:149`). For NIP-44 the caller gets a decryption under
`HKDF(x, "nip44-v2")` and learns nothing about `K`. **For NIP-04 the shared `x` is the AES-CBC
key verbatim** (`background.ts:154` → `:168`, `importKey('raw', x, { name: 'AES-CBC' })`;
`Phone.kt:1819`, `SecretKeySpec(sharedX(g, peer), "AES")`), so a granted site has an
encrypt-and-decrypt oracle under exactly `x(ns,e)`. The first draft was safe by luck.

The third draft answered this by having a device compare the requested peer against the label
points of the namespaces in its build. **That rule cannot be implemented as it was scoped**, in
three separate ways:

- **It was bounded to the epochs the device has seen.** A holder of `S` constructs `P(ns,e′)`
  for *every* `e′`, including epochs that do not exist yet, so a request naming epoch `e+5`'s
  label point passed the check and handed back an oracle under a key the account has not reached
  — one nothing later revokes.
- **Grants are not the only door.** The member-to-member round has no grant at all:
  `Phone.kt:2043 onEcdhReq` checks the sender's role (`:2046`) and the participant set (`:2059`)
  and never looks at `msg["grant"]`. One compromised member device asks the user's other device
  for its points for any peer it names.
- **There are five chokepoints, not one.** Extension: `background.ts:151-154` (the member-device
  path through `d.ecdh`), `:283-286` (the *pending* whole-key stage — `nip04lib.decrypt` with the
  raw account key and no round at all), `:454-457` (phase-1 pairing, forwarded to the phone).
  Android: `Nip55Provider.kt:39` and `Nip55Request.kt:136`, both into `Phone.nip04`/`nip44`
  (`:1813`, `:1818`).

So the rule is replaced by one that collapses the whole class. The problem exists *only* because
NIP-04 uses the shared `x` verbatim:

> **A device that holds the salt for any namespace MUST refuse every `nip04_*` request that
> arrives with a grant, and every `nip04_*` request from another member, outright.** Not by
> comparing points: by method. There is no epoch bound, no per-namespace list and nothing to keep
> in step with the build.

NIP-44 needs no point check at all, because `HKDF(x, "nip44-v2")` tells the caller nothing about
`K` and §3's extract salt differs from it by requirement rather than by luck. Keeping a point
comparison for `nip44_*` buys nothing; an implementation MAY keep one as belt and braces and
MUST NOT rely on it.

What that costs: a site or app with message access loses NIP-04 messages on an account that uses
a namespace. NIP-04 is deprecated, Cosign's own NIP-46 sites are already refused all four crypt
methods (`group.ts:409-410`, *"unsupported: Use your sign-in app for messages"*), and the two
functions §5 used to cite on the server — `groupNip04` and `groupNip44Key` (`group.ts:796-797`)
— **have no callers**. The server has no NIP-04 door; this rule belongs on the devices only.

A device that has no salt yet cannot be in a namespace (§4.4), and answers grants exactly as it
does today.

## 6. Checking what came back

> **Before anything is written under a fresh `K`, a device MUST verify every partial it received,
> by proof, and MUST NOT write if any proof fails or any two derivations disagree.**

`ecdhCombine` rejects only the identity point (`server/frost.ts:161`): no partial is verified,
unlike signing, which has `verifyPartial` (`frost.ts:127`) and a final check.

**What goes wrong, and it is not only an attack.** The trigger is *any* inconsistency between
participants: a stale share, a corrupted at-rest copy, two participants left on different
polynomials by a half-finished refresh, one platform's `ecdhPartial` disagreeing with another's.
Today each of those costs one visible NIP-44 MAC failure; under this mechanism it costs the write,
silently and for ever. So the check cannot be treated as an edge case.

**And the attack is worse than the third draft said.** It claimed one dishonest partner makes the
device derive a key *nobody* holds. A partner that has also held the account key whole — which
§4.2 requires be assumed — does better. It knows the device's own contribution exactly,
`D = s·Q − λ_srv·s_srv·Q`, both terms computable from `s` and its own share, so it returns
`X = T − D` for any point `T` it likes and the device derives `K = HKDF(x(T))`: **a key the
attacker chose and knows** — the content key, the tag key and `sk(ns,e)`, with which it reads the
epoch, writes it, and signs its boundary checkpoint (§7). In an unblinded round `T` is freely
chosen; under §8's mandatory blinding `r⁻¹` is unknown to the attacker and this degrades to
unpredictable corruption. **That is the strongest reason blinding is a MUST**, and §8 should be
read with it.

### 6.1 Why the previous draft's two checks are not enough

The third draft offered a known-plaintext check and a "two disjoint partner sets" check, and said
"either check is enough and neither needs new cryptography". The last clause was false, and it was
load-bearing.

- **The known-plaintext check does not exist at first use.** `HMAC(K,"kid")` against the newest
  pack the device can already read *in that namespace and epoch* — at the first write of an epoch
  there is none, and at namespace genesis there is none at all, ever.
- **Two disjoint partner sets are impossible, not merely hard.** COSIGN.md §3 fixes `t = 4` with a
  device holding 3 shares and a server 1, and `onEcdhReq` forces the participant list to be
  exactly the requester's shares plus the answering server's (`group.ts:713`) and at least the
  threshold (`:714`). The deriving device is therefore in **every** possible set and supplies 3 of
  the 4 points to both derives. So: the sets are never disjoint, and a wrong contribution from the
  device itself is common to both derives and invisible; with one answering partner there is only
  one set and no check at all — the ordinary case whenever two of three servers are unreachable,
  and permanent for a server stranded by a refresh (§7.2); and where two partners do answer,
  agreement is not evidence, because two colluding partners return `(λᵢsᵢ + δ)·Q` for the same `δ`
  and both sets give `(s+δ)·P`. One operator running two of the group's servers does that alone,
  and COSIGN.md §3 permits it by name.
- **The two drafts' rules contradicted each other.** §6 said the two-set check "is the one that
  must work" at first use in an epoch; §10 said that with two devices it is unavailable, so the
  known-plaintext check is the one that must work. In a two-device account at the first write of a
  namespace in an epoch neither existed, so the MUST forbade the write.

### 6.2 The check: a proof per partial

> **A responder MUST accompany each partial with a Chaum–Pedersen DLEQ proof that the scalar
> behind its partial is the same as the scalar behind its published share point: that
> `log_G(λᵢsᵢ·G) = log_Q(λᵢsᵢ·Q)` for the point `Q` the round is about. A deriving device MUST
> verify every proof before combining, and MUST NOT combine if one fails.**

The verifier already holds everything it needs: `λᵢ` from `lagrange()` (`frost.ts:68`) and the
public share point from the member list (`sharePub` in `publicMembers()`, `group.ts:1180`;
`Sig.sharePubAt` server-side). It costs one extra scalar multiplication and one hash per partial,
and it closes by copying what signing already does the asymmetry the previous draft complained
about. It is independent of the salt, of §7 and of the first-party rule, and it is a strict
improvement to today's NIP-44 reads on its own: a bad partial becomes a named error instead of a
MAC failure.

**The known-plaintext check stays** as the cheap steady-state check — `HMAC(K,"kid")` against a
pack the device can already read — because it catches a device's own stale state, which no
proof about a partner's scalar does. **The two-set check is demoted to a hint**: a device MAY
derive through a second set when one exists, and MUST NOT treat agreement as evidence.

Two things recorded here so they are not rediscovered:

- **A stopgap blinding makes possible, if the proof is not yet built:** interleave, in random
  order within one session, a derive the device *can* check (any past epoch whose packs it can
  read — it can derive every epoch) with the one it cannot. Blinded points are
  indistinguishable, so a partner cannot corrupt selectively, and `k` probes cut the
  slip-through to `p(1−p)^k`. It is statistical, and it does nothing at namespace genesis.
- **A trap:** "derive twice through the same partner with two different `r` and compare" looks
  sound and is not. Against an additive error in `G` it works; against `(λᵢsᵢ + δ)·Q` — the
  attack §6 names — both derives unblind to `(s+δ)·P` and agree.

### 6.3 When it fails

> **On a failed proof or a disagreement a device MUST NOT write, MUST NOT cache or use either
> value, MUST NOT treat it as an epoch change (§7), MUST keep the pending writes queued, and
> MUST surface a distinct named state.**

Every answer an implementer reaches for instead is exploitable: retrying the other partner
(the attacker corrupts both), taking the value two of three agree on (one operator running two
servers chooses it), proceeding after N attempts (silent data loss), retrying for ever (one
faulty or malicious partner wedges the namespace indefinitely, indistinguishable from an outage,
and with Marble's three-minute flush the notes sit on one device until that device is lost — a
free, unattributable denial of service).

A DLEQ failure names the culprit and a disagreement does not: with proofs in place a device can
exclude the partner whose proof failed and say which one it was. Without them it can say nothing
useful, which is the other reason §6.2 is not optional.

## 7. Epoch boundaries: the epoch seed and the backward key chain

**Status: the fifth design of this section, and the first that is meant to be built.** It is not
reviewed yet. Four reviews got us here and the history is worth two paragraphs, because each
mechanism failed for a reason the next one has to keep answering.

The first draft asked readers to reject a retired epoch's record dated after that epoch ended. A
removed device holds the old epoch's keys, computes every address, writes *now* and **dates** the
write under the boundary; on a replaceable event the newest date wins. It also needed `epochAt`,
which is server state only (`group.ts:1401`, `:1464`) and never reaches a device.

The second was a **boundary checkpoint**: a hash list of the retired epoch's records, signed
under the new epoch's key. Three reviews took it apart. It named no writer, so two honest devices
silently deleted each other's history; its chain was signed under keys a *removed* device holds,
so that device owned every epoch below the one it lost; it might never be written at all, with
the gap falling exactly in the window after a removal; and it rejected honest late work the same
way the clock rule did. Patching those produced union-over-checkpoints and a top-anchored chain,
which pulled against each other — and then the fourth review found the thing underneath all of
it:

> **A member device can pre-derive every future epoch's key.** The epoch lives only in the
> *public* label, the account's secret is permanent, `onEcdhReq` puts no constraint of any kind
> on `msg.peerX` (`group.ts:701-717`) and `ecdhPartial` has no epoch input (`frost.ts:152-156`).
> So any member device, while it is still a member, runs one ordinary round per epoch and keeps
> `K(ns,e)`, `K(ns,e+1)`, `K(ns,e+2)` — several hundred epochs in a night, more than the account
> will reach. Being reported lost takes away nothing it already took, so "the current epoch's
> key, the one no removed device has" did not exist.

So this version does not try to patch the checkpoint. It changes what an epoch's key *is*.

### 7.1 The epoch seed: a key an epoch cannot be derived before it exists

> **The label of epoch `e` MUST include the epoch's own seed `E_e`, a value that comes into
> existence at the boundary and is not predictable before it.** §3's message becomes
>
> ```
> msg = "cosign-app-key:v1" ‖ 0x00 ‖ ns ‖ 0x00 ‖ epoch_be4 ‖ 0x00 ‖ E_e ‖ i_u8
> ```
>
> with the HMAC key still `S` (§4.4). **`E_e` is the group record's `epoch.id`** — 16 random
> bytes minted at each refresh and carried in the record's encrypted content, which every member
> reads and nothing else does (NIP-XX.md, kind 30242). A device that is not a member of epoch `e`
> never receives it.

That is the whole of the fix for pre-derivation: a device cannot construct `P(ns,e)` before epoch
`e` exists, so there is no round it can run in advance. It does not need the seed to be secret —
unpredictability before the boundary is what the attack needs taken away — but the seed happens
to be secret too, which is defence in depth for the one adversary §4.2 is about: somebody holding
the key whole *and* the salt still cannot reach an epoch they were never a member of.

**One thing I want the reviewer to attack, because I could not settle it.** The seed is
**server-authored**: a server mints it at the refresh. So a server that is willing to help a
device which is about to be removed can hand it the next few seeds in advance, and
pre-derivation comes back. That collusion is one device plus one server, which §11.5 already
accepts as the threshold for everything else — but it is accepted there for *signing*, and
accepting it here extends it to the namespace's whole future. The candidate hardening is to
derive the seed from the refresh instead of letting any one party choose it, for example
`E_e = H("cosign-epoch-seed:v1" ‖ epoch_be4 ‖ each dealer's commitment)`, so no single dealer
can fix it and a device that is not a dealer cannot predict it. That is a change to the refresh
and to the group record, and it is not in this draft.

**What the seed costs** is the thing §7.2 exists to pay: a device that joins at epoch `c` has
`E_c` and nothing older, so it cannot derive any epoch below `c`, and the seeds of retired
epochs are nowhere — the group record is replaceable and holds only the current one.

### 7.2 The backward key chain

> **At each boundary, the first member device to see the epoch move MUST write a wrap: the
> previous epoch's key, sealed under the new epoch's key.**
>
> ```
> wrap_e   = AEAD(key = HKDF-Expand(K(ns,e), "wrap"), plaintext = K(ns,e−1))
> address  = d = HMAC(K_tag, "wrap:" ‖ epoch_be4)          (epoch e, the wrapping epoch)
> ```
>
> A device that can derive the current epoch unwraps `e−1`, then `e−2`, and so on to the
> namespace's first epoch. **A reader MUST treat a wrap that does not decrypt and authenticate
> as absent**, and MUST NOT accept any other route to an old key.

This is what makes the seed affordable, and it is strictly better than the chain of hash lists it
replaces:

- **It is unforgeable by anyone outside the current epoch.** The wrap is an AEAD under
  `K(ns,e)`. A removed device cannot produce one a reader will accept, and does not need to be
  stopped by a rule — it is stopped by not having the key. The old chain was a *signature* chain
  whose keys a removed device held, which is how it owned every epoch below the one it lost.
- **It only ever goes backward.** A device that holds `K(ns,e)` learns `K(ns,e−1)`; nothing in the
  chain ever yields `K(ns,e+1)`. So the chain gives a removed device nothing it did not already
  have, and gives a newcomer exactly the history the account means it to have.
- **Union is safe and needs no rule.** Several devices may write a wrap at the same boundary;
  every honest one has the same plaintext, and a reader takes the first that authenticates. There
  is no "newest wins", no tiebreak, and no race that loses data — which is what sank the
  checkpoint's union.
- **It is cheap.** One small event per boundary, and unwrapping 300 epochs is 300 symmetric
  operations.

**Its own failure mode, stated plainly: one missing wrap severs everything below it.** That is
why the writer is "the first member device to see the epoch move" rather than "the device that
asked for the refresh", why every member device writes one if it finds none, and why the rule
belongs to the epoch change rather than to the next write (§7.6). It is bounded, and the bound is
worth saying: **devices that already hold the old keys keep them locally**, so a severed chain
costs a *newcomer* the history below the break and costs nobody else anything. §4.5's severed
chain is the same loss, deliberately.

### 7.3 What stops a removed device rewriting a retired epoch

The seed and the chain fix pre-derivation and the walk-back. They do **not** by themselves answer
the question §7 was created for: a device removed at the `e−1 → e` boundary still holds
`K(ns,e−1)`, so it can still write records of epoch `e−1` that every reader accepts, because
records of `e−1` are judged by `e−1`'s key.

> **So a retired epoch's records are acceptable only as the current epoch says they are. At each
> boundary, alongside the wrap, the writing device MUST seal a manifest: for each record of epoch
> `e−1` that it holds, the record's address and the hash of its encrypted body.**
>
> ```
> manifest = AEAD(key = HKDF-Expand(K(ns,e), "manifest"), plaintext = the list)
> address  = d = HMAC(K_tag, "manifest:" ‖ epoch_be4)
> ```
>
> A reader takes the **union** of every manifest at that address that authenticates under
> `K(ns,e)`, and accepts a record of `e−1` if any of them names it with a matching hash.

This is the old boundary checkpoint, with the one change that matters: **it is sealed under the
new epoch's key rather than signed by it.** Three of the fourth review's criticals go with that
change, and they go for the same reason — forging or adding to a manifest now requires
`K(ns,e)`, which means being a member of the current epoch:

- The old chain's top was unauthenticated because anything that could *sign* could mint a link,
  and a removed device could sign. Now minting requires the current key. A compromised **current**
  device can still mint — and that is §11.3, which this document has always accepted. The trust
  boundary is where it was, instead of one epoch below it.
- The union's "weakest member" problem bounded the mechanism by the weakest *anything*; it is now
  bounded by the weakest current member, which is the same bound as reading and writing the
  namespace at all.
- "Two honest devices delete each other's history" was a race between replacements. Union plus
  **add-only** manifests means a device can only ever add, and honest views merge.

> **Three reader cases, and only the first is an acceptance:** address named with a matching hash
> — accept as a record of `e−1`; address named with a different hash, or not named at all — hold
> it as unadopted and **never** promote it on a relay copy alone. **A record of a retired epoch
> MUST be promoted into the current epoch only from a device's own local provenance** — it held
> that record before the boundary — and never because it appeared on a relay.

That last clause is the fourth review's third critical, which has no other answer: an honest late
write and a removed device's forgery are the same object to a reader, so "re-sign whichever turns
up" notarises the forgery. Local provenance is the only thing that distinguishes them, and it
needs a per-record "held before the boundary" marker the namespace does not have today (§7.6).

### 7.4 What a newcomer does, and what `unverified` means now

The replacement for a lost phone is the path this section exists for, and the previous draft
ended it in either that bypass or total silent loss. With the chain it is ordinary:

- It joins at epoch `e`, derives `K(ns,e)`, unwraps the chain, and **reads everything it can
  decrypt**. Decryption is the proof that the data is the account's, so there is no need to
  withhold it.
- It adopts a record of a retired epoch as *history* when a manifest names it, and shows the rest
  as **unadopted** rather than refusing to show it.
- **`unadopted` MUST mean "ask once, per epoch", not "refuse".** A retired epoch with no manifest
  — because the only device that saw it is the lost one — gives a user a choice they can
  understand ("notes from before you lost your phone: keep them?"), which is the same shape as
  the namespace's own halt on a mass change. Refusing was the previous draft's answer and it
  loses the user's notes while the keys to read them sit on the device.

### 7.5 What this fixes, what it does not, and what it changes elsewhere

**Fixed:** pre-derivation (§7.1); the walk-back and the newcomer (§7.2, §7.4); a removed device
owning every epoch below the one it lost, and the unauthenticated top of the chain (§7.3); the
union race (§7.3); the promotion bypass (§7.3's last clause, given §7.6's marker).

**Not fixed, and not fixable here:**

- **A breached current device.** It derives everything, writes what it likes, and mints
  manifests. §11.3. This design moves the boundary back to "current member" and no further.
- **Removal is unconditional while the epoch move is not.** `target.removed = now()`
  (`group.ts:1334`) always happens; `startRefresh` (`:1341`) needs a plan, accepts only
  `S.epoch + 1`, and completes only on every dealer's part — and the extension has no
  `remove_member` at all. Until the epoch moves, a removed device is still a member of the
  *current* epoch as far as the namespace is concerned, and nothing here judges it. **A client
  MUST treat a removal as unfinished until the epoch has moved, and say so** ("finishing on your
  other devices"). That is a requirement on Cosign, not on the namespace, and it is new.
- **Everything in §11.** The salt, the whole-key holder, the first-party caller, the relay.

**Changes elsewhere:** §3's message gains `E_e` (so its bytes and vectors change, which is why
step 2 of the build plan waited for this); §8's tag key may still be one key across epochs, but
every per-epoch address — wrap, manifest — carries the epoch, as §8 already requires; and the
namespace's own mass-change halt must cover records made unadopted by a manifest, not only packs
that fail to decrypt during a pull.

### 7.6 What it depends on that does not exist yet

Three things, and none of them is a detail:

- **The member library does not tell the app the epoch moved.** The epoch is written only by
  `refreshed()` (`device.ts:305`, `Phone.kt:610`), with no callback and no listener. Every rule in
  §7.1–§7.3 is anchored to the boundary, so this comes first in code, on both platforms.
- **The namespace has no per-record provenance marker**, so §7.3's promotion rule cannot be
  implemented yet. A record needs to carry, locally and not on any relay, that this device held
  it before the boundary.
- **The seeds of retired epochs are not retained anywhere**, which is what the chain is for — so
  the chain is load-bearing from the first boundary, not an optimisation added later. A device
  MUST write the wrap at the first boundary it sees, or the history below it is reachable only by
  the devices that already hold those keys.

And one rule kept from the previous draft, because it was right and is unrelated to all of this:

> **A failed round is not a new epoch.** When no member answers, a device MUST say so and stop:
> not fall back to another epoch's key, and not drop the write. The round failing and the epoch
> moving look identical today (`group.ts:794`), and a server outage must not become silent write
> loss.

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
addresses it already knows. **Keeping one tag key makes epoch separation of addresses the
namespace's job rather than the key schedule's** — which is why §7.1 requires the epoch in the
boundary checkpoint's own address, and why any other per-epoch record a namespace adds must do
the same or collide with its predecessor at a replaceable address.

> **A device MUST blind the point it asks about**, and the steps are given as bytes because the
> natural implementation of them is wrong:
>
> 1. pick `r` at random in `[2, n-2]` from the system's randomness — never a fixed `r`, not even
>    "for tests";
> 2. compute `Q = r·P(ns,e)` and take `x(Q)`, 32 bytes;
> 3. **every** party then works over `lift_even(x(Q))` — the answering members *and the deriving
>    device's own partial*;
> 4. combine, `lift_even` the 32-byte answer, multiply by `r⁻¹ mod n`, take the x-coordinate.

**Step 3 is the trap.** Today both platforms pass the peer's **x-only hex** to their own
`ecdhPartial` (`device.ts:189`, `Phone.kt:1780`) and every responder lifts the same way
(`frost.ts:154`, `Point.fromHex('02' ‖ peerX)`; `core/Secp.kt:24`, `byteArrayOf(2) + xOnly`), so
all participants work over `0x02 ‖ x` and the sum is `±s·Q`. Under blinding the device holds
`r·P` **as a point** for the first time, and the obvious code multiplies that point by its own
scalars. If `r·P` has odd y, the device's partials are over `−Q` while every partner's are over
`+Q`; the sum is neither `s·Q` nor `−s·Q`; the result is garbage with **no error**, and §6 is
what would have to catch it. So the re-lift is explicit on both sides: `ecdhCombine` returns 32
bytes and not a point (`frost.ts:162`), and `Phone.kt:1782` discards parity with
`copyOfRange(1, 33)`. The primitives exist — `Secp256k1.pubKeyTweakMul` and
`BigInteger.modInverse` on Android (`core/Refresh.kt:84`, `:35`), `Point.multiply` in TypeScript,
though `inv()` is module-private at `frost.ts:30` and would need exporting.

> **A blinded round MUST bypass the device's ECDH cache rather than fill it.** `Kept`
> (`Phone.kt:1637-1649`) has no cap and no TTL and is cleared only on screen-off (`:276`); under
> mandatory blinding every entry is a one-shot that can never hit, so caching them only grows the
> cache within a session.

The second draft made this optional on the grounds that a secret salt already hides the label
from the server. That was backwards, and it is the mistake this draft exists to correct. **The
salt hides how to *construct* `P`; it does nothing about `P`'s value once a device puts it on
the wire**, and putting it on the wire is the whole of the round: `onEcdhReq` takes `msg.peerX`
as plain hex and must, in order to answer (`server/core/group.ts:701`, `:717`). So anyone
holding the key who sees **one** `ecdh_req` — on a relay, on a server, in a log — computes
`s·lift(peerX)` at home and has `K`, with no threshold, no grant, no round and no salt. The
pre-import nsec that §4.2 is about needs to watch once.

Worse, §9's own change makes those rounds easy to pick out: a derive names the device's own
member key as its grant, so `msg.grant === from.pk` marks it. Harvesting is targeted, not bulk.

There is a second reason, which §6 supplies and which is the stronger of the two: in an
unblinded round a partner that has also held the key whole can make the device derive **a key
that partner chose and knows** (§6), because it can compute the device's own contribution
exactly. Blinding does not prevent that partner from corrupting the derive, but it downgrades the
attack from a chosen key to unpredictable corruption, which §6's proofs then catch. Unblinded
there is nothing to catch: the derive succeeds and the attacker reads everything written under
it.

So the defences are complements and the second draft had them as alternatives: **the salt stops
offline enumeration, blinding stops online harvesting and removes the chosen-key attack**, and a namespace needs both. What
blinding costs is real and worth paying: every derive is a fresh round — once per epoch, not
once per pack, so the cost is small — and a peer that never recurs on a regular cadence is itself
a pattern — a pattern that reveals *that* a namespace is being derived, which is the cheaper
secret to lose.

## 9. The server change this needs

The first draft claimed none. In fact every round is refused unless it names a live grant
(`group.ts:716`): `if (!liveGrant(msg.grant)) return respond({ ok: false, reason: 'revoked: …' })`.
So as written the app key would be reachable through a grant and would die with one — and if a
device borrowed an ordinary grant, the namespace would appear in the user's list of connected
apps, where **Remove** would silently break it.

The third draft's answer was for a server to accept a round that names the device's own member key
as its grant, with no site lookup. **That is wider than its purpose, and the width is the
capability 0.12.6 removed.** A server cannot tell a label point from a counterparty's pubkey — §9
said so — and under that rule it cannot tell an app-key derive from any other decryption either.
So the rule would not be "accept app-key rounds"; it would be *accept **any** ECDH the device asks
for, for **any** peer, with no grant, no record anywhere, and nothing the user can remove*. Today
a device must name a live grant, so **Remove** in the connected-apps list genuinely stops
decryptions and the grant is the audit trail. §11.11 says the *namespace's* access cannot be
revoked; that rule would have made **every message the account can decrypt** reachable the same
way from a compromised signer process.

> **The change: a device MAY hold one reserved grant of its own.** A client creates it through
> the existing `grantApp` with a reserved origin; it is filtered out of the connected-apps list
> (`pushState`, `group.ts:963`) and out of `revoke`'s reach, and it is not shown to the user.
> Everything else is unchanged: the grant check at `:716` stays load-bearing, the round is still
> counted and noted, and nothing new is opened.

No protocol change is needed for it — `grantApp` already takes any 64-hex pk the device names
(`group.ts:729-746`), so a device can already make a grant whose pk is its own member key. What
the third draft objected to was only that such a grant is *shown* and *removable*; hiding one
reserved grant is the whole of the fix.

**If the grantless path is taken instead**, two things are required rather than optional: the
server MUST `note()` and rate-limit grantless rounds, so that "this device read N things with no
app asking" is visible somewhere; and the rule MUST be written as
`mayAct(from) && msg.grant === from.pk`, not `isDevice(from)`. The reason is the paper. Removed
devices are blocked (`group.ts:235-241`, `:90`) and servers are blocked (`:712`), but `case
'members'` admits any member that is not a device (`:254`) — so the **paper member itself** can
send a `members` list, and `mergeMembers` flips a backup record to `role: 'device'` on being told
so (`:1193-1198`), setting only `viaServer`. `isDevice` ignores `viaServer`; `mayAct` (`:101`)
does not. Today only the threshold arithmetic saves the round (paper 2 + one server 1 = 3, below
`t = 4`, `:714`) — and that does not save a threshold-2 key, which COSIGN.md §3 says existed
under 0.1.

**Independently of this proposal, `case 'members'` should be `from.role === 'server'` rather than
`!fromPhone`.** The flip it allows also makes the paper `fromPhone` for `app_grant`,
`phone_signed`, `refresh_commit`, `mail_for`, `revoke` and `undo`. That is a live finding, not a
design question, and it belongs on the fix list whatever happens to §9.

One claim the third draft made that the code does not support, now removed: *"and where 90 days
unused expires it"*. Nothing expires a grant — `lastUsed` is only ever written (`group.ts:762`,
`:944`) — and COSIGN.md §6.2 (`:397`) says a client **MAY** pick 30, 60 or 90 days, or never. The
other two legs of the argument (it would appear as a connected app; **Remove** would break it)
stand on their own.

A server still cannot tell an app key from a message being read, which is why the first-party
rule has to live on the device.

## 10. Two devices, no server

Two devices reach the threshold between them (6 points of 4), so a namespace can be derived with
no server at all by the device-to-device round of COSIGN.md §5.5 — the same path and the same
rules. Three things to say plainly about it:

- **§6's two-set check is not available there**, and §6.2's proofs are, which is the other reason
  the check is a proof and not a comparison. The known-plaintext check still applies.
- **COSIGN.md §5.5's header says *(not built)***, so this path is a plan, not a capability. On
  Android the member-to-member responder does exist (`Phone.kt:2043-2068`); the extension does not
  answer an `ecdh_req` from a device at all (`device.ts:205-206`, which returns unless the sender
  is a server).
- **That path needs no grant** (`Phone.kt:2043` never looks at `msg["grant"]`), so §9's premise
  "every ECDH round is refused unless it names a live grant" is true of servers and false of the
  member path. It needs no server change, and it is ungated — which is why §5's refusal has to
  cover member-to-member requests too.

## 11. What it does not protect against

1. **Anybody who held the key whole *and* the namespace salt** (§1, §4.2, §4.4). Every
   namespace, every epoch, for ever, offline, undetectable, and no refresh or re-split reaches
   them. The key alone is not enough — an nsec from before an import cannot construct the label
   — but a member device that was taken out had both. This is the ceiling on everything else
   here.
2. **The salt itself, which never rotates and is copied the most.** `S` is in every member
   device and on every paper, it does not change when the epoch does, and **a leak of it cannot
   be noticed** — there is no use of it that looks different afterwards. A device reported lost
   keeps it for ever and the removal flow does nothing about it; a paper COSIGN.md §8.1 calls
   worthless after a new one is printed still carries a live salt; a stale backup of a device
   yields a dead share and a live salt. It was also generated on the machine that held the
   whole key at the time, which for an imported account is usually the machine an nsec leaks
   from — so §4.2's protection is about the *bytes* of an old nsec, not about the computer they
   were on. §4.5 is the only answer and it is a deliberate, visible act.
3. **A breached device in the current epoch.** It derives everything the namespace has, writes
   what it likes and seals manifests that every reader believes (§7.3). This is the trust
   boundary the whole of §7 is built to sit on: "a member of the current epoch" and no wider.
   Removing it moves the epoch and closes the future to it — which is true only because of
   §7.1's seed, and was false in the two drafts before this one. It keeps what it already took,
   `S` included (case 2). **Two caveats that are live:** the seed is server-authored, so a
   device colluding with one server may be handed future seeds in advance (§7.1, and §11.5's
   accepted threshold); and a removal is not final until the epoch has actually moved (§7.5).
4. **A removed device's past.** Every key it derived, it keeps: it reads those epochs' records
   for ever, wherever it kept them, and nothing can take that back. What §7 takes away is the
   ability to make its writes *count*: it cannot seal a manifest or a wrap under the current
   epoch's key (§7.2, §7.3), so a reader that follows the chain down from the current epoch never
   adopts what it wrote. The two drafts before this one claimed that and did not have it — the
   old chain was signed under keys the removed device held.
5. **A stolen device plus one cooperating member.** 3 points and 1 is the threshold, as it is
   for signing (COSIGN.md §12's accepted baseline).
6. **An XSS on a first-party origin.** It is first-party as far as the browser and this rule are
   concerned. The response is §4.5's new salt, and nothing automatic notices.
7. **Servers keeping history.** What a server kept, it keeps (§5.4). The records are not the
   account's events and never pass through a server, so a server sees only derive rounds — but
   the namespace also gets no backup from the servers, which a namespace used to storing things
   under the npub may not expect.
8. **Relays.** An unfamiliar pubkey's records, their number, size, timing and source address.
   A relay that correlates two identities by address and time will.
9. **Per-relay allow-lists.** A namespace that needs its `pk(ns,e)` allow-listed to get past
   spam filtering hands that relay's operator a dated map from each epoch's key to the account
   that asked — the link §8 otherwise does not publish.
10. **The platform's answer to "who is calling".** On a rooted phone, or with a replaced
   extension, that answer is worth what the device is worth, which is case 2.
11. **`S` plus any live grant on any live device is every epoch, including epochs that do not
    exist yet.** Each ingredient is in this list separately (1, 2, 6, 10) and the product is the
    one that decides how load-bearing §5 is: a salt-holder constructs `P(ns,e′)` for any `e′`, and
    before §5's rule a grant turned that into an oracle under `x(ns,e′)`. §5's refusal of
    `nip04_*` is the only guard against it, which is why it is written by method rather than by
    point comparison.
12. **This access cannot be revoked.** Every other access in Cosign can be taken back from a
    device: a site's grant, an app's, a server's share. A first-party caller's is in the build.
    The user cannot withdraw it except by removing the device or abandoning the namespace
    (§4.5), and nothing in the interface will offer to.

## 12. What this would change in COSIGN.md

- **§5.6**: a second use for the decryption round, with §2's hash-to-curve requirement, §3's
  encoding, §5's "`x` is never a key" and the refusal of `nip04_*` from a grant or a member,
  §6's **proof per partial** and the rules for when it fails, and §8's **mandatory** blinding —
  including that a round MUST NOT be answered or coordinated with an unblinded label point, and
  the parity rule of §8's step 3.
- **§6.2**: an app key is not a grant and no app's grant reaches one; §9's reserved own-device
  grant exists, is never shown as a connected app and cannot be revoked from that list; and no
  grant expiry applies to it.
- **§6.3, §6.4**: §4.1's first-party rule per door, including that NIP-46 has no such call.
- **§7.3, §7.7**: that a refresh rotates every namespace's keys, that the boundary is a
  checkpoint and not a clock (§7), and that §7's "only a committed epoch" is a requirement on
  COSIGN.md §7.7 **whenever that is built** — today no client sends `refresh_commit` at all
  (this document's §7.3).
- **§3 and the vectors**: the label now carries the epoch's seed (§7.1), which is why the bytes
  and the test vectors could not be fixed before §7 was settled.
- **§5.5**: that §10 depends on it, that its header still says *(not built)*, and that the
  member-to-member round is ungated by design and so carries §5's refusal itself.
- **§8.1**: §4.4's consequence in full — a superseded paper carries a live salt, so "worthless
  after a new one is printed" is no longer true of it.
- **A new rule in the member library on both platforms**: the app is told when the epoch moves
  (this document's §7.3). Nothing in §7 can be implemented without it.
- **§3**: nothing. The namespace salt MUST NOT go in the group record — an earlier draft of
  this list said it should, which contradicted §4.4's own MUST, and the record is a published
  event, so doing it once could not be taken back. What belongs there is the **commitment** of
  §4.4, which is a hash and reveals nothing.
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
  caller and all of it — and §7.2 requires the namespace's own mass-change halt to cover records
  made unacceptable *by a checkpoint*, which is the form that erasure takes and which no halt
  written about a failed pull would catch.

## 14. Still open, and who answers each

1. **Where the first-party list lives** — mine. Compiled in (as §4.1 says) means a release to
   add a caller and no attack surface; in the signed member record means faster and a new thing
   for a compromised device to write. I would keep it compiled in while there is one caller.
2. ~~Whether the Tauri host can be first-party~~ — **answered: yes**, after the four changes
   in §4.1, which that app is making. What remains open there is its own: where the derived key
   lives inside the app, which is a vault change and needs its own review.
3. ~~Whether the paper carries `S`~~ — **answered: it does** (§4.4), with the consequence
   stated there: a paper plus a whole-key copy opens every namespace for ever.
4. ~~**Whether `S` can be added to an existing account without a refresh**~~ — **answered by the
   author: existing accounts get `S` in the same release as new ones, and a namespace stays off
   until every member device has acknowledged it.** So the acknowledgement is not a nicety to be
   added later: it is the gate, it has to work on an account whose devices are not all online at
   once, and "off" has to be a state the app can be in without looking broken. What follows is
   the reasoning that led there, and it stands — the answer
   is **yes**, with a caveat the second review supplied: `S` is not key material and nothing in
   the maths depends on it, so it is dealt to the current member devices with no epoch change
   and no new shares. But "and acknowledged" was hand-waving — there is no acknowledgement in
   the protocol, and the paths it would travel drop things silently: a server's held mail is
   capped at 50 entries and expires after 30 days, and the ciphertext sits in that server's
   state meanwhile. So **a namespace MUST NOT start until every member device's own
   acknowledgement has been seen**, checked against the commitment of §4.4, and that
   acknowledgement has to be specified before any of this is built. Otherwise two devices derive
   into disjoint invisible data sets, which is §3's failure reached by another road.
5. **Whether to ask for the device's lock** on a derive, once a day rather than once a sync —
   open, and it belongs in the user-verification document if the answer is yes.
6. **Whether the DLEQ proof of §6.2 lands in Cosign on its own, before any of this.** Mine, and
   I think yes: it is the smallest piece of real code here, it is independent of the salt, of §7
   and of the first-party rule, and it turns a bad partial in today's NIP-44 reads into a named
   error instead of a MAC failure. What it needs that this document does not supply is the
   arithmetic written into three codebases and a vector beside
   `FrostVectorsTest.kt:56 ecdhPartialsMatchTheServer`; the Kotlin side goes through a JNI
   `Secp256k1` whose surface has only been sampled.
7. **Who writes the boundary checkpoint when the device that asked for the refresh never comes
   back** — §7.1 says any member device that finds none after a short delay, and "short" is not
   specified. It trades a window in which a retired epoch is `unverified` against a flurry of
   union members at every boundary. Mine, and it needs the epoch-moved callback of §7.3 before
   it can be measured.
8. **The stranded server of §7.3.** A server offline across an immediate refresh never recovers,
   which halves the answering partners §6 wants and tells nobody. That is a Cosign bug this
   proposal would depend on; it needs its own fix and its own tests, and the fix is not in this
   document.
