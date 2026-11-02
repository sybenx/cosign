# When one of your devices may believe in another — draft 2

> **Status after its own independent red team (`~/igloo/cosign-pinned-members-redteam.md`,
> 2026-11-02): not buildable as written — buildable with three changes.** The shape is right
> (derive the point, prove the scalar, pin the kind first-hand) and **§2.2's share proof is safe**:
> the reviewer could not get a chosen value into `e`, could not reuse `R`, and could not combine
> proofs across indices — and executed the control, which is that the *same* construction with
> `idx` and `P_idx` removed from the challenge **does** forge a group signature. The per-index
> binding is load-bearing, and §2.2 should say so beside the challenge.
>
> What breaks is underneath it. **§2.1 never names what it derives from**, and the only anchor it
> cites — 0.12.8's `sound()` — is forgeable by the author of the list: `vss_commitment` constrains
> a weighted *sum* of the first `threshold` points, so an attacker holding three of four solves the
> fourth and the check passes (executed, full chain). Anchored on the device's **own** `s·G` points
> the same attack is refused 200 times out of 200 — but `onMembers` overwrites the phone's own
> points from the server's list today. **Two own points are enough to re-enable the forgery**, and
> the path that has two is a paper recovery, not a corner case; every co-signer and server holds
> one and can never anchor §2.1 at all, so §2.1 is device-only and its claim to be "0.12.8's fix
> applied where it was left undone" is backwards. And **§2.3's handoff channel is not authenticated
> by the user's scan** — see live finding 17, which is a critical hole in the join handshake in its
> own right, found under this document and not caused by it.
>
> **The change to make instead of §2.1's candidate search: pin the polynomial commitment, not
> points.** It is first-hand at DKG, at dealing and at every refresh, needs no anchor and no
> candidate search, works for a member holding one share, and deletes the §9.1 open question
> outright. It is the useful half of §6's epoch record without the signing round. Draft 3 is that.
>
> §7 — remove the `site_key` receiver — is verified and still right, so site-dms stays parked
> whatever else changes.

**Status: proposal, for review — superseded in part, see above.** It replaces
[`device-evidence.md`](device-evidence.md), whose mechanism was rejected by its red team
(`~/igloo/cosign-device-evidence-redteam.md`, 2026-10-28) — not the problem, which is real and
was found three times in one week, and not §1's rule, which survives word for word. What was
wrong was the evidence scheme underneath it.

The reviewer's verdict in four lines:

- Evidence (b) — "a verified partial" — **was forgeable by exactly the server it was meant to
  exclude**, and they executed it against this repository's own FROST build. Fixed server-side in
  0.12.8 (`Sig.sound`), still live on the phone and in the extension.
- Evidence (b) **can never be earned about a device**: `partners()` is servers only, and both
  `sign_req` and `ecdh_req` accept a round only from a server. The member it exists to prove is
  the one a device never exchanges a partial with.
- **Nothing authenticates which member key holds which share indices.** Whichever half of that
  mapping a device records, the server supplies the other — and §2(b)'s "record the indices, not
  the key" turned the stricter-looking rule into a direct key-exfiltration path.
- Making `vouching` durable, which draft 1 proposed, **permanently widens `onRepair`**:
  `vouchedFor` is its only gate (`Phone.kt:1420`).

So draft 1 asked the wrong question. It asked *what counts as evidence*, and built a ledger of
beliefs. The question is narrower and has an answer: **a device must be able to work out, for
itself, which key holds which shares.** Three mechanisms do that, and none of them is a ledger.

## 1. The rule — unchanged

> **A device MUST NOT seal a secret to, or accept a secret from, a member it knows only because a
> server said so.**

This is the device-side twin of `mayAct` (`group.ts:101`). A server's gate cannot stand in for it,
because the secret never passes through a server.

What is new is everything about how a device decides it knows a member otherwise.

## 2. Three mechanisms

### 2.1 Points are derived, never taken from a list

> **A device MUST compute every share point from the group key, and MUST NOT use a point that
> arrived in a message.** If the points it holds cannot rebuild the polynomial, it MUST refuse
> rather than fall back to the list.

This is 0.12.8's server-side fix (`Sig.sound`, `server/sign.ts:53`) applied where it was left
undone. The device side is where it matters most: `groupJson` flattens `g.members.flatMap { it.points }`
into the group JSON a partial is verified against, and `onMembers` (`Phone.kt:1455`) replaces the
member list wholesale.

`FrostNative.sharePubAt` is already bound (`core/FrostNative.kt:23`), and it goes through
`vss_commitment`, which refuses unless the rebuilt polynomial's constant term is the group key. A
device holds 3 points against a threshold of 4, so it needs one trusted fourth: form a candidate
group of its own 3 points plus one point from the list and call `sharePubAt`. The degree-3
polynomial through 3 correct points is an injective function of the fourth, so exactly one
candidate passes. Once one does, derive every other index from that group and ignore the list's
points for ever after. Both halves of this were demonstrated by the reviewer.

This alone makes a partial mean something again. It does not say **who** holds the share.

### 2.2 A share proof says who

A new primitive, and the smallest one that answers the question draft 1 could not.

> **A member MAY prove it holds the share at an index by publishing a proof of knowledge of that
> share's scalar, bound to the index, the point, its own member key, its kind, the group and the
> epoch.** A device MAY treat a member as holding exactly those indices for which it has verified
> such a proof against a point it derived itself.

```
  e = H(tag "cosign/share-proof" ‖ groupX ‖ epoch ‖ idx ‖ P_idx ‖ member_pk ‖ kind)
  R = k·G,  z = k + e·s_idx
  verify:  z·G == R + e·P_idx,   with P_idx derived per §2.1
```

Four properties matter, and each is doing a specific job:

- **A member without the share cannot produce one.** It is a proof of knowledge of the discrete
  log of a point the verifier derived. Nothing in it is taken on anyone's word.
- **The member key is inside the challenge**, so a proof is worthless attached to any other key.
  This is the binding draft 1 did not have, and it is what closes the exfiltration path: a server
  cannot list proven indices against its own `pk`, because the proof names the `pk`.
- **It is non-interactive, so a server can carry it and cannot forge it.** This is what kills the
  reviewer's C3 outright. No device-to-device round, no §5.5, no awake-peer discovery, no change
  to who signs: a device emits its proofs once per epoch, servers relay them exactly as they relay
  a member list, and a new device verifies them whenever it likes. Replay is not a threat, because
  a replayed proof asserts a true statement about a real holder.
- **It is epoch-bound, so a refresh invalidates it** — which is the honest answer to draft 1's open
  question 2, and one that costs nothing: each member re-emits after a refresh, automatically, so
  "re-earn each epoch" no longer means a quiet device goes unproven.

The primitive is not new work so much as a strict simplification of one we shipped in 0.12.7:
`ecdhProve`/`ecdhVerify` (`server/frost.ts:187`) is the same shape with a second base and a second
response. Drop `R2` and `Q` and this is what is left, with its own domain tag.

### 2.3 Kind is pinned by the device that dealt the shares

A share proof says "this key holds index 7". It does not say whether index 7 is a phone or a
co-signer, and it cannot: a co-signer that genuinely holds index 7 can prove it, and if its own
proof is also where its kind comes from, a dishonest one calls itself a device and collects
whatever devices send each other. Self-assertion is enough for `attended`
(`claude/devices-and-cosigners` §2), where the worst case is a worse choice of signer. It is not
enough here, where the worst case is the account's secrets.

So kind comes from the one place a server is not: **the moment the user's own device dealt the
shares.**

> **A device MUST keep a pinned table of `(member key, indices, kind)` for every member it learned
> first-hand, and MUST refuse a member list that re-points a pinned index to a different key, or
> changes a pinned member's kind, except by one of the resolutions in §4.**

A device learns a member first-hand in exactly two ways:

1. **It dealt the shares.** `onRepair` already knows both halves — `newPk` and `ks` — at the moment
   it sends the sigmas (`Phone.kt:1412-1453`), having checked `making?.pk == newPk`, which is set by
   a code the person scanned on *this* device and unlocked. Nothing a server says is involved.
   Writing the pin there is three lines.
2. **The device that dealt them handed over its table**, during enrollment, over the channel the
   person authenticated by scanning. A new device receives its share material from the voucher in
   the `sigma` message (`Phone.kt:1451`); the voucher's pinned table rides along in it.

The second is draft 1's evidence (c) with the machinery taken out. There is no standing credential,
no signature format, no chain-length rule, no expiry, and no "enrollment key" — a credential draft
1 named and the reviewer could not find, because it does not exist. There is a one-time table copy
over a channel whose authentication is the user's own scan, and a device that was never handed a
table simply has a smaller one.

> **A pinned entry MUST be dropped when the member leaves the list, and `vouching` MUST stay
> short-lived.** Draft 1 proposed making it durable; `vouchedFor` is the only gate on `onRepair`,
> so a durable vouch is a permanent licence to mint share material to a key the user may have
> retired. Standing lives in the pinned table, which authorizes nothing by itself.

## 3. What a device does with no standing for a member

Unchanged from draft 1 §3, with the storage the reviewer asked for:

> **It does not send, and it does not fail.** A secret that cannot be sealed yet is **held, not
> dropped**, and sealed when the proof arrives. Nothing is shown to the person.

> Held secrets MUST live in the signer process only, encrypted at rest, and never in `group` or
> `membership`. Absence of a member from a list MUST purge everything held for it and every pin of
> it. **Removal MUST be positive** — a `removed` entry, not inferred from a member being missing,
> because the list that is missing it is a server's to choose. A proof MUST be current-epoch at the
> moment of sealing, not at the moment it was verified.

> **A device MUST NOT ask a server to carry a secret to a member it cannot verify**, and MUST NOT
> fall back to a weaker check when a server says the member is real. Concretely: `sharedX`'s
> fall-through to unverified `points` (`Phone.kt:1801-1817`) must go, and a `points`-only answer
> must count as that server failing rather than succeeding.

## 4. The re-pointings that are legitimate

§2.3's refusal breaks the account unless these are enumerated, because each of them does exactly
what it forbids. A device MAY accept a change to a pinned entry when, and only when:

- **A refresh it took part in** moved the points. Every point is recomputed from the dealers'
  commitments, so this is first-hand by construction — provided the plan's old points are taken
  from the plan for this device's own indices only and derived for every other
  (`core/Refresh.kt:31` currently validates only its own, which is how a forged holder is laundered
  through a refresh and comes out self-consistent). A plan whose holders contain an index that does
  not derive MUST be refused, and `refresh_plan` MUST be accepted only from a server.
- **A paper recovery it witnessed** promoted a backup to a device: the key against those indices
  changes legitimately. The server-side rule already distinguishes a server that saw the recovery
  from one repeating what it was told (`group.ts:1262`); the device needs the same distinction, and
  has it when the recovery passed through this device's own unlock.
- **A device growing its shares** after such a recovery (`group.ts:1270`): the indices against a
  pinned key change, the key does not.

Everything else — a pinned index appearing against a new key, a pinned key appearing with new
indices, a pinned kind changing — is refused, and **shown to the person**, because by here nothing
honest produces it.

## 5. Against the review, item by item

| | Draft 1 | Draft 2 |
|---|---|---|
| C1 forgeable partial | the mechanism | §2.1 derives the point; server side shipped in 0.12.8 |
| C2 `viaServer` cleared early | cited as the sound precedent | fixed in 0.12.8; `mergeMembers` still copies a peer's `sharePub` (`group.ts:1270`) and must derive it |
| C3 (b) unobtainable about a device | claimed free | §2.2 is non-interactive; no device-to-device round |
| C4 no key↔indices binding | made worse by the MUST | §2.2 puts the member key in the challenge |
| H1 durable vouch widens `onRepair` | proposed durability | §2.3 keeps `vouching` short-lived |
| H2 removal undone from the device's side | queue unplaced | §3 places it and makes removal positive |
| H3 refresh launders a forgery | unaddressed | §4 derives every point but this device's own |
| H4 `site_key` receiver injects signing authority | §4 said remove it | still: remove it (§7) |
| M1 an injected "server" stops signing | unaddressed | §2.1 fails it at verification; wrap the aggregate per partner |
| M2 `parts` optional on the wire | forbidden in prose, present in code | §3 makes it a failure |
| L1 "enrollment key" does not exist | named it | §2.3 does not need one |

## 6. Why not the epoch record

The reviewer's own recommendation was the signed epoch record — kind 30242, `d="frost"`, specified
in `COSIGN.md:149` and `NIP-XX.md:47` and built nowhere. It is the better long-term answer for a
different question, and it is not the cheaper answer for this one.

It authenticates key↔indices by being signed with the group key, which takes four points, which no
single server can raise. That is a strong property and we should have it. But: it needs a signing
round on **every** membership change and every refresh; its content is encrypted "under a random
group secret that every member holds", which a device being added does not hold yet, so the
record cannot be the thing that tells a new device who the members are; and `epoch.id`, which its
own schema requires, appears in no source file — the counter is all that exists.

A share proof needs no quorum, no new encryption key, no new event kind, and no publishing
discipline, and it answers the question the secrets depend on. The two are complementary, not
rival: the record would authenticate labels, roles and removals, and the proof would still be what
says a key holds a share. If the record gets built, §2.3's pinned table can be seeded from it
instead of from a handoff — which is a simplification to look forward to, not a prerequisite.

## 7. What is still the recommendation

Unchanged, and it is the part of draft 1 that survived review intact:

> **`claude/per-site-signer-keys` MUST drop `changed()`'s copying loop and the `site_key` receiver
> before it ships.** Not gate them: remove them.

The reason is stronger than draft 1 gave. `Bunker.adopt` (`core/Bunker.kt:115`, on that branch) dedupes on the
mailbox public key alone — it does not check `origin`, does not check `by`, and keeps the sender's
`client`, which is the NIP-46 client key authorized to use that mailbox. So the receiver does not
leak mailboxes; it **installs a signing door into the account through the user's own phone**, and
one colluding server is enough to answer the grant. A rule about who a secret may come from does
not make that safe, even when the rule works.

And draft 1's description of the cost was wrong in the user's favour. It is not "signed in on the
phone, not on the laptop". It is, in the DM spec's own words, that a site is answered only while
its home device can be reached — an intermittent signer error, the least legible failure there
is — plus a residual on a lost device that cannot be revoked. The recommendation stands anyway.
It is just not free.

## 8. Attack this first

For whoever reviews it. These are the places I would expect it to break, named so that a reviewer
does not have to find them before starting:

1. **Does the share proof leak anything a FROST partial does not?** `z = k + e·s` with a fresh `k`
   is a textbook Schnorr proof of knowledge, but a FROST partial is `z = k + λ·c·s` over the same
   share. Nothing attacker-chosen enters `e` as specified — every field is the prover's own or the
   group's — but if a reviewer can get a chosen value into `e`, or can reuse a proof's `R` as a
   signing commitment, the proof becomes a partial-signature oracle. This is the one that would
   make the design worse than the problem.
2. **Is the §2.1 candidate derivation actually injective** in practice as well as in argument, and
   what does a device do when it holds fewer than `threshold - 1` points — a device with one share,
   or a browser member?
3. **The handoff is a table from another device.** It arrives in `sigma`, which is sealed to the
   new device's key, from a voucher the person scanned. What does a hostile voucher get? (The
   person chose it, so the honest answer may be "everything, and that is the trust model" — but it
   should be said rather than assumed.)
4. **Kind pinning and the `attended` decision.** `claude/devices-and-cosigners` makes `attended`
   self-asserted. Is there a path where a member's self-asserted `attended` plus a pinned kind of
   `cosigner` still gets it treated as a device by some caller?
5. **§4's three resolutions are where the account bricks.** A first honest paper recovery that the
   second device did not witness: what does it see, and can it ever recover without the user
   re-scanning?
6. **The extension.** It lives in `~/marble/extension` since the split, keeps points it already
   knows but takes the server's point for any index it does not (`src/member/device.ts:221`), has
   no equivalent of the phone's `list.none { it.idx == m.idx }` guard, and verifies partials not at
   all. Everything here has to be true there too, in a different repository and a service worker
   that dies.

## 9. Still open

1. **A device with one share.** §2.1 needs `threshold - 1` honest points to pin the candidate. A
   member with fewer must get its first point some other way, and the only first-hand one it has is
   the enrollment handoff — which means the handoff carries points as well as the table, and a
   device that was never handed one cannot derive at all. This is the weakest joint in the design.
2. **Where the proofs are carried.** A member message relayed by servers is the obvious place and
   needs no new kind. Publishing them as a replaceable event per member would also let a device
   fetch them without any server being awake. I have not chosen.
3. **Whether `mergeMembers` should derive as well.** It copies a peer's `sharePub` today
   (`group.ts:1270`), which was half of C2. 0.12.8 fixed what verification does with that copy, not
   the copy. Deriving it there is a two-line change and I think it should happen regardless of this
   document.
4. **What the person is shown** when §4's refusal fires. "Something changed about one of your
   devices and this phone did not see it happen" is true and unhelpful. The honest version names
   the device and offers the one recovery that works, which is re-scanning — and that is a screen
   nobody has designed.
