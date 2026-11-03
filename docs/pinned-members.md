# When one of your devices may believe in another — draft 3

**Status: proposal, for review. Nothing here is built.** Third draft. The problem has not moved
since draft 1; the answer has, twice, because both earlier answers were broken by their reviews.

- [`device-evidence.md`](device-evidence.md) (draft 1) asked *what counts as evidence* and built a
  ledger of beliefs. Its review broke all three kinds.
- Draft 2 asked the better question — can a device work out for itself which key holds which
  shares — and answered it with a candidate search over the member list. Its review
  (`~/igloo/cosign-pinned-members-redteam.md`) **confirmed the share proof is safe**, executed the
  control that shows why, and then broke the search: the rebuild constrains a weighted *sum* of the
  first `threshold` points, so three points in hand solve the fourth. Draft 2's §2.1 never said the
  three had to be the device's own, and the code makes them not be.
- This draft keeps the share proof, drops the search, and **pins the polynomial commitment
  instead of points.** That was the reviewer's own recommendation, it is first-hand at every moment
  that matters, and it removes the two criticals rather than patching them.

What survives from draft 1 untouched: §1's rule, and §9's recommendation that per-site mailbox keys
are not copied between devices at all.

**One prerequisite, and it is not optional.** Draft 2's enrollment handoff rides a channel the
user's scan does not authenticate, and the reviewer found that this is a critical hole in the join
handshake in its own right — any watcher of the invite's relays can enroll a joining phone into a
key it holds alone. That is **live finding 17**, it is written up with its fix, and §2.3's
bootstrap depends on it being closed. Nothing here is buildable before it is.

## 1. The rule — unchanged since draft 1

> **A device MUST NOT seal a secret to, or accept a secret from, a member it knows only because a
> server said so.**

The device-side twin of `mayAct` (`group.ts:101`). A server's gate cannot stand in for it, because
the secret never passes through a server.

## 2. The pinned commitment

### 2.1 What is pinned

A weighted FROST key is a polynomial `f` of degree `threshold − 1`. Its **commitment** is the list
of coefficient points `[f(0)·G, a₁·G, … a_{t−1}·G]` — the group key and the rest. The commitment
determines *every* share point: `f(k)·G = Σ Cⱼ·kʲ`. Nothing else is needed.

> **A member MUST store the group's commitment, and MUST derive every share point from it.** It
> MUST NOT read a share point from a message, from a member list, or from its own stored copy of
> one. A member that has no pinned commitment has no points, and MUST refuse rather than fall back
> to a list.

This is draft 2's §2.1 with the search deleted. The candidate search existed only to get from
points back to a commitment; pinning the commitment means never making that trip. Three things fall
out at once:

- **The weighted-sum attack has nothing to stand on.** It needed `threshold − 1` free points to
  solve the last; here there is no basis to choose and no point taken from anyone.
- **It is sound for a member holding one share.** Draft 2's construction needed `threshold − 1` own
  points, which made it device-only and made its claim to be "0.12.8's fix applied where it was
  left undone" backwards. A co-signer with one share derives from a pinned commitment exactly as a
  device does.
- **Draft 2's weakest open question disappears** rather than being answered. There is no "device
  with one share" case, because the commitment is not reconstructed from holdings.

### 2.2 How it is carried forward — first-hand, by arithmetic

A refresh moves every share. It does **not** move the group key, and it does not need a list:

> **A member MUST recompute the commitment at each refresh from the dealers' commitments it has
> already verified, and MUST NOT take a point, or a commitment, from the plan.**

Each dealer picks `g` of degree `threshold − 1` with `g(0) = 0` and publishes commitments to g's
coefficients; every member already checks its own deltas against them
(`core/Refresh.kt:88`, `checkDelta`). Since `f' = f + Σ g_d`:

```
  C'₀ = C₀                    (the group key, unchanged — which is the point of a refresh)
  C'ₖ = Cₖ + Σ_d C_{d,k}      for k ≥ 1
```

So a member that pinned `C` computes `C'` from data it has verified itself, and every new point
follows. This is not an improvement in strength only — it deletes the laundering the draft-2 review
found, where `finish()` takes **other** holders' old points from the plan
(`core/Refresh.kt:72`) and so writes a forged holder's point forward into something the device
derived. With a pinned commitment there is no slot for a supplied point to occupy.

> **A plan whose `holders` contain an index the recomputed commitment does not account for MUST be
> refused**, and `refresh_plan` MUST be accepted only from a server — including when it arrives
> inside a `mail` wrapper, which currently re-dispatches with a sender the wrapper names
> (`Phone.kt` `onRefreshMsg`). The role check must be applied to the inner sender, not the outer.

### 2.3 How it is bootstrapped — three moments, all first-hand

The commitment has to enter a member once. Every honest route is a moment the user is present for:

1. **This device made the key.** In the weighted flow the phone computes the polynomial itself, so
   the commitment is its own by construction. Pin it there.
2. **This device was dealt its shares by a device the user scanned.** The share material arrives in
   `sigma` from the voucher (`Phone.kt:1451`); the commitment rides with it. **This is the route
   that needs finding 17 closed first** — today the joining device takes the whole group from
   whichever `welcome` arrives, from any sender, so "the channel the person authenticated by
   scanning" is not what that channel is. With finding 17's two conditions in place (a sigma from
   the scanned inviter, and the resulting share lying on the group's polynomial) the channel is
   what draft 2 claimed it was, and the commitment can ride it.
3. **This member was enrolled as a co-signer**, which is a different trust question and out of
   scope here: a co-signer is not a party any device seals a secret to (§9).

> **A member MUST pin the commitment at one of those moments and never re-bootstrap.** There is no
> "re-anchor if it looks wrong" rule, because both readings of one are bad: refusing for ever
> bricks a legitimate recovery, and accepting a new anchor is the hole re-opened. §6 is the complete
> list of changes a pinned commitment may undergo, and anything else is refused and shown.

## 3. The share proof says who holds which index

Unchanged from draft 2 except where its review asked for a MUST. The reviewer attacked it hard and
it held: no chosen value into the challenge, no reuse of the nonce commitment, no combining across
indices or epochs.

> **A member MAY prove it holds the share at an index by proving knowledge of that share's scalar,
> bound to the index, the point, its own member key, its kind, the group and the epoch.** A device
> MAY treat a member as holding exactly those indices for which it has verified such a proof against
> a point derived from the pinned commitment.

```
  e = H(tag "cosign/share-proof" ‖ groupX ‖ epoch ‖ idx ‖ P_idx ‖ member_pk ‖ kind)
  R = k·G,  z = k + e·s_idx
  verify:  z·G == R + e·P_idx,   P_idx from §2.1
```

> **`idx` and `P_idx` in the challenge are load-bearing and MUST NOT be removed.** The reviewer
> executed the control: four λ-weighted proofs of this construction do **not** make a group
> signature, and the *identical* construction with those two fields taken out **does**. A later
> tidy-up that drops them looks harmless and hands an attacker a quorum-free forgery primitive. This
> paragraph exists so that nobody does it.

> **`k` MUST be fresh for every proof, from a CSPRNG, and MUST NOT be derived from any field of
> `e`.** Every field of `e` is stable within an epoch, which invites an implementer to cache or
> derive the nonce per epoch. Two challenges under one nonce return the share scalar — the reviewer
> executed that too.

The primitive is a strict simplification of 0.12.7's `ecdhProve`/`ecdhVerify`
(`server/frost.ts:187`): drop the second base and the second response. It is non-interactive, so a
server can carry it and cannot forge it — which is what makes it obtainable about a device at all,
and the reason draft 1's evidence (b) could not be.

## 4. Kind comes from the count, not from the claim

Draft 2 pinned `kind` at the moment the shares were dealt, because a co-signer that genuinely holds
its index can prove it and would otherwise call itself a device. The reviewer showed the weaker
half of that — one holder emits two valid proofs, one saying device and one saying cosigner — and
also the cheaper answer, which is that the weight table already separates them:

> **A member's kind MUST be read from the number of indices it has proven, under the group's weight
> table, and MUST NOT be read from its own claim.** A device holds 3, a paper backup 2, a co-signer
> 1. `kind` stays inside the challenge so that a proof is bound to the claim its maker made, and a
> verifier ignores it.

> **An unproven member has no kind.** It MUST NOT default to `device`, which is what the code does
> today in several places and is the direction that loses. No proofs, no standing, nothing sealed —
> §5.

This needs the weight table written down as a rule the code enforces rather than a convention it
happens to follow, and that is §11's first open item.

## 5. What a device does with no standing for a member

> **It does not send, and it does not fail.** A secret that cannot be sealed yet is **held, not
> dropped**, and sealed when the proof arrives. Nothing is shown to the person.

> Held secrets MUST live in the signer process only, encrypted at rest, and never in `group` or
> `membership`. **Removal MUST be positive** — a `removed` entry, not inferred from a member being
> absent from a list, because the list that is missing it is a server's to choose. Removal MUST
> purge everything held for that member and every proof of it. A proof MUST be current-epoch at the
> moment of sealing, not at the moment it was verified.

> **A device MUST NOT ask a server to carry a secret to a member it cannot verify**, and MUST NOT
> fall back to a weaker check when a server says the member is real. Concretely: `sharedX`'s
> fall-through to unverified `points` must go (`Phone.kt:1801-1817`), and so must the server's
> (finding 16(a)) — a `points`-only answer is that partner failing, not succeeding.

## 6. The changes a pinned commitment may undergo

This is the complete list. Anything else is refused, and shown to the person, because by here
nothing honest produces it.

- **A refresh this member took part in**, recomputed as §2.2. The group key is unchanged; if a
  recomputation would change `C₀`, the plan is refused.
- **A paper recovery this member witnessed**, where a backup's indices come to belong to a new key.
  The commitment does not change at all — only which member proves which index — so this is not a
  change to the pin, and the proofs carry it on their own. (The server-side rule already
  distinguishes a server that saw the recovery from one repeating what it was told,
  `group.ts:1262`; the device needs the same distinction and has it when the recovery passed
  through its own unlock.)
- **A device growing its shares** after such a recovery: again no change to the commitment, and
  the new indices are proven like any other.

That is the whole of it, and it is shorter than draft 2's §4 because pinning a commitment rather
than a table of points makes two of the three cases stop being changes.

## 7. Against the two reviews

| | Draft 1 | Draft 2 | Draft 3 |
|---|---|---|---|
| forgeable partial | the mechanism | derive the point | derive from a pinned commitment |
| rebuild is a weighted sum | not seen | **the critical** | no basis to choose; §2.1 |
| fewer than `threshold − 1` own points | — | **the critical**; device-only | sound at one share; §2.1 |
| no key↔indices binding | made worse | the member key in the challenge | unchanged, and confirmed safe |
| (b) unobtainable about a device | claimed free | non-interactive proof | unchanged |
| handoff channel unauthenticated | — | **the critical** | finding 17, a prerequisite; §2.3 |
| `kind` self-asserted | — | pinned at dealing | from the proven count; §4 |
| unproven defaults to `device` | — | not seen | forbidden; §4 |
| nonce unspecified | — | not stated | MUST be fresh; §3 |
| refresh launders a forgery | — | derive all but own | no slot for a supplied point; §2.2 |
| `refresh_plan` server-only bypassed by `mail` | — | not seen | inner sender; §2.2 |
| durable vouch widens `onRepair` | proposed it | keep it short-lived | unchanged |
| `site_key` receiver | remove it | remove it | remove it; §9 |

## 8. Why not the epoch record

The epoch record — kind 30242, specified in `COSIGN.md:149` and `NIP-XX.md:47`, built nowhere —
authenticates key↔indices by being signed with the group key, which takes four points and which no
single server can raise. It is the better long-term answer to a wider question and we should have
it.

A pinned commitment is the useful half of it without the cost: no signing round on every membership
change and every refresh, no group secret that a device being added does not yet hold, and no
`epoch.id`, which the record's own schema requires and which appears in no source file. The record
would additionally authenticate labels, roles and removals; the commitment plus proofs is what makes
the *secrets* safe. If the record is built later, §2.3's bootstrap can be seeded from it — a
simplification to look forward to, not a prerequisite.

## 9. What is still the recommendation

Verified by both reviewers and unchanged:

> **`claude/per-site-signer-keys` MUST drop `changed()`'s copying loop and the `site_key` receiver
> before it ships.** Not gate them: remove them.

`Bunker.adopt` on that branch dedupes on the mailbox public key alone — it does not check `origin`,
does not check `by`, and keeps the sender's `client`, the NIP-46 client key authorized to use that
mailbox. So the receiver does not leak mailboxes; it installs a **signing door** into the account
through the user's own phone, and one colluding server answers the grant. No rule about who a secret
may come from makes that safe, including the rules in this document.

## 10. Attack this first

For whoever reviews draft 3. Draft 2's list is spent; these are the new joints.

1. **The bootstrap is now the whole trust root.** §2.3 has three moments and one of them depends on
   finding 17 being fixed. Is finding 17's fix sufficient to make route 2 sound, or does an
   attacker still have a path into a joining device's commitment?
2. **The refresh recomputation.** `C'ₖ = Cₖ + Σ C_{d,k}` is right if every dealer's commitment is
   verified and the dealer set is authentic. Who decides the dealer set, and can a member be made to
   recompute from a dealer list it did not agree to? `onRefreshMsg` dispatches on any member pk
   today.
3. **Never re-bootstrapping.** A member whose pinned commitment is wrong — a bug, a restore from
   backup, a half-finished refresh — has no way out but re-scanning. Is there a state where a real
   user is stuck and the only honest answer is "set this device up again"?
4. **Kind from the count.** Does any code path give a co-signer more than one share, or a device
   fewer than three, in a way that makes the weight table a bad discriminator? A paper backup's two
   is adjacent to nothing today, but it is one weight change away from a device.
5. **Storage.** The commitment is a small public value, but it is now the thing everything derives
   from. What does an attacker who can *write* the member's storage get that it did not have before?

## 11. Still open

1. **The weight table as an enforced rule.** §4 reads kind from the proven count, which needs
   "a co-signer holds exactly one share, a device exactly three, a paper exactly two" to be
   something the code refuses to violate rather than something it happens to do.
2. **Where proofs are carried.** A member message relayed by servers needs no new kind. A
   replaceable event per member would let a device fetch them with no server awake. Not chosen.
3. **Epoch skew.** A proof is epoch-bound; a member a generation behind produces proofs nobody can
   verify, and §5's hold-quietly rule makes that invisible. The honest behaviour is probably to
   report a member whose proofs are stale rather than hold for it in silence.
4. **What the person is shown** when §6's refusal fires. "Something changed about one of your
   devices and this phone did not see it happen" is true and unhelpful; the honest version names the
   device and offers the one recovery that works, which is setting it up again. Nobody has designed
   that screen.
5. **`mergeMembers` still copies a peer's `sharePub`** (`group.ts:1270`). 0.12.8 fixed what
   verification does with that copy, not the copy. Under this document the server should derive it
   too, and that is a two-line change worth making regardless.
