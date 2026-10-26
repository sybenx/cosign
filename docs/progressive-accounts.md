# Progressive accounts — proposal

**Status: proposal, for review. Nothing here is built.** It is written as specification
text so that it can be argued with and attacked; it is not part of
[COSIGN.md](COSIGN.md) until it has been reviewed and the author agrees. What it would
change in that document is listed in §11.

An account in COSIGN.md 0.2 begins at its final shape: a device, two or three servers,
a threshold of 4, all arranged in one setup flow (§3, "At least two servers, from the
start"). That is the right end state and the wrong beginning. It asks someone who has
nothing but a phone to pick servers before they have anything worth protecting, and it
makes an always-on member run by someone else a condition of having an identity at all.

This proposal starts where people actually start — one device holding one key — and
describes how an account grows into a threshold key as the user acquires the things that
make one possible, with **no step the user has to understand, choose or name**. The
design constraint, in the author's words: *our design should not require Cloudflare to
be online. A phone and a tablet should be enough to do anything.*

The parameters do not change. Threshold 4, a device worth 3, a server 1, the paper 2
(§3) carry every stage below; nothing here needs new cryptography, and the only
normative rule it removes is the requirement to have two servers from the start.

## 1. The rule everything follows

> **The invariant.** After the loss of any one member, the members that remain MUST
> still reach the threshold.

Every stage, every transition and every removal below is a consequence of it. It is also
the real reason COSIGN.md asks for two servers: a device (3) and two servers (2) make 5,
and losing the device leaves the paper (2) and two servers (2), which is 4. The rule is
what matters; two servers is one way to satisfy it.

A second rule governs when the user may stop keeping the key themselves:

> **The forgetting rule.** A client MUST NOT destroy or stop backing up the whole key
> until the invariant holds **and** every copy of the whole key is accounted for (§3.3).

## 2. The stages

Stages are a description of how an account grows, not a classification of users. **A
client MUST NOT show the user a stage, name one, or ask the user to advance.** It
arranges what it has and says, in one plain sentence, only what the arrangement means
for them (§0a of [servers-optional.md](servers-optional.md)).

### 2.0 One device, one key

The user's first device holds the whole key, as every signer does today. It is the
NIP-46 signer for everything else they use (§6.1): a site or app on another machine asks
it, and it signs alone.

- There is no threshold and nothing is split. The key MUST be backed up by the user —
  written down, or copied to a second device (§2.1) — because nothing else holds it.
- A device holding the whole key can sign alone, forever. It cannot be reported lost in
  any meaningful sense: there is nobody to refuse it. The client MUST say this once, in
  one sentence, and MUST NOT nag.

### 2.1 Two devices, two copies

The user signs into a second device of their own. The whole key goes to it, by QRST
transfer (§3, "Creating the key") or any means the user chooses.

- **This is a copy, not protection.** Either device can sign alone; losing either one
  loses nothing; a thief with either one has the identity for good. What it buys is
  availability: whichever device is awake answers, so NIP-46 sites work when one of them
  is off.
- The client MUST describe it as a copy, in those words or plainer ones. It MUST NOT
  describe two copies as a threshold, a split, or "secured".
- Each device holds the per-site signer keys (§6.1), so either answers a site.

### 2.2 Three or more devices: the split

When the user's third device is added — or the second, if the split also makes a paper
backup (§2.3) — the account MAY become a threshold key: **each device holds 3 shares at its own indices,
the threshold stays 4.**

- Any **two** of the user's devices sign (3 + 3 = 6). **No single device signs** (3 < 4).
- A stolen device is worth nothing on its own, can be reported lost (§7.2), and is cut
  out by the refresh that follows.
- Two devices are enough to do everything: sign, add a device by repair (§7.1, which
  needs 4 points), report one lost, and deal a refresh (§7.3, which needs two dealers and
  has them). **Nothing outside the user's own hardware is required at this stage.**
- The split is a rebuild and re-split (§3): one device, which already holds the whole
  key, deals the new shares and wipes it. It exposes nothing that was not already
  exposed, which is why this transition is safe to make here and nowhere else.
- A client MUST NOT split unless the invariant will hold afterwards and §3.3 is
  satisfied. Three devices satisfy the invariant (losing one leaves 6). Two devices do
  not (losing one leaves 3), so a two-device split MUST make the paper backup as part of
  the same step (§8.2 computes its shares by repair), not afterwards.
- **The paper backup is not the written-down key.** At §2.0 and §2.1 a written copy is
  the whole key; the paper backup of §8.1 is a 2-point member of a split key, worth
  nothing on its own. The first is destroyed when the account splits (§3.3); the second
  only exists after it.

### 2.3 A holder that is not in the house

Three devices satisfy the invariant and still lose everything to one burglary, one fire
or one flood, because they are in the same place. The account SHOULD therefore have at
least one holder that is somewhere else:

- **The paper backup** (2 points, §8.1), kept away from the devices. It costs nothing,
  needs nobody, and covers correlated loss. With it, two devices are enough to satisfy
  the invariant and the user may forget the key.
- **An always-on member** (1 point, §7): a server, which is what makes a lost device a
  tap rather than an errand — see §7.1 for exactly what it adds and what it costs.

After this, and only after this, the forgetting rule is satisfied: the whole key may be
destroyed, and the user is holding no secret that can be stolen in one piece.

### 2.4 What each stage can do

| | Everyday signing | One device stolen | One device lost | Everything in the house lost |
|---|---|---|---|---|
| 2.0 one device | it signs alone | the identity is gone | the identity is gone | the identity is gone |
| 2.1 two copies | either signs alone | the identity is gone | nothing lost | the identity is gone |
| 2.2 three devices | any two, together | worth nothing; report it | still signing on the other two | the identity is gone |
| 2.2 + paper | any two, together | worth nothing; report it | the other device and the paper | recoverable from the paper |
| 2.3 + always-on | **any one device**, at any time | worth nothing; report it and it is refused at once | still signing, alone | recoverable from the paper |

## 3. Transitions

### 3.1 What each one is, mechanically

| From → to | Mechanism | Who must be present |
|---|---|---|
| 2.0 → 2.1 | copy the key (QRST transfer) | both devices |
| 2.1 → 2.2 | **rebuild and re-split** (§3): one device deals, every holder gets new shares, the whole key is wiped everywhere | every device holding a copy (§3.3) |
| 2.2 → add a device | **repair** (§7.1): new indices, same key, no rebuild | the new device and 4 points of helpers |
| 2.2 → add an always-on member or paper | **repair** at new indices, threshold unchanged | 4 points of helpers |
| any → remove a member | **report lost** (§7.2) then **refresh** (§7.3) | 4 points, two of them dealers |

Only the 2.1 → 2.2 transition rebuilds the key. Everything after it is repair and
refresh, which never reconstruct it.

### 3.2 Weights never need to change

Because a device is worth 3 and the threshold is 4 at every stage, adding a member never
requires a new threshold or a redistribution. The arithmetic that changes is only *who
holds what*:

- devices 3 each, threshold 4 → any two devices;
- plus an always-on member at 1 → **one** device plus that member;
- plus the paper at 2 → one device plus the paper.

Adding an always-on member therefore **lowers** the everyday requirement from two of the
user's devices to one device and that member. That is the trade it exists to make, and
it is the same trade COSIGN.md §12 already accepts ("a stolen unlocked device plus one
cooperating server is 4 points"). A client MUST NOT present an always-on member as
strictly safer: it makes the account survive one device being asleep, and it makes a
stolen unlocked device one cooperating member away from the identity, which is why that
member MUST be able to refuse (§7.2's instant block).

### 3.3 Leaving the copy stage is one-way, and only once every copy is accounted for

At stage 2.1 every device holds the whole key. A split cannot take that back from a
device that is not there: a device that is offline when the account splits still holds a
whole key, and no refresh, removal or epoch reaches it.

- A client MUST NOT split unless every device that holds a whole copy either takes part
  in the split or is **known to have wiped it** (it says so, and the client has heard it).
- **A copy the user wrote down counts.** A key written on paper, kept in a password
  manager, or mailed to themselves at §2.0 is a whole copy that no protocol can reach.
  A client MUST remind the user of it once when the account splits, in one sentence, and
  MUST NOT claim the old copy stopped working, because it did not.
- A device that cannot be reached MUST be treated as still holding the whole key: it is
  listed as such, the user is told in one sentence, and removing it from the account does
  **not** make its copy harmless. The only remedy is to reach it, or to accept that the
  copy exists.
- This is the sharpest edge in the whole model. It is the price of starting with copies,
  and starting with copies is what makes the first stage usable at all.

## 4. Is this device yours?

The one question this design asks the user, and the only one that passes the test for
asking anything: *the software cannot know the answer, the user always can, and the
answer changes what happens immediately.*

- **Yours.** The device becomes a member: 3 shares by repair (§7.1) at stage 2.2, or a
  copy of the key at stage 2.1. It signs with the user's other devices, follows
  refreshes, and can report another device lost.
- **Not yours** — a library, work or borrowed machine. It is a **guest**: it holds no
  shares and no key, it stores nothing that outlives the session, and it signs by asking
  one of the user's own devices, where the prompt and the destructive check happen
  (§5.2). A guest's grant MUST end with the session rather than taking the 90-day default
  of §6.2, and it MUST be listed on the user's devices with where it is, so signing it
  out is one action.
- A client MUST default to **guest** when the answer is not given.
- A guest is the existing NIP-46 or QRST path (§6.1) with a shorter grant. It needs no
  new protocol.

## 5. Signing between the user's own devices

This is COSIGN.md §5.1's first preference and §5.5, stated normatively, because the
progressive model depends on it: at stage 2.2 there is nothing else to sign with.

### 5.1 Presence

- A device announces **awake** to the user's other member devices when it connects and at
  a slow interval while connected (reference: 60 s), and **asleep** when it can.
- These announcements MUST NOT be sent to a server, and a server's word about them MUST
  NOT be accepted.
- A device whose last announcement is older than a small multiple of that interval
  (reference: 150 s) is treated as asleep.

### 5.2 Asking

- A device needing the rest of a signature MUST ask an awake device of the user's before
  any server. No server then sees the event at all.
- If no awake device answers within a short time (reference: 4 s, with the question
  re-sent), the coordinator falls back to the servers, and the device that did not answer
  is treated as asleep until it says otherwise.
- A device MUST NOT be asked for two rounds in parallel.
- Nothing about this is configurable and nothing is asked: the arrangement is whatever is
  best at that moment, and it changes as devices come and go.

### 5.3 Answering

A device asked by another member device MUST, before giving any partial:

- check the digest is that event's id under the account's key, computed from the event it
  was shown and not taken on trust;
- refuse an event whose `created_at` is more than 30 s in the past (relays replay recent
  ephemeral requests, §5.2) or more than 10 minutes in the future (§5.3);
- refuse a round whose epoch is not its own (§5.4);
- refuse if it has been reported lost;
- answer a request it has already answered **word for word**, and never make a second
  partial for the same request (§11).

A host holding the user's archive SHOULD do the destructive check itself (§5.3) and MAY
refuse. A host without the archive relies on the asking device's check, which §5.5
accepts between two of the user's own devices.

### 5.4 The epoch guard

- Every device-to-device round MUST carry the epoch it is in, and a device MUST refuse a
  round in any other epoch. Being behind is not a refusal of the request: the coordinator
  goes on to another member.
- A device that has been offline MUST catch up before taking part in a device-only round.
  Without this, a device removed while it was offline (§7.2) could sign with a device that
  missed the news — the hole that servers close today by refusing.

### 5.5 Shared secrets

Decryption and NIP-44 conversation keys (§5.6) go the same way: two devices hold 6
points, so the user reads their own messages with no server involved. The rule that
partials go only to active member devices is unchanged.

## 6. Keeping the whole key, on purpose

Some people will keep their nsec, and that is a choice this design MUST support rather
than discourage: *we literally allow QRST sign-in for those that want to raw dog their
nsec.*

- A client MUST offer sign-in by transferring the key itself (QRST), MUST keep working
  normally afterwards, and MUST NOT nag, gate features, or mark the account as deficient.
- It MUST say once, in one sentence, what it costs: any device holding the whole key can
  sign alone and cannot be reported lost.
- Going the other way — reconstructing the whole key from a split account — stays as
  COSIGN.md has it: the guarded path of §7.6, the escape hatch of §8.4, and *announce
  before showing* (§3), so every member learns of it before the key is shown.

## 7. Always-on members

### 7.1 What one is for, and what it is not for

An always-on member holds **one** share. It is not a custodian, not a coordinator for
anyone else's requests (§5.6), and not a condition of having an account. What it adds:

- **One device is enough at any moment.** Without it, two of the user's devices must be
  awake together.
- **A lost device is refused at once**, by a member that is always there to refuse
  (§7.2), rather than only when another device happens to be awake.
- **It holds what an absent member missed**: refresh deltas and notices wait on it (§7.3)
  and are handed over when that member next appears. With no always-on member, the
  dealers must keep their deltas and re-send until each holder acknowledges.
- **It enforces waits** (§7.4).

What it is not: a second opinion that matters (the device is the gate, §5.2), and not a
backup (it is one point; it cannot recover anything alone).

### 7.2 Self-describing, and small

- A server announces itself (kind 30243, §9.5). It SHOULD say what it is in words the
  user will read: who runs it, where it runs, whether it is always on, what happens to its
  share if it dies, and whether enrollment is open or by invitation.
- A client MUST show that description before adding the server, MUST say who is making
  the claim, and MUST NOT present an unverified claim as verified. A self-description is a
  claim, not a guarantee.
- A member that is only ever somebody's fourth point needs **one share, the grants and
  the member list, and no archive** — the only part that grows. The destructive check is
  the device's (§5.2), and history and Undo can come from the user's own devices. Such a
  member belongs beside a relay or inside one (§9.1) and is small enough to run for
  people one invites.
- Public servers remain allowed and useful. They MUST NOT be designed in: no part of this
  document may require a particular operator, host or company to be reachable.

### 7.3 Removing one

> Members are never dropped to tidy up. An unused member costs nothing and is the thing
> that makes a loss recoverable.

A client MUST NOT remove a member because it is unused, because the user has acquired
other devices, or to reach a target number. A member is removed only when:

1. **the user removes it**, explicitly, from a device (always allowed, subject to 4
   below); or
2. **it is gone**: at least two other always-on members have seen it silent for 7 or more
   days (§7.7), not on one device's word — so in an account with one always-on member or
   two, this case can never be reached and only the user can remove it; or
3. **the user no longer trusts it**, which is case 1 with a reason.

And in every case:

4. **the invariant MUST still hold afterwards** (§1). A removal that would leave the
   account unable to lose one more member MUST be refused, and the client MUST say why,
   in one sentence, and offer to add another member first.
5. A member the user added by hand MUST NOT be removed without the user's say-so, however
   silent it has been. After a week of silence the client says so **once**, plainly, and
   offers to add another; it does not ask again.
6. A silent replacement — dropping a member and adding a fresh one in the same refresh —
   is allowed only for a member the client chose automatically, never for one the user
   added, and only when 4 holds throughout.

These are the rules the author already approved for servers, restated in terms of the
invariant rather than a server count, because under this proposal an account may
legitimately have one always-on member or none. *This corrects the earlier phrasing
"never fewer than two servers": the floor is the invariant, not a count.*

## 8. Today's accounts

- A client MUST NOT change an existing account's membership to make it match a stage.
  Accounts made under COSIGN.md 0.2 are already at §2.3 — a device, two or three servers,
  a paper — and already satisfy the invariant.
- The only behaviour that reaches them is §5: their devices start signing with each other
  when both are awake, and their servers stop seeing those events. No membership change,
  no epoch change, nothing to migrate, nothing shown.
- Accounts created after this proposal begin at §2.0 and grow. There is no flag
  distinguishing them, and no stage recorded anywhere: the arrangement is read off the
  member list, every time it is needed.

## 9. Threat model

The ones that are new or that change, worst first. The standing properties of §12
(one piece signs nothing; the servers together are 3; a thief with 4 points of one epoch
holds the identity for good) are unchanged by anything here.

1. **A whole copy that was never wiped** (§3.3). The worst problem in this model. A
   stage-2.1 device that is offline when the account splits holds the key for good, and
   nothing in the protocol can reach it. Mitigation is bookkeeping and honesty, not
   cryptography: the client knows which copies it has heard wiped, says which it has not,
   and never claims the account is split while one is outstanding.
2. **The copy stage itself** (§2.1). Two copies is two chances to lose the identity
   outright, and a client that lets a user sit there indefinitely has left them where
   every single-key signer already is. It is a stage to pass through, not an end state —
   but the client MUST NOT force the user out of it either.
3. **Everything in one place** (§2.3). Three devices satisfy the invariant and still go
   up in one fire. The paper is the cheapest answer and needs no operator.
4. **An always-on member plus a stolen unlocked device** is 4 points (§3.2). Accepted,
   as §12 already accepts it, and the reason the member must be able to refuse. Note what
   changes: at §2.2, with no always-on member, a stolen unlocked device is worth
   *nothing*, because there is no 1-point member in the world to complete it. Adding one
   gives that up for liveness, deliberately.
5. **A device removed while offline, signing with a device that missed the news**
   (§5.4). Closed by the epoch guard. Without it, device-to-device signing reopens a hole
   that servers close today by being the ones who refuse.
6. **A guest on a hostile machine** (§4). It holds nothing, so a keylogger takes nothing;
   the exposure is bounded by the session and the grant, and signing out is one action.
   This is strictly better than typing an nsec into a library computer, which is what
   people do today.
7. **A self-described server** (§7.2). "Always on and safe from catastrophe" is a
   sentence someone typed. A client that repeats it as fact is lying on their behalf.
8. **Keeping the nsec** (§6). Unrevocable by design, chosen knowingly, and not this
   document's business beyond saying so once.
9. **Nonce reuse across devices.** Two devices answering rounds concurrently is new
   traffic on the same shares; a device MUST keep nonces in memory only and MUST NOT
   resume a round across a restart (§3, "Nonces"). A round lost to a restart is a round
   that must fail, not one to pick up.
10. **A relay that keeps nothing.** With no always-on member, deltas live only with the
    dealers until each holder acknowledges (§7.1). A holder that is away for longer than
    the dealers keep trying is re-added by repair (§7.3), which needs the invariant to
    have held all along.

## 10. What this does not answer

1. **Who vouches at stage 2.2 when the second device is the only other member?** §7.1
   wants two devices to vouch for an instant add, or one with its lock; with exactly two
   devices the second case is the only one available, and the wait of §7.4 has no
   always-on member to enforce it. Either the wait is held by the other device, or adding
   a third device at this stage is instant on one lock. This proposal does not choose.
2. **Whether a device should ever hold fewer than 3 shares** — an old phone in a drawer,
   a cheap always-on box at home — and whether "a device of mine that is worth 1" is a
   useful third category beside device and guest.
3. **How a client knows a copy was wiped** (§3.3) beyond the device saying so.
4. **Whether the paper should be mandatory before splitting at two devices**, as §2.2
   requires, or merely strongly offered. Making it mandatory is a gate, and gates are
   what this design avoids; not making it mandatory leaves the user one loss from nothing.

## 11. What this would change in COSIGN.md

- **§3**: "At least two servers, from the start" becomes the invariant of §1. The
  parameters (t = 4, device 3, server 1, paper 2) are untouched.
- **§4**: a third kind of participant, the **guest**, which holds nothing (§4 above).
- **§5.1, §5.5**: device-to-device signing becomes normative and built, with the presence,
  asking, answering and epoch rules of §5 above.
- **§7**: a new subsection for removing a member, as §7.3 above; §7.7's dead-server rule
  becomes a special case of it.
- **§9.5**: the self-description fields of §7.2 above, and the rule that a client must
  show them and must not dress a claim as a fact.
- **Status**: the stages of §2, and the note that no part of the design requires a
  particular operator to be reachable.
