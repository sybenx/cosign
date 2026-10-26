# Progressive accounts — proposal, second draft

**Status: proposal, for review. Nothing here is built.** Written as specification text so
it can be attacked. It is not part of [COSIGN.md](COSIGN.md) until it has been reviewed
and the author agrees; §12 lists what it would change there.

This draft answers an independent red-team review of the first one
(`~/igloo/cosign-redteam-findings.md`, verdict: *don't build it as written*, four critical
findings). Everything it found is resolved here except one, which is a decision for the
author and is set out as a decision in §11 rather than settled quietly.

**What changed from the first draft**, in short:

- The second device **never receives a copy of the whole key** (was: a copy, plainly
  described). A phished join code now costs 3 revocable points instead of the identity.
- The whole key lives on **exactly one device** and is destroyed as soon as the invariant
  holds. Writing it down is no longer required of anyone.
- **Today's shape — distributed key generation with two or more always-on members — is the
  silent default** whenever one is reachable. The stages below are for when none is.
- A second rule beside the invariant: **what is kept away from home must reach the
  threshold on its own.** "Recoverable from the paper" was wrong; the paper is 2 and the
  threshold is 4.
- The member list is **signed by the user's devices**. Servers relay it and never author
  it. Without this, one server can make itself a device (red team C1).
- Reporting a theft is **never refused** by the invariant, and mutual reports take both
  devices out, so reporting first no longer wins.
- New members are on **probation**, and a device that has been offline must hear a signed
  epoch head from someone other than its asker before it co-signs.
- The claims about what a stolen device is worth are corrected: at every stage with a
  live helper, one device plus that helper signs.
- The first draft's four open questions are answered: what a granting operation costs is
  now the single open **decision** of §11; a member worth 1 point is useful only as an
  always-on holder that is away from home and can refuse (§8.1); a wiped copy is one whose
  key was destroyed, and a copy that was written down can never be known wiped (§4.3,
  §4.4); and the paper is not a gate before a two-device split — §3.2 simply doesn't claim
  to be a split.

---

## 1. The two rules

> **The invariant.** After the loss of any one *failure domain*, the holders that remain
> MUST still reach the threshold.
>
> **The outside rule.** What is kept away from where the devices live MUST reach the
> threshold on its own.

A **failure domain** is one physical device, or one server operator. Two apps on one
handset (COSIGN.md §4.1) are one domain, not two; a client that cannot tell assumes the
worst. Counting members instead of domains is how an account with 6 points on one phone
comes to believe it is safe.

The invariant is why COSIGN.md 0.2 asks for two servers: a device (3) and two servers (2)
is 5, and losing the device leaves the paper (2) with those servers (2), which is 4. The
rule is what matters; two servers is one way to satisfy it.

The outside rule is separate because the invariant counts *one* loss and a fire is not
one loss. Shapes that satisfy it: the paper plus two always-on members (today); two papers
in two places; the paper plus a device that lives somewhere else. The paper **alone** does
not: it is worth 2.

> **The forgetting rule.** A client MUST NOT destroy, or advise the user to destroy, a
> whole-key copy until **both** rules hold without it.

- The invariant MUST NOT be read as a reason to refuse anything a user does to *protect*
  themselves. Reporting a device lost or stolen is never refused, never delayed and never
  gated on the account's shape (§6.3). Where it leaves the account short, the client says
  so in one sentence and asks for the physical step that fixes it.
- Only **voluntary** removals and automatic replacements are refused by it (§8.3).

## 2. The default: don't start at the beginning

A new account SHOULD be created the way COSIGN.md already describes — distributed key
generation between the first device and two or more always-on members — **whenever one is
reachable**, with no question asked and no stage shown. No whole key is ever made, which
is strictly better than anything in §3, and it is what the reference implementation does
today.

The stages in §3 are for the cases that shape cannot serve:

- no always-on member is reachable, or the user declines them;
- the user wants to hold their own key (§7);
- an existing nsec is being brought in (COSIGN.md §3).

A client MUST NOT present the stages as a ladder, name them, or ask the user to advance.
It arranges what it has and says, in one plain sentence, only what the arrangement means.

## 3. The stages

### 3.1 One device, the whole key

The first device holds the whole key, as every signer does today, and is the NIP-46 signer
for everything else the user runs (COSIGN.md §6.1).

- There is no threshold and nothing is split. A device holding the whole key signs alone,
  for ever, and cannot usefully be reported lost: there is nobody to refuse it.
- The client MUST say once, in one sentence, that losing this device loses the account
  until a second holder exists, and MUST offer the two things that fix it — a second
  device, or the paper — **before** offering to write the key down.
- Writing the key down MUST NOT be required. Where the user chooses it, the client says
  plainly that the written copy stays a working key for ever, and records that a whole
  copy may exist (§4.3).

### 3.2 A second device: pieces, not a copy

The user signs into a second device of their own. **The whole key is not sent to it.**
Instead the first device deals the split it will keep for good: itself 3 shares, the new
device 3, threshold 4 — and keeps the whole key until §3.3.

- The new device alone is 3 points and signs nothing. It signs **with** the first device
  (6), which is already §5's device-to-device round.
- The first device goes on signing alone, because it still holds the whole key. Nothing
  the user can do becomes impossible while the account is in this shape.
- **A phished join code costs 3 points, not the identity.** This is the reason for the
  change: those 3 points are useless alone and are removed by a report and a refresh, where
  a copy of the key never could be.
- A client MUST NOT describe this as a split that protects against a stolen device. Until
  §3.3 the first device is still the whole key.

### 3.3 The invariant holds: the whole key goes

As soon as a third holder exists — a third device, the paper, or an always-on member — the
first device destroys the whole key and keeps only its 3 shares. It MUST be destroyed by
**destroying the key that encrypts it** (§4.4), not by deleting a record.

From here the account is an ordinary Cosign account: any two devices sign, or one device
and an always-on member; a stolen device is worth nothing on its own and is cut out by a
report and a refresh; the member list is signed (§4.1).

A client MUST NOT reach this stage while any whole copy is unaccounted for (§4.3).

### 3.4 The outside rule holds: a fire is survivable

The paper alone is 2 points and recovers nothing. Until what is away from home reaches 4
on its own, the honest sentence is: **a fire or a burglary that takes everything takes the
account, unless what you keep elsewhere adds up on its own.**

- Valid: the paper plus two always-on members; two papers in two places; the paper plus a
  device kept elsewhere.
- The paper MUST be openable without the user's devices: before an epoch commits, the
  dealers read their contributions back from at least two independent relays, and
  re-publish them periodically (COSIGN.md §8.2 already stores them on relays, every server
  and every device — the relays are the only part of that which survives the house).

### 3.5 What each stage really gives

| | Everyday signing | One device stolen, before it is reported | One device lost | Everything in the house lost |
|---|---|---|---|---|
| §2 default (DKG + two always-on) | one device, any time | signs as the user until reported; worth nothing after | still signing | recoverable: paper + two always-on |
| §3.1 one device | it signs alone | **the identity is gone** | the identity is gone | the identity is gone |
| §3.2 two devices, key on the first | the first alone; both together | the first: the identity. The second: signs while the first is reachable | first lost: gone. Second lost: nothing | the identity is gone |
| §3.3 three holders | any two, or one with an always-on member | signs while any other holder answers; worth nothing after a report | still signing | gone unless §3.4 holds |
| §3.4 | as above | as above | as above | **recoverable** |

The third column is the correction the review asked for: **a stolen device is worth nothing
only when no other holder answers it.** The user's own devices co-sign for each other
automatically, so a tablet at home on Wi-Fi is a live helper. What a report and a refresh
end is everything *after* the report.

## 4. Copies, and what "wiped" means

### 4.1 The member list is signed by the user's devices

A member list is authoritative only as a record the user's **devices** sign. Servers relay
it; they never author it.

- The record is either COSIGN.md §3's epoch record (kind 30242, signed by the group key)
  or a chain of membership changes, each signed by the `E` key of the device that made it
  and verifiable against that device's membership at the time. Removals are monotone: once
  a device has verified a removal, no later record may bring that member back.
- A device MUST NOT add a member, change a member's role, or change which indices a member
  holds on a server's word. A server MUST NOT take members from another server. Points
  move only by a refresh the device worked out itself.
- A device co-signs for another member only if it verified that member's addition: it
  helped, it vouched, or it holds the signed record.
- Until the signed record exists, **§5 MUST NOT ship**: a device that co-signs on a
  server-written list lets one server sign as the user (red team C1). This is the single
  blocking dependency in this document.

### 4.2 Nothing silently becomes a holder

Every operation that **creates or enlarges a share-holding member** — adding a device, a
server or a paper, and `grow` — is a *granting* operation and follows §11. Signing,
decrypting and connecting sites are not: they are revocable, and they stay instant and
silent.

### 4.3 A whole copy may exist

- A client MUST keep a durable flag — *a whole copy of this key may exist* — set by any
  history of §3.1, §3.2, an import, a take-out, or the user writing the key down.
- While it is set, the client MUST NOT show the account as split, protected against a
  stolen device, or safe. It MUST NOT be cleared by anything except the user saying the
  copy is destroyed, recorded with the date.
- No protocol can reach a copy. This is the price of §3.1 and the reason §2 is the
  default.

### 4.4 Wiped means its key is destroyed

A whole key, and any share, MUST be stored encrypted under a key of its **own** in the
platform's keystore, and wiping it MUST destroy that keystore entry. Deleting a record is
not wiping: preference files keep backups, flash keeps deleted blocks, and browser storage
keeps old values until compaction.

## 5. Signing between the user's own devices

COSIGN.md §5.1's first preference and §5.5, stated normatively. **Gated on §4.1.**

### 5.1 Presence

- A device announces **awake** to the user's other member devices when it connects and at
  a slow interval while connected (reference: 60 s), and **asleep** when it can. Never to
  a server, and a server's word about it is never accepted.
- A device whose last announcement is older than a small multiple of that interval
  (reference: 150 s) is treated as asleep.
- Each announcement carries a counter that only increases. Two live counters for one
  member key, or a counter that goes backwards, mean two copies of that device: other
  devices MUST stop co-signing for it and MUST tell the user which device it is.

### 5.2 Asking

- A device needing the rest of a signature MUST ask an awake device of the user's before
  any server, so that no server sees the event.
- If no awake device answers within a short time (reference: 1.5 s, the question re-sent),
  the coordinator asks the servers, and the device that did not answer is treated as asleep.
  Where presence is already stale, a coordinator MAY ask a device and a server at once.
- A coordinator MUST verify each partial it receives, so one bad co-signer is identified
  and skipped rather than failing every round.

### 5.3 Answering

A device asked by another member device MUST, before giving any partial:

- check the asker is a member whose addition this device verified (§4.1), and is not on
  probation (§11) or contested (§6.3);
- check the digest is that event's id under the account's key, computed from the event it
  was shown;
- refuse an event more than 30 s old (relays replay recent requests) or more than 10
  minutes in the future;
- refuse a round whose epoch is not its own (§5.4);
- refuse if it has itself been reported lost;
- answer a request it has already answered word for word, never with a second partial.

**The answering device runs the destructive policy itself** (COSIGN.md §5.3). It is a
co-signer, not a courier, and the asker may be a stolen device. With no archive of its own
it MUST still hold the always-held kinds — a request to vanish, a mass deletion, an
emptied profile, follow or relay list judged against whatever it has — for approval on a
device other than the asker. These are rare, so the cost is a prompt the user would want.

### 5.4 The epoch guard

- Every device-to-device round carries its epoch, and a device MUST refuse a round in any
  other epoch.
- A device that has been offline for longer than the presence timeout MUST hear a fresh
  **epoch head** — the signed record of §4.1, or a signed statement "I am on epoch *n*,
  nothing pending" — from a member **other than its asker** before it answers that asker.
  Equality of epochs proves nothing when both parties are behind: that is how a device
  removed while it was offline signs with a device that missed the news.
- Reports, removals and epoch heads are published to several relays, and devices read from
  several.
- With exactly two devices this rule cannot be met, because the only other member is the
  asker. That is another reason §3.2 is not a protected shape.

### 5.5 Refresh plans

A device accepts a refresh plan only if all of these hold:

- at least **two** dealers, which are distinct members, neither contested nor on probation;
- the holders are exactly its own verified member list, minus members whose removal it
  verified;
- the plan's starting points match the commitments it holds.

Otherwise it ignores the plan and tells the user. A single dealer knows every delta, so a
one-dealer plan plus any old share maps that share forward; and a plan that omits a member
strands it silently, which is a removal without a report.

Epoch identity is the hash of the committed plan. Where two plans claim one epoch, the one
that respects every verified removal wins, ties broken by the lower hash; a plan including
a member some device has verified as removed is invalid everywhere.

### 5.6 Shared secrets

Decryption and conversation keys (COSIGN.md §5.6) go the same way, so two devices read the
user's own messages with no server. Partials go only to members whose addition this device
verified, never to the paper and never to a removed member.

## 6. Devices, guests, and losing one

### 6.1 Is this device yours?

The one question this design asks, and the test it passes: the software cannot know the
answer, the user always can, and the answer changes what happens immediately.

- It MUST be asked on a device that is **already a member**, after that device scans the
  newcomer's code — never on the newcomer, which may be the attacker's machine. The
  newcomer's name is shown as its own claim ("calls itself *Pixel 7*").
- It MUST state the consequence in one sentence: *it will be able to sign as you whenever
  another of your devices is awake, and to report your other devices lost.*
- "Yours" makes the newcomer a member under §11 and puts it on probation (§11).
- A join code and a sign-in code MUST be distinguishable by the app, and a join code that
  arrived by a pasted link or a handoff rather than a camera scan MUST use QRST `compare`.

### 6.2 Guests

A machine that is not the user's holds no shares and no key, stores nothing that outlives
the session, and signs by asking one of the user's own devices, where the prompt and the
destructive check happen. Guest is the **default** when the question is not answered.

- A guest grant MUST have an absolute life (reference: 12 h) and an idle life (reference:
  30 min), both counted by the user's devices, not by the guest: a hostile machine will
  not end its own session.
- A guest MUST NOT be able to have anything signed that is part of Cosign's own control —
  membership records, the epoch record, operator and server lists — and MUST NOT receive a
  decryption without a prompt on the user's device.
- "Where it is" is the guest's claim and is labelled as one.

### 6.3 Reporting a device lost

- A report is never refused, never delayed, and never gated on the account's shape (§1).
- **Mutual reports take both devices out.** A device that has been reported lost keeps,
  for a window (reference: 7 days), the right to do exactly three things: report *its
  remover* lost, cancel a wait, and cancel a recovery. It may not sign, decrypt, vouch or
  deal. Two devices that report each other are both out and the account falls to the
  remaining holders or the paper.
- A device on probation cannot report another device.
- The refresh that follows a removal MUST be dealt by two members, neither contested.
- Serverless, a report is a message signed by the reporter's own key, carried
  device-to-device and published to several relays. A device that sees a report naming
  *itself*, from a member it has not removed, reports that member in return, which is how
  the rule above is reached without a server.
- While a paper recovery is pending, no member may vouch, export, or add a server or paper
  instantly: neither side of a contest may escalate during it.

## 7. Keeping the whole key, on purpose

Some people will keep their nsec, and this design MUST support that rather than discourage
it.

- A client MUST offer sign-in by transferring the key itself (QRST), MUST keep working
  normally afterwards, and MUST NOT nag, gate features or mark the account as deficient.
- It MUST say once what it costs: any device holding the whole key signs alone and cannot
  be reported lost.
- Reconstructing the whole key from a split account stays as COSIGN.md has it: the guarded
  path of §7.6, the escape hatch of §8.4, and *announce before showing* (§3).
- A whole-key signer MUST use fresh per-signature randomness (BIP-340 aux), never a stored
  counter, because copies of a whole key are copies of its signing state.

## 8. Always-on members

### 8.1 What one is for

It holds **one** share. It is not a custodian, not a coordinator for anyone else's
requests, and not a condition of having an account. What it adds:

- one device is enough at any moment, where otherwise two of the user's devices must be
  awake together;
- a lost device is refused by a member that is always there to refuse it;
- it holds what an absent member missed — refresh deltas and notices — and hands them over
  when that member next appears. With no always-on member, dealers MUST keep their deltas
  and re-send until each holder acknowledges, with no expiry;
- it enforces waits.

What it is not: a second opinion that matters (the device is the gate), and not a backup —
one point recovers nothing.

**One device and one always-on member is not a shape to aim for.** It is 4 points, so it
signs, but losing either leaves 3 and the invariant fails both ways, and a paper does not
fix it (2 + 1 = 3). A one-device account needs two always-on members and a paper, which is
COSIGN.md 0.2's shape. One always-on member is worth having only beside two or more
devices.

### 8.2 Self-describing, and small

- A server announces itself (COSIGN.md §9.5) and SHOULD say, in words the user will read,
  who runs it, where it runs, whether it is always on, what happens to its share if it
  dies, and whether enrollment is open or invited.
- A client MUST show that description before adding it, MUST say who is making the claim,
  and MUST NOT present an unverified claim as verified.
- A member counts as **the user's own** — for NIP-46 signer keys and for privacy — only
  because one of the user's devices added it as such in the signed record (§4.1). It MUST
  NOT be inferred from any list a site could get signed.
- A member that is only ever somebody's fourth point needs one share, the grants and the
  signed member record, and **no archive**, which is the only part that grows. It belongs
  beside a relay or inside one, small enough to run for people one invites.
- Public servers stay allowed and useful, and MUST NOT be designed in: nothing here may
  require a particular operator, host or company to be reachable.

### 8.3 Removing one

> Members are never dropped to tidy up. An unused member costs nothing and is what makes a
> loss recoverable.

A member is removed only when the user removes it; when at least two other always-on
members have seen it silent for 7 days or more (so in an account with one or two such
members, only the user can); or when the user stops trusting it. And in every case:

- both rules of §1 MUST still hold afterwards. A voluntary removal that would break them
  is refused, with one sentence saying why and an offer to add another member first. This
  never applies to reporting a theft (§6.3).
- A member the user added by hand MUST NOT be removed automatically, however silent. After
  a week the client says so **once** and offers to add another.
- A silent replacement is allowed only for a member the client chose itself, never one the
  user added, and only while §1 holds throughout.

*This replaces "never fewer than two servers": the floor is the rules, not a count.*

## 9. Today's accounts

- A client MUST NOT change an existing account's membership to match a stage.
- Accounts made under COSIGN.md 0.2 satisfy the invariant **if they have a paper**. A
  device with two servers and no paper does not: lose the device and 2 points remain. The
  client says so once, in one sentence, and offers the paper. It does not ask again.
- The only behaviour that reaches existing accounts is §5, and only after §4.1. Their
  devices then sign with each other when both are awake, and their servers stop seeing
  those events. No membership change, no epoch change, nothing to migrate.
- No stage is recorded anywhere; the arrangement is read off the signed member record every
  time it is needed. The exception is §4.3's flag, which is not about members.

## 10. Threat model

The standing properties of COSIGN.md §12 are unchanged: one piece signs nothing, all the
servers together are 3 points, and a thief who holds 4 points of one epoch holds the
identity for good. What this document adds or alters:

1. **A server that writes the member list** (§4.1). Closed by the signed record. Open in
   today's code: a server can inject a member that other servers treat as a device, which
   is permanent lockout rather than theft, because it holds no shares. Blocking for §5.
2. **A granting operation on one device's word** (§11). The open decision. Unresolved, it
   is the shortest path from one stolen device to the whole key.
3. **A whole copy nothing can reach** (§4.3). Mitigated by never making one by default
   (§2), by never sending one to a second device (§3.2), by crypto-shredding what the
   protocol holds (§4.4), and by an honest durable flag. Not solved, and not solvable.
4. **A fire** (§3.4). The paper alone recovers nothing. The first draft said otherwise and
   would have had users destroy a working off-site backup for one that cannot work.
5. **A stolen device with a live helper** (§3.5, §5.3). It signs until it is reported. The
   answering device's own destructive check is what keeps "until reported" from including
   a request to vanish.
6. **The removal race** (§6.3). Mutual reports take both out: a thief can deny service, not
   take over. Open in today's code, where the first report wins and the loser is silenced.
7. **A device that was away** (§5.4). Closed by epoch heads from someone other than the
   asker; equal epochs prove nothing.
8. **A plan with one dealer, or a plan that omits a member** (§5.5). Closed by the three
   conditions, which the servers already enforce and devices did not.
9. **A cloned device** (§5.1). Detected, not prevented, by presence counters.
10. **A guest that never ends** (§6.2). Bounded by lives the user's devices count.
11. **An operator list signed by the user for a site** (§8.2). A member never signs
    Cosign's own control kinds for a site; "the user's own server" comes only from the
    signed record.
12. **Storage is not uniform.** A device's 3 points are as strong as that device's storage:
    an Android keystore, or a file in a browser profile. An account is as strong as its
    weakest member, and a client MUST NOT imply otherwise.

## 11. The one open decision: what a granting operation costs

Granting operations are the ones in §4.2 — adding a device, a server or a paper, growing a
member, taking the key out. They are **permanent**: the pieces they hand out are 3 points
(a device), 2 (a paper) or 1 (a server) of the current epoch, and with the granting
device's own 3 that is at or past the threshold, which is the key itself. No report and no
refresh reaches it afterwards.

**The author's position** (2026-10-26, from §10 of the first draft): *I have my phone, my
tablet. I can use either to sign into my computer. If they can all coordinate and can be
LIVE, then we treat them as worthy piece holders.* And: *I think if you can fingerprint in
with one device, you're good. It's the second gate past just stealing a phone.* So: either
device may vouch, with its own lock asked for at that moment (COSIGN.md §7.1 already
requires it, with no cached unlock), the other device helps silently, every member is told
afterwards, and nothing waits.

**The review's objection.** The fingerprint is one gate, and thinner than it looks:

- phone biometric prompts fall back to the PIN, and watching the PIN then taking the phone
  is the common high-value theft (Apple's Stolen Device Protection exists for exactly this
  and answers it with biometrics-only plus an hour's delay away from familiar places);
- the keystore argument holds only for Android: the extension and the Tauri Mac keep their
  shares in profile files, so a copied profile vouches with no prompt to pass at all —
  **verified in today's extension code**;
- today's servers accept `lock: true` as a claim, so this is already reachable through any
  honest server, and §7.1's hardware-bound lock (see
  [user-verification.md](user-verification.md)) is not built.

**The options the review proposed**, either of which would close it:

| | What the user does | What a thief with one device and a watched PIN gets |
|---|---|---|
| **A. As the author decided** | nothing extra: fingerprint on one device, instant | the whole key, in seconds |
| **B. Two devices confirm** | "confirm on your tablet too" — a physical step, each with its own lock | nothing, unless they hold two devices |
| **C. A short delay** | nothing, unless they are in a hurry: the add completes in an hour, any device can cancel, and the newcomer gets no pieces before then | an hour in which every device is told and can cancel, and the owner can report the device |

B and C can be combined: two confirmations make it instant, one makes it an hour.
Signing stays instant and silent under all three — this is only about handing out pieces.
C is the one that costs the user nothing when they are not in a hurry, and it is the shape
COSIGN.md §7.4 already has (a wait that every member enforces and any device can cancel),
with the one change that the newcomer receives **no pieces** until it ends, because a wait
that only delays trust is useless once the pieces are delivered.

**This draft does not choose.** Every other section is written so that either answer fits:
§4.2 names the operations, §11 decides what they cost. Probation (below) is assumed in
both, because it costs nothing either way.

**Probation.** A newly added member MAY sign, and MUST NOT vouch, help a repair, report
another member lost, deal a refresh, or cancel anything, for a window (reference: 72 h).
Nothing about it is shown to the user, and it blunts §10.2, §10.5 and §10.6 whichever way
the decision goes.

## 12. What this would change in COSIGN.md

- **§3**: "At least two servers, from the start" becomes the two rules of §1, counted by
  failure domain. The parameters are untouched.
- **§3 (epoch record)**: it becomes the authoritative member record, signed, with monotone
  removals — and it has to be built (§4.1).
- **§4**: a third kind of participant, the guest, which holds nothing.
- **§5.1, §5.5**: device-to-device signing becomes normative, with §5's presence, asking,
  answering, epoch-head and plan rules, and the answering device as a destructive gate.
- **§7.1**: granting operations are named as a class (§4.2) and priced by §11; "pieces are
  computed only for an add this device started or confirmed" becomes a MUST.
- **§7.2**: mutual reports take both devices out, and a removed device keeps revoke-only
  rights for a week.
- **§7.4**: a wait means the newcomer receives nothing until it ends.
- **§8.1–8.3**: the outside rule, and the paper readable from relays without the devices.
- **§9.5**: the self-description fields, and that a client must not dress a claim as a fact.
- **§12**: the storage caveat of §10.12, and that a stolen device with a live helper signs
  until it is reported.
