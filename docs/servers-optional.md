# Servers optional

A write-up, not a decision, and nothing here is built. It answers a question the user
asked: *is there any possible way we can get around needing dedicated cosign servers? Or
does it mean we have to hand sites FROST key shares? Is that acceptable?*

Short answer: **you can get rid of dedicated servers, and it doesn't need sites to hold
shares.** The thing a server supplies in the everyday path is one point, and a second
device supplies three. Giving a site a share is possible and the weights already have a
slot for it, but it is either redundant — you have a second device — or load-bearing for
the one person who can least afford it, and it quietly breaks the invariant the whole
design rests on. The honest cost of dropping servers is paid somewhere else: **a lost
device stops being a tap and starts being a trip to the paper backup.**

## 0a. Nothing is asked of the user

A steer from the user, which decides more of this than it looks: *people should just be
automagically shifted around to the best set of circumstances for themselves.* Telling
someone "you now have enough devices to stop relying on servers" is asking them to manage
their keys, and that is the thing this design exists to abolish.

So everything below is chosen by the software, continuously, with no prompt and no setting:
which member supplies the fourth point (an awake device if there is one, a server
otherwise), when a refresh happens, which sites are reissued to, and whether an always-on
member is used or merely kept. The user is shown only what they must physically do — scan
a code to add a device, keep the paper somewhere — and told in one plain sentence when an
arrangement changes something they would care about. That is a sentence, not a choice.

A corollary worth keeping in view: **not using a server is better than not having one.**
An unused server costs nothing, sees nothing, and is still the point that turns a lost
device into a tap rather than a trip to the paper (§3).

## 1. Where the fourth point comes from

Threshold 4. A device holds 3, a server 1, the paper 2 (§3). So every signature is a
device plus one more point, and there are exactly three ways to find it:

| The fourth point | What it is worth | What it costs |
|---|---|---|
| Another of the user's devices (3) | 6 points, **no server sees the event at all** | both devices must be reachable |
| A server (1) | 4 points, always on | that server sees every event it co-signs |
| A site or app holding 1 | 4 points | see §4 — it doesn't survive the arithmetic |

The first of these is already in the specification twice: §5.1 prefers another device
when one is awake, and §5.5 says two devices may sign with no server at all. Neither is
built, and neither was ever waiting on a second device to exist: this account has had a
phone and a tablet signed in for a while, with a browser extension or two beside them, and
the Mac makes a third today. Several devices have been the normal shape all along —
device-to-device signing is simply unbuilt, and §5.1 has preferred it on paper the whole
time.

So "servers optional" is not a new mechanism. It is §5.1 point 1, finished.

## 2. Device-only signing (§5.5): what is missing

The maths needs nothing new: a round of a device's 3 shares plus another device's 3 is
the same round as 3 plus a server's 1, with more partials in it. What is missing is
plumbing, and all of it is in the repository rather than in the spec:

- **Presence.** §5.1 wants "awake" announcements between the user's own devices, at a slow
  interval, never to a server. Nothing announces anything today.
- **A device will not co-sign for a device.** The phone takes a sign request only from a
  member whose role is `server` (`Phone.kt`, `onSignReq`); the member library asks only
  servers (`withAServer`). The checks underneath generalise — the phone already requires
  the asker's commitments to be exactly the asker's own indices, which a device satisfies
  with three — so this is a role filter and a second code path, not new cryptography.
- **The epoch guard of §5.5.** A device-only round must carry the epoch, a device must
  refuse any round below the newest epoch it has seen, and after coming online it must
  catch up before taking part. Otherwise a device removed while it was offline could sign
  with one that missed the news. Servers are what close that hole today.
- **An archive on both devices.** The destructive check is the device's own (§5.2), so the
  device that answers needs the recent versions of the user's lists. The phone has them;
  the Mac has none.
- **Refresh with two devices dealing.** A refresh wants two independent dealers so that no
  one of them alone can map an old share onto the new epoch. Two devices are two dealers,
  and the runner already takes a list of dealer keys. A server, though, refuses to take
  part in a refresh unless one of the dealers is a server (`group.ts`, the `plan.dealers`
  check) — that rule stays right for a group that has servers, and does not apply to one
  that has none.
- **Waits move into the devices.** A wait is enforced today by servers refusing to take
  part before it ends (§7.4). With no server, the other device has to hold it: it keeps
  the newcomer's "not before" date and refuses any round that includes the newcomer's
  indices until then. That is enforceable, and it is the only part of §7 that needs
  rewriting for serverless groups.
- **Delivering deltas to a device that is away.** Refresh deltas wait on the servers *and*
  on relays (kind 1059, 30-day expiry, §11). With no server, only the relays hold them,
  and a relay is not obliged to keep anything. The dealers must therefore keep their
  deltas and re-send until the holder acknowledges — the acknowledgement already exists
  (`refreshed`).
- **Nothing extra for devices that are away.** A refresh does not need everyone awake, and
  it never did: the two dealers must be online, and every other holder gets its own deltas
  sealed to it and applies them whenever it next connects. Today those wait in the servers'
  mail (50 items, kept 30 days, handed over when a member next says anything) and the
  dealers also re-send their parts for about twenty seconds. The members that are awake move
  to the new epoch at once; one that was away is simply on the old epoch until it catches
  up, and while it is, it cannot co-sign with the ones that moved — the account goes on
  signing with whoever did. With no server there is no mailbox, which is the gap above:
  the dealers have to keep their deltas and re-send until each holder acknowledges.
- **Waking the phone.** Push today is a server POSTing "wake up" to the user's push
  endpoint (§10). Nothing about that needs a server: it is an HTTPS POST that any device
  can make, as long as it holds the endpoint. A device that is awake can wake the other
  one. The endpoint is content-free, so handing it to the user's own devices costs
  nothing.

None of that is large. It is a week-shaped piece of work, not a quarter-shaped one.

## 3. The invariant, and what serverless really costs

The rule behind "at least two servers, from the start" (§3) is simpler than it looks:

> **After losing any one member, the rest must still reach 4 points.**

Today: device 3 + two servers 2 = 5. Lose the device, the paper and two servers make 4.
Lose a server, the device and the other server make 4. That is the whole reason for the
second server.

Serverless groups satisfy the same rule with their own shapes:

| Group | Everyday | Lose one member |
|---|---|---|
| 1 device, 0 servers | **cannot sign** (3 < 4) | — |
| 2 devices, 0 servers | 6 | **locked out**: 3 points left, until the paper |
| 2 devices + paper, 0 servers | 6 | survivor 3 + paper 2 = 5 ✓ (get the paper out) |
| 3 devices, 0 servers | any two: 6 | 6 ✓, and two dealers left for the refresh |
| 1 device + a relay holding 1 | 4 | paper 2 + relay 1 = 3 ✗ — still wants a second |

So: **two devices and no paper is the one shape that looks fine and isn't.** Both devices
work, the user signs happily for a year, and the day a phone goes in a river they have 3
points and no fourth anywhere. With servers, that same day is a tap on the other device.
That is the real price of dropping servers, and it is the one thing a person must be told
plainly at setup: *no server means a lost device means the paper.*

Three devices avoids it (phone, laptop, tablet — or the Mac app, the extension and the
phone, which is a shape plenty of people already have). So does keeping the paper.

## 3a. Yours, or not yours

A steer from the user, and the best shape in this document: *if you're on the internet
using Nostr, you're on a device. The only time I can imagine you don't have enough of
your key on that device is a library computer or a work computer or a friend's computer…
so maybe there's a decision you make about whether the device you're signing into is
yours or not. And that decides how many pieces it gets. How much authority.*

**Yours: a full device, 3 points.** The existing add-a-device flow (§7.1) — show a code,
scan it with a device you already have, confirm with its lock — and from then on nothing
is asked again. It signs with any other awake device of yours and no server sees the
event; it follows refreshes; it can report another device lost. This is built.

**Not yours: a guest, 0 points.** It holds nothing, stores nothing, and signs by asking
one of your own devices, which is where the prompt appears and where the destructive check
happens (§5.2). This is also already built — it is precisely what a browser with no
extension does today through QRST sign-in or nostrconnect (§6.1). What is missing is only
that it behaves like a guest: a grant that ends with the session rather than the 90-day
default (§6.2), nothing written to disk, and a line in the device's own list saying where
it is, so signing it out is one tap. On a machine that isn't yours this is the whole of the
defence, and it is a good one: a keylogger cannot take a piece that was never there, and
the worst case is a session that signs while you are sitting in front of it.

**Why this question is allowed, when §0a says not to ask.** Because the software cannot
know the answer, the user always can, and the answer changes what happens immediately. That
is the test for any question in this design, and almost nothing passes it: not how many
servers to have, not when to refresh, not which member signs. "Is this your own computer?"
passes, it is the same question every site already asks as *stay signed in?*, it is asked
once at the only moment it matters, and it is never asked again.

**What that leaves for servers.** If your own devices are full members and guest sessions
hold nothing, the only person who needs an always-on 1-point member is someone with a
single device of their own — and they need one absolutely, not as a convenience: one device
is 3 points, and 3 points sign nothing (§3). So:

| Devices of your own | What an always-on member is for |
|---|---|
| One | **Required.** It is the fourth point for everything, including every guest session, since the phone alone cannot sign |
| Two or more | Nothing, in the everyday case. The devices sign each other's rounds and the server sits unused — and is still what makes a lost device a tap rather than a trip to the paper |

Which answers the user's *first we make sure we have to do that*: you have to, for one-device
accounts, which is every account on its first day. The resolution is that nobody ever
decides anything — an account is created with servers as §3 says, and as the user adds their
own devices the servers quietly stop being used. The server is scaffolding that stays up as
insurance, not a dependency anyone has to think about.

**And it can be small.** §9.1 already says a server belongs beside a relay or inside one,
and §9.4 measures it: about 5 ms per co-signature, a few KB of state per user. The only part
that grows is the archive, and a server that is only ever somebody's fourth point does not
need one: the destructive check is the device's gate anyway (§5.2), and history and Undo can
come from the user's own device. **One share, the grants, the member list, no archive** — a
relay-shaped member that an operator can run for people they invite, which is how relays
already work and what the user described.

## 4. Sites and apps as co-signers

The idea: when the user approves a site, the phone makes it a weight-1 share through the
existing add-a-device path (§7.1 repair), the site keeps it in browser storage, and from
then on site + device = 4. No server anywhere. It is a tempting idea, the weights already
have a 1-point slot, and the share would live on the user's own machine rather than on a
stranger's VPS — which sounds like an improvement.

It does not survive three questions.

**Points add up.** The design's first property is "one piece signs nothing" (§12), and it
holds because the non-device pieces are few and counted: all three servers together are 3,
one short. One-point holders that arrive by the dozen are not few. Four connected sites
are 4 points. One actor who runs four sites, or one attacker who gets the browser profile
of someone with four connected sites, signs **without any device at all** — exactly what
the threshold is for. And the paper makes it worse: paper 2 + two sites 2 = 4, so a stolen
paper plus two sites takes the account, and the wait that defends the paper (§7.4) is
enforced by the servers that no longer exist.

You can re-weight to buy headroom — t = 8, device 6, paper 4, site 1 gives room for three
site shares with a paper and seven without — and you can cap the count, enforce it in
every member, and drop the oldest site at each refresh. That is all buildable. It costs
six FROST participants per device (six partials, six commitments per round, bigger
messages) and it adds a cap that the user will meet at the worst moment. And it leaves the
second question.

**A web page's code is not the user's.** An installed app and a reviewed extension are
pinned: the user chose a version, and a new one arrives visibly. A page is re-delivered by
its operator on every load. A share in `IndexedDB` is protected from *other* sites by the
origin boundary and from nobody at all by the origin itself: the operator ships different
JavaScript tomorrow and the share is theirs, along with whatever the user's device will
co-sign with it. A site holding a point is therefore a point the site's operator holds, at
their discretion, for as long as the grant lasts. Removing the grant (§6.2) does not undo
it — the share stays a share, and a refresh is what takes it away, which means every site
share is live until the next refresh.

**And it buys almost nothing.** The site's point only helps in a round a device joins and
approves, so a user with two devices gains nothing from it. The only person it helps is
the one with a single device and no server — who is precisely the person it should not be
sold to, because their fourth point is then in a browser store that a cleared cookie jar,
a reinstalled browser or a private window makes disappear. Three points left, locked out,
same cliff as §3 but reached by housekeeping.

**What the instinct is right about.** The user's underlying wish — let the things I
already use carry this, stop needing a dedicated box — is right, and there are two ways to
have it:

- **The browser becomes a device, not a shareholder.** An extension already is one (§6.3),
  with 3 points, added by the ordinary scan-and-vouch, visible in the member list,
  revocable by report-lost, and pinned code. An installed PWA can be the same. Then
  "the site I use holds part of my key" is true in the only form that is safe, and sites
  themselves keep holding nothing, which is what makes a grant worth having.
- **The 1-point member lives inside a relay.** §9.1 already says a server belongs beside a
  relay or inside one: it needs no outbound connections, no new address, and no new
  infrastructure — the user adds it to the group's relays and it answers member traffic.
  "No dedicated cosign servers" can mean *no separate thing to run or pay for* rather than
  *no always-on member*, and that keeps the lost-device tap.

### 4.1 One identical share for every site

A variant the user raised: *I thought each server or site's piece was identical? So 4 add
up to 1? And we use id's signatures or origin to differentiate.*

**The arithmetic is right.** A share is an index and a scalar. Copies of one share are one
participant, not several: a round uses one Lagrange coefficient per index, so a hundred
sites holding the same piece are worth 1 point between them. That does fix §4's collusion
problem completely — no number of sites reaches the threshold.

It replaces it with a worse one. **A share that every site holds is a bearer token worth
one point.** Nothing in the maths asks who is holding it; whoever has a copy can compute
that index's partial. The number of copies grows with every site the user approves, each
copy sits in JavaScript its operator re-delivers on every load, and so the token is public
in the limit — the time to public is just how many sites you have signed into.

What one public point does, exactly:

- **A stolen device plus the token is 4 points.** In a serverless group that is the one win
  being given away: today a stolen phone holds 3 and there is no 1-point member anywhere to
  be its fourth, so it is useless. With the token in the world, a stolen phone *is* the
  account — which is the nsec-on-the-phone position Cosign exists to improve on. And report
  lost cannot help: the refusal works because a member refuses, and a bearer token has no
  one to refuse — the thief is as much a holder as anyone.
- **The paper plus the token is 3.** Still short. The one mercy in the design.
- **A site that is merely sloppy leaks it.** One holder that replays a nonce across two
  messages hands over the secret itself: two partials on one index with one nonce pair
  solve for the share. §3 already forbids keeping nonces where a copy or a restore could
  replay them, and browser storage is exactly where copies and restores happen — profile
  sync, browser restore, two tabs of the same origin. One secret in N browsers is N chances
  at it, and the share that leaks is everyone's.

**Revocation stops being possible.** You cannot revoke one holder of a shared secret. A
refresh rotates the share, which does genuinely kill every leaked copy — but then the new
value has to be handed to every site the user still wants, so every refresh re-publishes
the token to a wider circle than the last one. What that describes is a shared password,
rotated now and then, given to every site you sign into.

**Origin and signature checks are policy, not maths** — the hub's reading is right. They
say who is *claiming* to ask. They cannot stop a holder from computing its own partial,
because that needs no permission from anyone. Origin policy is valuable, and it already
exists in the only place it can be enforced: the device, through grants (§6.2). Nothing
about it requires the site to hold a piece.

There is also no way to bind a share to a machine inside a browser. A non-extractable
WebCrypto key cannot do the scalar arithmetic a FROST partial needs, so the share has to
be reachable by the page's own code, and therefore by whoever serves that code.

**The rule that falls out of all three variants** — per-site shares, one identical share,
and a server — is worth stating on its own, because it decides the question:

> A point is only safely revocable if exactly **one** party holds it and that party can
> **refuse**.

A server satisfies it. A relay holding the 1 satisfies it (§9.1). An always-on box the user
owns satisfies it. A second device satisfies it with 3 points instead of 1. A browser
holding a member share of its own — an extension or installed PWA, one holder, pinned code,
removable on its own — satisfies it, and is the honest form of "the thing I already use
carries part of my key"; note that anything holding 1 point does arm a stolen device until
report lost, which is fine precisely because that holder is the one who refuses. A piece
copied to every site satisfies neither half.

### 4.2 The same share, with refresh

The user's answer to §4.1: *if we're ever concerned about one leaked piece, we cycle our
keys. Otherwise they cycle on a regular basis automagically, 30 days. Reissuing can be
silent if you're active.* And: report lost in an account with several devices is the
remaining devices refreshing at once, which makes the stolen device's 3 points and every
old copy of the site piece worthless together.

**First, what actually runs today.** Periodic refresh is §7.7, "approved; not built yet",
and that is half true: the server side is on main — pending shares, the check signature,
the commit, a minimum epoch age of 25 days, pending dropped after 48 hours — and the
phone's side, the thing that notices an epoch is 30 days old and asks, sits on an unmerged
branch. **So nothing cycles automatically at the moment.** Refresh runs after a device is
reported lost and after the paper is used, and that is all. Anyone reasoning about
cadence should know that the cadence is currently zero, and that it is one merge from
being 30 days.

**Second, how fast a refresh is.** Measured just now over public relays, in the end-to-end
test, a quiet refresh with everyone awake: **1.3 s** for both other members to reach the
new epoch and **1.6 s** for the device that only followed, including the two-phase check
and commit. A report-lost refresh is one phase, so faster. The refresh is not the slow
part of anything; noticing the phone is gone is.

**What refresh genuinely fixes.** A leaked copy of the piece is worth a point only in the
epoch it came from: shares of different epochs do not combine. So a copy that leaked last
month and a device stolen this month are 3 points and 1 point that cannot be added
together. The "it becomes public in the limit" objection of §4.1 is answered — with
cycling, public means *public for one epoch*, and an on-demand refresh closes it sooner.
That is a real correction and it stands.

**What refresh does not fix, and cannot.** Every site that is still approved holds a
**current** piece at all times — silent reissue is the whole point of the design. So the
dangerous combination is not stale, it is continuous: the unlocked phone (3) and any one
approved site's piece (1) are 4 points **of the same epoch**, and 4 points of one epoch is
not a signature, it is the key. They interpolate to the account's secret, which is why §12
says it in so many words: *the identity is permanent; 4 points of one epoch in a thief's
hands cannot be undone.* No refresh reaches that thief, because they need no member's help
ever again — they have the key, not a share of it. There is no exposure window to measure:
reconstruction is instant and permanent, and the 1.6 s refresh arrives after the fact.

Set against today's refusal, the difference is the whole of it:

| | Thief has the unlocked phone (3) |
|---|---|
| **Today** | needs a server to **cooperate** for its 1. Report lost and every honest server refuses, so the thief never reaches 4 at all. The refusal is the protection; the refresh is the cleanup |
| **With a shared site piece** | needs nobody. The fourth point is already in their hands, or in any browser profile they also took. There is nothing to refuse, and nothing to clean up |

**And the weights cannot be arranged out of it.** The piece is useful exactly when it is
dangerous. "Useful" means it completes a device's set — that is the only thing a 1-point
member does — and the thief's phone is a device. Re-weighting to t = 8 with devices at 6
makes a stolen phone plus the piece 7 points and safe; it also makes an honest phone plus
the piece 7 points and useless. Any weighting where the piece can finish a signature is a
weighting where it finishes the thief's.

**What is left even granting everything else:**

- **Not that a site you approve receives the piece** — holding it gives a site nothing it
  could not already do, since an approved site can already ask the user's devices to sign.
  The piece is not a capability, it is a copy. What matters is how many places a current
  copy sits in: every site, every CDN in front of one, every dependency in its build, and
  every browser profile that can be lifted — and any one of those copies, with the phone,
  is the key.
- **Nonce hygiene** is manageable but must be exactly right: one index in N browsers is N
  chances that one of them persists a nonce and gets duplicated or restored, and two
  partials on one index with one nonce pair solve for the piece itself. The rule is that
  the piece may be stored and a nonce never may. A page reloaded mid-round must lose the
  round, not resume it.
- **Every site removal becomes an epoch bump.** §6.2 and §12 promise that removing a
  grant ends the site: with a shared piece that is only true after a refresh, so removal
  has to trigger one. That is workable — it is also an epoch bump per sign-out, each one
  having to reach every offline device and renew the paper's parts (§8.2).
- **The phone-only user is where it all lands.** The piece changes nothing for someone
  with two devices, and that is the only case it was for. For the one-device user it is
  load-bearing — and that user has one dealer, so their refresh is the weakest in the
  design, and their fourth point lives in a browser store that a cleared cookie jar
  removes. The feature is for the person who can least afford it.

**Verdict.** Refresh answers the objection it was aimed at, and §4.1 was too absolute
about "public forever": with cycling, a stale copy really is harmless. It does not make
the scheme acceptable, because the risk was never accumulation — it is that the fourth
point sits, current, in the hands of parties who cannot be asked to refuse. The rule at
the end of §4.1 survives untouched, and now with a reason rather than a worry: **the point
that completes a signature must be held by a party that can refuse, because a party
holding four points of one epoch never has to ask anyone anything again.**

**What it would take.** Not a cadence and not a weighting. It would take the completing
point being a party that can refuse — a relay holding the 1 (§9.1), a box the user owns,
another device, or the user's browser holding a member share of its own, one per browser
rather than one copied to every site. All of those are available without a dedicated
server, and all of them keep report lost meaning what it says.

**One thing worth doing out of this exchange regardless:** merge the phone's side of §7.7
so that keys really do cycle every 30 days. The user already believes they do, the server
half is waiting for it, and quiet refresh is worth having on its own — it is what makes a
leaked anything age out.

## 5. Transport

Nothing changes: it is already relays only. Live rounds are ephemeral gift wraps (kind
21059), anything that must wait for an offline member is kind 1059 with a 30-day
expiration, and sites reach devices through their own doors (§6.3, §11). A server never
had a transport role; it is a member that happens to be always on. The one transport
consequence of dropping servers is the delta storage in §2 above: relays become the only
place a waiting delta sits, so dealers must re-send.

## 6. What servers do today, and who covers it

| What a server does | Without servers |
|---|---|
| The fourth point, always available | the other device (3). Both must be reachable; push wakes the phone, sent by the other device |
| The lost-device refusal (§7.2) | **intact** — a stolen device has 3 and the surviving device refuses it. The block never needed a server, only an honest remaining member |
| Policy: the destructive check, the 95% that goes through silently (§5.2–5.3) | **intact** — the device was always the gate; a server's check is a second opinion |
| Dealing and committing refreshes (§7.3, §7.7) | two devices deal. Quiet refreshes lose their point: they exist to rotate away from servers that may have kept something |
| Holding deltas for a member that is away | relays, plus dealers that re-send until acknowledged |
| Liveness and push wake (§10) | presence between devices; push is an HTTPS POST any device can make |
| Enforcing waits (§7.4) | the other device refuses rounds including the newcomer until the date passes |
| The dead-server swap (§7.7) | moot. Devices are never swapped silently — the rule the user set for servers (never drop one the user added, never go below two) is the rule here too |
| An always-on signer for phone-asleep NIP-46 sites (§6.1) | **lost.** A site waits for a device. Only a server the user runs themselves ever fixes this, and §6.1 already says it must be theirs |
| The archive, change history and Undo (§5.4) | each device keeps its own. A device that was away judges against an older version, which §5.2 already accepts |
| The web page: settings, grants, report-lost without the phone | an app on a device the user still has |

## 7. Threat model, serverless

- **A malicious site's share** — the §4 case. Not built, and not recommended.
- **One identical share held by every site** — §4.1, §4.2. Fixes the collusion arithmetic
  and replaces it with a piece that cannot refuse: a stolen device plus that piece is 4
  points of one epoch, which is the key itself, and no refresh reaches someone who needs
  no member's help again.
- **A stolen phone** (3) — cannot sign: the remaining device refuses it, and there is no
  1-point member anywhere to make its fourth. Strictly better than today, where a thief
  with an unlocked phone and one cooperating server has 4 (§12).
- **A stolen paper** (2) — cannot sign, and cannot recover anything on its own, because
  the two servers it would have combined with do not exist. Also strictly better than
  today, and it removes the attack the 3-day wait was built for.
- **A stolen phone *and* the paper** — 5 points, a takeover. Unchanged from today.
- **Revocation** — report-lost blocks at once and the refresh makes the old piece
  worthless, same as now, provided two members survive to deal. With exactly two devices
  and one lost, the survivor must first use the paper to add a replacement; a single
  dealer refreshing alone is a dealer who could later map an old share onto the new epoch.
- **Nobody sees the user's events** — no public server co-signs, so the archive, the
  grants and the decryption counterparties stay on the user's own machines. This is the
  biggest win and it should be said first to anyone choosing this shape.
- **Share count** — stays small and fixed: 3 per device, 2 for the paper, nothing that
  grows with use. That is the property §4 would have given away.
- **One device and no server** — not a supported account: 3 points sign nothing. It must
  be refused at creation rather than discovered later.

## 8. Compatibility

- **Today's servers** are unaffected: a group may have any number of them, and the only
  normative change is §3's "at least two servers, from the start", which becomes a rule
  about points rather than about servers — *after losing any one member the rest must
  still reach 4* — satisfied by two servers, by three devices, or by two devices and a
  paper.
- **nostrconnect** keeps working, with the §6.1 limit it already has: the signer key goes
  only to the user's devices and to a server the user runs, so in a serverless group a
  nostrconnect site is answered when a device is awake, and waits otherwise.
- **QRST sign-in** needs no server at all: the ticket goes to the holders of the signer
  key, which are the user's own devices, and the site redeems it over relays.
- **The fallbacks stay fallbacks.** A group with no servers still shows a QRST code, still
  accepts a `nostrconnect://` code, and still works with NIP-55 and NIP-07 — none of
  those doors ever involved a server.

## 9. Recommendation, and the smallest first step

1. **Build §5.1 point 1 — device-to-device rounds — inside accounts that already have
   servers.** *(The member library's half is done; the Android library's is not.)* Presence, a device answering another device, the epoch guard, and an archive
   on the Mac. Nothing in the spec changes, no account changes, and the everyday round
   stops going through anyone else's machine whenever two of the user's devices are both
   awake. This is the same code a serverless account needs.
2. **Then stop asking the question at all.** A group does not have to drop its servers to
   stop routing through them: with step 1 in place, two awake devices sign each other's
   rounds and the servers sit there unused, silent, and still holding the point that makes
   a lost device a tap rather than a trip to the paper. That is the best arrangement in
   both directions and nobody has to choose it. A group with no servers follows for anyone
   who wants it, under the points rule of §3 — but as a consequence, not a setting, and
   never a prompt (§0a).
3. **Do not give web pages shares**, per-site or one identical piece for all of them, with
   or without cycling (§4, §4.1, §4.2). A browser that should carry part of the key carries
   it as a member of its own — extension or installed PWA, added by a scan, removable on its
   own — and that is the "yours" case of §3a. A browser that shouldn't is a guest, and holds
   nothing.
4. **Make the always-on member small and relay-shaped** (§3a): one share, the grants, the
   member list, no archive, beside or inside a relay, runnable for invitees. It is already
   blessed by §9.1, it is what a one-device account cannot do without, and it keeps the
   lost-device tap for everyone else.
5. **Make "not yours" behave like a guest** (§3a): a grant that ends with the session,
   nothing written to disk, and a line in the device's list saying where it is. The signing
   path already exists; only the defaults are wrong.
6. **Merge the phone's side of §7.7**, so keys cycle every 30 days as the specification
   says and as the user already believes. Done, on a branch: the server half was already on
   main, a quiet refresh takes about a second and a half, and it is what makes a leaked
   anything age out (§4.2).

Step 1 is worth doing whether or not the rest is ever agreed: it is a privacy improvement
for every existing account, it is already in the specification, and it is the only part
with real code in it.
