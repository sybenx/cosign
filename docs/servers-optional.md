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
built, and neither was waiting on a second device to exist: the browser extension has been
a member device with 3 points for a while, and two phones would have done as well. What
changed is that the Mac app put a second device in daily use beside the phone, which is
what makes an unbuilt preference worth building.

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
- **One identical share held by every site** — §4.1. Fixes the collusion arithmetic and
  replaces it with a bearer token: a stolen device plus that token is 4 points, with no
  holder left who can refuse, and a refresh is the only revocation it has.
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
   servers.** Presence, a device answering another device, the epoch guard, and an archive
   on the Mac. Nothing in the spec changes, no account changes, and the everyday round
   stops going through anyone else's machine whenever two of the user's devices are both
   awake. This is the same code a serverless account needs.
2. **Then let a group have no servers**, as a setup choice, gated on two devices plus a
   paper or on three devices, with the sentence *a lost device means getting the paper
   out* said plainly at setup and in settings.
3. **Do not give web pages shares**, per-site or one identical piece for all of them
   (§4, §4.1). If a browser should carry part of the key, it carries it as a member of its
   own — extension or installed PWA, added by a scan, removable on its own.
4. **Offer the 1-point member inside a relay** for people who want always-on without
   running anything: it is already blessed by §9.1 and it keeps the lost-device tap.

Step 1 is worth doing whether or not the rest is ever agreed: it is a privacy improvement
for every existing account, it is already in the specification, and it is the only part
with real code in it.
