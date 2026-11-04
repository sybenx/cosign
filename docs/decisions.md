# Decision log

One line per decision, oldest first. A later line wins over an earlier one; superseded lines stay,
marked, so the reasoning trail survives. "User" means the account owner decided it; "review" means
an independent review proposed it and the user accepted it. Sources: the session memory notes
(`signer-architecture`, `user-no-forcing`, `cosign-no-server-history`, `notes-sync-decision`,
`spec-before-build`, `cosign-interop-bar`, `keykin-reevaluation`), the Keykin re-evaluation plan
(2026-11-02) and `~/igloo/cosign-live-findings.md`.

Add a line whenever a decision is made. If a line contradicts the spec, the spec is wrong until
this log says otherwise.

## How we work

- 2026-10-23 · User: build for what people have; no rules that force a setup. Keep only rules that are security-critical, and explain those as safety.
- 2026-10-23 · User: judge trade-offs against the baseline of one device holding the whole nsec. Anything no worse is accepted and not flagged again.
- 2026-10-24 · User: the user's answers may be dubious on design detail; reviewers propose a safe default in a line and do not keep asking.
- 2026-10-24 · User: feature freeze on Cosign. Only fixes from real use ship until the user lifts it.
- 2026-10-26 · User: protocol or key-handling changes get spec text and an independent red team before any code. UI can go mock → build.
- 2026-10-27 · User: the bar is that standard NIP-46 tools (nak, Grimoire, nostr-tools) just work.
- 2026-11-02 · User: complexity is a cost, but robustness wins ties. Hard maths comes from standard FROST libraries.

## Names and scope

- 2026-10-24 · User: the app is Marble (reference app, a proof of concept). Any app may implement the protocol; integrating apps are listed above Marble.
- 2026-10-24 · User: words people read say "sign-in app", never signer, Nostr, key or relay. Developer docs keep the terms.
- 2026-11-02 · User: the protocol's working name is **Keykin**; Keystr is dropped and not pursued. Old `cosign` names stay readable for ever.
- 2026-11-02 · User: Nostr-native scope. Data services (files, sync, calendars) are other projects; Keykin only stays compatible with them.
- 2026-11-02 · User: the aim is ~90% of a Google account, one npub for life, safer than an nsec in a password manager, and no single app, site, server or company able to stop sign-in.

## Key model

- 2026-10-23 · User: servers sign with the device; the device is the remote control and the destructive gate. *(Server roles narrowed by 2026-10-27 and 2026-11-02 below.)*
- 2026-10-23 · User: paper backup holds a long-lived backup keypair, not a share; each refresh seals the new backup contributions to it.
- 2026-10-24 · User: weighted FROST, threshold 4: each device 3 shares, each server 1, paper 2. Device + any server signs, two devices sign, all servers never. Supersedes the equal-pieces 2-of-N model.
- 2026-10-24 · Review: the paper is always weight 2, and accounts start with at least two servers.
- 2026-10-24 · User: a server holds exactly one share per account, whoever runs it.
- 2026-10-24 · User: servers from different operators is SHOULD, not MUST; fill from one operator if needed and say so plainly.
- 2026-10-24 · User: new keys by DKG; an existing nsec may be imported (dealt, then wiped).
- 2026-10-24 · User: the device asks the fastest server first, others after a short hedge (~300 ms).
- 2026-10-26 · User: servers are for people with one device; with several devices, devices co-sign each other first and servers are a silent backup.
- 2026-10-26 · User: at sign-in the one question is "is this device yours?". Yours = a full device (3). Not yours = a guest with no shares, signing through your own device, expiring.
- 2026-10-26 · User: the shared per-site share is rejected (a stolen phone plus the site share of the same epoch is the key).
- 2026-11-02 · Review: keep device 3 / server 1 / paper 2, threshold 4. Plain 2-of-3 and device 2 / server 1 / paper 1 at t=3 are rejected.
- 2026-11-02 · Review: add invariants I1–I5, checked by servers against the signed group record, and pin member kinds at the add flow.
- 2026-11-02 · User: a family or friend "helper" may hold 3 shares, only on the user's opt-in. It can post as the user with one server; the opt-in screen says so once.
- 2026-11-02 · User: a helper never vouches instantly and cannot cancel waits.
- 2026-11-02 · Review: backup pieces are wrapped a second time to a release key held only by devices and servers, released through a server's wait (closes helper + paper = 5).
- 2026-11-02 · User: a separate read-only data key, held whole by trusted devices, is allowed for data services. It is random, never derived from the account key.

## Adding and removing devices

- 2026-10-23 · User: one device vouching is instant only with its own lock asked at that moment; two devices vouching is instant; otherwise a wait.
- 2026-10-23 · User: the wait W is 3 days.
- 2026-10-23 · User: report lost needs the reporting device's lock (or a passkey on a server page); it is instant and is never delayed.
- 2026-10-24 · Review: "This wasn't me" tiebreak cut; removal is final, re-add instead. *(Refined 2026-10-26, see below.)*
- 2026-10-24 · User: a 7-day escape hatch: if no server answered for 7 days, device + paper (or two devices) may rebuild the key after the lock and a plain warning.
- 2026-10-24 · User: monthly silent refresh while a device is online; dead servers swapped in it; never a deadline; nothing shown.
- 2026-10-24 · User: a server never deletes a finished account's share for inactivity; only a guarded forget does.
- 2026-10-25 · User: never silently drop a server the user added, nor one on a two-server account; say once, calmly, after a week quiet. *(Updated 2026-11-02: no server is ever swapped silently; see below.)*
- 2026-10-26 · User: any one live device can vouch for a new one; its fresh lock is "the second gate past just stealing a phone".
- 2026-10-26 · User (live finding #3, shipped 0.12.6): a removed member may, for 7 days, report its remover; then both are removed. *(This is the "contest"; reconciled below.)*
- 2026-11-02 · User: a passcode alone counts as no lock, so the 3-day wait applies to whatever that device starts.
- 2026-11-02 · Review: the lock is a P-256 key in secure hardware (Secure Enclave, Android Keystore, WebAuthn with user verification) whose signatures servers check. An extension or a passcode-only phone may hold 3 shares but never counts as "with lock".

### Report lost: "final" versus "contest", reconciled 2026-11-02

COSIGN.md §7.2 says removal is final with no contest; the code since 0.12.6 lets a removed member
answer back for 7 days. They are not about the same thing, and both survive in this form:

- **Removal is final.** Nobody is ever put back. A device removed by mistake is added again as a
  new member. That is what the 2026-10-24 review cut: a tiebreak that reinstates one side.
- **Mutual removal stays.** For 7 days a removed device may report the device that removed it, and
  then both are out. This is what turns "the thief reports first and keeps the account" into "the
  thief can at most take an honest device down with it". The user accepted that cost (finding #3).
- **Changed in Keykin Core:** a removed device may no longer cancel waits or recoveries in that
  window (0.12.6 lets it). Instead, every wait a member started ends when that member is removed,
  so the honest device's counter-report already cancels the thief's pending actions. Letting the
  removed side cancel recoveries would let a reported thief block the owner's paper recovery.

**The reconciled text wins**, as written in Keykin Core §6.5. COSIGN.md §7.2 is left as it is,
because it describes the code during the freeze.

## Servers and push

- 2026-10-23 · User: relays first; HTTPS later as a fast path.
- 2026-10-23 · User: a public server never holds a NIP-46 signer key or finishes a decryption; per-site signer keys live on the user's devices and servers the user runs.
- 2026-10-24 · Review: decryption partials go only to active member devices, never to the backup key or a removed member.
- 2026-10-24 · User: public servers must not reach private, loopback, tailnet or metadata addresses because a stranger named them.
- 2026-10-27 · User: servers keep no history. Devices keep their own history and do Undo. No paper-sealed list copies.
- 2026-11-02 · User: public servers hold one share, enforce the waits, send wake-up push, store as little as possible, keep no history.
- 2026-11-02 · User: devices do everything a server would when they can. Actions stage offline: drafts wait for a co-signer, signed events wait for relays, events keep the time they were written.
- 2026-11-02 · User: each app maker runs its own stateless push gateway; we run one only for Marble if it ships on the App Store. UnifiedPush on Android needs none. Servers send standard Web Push (RFC 8291 + VAPID).
- 2026-11-02 · User: HTTPS is SHOULD for servers, not MUST. Relays are MUST.
- 2026-11-02 · User: wait warnings may also go to an optional email or webhook channel.
- 2026-11-02 · User: background signing shows an honest, quiet notice ("Signed a note for Primal · Undo").
- 2026-11-02 · User: no shaming mechanism for bad servers yet.
- 2026-11-02 · Review: servers keep one stateless rule: destructive kinds need a fresh lock signature or the wait.
- 2026-11-02 · Review: request lifetimes by class: site sign 45–60 s, ask 2 minutes, member (staged) 7 days. `created_at` never decides freshness. No future `created_at`.

## Key export and families

- 2026-10-24 · User: "take my key out" exists (with paper instantly, via servers after the wait). *(Superseded 2026-11-02 for the master key.)*
- 2026-11-02 · User: the **master key is never exported**. Child keys may be, in stages: any child, then only imported children, then none. Every export needs the lock or the wait.
- 2026-11-02 · User: importing a raw nsec over QRST stays allowed.
- 2026-11-02 · User: key families: a master claims child keys after a ~14-day challenge window counted from first seen; disputes fall back to followers, contacts and NIP-05. Offer both "import nsec" and "new master plus current key as child".
- 2026-11-02 · User: once a family claim has settled, contests from the child are ignored.
- 2026-11-02 · Review: app-password children have no contest rights.

## Data and other specs

- 2026-11-01 · User: Marble notes sync builds as to-self encryption with packs (option A), not a derived app key.
- 2026-11-02 · User: fold into the account layer what app keys, DMs and notes sync need. App keys stay parked.
- 2026-11-02 · User: social recovery is to be investigated (worth it? cheap?). Recommendation on file: friends hold the backup key 2-of-3, never FROST shares.

## Live holes and process

- 2026-11-02 · User: live findings #17, #4, #5, #7 and #1 are not patched during the freeze (the user is the only user and the nsec is in Bitwarden). Keykin Core closes them, and they MUST be closed before a second user.
- 2026-11-02 · User: spec in layers (core, modules, freeze), each red-teamed independently, before code.

## Keykin Core draft 2 (red team 1 fixes; user answers 2026-11-02)

- 2026-11-02 · User: **the bar is an nsec in a password manager.** Every measure must beat it on security *and* on user experience, or it goes. So no fingerprint gate on opening stored shares or on background signing, and no "only while unlocked" rule.
- 2026-11-02 · User: extension shares (#5) are encrypted at rest only where that costs no extra prompt (SHOULD). Plain-stored shares already beat a whole nsec in nos2x-style storage.
- 2026-11-02 · User: a passcode-only phone cannot cancel a recovery wait (Q1).
- 2026-11-02 · User: far-future `created_at` is refused only for replaceable and addressable kinds (0, 3, 10002 and the rest); a deliberately scheduled ordinary post is allowed (Q2).
- 2026-11-02 · User: a single deletion is a 10-second Undo hold on the device, no lock, no wait. Only mass deletions (5 or more targets, or a burst) and list wipes need the lock or the 3-day wait; the server's stateless rule matches (Q3).
- 2026-11-02 · User: a removed device cannot cancel waits during its 7-day window (Q4).
- 2026-11-02 · User: joining always shows the 6-digit compare on both screens, even after a camera scan (Q5).
- 2026-11-02 · Review, not yet questioned: the paper may cancel waits started without a lock; a running recovery wait freezes lockless changes; optional email/webhook notice channels are a core wire item; migrated accounts are always masters.
- 2026-11-02 · Review (red team 2, judged against the nsec bar): receive keys dropped (shares simply never go on relays); waits run on changes, several at once; a refresh names two dealers and commits after two servers, or one after 24 h; mutual removal cannot target a recovery; data keys survive a recovery; vouching always asks the person.
- 2026-11-02 · Process (hub rule): red-team rounds 1–4 each found critical or high problems, so patching stopped after round 4. `docs/keykin/simplification.md` proposes cutting refresh and lockless report-lost from the core; waiting on the user.

## Simplification (user, 2026-11-02, after red-team round 4)

- 2026-11-02 · User: **refresh is dropped from the core** and becomes an optional future module. Pieces of removed devices and dropped servers stay mathematically valid; blocking at servers is the protection, and after a serious leak the fix is a new key with key families. Note for the module: consider a simpler variant, such as refreshing only when every current member is online together, with the paper re-made and checked at print time rather than silently.
- 2026-11-02 · User: **reporting a device lost needs a face or fingerprint, or two devices together, or the paper** (as decided 2026-10-23). Mutual removal, notices to removed phones and `deposit` go with it.
- 2026-11-02 · User: "Grimoire" is the web client at grimoire.rocks. nak stays the must-pass tool; the interop plan ranks the clients most worth smooth compatibility.
- 2026-11-02 · Process: red-team round 5 (draft 5) found 0 critical, 4 high. Patching stopped again; `simplification.md` (second part) proposes requiring a lock, two devices or the paper for every account change (no lockless 3-day path), a fixed data key, and at least 3 servers. Waiting on the user.
- 2026-11-02 · User: the optional "Refresh now" module is wanted if it stays simple (started by hand, every member online, old epoch valid until all confirm, paper reprinted and checked, old paper dead after commit and said so first). Written after the core passes a clean round.
- 2026-11-02 · User: doesn't use Grimoire; the interop top set is chosen by use (nak must pass).

## Second simplification (user, 2026-11-02, after red-team round 5)

- 2026-11-02 · User: **every account change needs a face or fingerprint, a second device, or the paper.** No "wait 3 days instead". The 3-day wait stays only for paper recovery and held mass deletions. *(Supersedes 2026-11-02 "a passcode alone counts as no lock, so the 3-day wait applies".)*
- 2026-11-02 · User: **the private-data key stays the same** when a device is reported lost; changing it comes with the optional refresh module.
- 2026-11-02 · User: **accounts must have at least 3 servers.** The app adds public ones automatically, alongside a user's private server.
- 2026-11-02 · Process: red-team round 6 (draft 6) found 1 critical, 6 high. Stopped again; `simplification.md` part 3 proposes moving server changes, helpers and paper replacement into the "Refresh now" ceremony, replacing the record chain with a set of independent signed changes, biometric-only locks, and typed codes for two-device approvals. Waiting on the user.

## Third simplification (user, 2026-11-02, after red-team round 6)

- 2026-11-02 · User: **adding, swapping or removing a server, adding a helper, and replacing the paper happen only in "Refresh now"** (every staying member online together, shares re-dealt, paper reprinted and checked). Everyday changes (add a device, report one lost, paper recovery) stay instant, as independent signed approvals.
- 2026-11-02 · User: **a lock is biometric-only**: no passcode fallback; browser passkeys don't count as locks.
- 2026-11-02 · User: **a two-device approval means typing a 6-digit code** from one device into the other, not a tap.
- 2026-11-02 · User: **a dead server, public or private, is replaced only in a refresh with a reprint, never by a silent swap.** After a week quiet, the app says so once, calmly, and offers "Refresh now". *(Updates the 2026-10-25 quiet-servers line and the 2026-10-24 "silent auto-swap for public servers".)*
- 2026-11-02 · Process: red-team round 7 (core draft 7 + refresh draft 1) found 1 critical, 5 high. Stopped again; `simplification.md` part 4 proposes cutting in-place migration from 0.12 (re-import the nsec instead), honest refresh wording ("destroy your old paper"), slip fixes, and lock re-registration as an everyday change. Waiting on the user.

## Fourth simplification (user, 2026-11-02, after red-team round 7)

- 2026-11-02 · User: **no in-place move from Cosign 0.12.** The user's account moves by importing the nsec (from Bitwarden) into a fresh Keykin account: same npub, new pieces; the old 0.12 servers forget theirs.
- 2026-11-02 · User: **keep "Refresh now" with honest wording**: "destroy your old paper", never "it stops working". Refresh kills honest members' old pieces (so server swaps are safe) but not pieces someone kept.
- 2026-11-02 · User: **re-registering a face or fingerprint is an everyday change**, approved by a second device with a typed code or by the paper.
- 2026-11-02 · Process: red-team round 8 found **no critical or high problem in Keykin Core** (0/0 in the core; 3 high in `refresh.md`). Core passes the stop rule; its mediums/lows fixed as draft 8.1; test vectors written (`docs/keykin/vectors/`). Refresh judged on its own: 3 high, all fixable by reordering and widening the second-dealer role; `simplification.md` part 5 asks the user.
- 2026-11-02 · Hub (under the user's "if it's easy, just do it"): "Refresh now" draft 3 got its own red team and still had 1 critical, 2 high → parked with the reason in `refresh.md`. **Keykin Core is the deliverable**; core §10 states what an account can't do without refresh (no server replacement, fixed data key, same paper after recovery).
- 2026-11-02 · User: **refresh unparked 2026-11-02: required, redesign in progress.** "We cannot stop at 'good enough for one user'. We can't park it." Replacing servers, the helper and the paper must work; the core isn't the deliverable without it. A design panel in the hub session is choosing the approach (proactive refresh, redistribution by a qualified subset, device-dealt "move house", others); this session writes up and red-teams the winner.
- 2026-11-02 · User: **one member per machine.** With a desktop member app installed, browser extensions on that machine hold no pieces and relay NIP-07 to the app over native messaging (as NIP-55 apps share one member on Android, and the iPhone Safari extension relays to its app). With no app, one extension is the member. Several browsers share the one member. An extension member that finds the app hands its membership over and retires. A SHOULD on members (core §4.6), plus one wire addition: a device may remove itself.
- 2026-11-02 · Process: the one-member-per-machine rule (core §4.6) got a focused red team: 0 critical, 2 high (both handover specification gaps). Reviewer verdict: keep the rule. Not patched under the stop rule; fixes proposed in `simplification.md` (last part).
- 2026-11-02 · Review: the one-member-per-machine handover fixes (H1, H2 and the commit order) applied in core 8.4.
- 2026-11-02 · Review: the quick re-check of core §4.6 (draft 8.4) found no critical or high problem; its mediums and lows are folded into core 8.5. The one-member-per-machine rule passes.

## Keykin Upkeep (2026-11-02)

- 2026-11-02 · Hub design panel (4 approaches, 3 judges, 2 red teams) → **Keykin Upkeep**, written into Core as draft 9: fixed seats for servers, paper and helper; replacement = repair at the same seat index (a newcomer never adds weight); every seat change and report-lost carries a mandatory additive redeal (old pieces die; data and release keys rotate); members track a set of applied redeal ids instead of epoch moves; nothing needs everyone online. Replaces `refresh.md`.
- 2026-11-02 · Default (UI): after 7 days with every server unreachable from 2 networks, a calm card offers to move all three.
- 2026-11-02 · Default (UI): after report-lost or a server swap, one quiet cue (a filled dot on Backup) suggests a new paper; never a banner, never forced.
- 2026-11-02 · Default: the user signs the public server list for now; the app pins it; co-signers are added once other operators exist.
- 2026-11-02 · Process: red-team round 9 (core draft 9, Upkeep) found 0 critical, 6 high. Stopped; `simplification.md` (round 9 part) proposes cutting the servers' beacon check (beacon becomes a paper signpost only), a running release key, per-redeal material items, any-4-points `need_repair`, and "new paper" instead of same-key paper repair. Two questions for the user. Seats stay replaceable.
- 2026-11-02 · User: kept the three Upkeep UI defaults (7-day calm card offering to move all servers; quiet dot on Backup; the user signs the public server list for now).
- 2026-11-02 · Hub, under the user's standing rules (the user can overrule): **servers stop checking the beacon**; it becomes a paper-only signpost, published at creation and never deletable through a site grant.
- 2026-11-02 · Hub, same basis: **a paper missing a piece is fixed by printing a new paper** (quiet dot on Backup), never by a silent same-key repair.
- 2026-11-02 · Process: red-team round 10 (core draft 10) found 0 critical, 2 high (signpost rewritable by a lockless thief; helper + paper repairing the backup seat). Stopped; `simplification.md` (round 10 part) proposes local fixes plus dropping step-back and simplifying `rerepair`. No user questions.
- 2026-11-02 · Process: red-team round 11 (core draft 11) found 0 critical, 1 high (paper recovery after every printed server is replaced depends on the signpost). Stopped; `simplification.md` (round 11 part) proposes forwarding notes on retired servers plus a lookup via the signed public list, and medium/low fixes. No user questions.
- 2026-11-03 · Process: rounds 12 (0 critical, 1 local high → draft 13) and **13 (0 critical, 0 high)**. Round 13's mediums and lows folded into **Keykin Core draft 13.1**; test vectors regenerated; interop plan updated. Loop done per the hub's standing order.
- 2026-11-03 · Open for the user: a lone device with no working lock that has lost its paper can never make a new paper or replace a server (a fix needs a new mechanism, e.g. a server-enforced wait only for a new paper).
- 2026-11-03 · User: **keep "no wait path".** A lockless single phone that has lost its paper can't make a new paper or replace a server; that stays a stated limit (core §10). The app **quietly suggests** a second device (a browser extension on a laptop counts), never a hard push (no-forcing rule).
- 2026-11-03 · Hub: Phase 2 starts: the modules, one at a time under `docs/keykin/modules/`, each red-teamed with its seams to the core until no critical or high, then one seam review across all.
- 2026-11-03 · Spec (from the Doors red team, backed by ios-server-needs.md B11): a server **may watch for NIP-46 requests** for the account's signer public keys, only if the person opts in (default off); it never holds a signer key or grant. `own` servers no longer coordinate or hold grants. Core 13.3.
- 2026-11-03 · Review, modules (all fixes local): Server profile draft 4 (closing servers keep recovery waits; destroyable enrol keys), Device policy draft 4 (device runs §5.8 itself; deleting a whole list is Held), Doors and grants draft 3 (private-scope NIP-46 keys stay on their home device; no `auth_url`), Backup draft 2 (one backup set renewed together; heir pieces follow seats; any signing ends an heir wait; friends hand over only in person or on video). Core 13.5: what a watching server and the heir record keep.
- 2026-11-03 · Spec (Account admin draft 1, from the no-forcing rule and the bar): **"Not now" on the backup destroys the backup secret at once** (and an unfinished paper flow after 24 h), so no device keeps 5 points indefinitely; the account then has no paper until a later F7. Core 13.6 §4.3 step 4.
- 2026-11-03 · Spec: the **passkey page on servers for reporting a device lost is dropped**: core §6.1 counts no passkey as a lock (earlier user decision on biometric-only locks). Core 13.6 §12.
- 2026-11-03 · Review, modules round 2 (all local, small core clauses 13.7–13.11): Server profile 5, Device policy 5, Doors 4 (NIP-46 signer keys never leave their home device), Backup 3 ("final note" cut; holder keys; holders read back before the paper change), Account admin 2 (key deletion is its own approved `account_delete`, no hold path; erase-posts stays a Held vanish).
- 2026-11-03 · Open for the user (sent to hub): Helper (a core kind list for helper-led rounds; a one-tap "stop helper" flag) and Key families (NIP-03 anchored window instead of first seen; one double-signed family event, no contests, no app role; imported 0.12 accounts may be children). Both modules paused on these.
- 2026-11-03 · Spec: core 13.12 pins the reference implementation's first 17 issues (approval `expiry`, pair/paper/recovery/release_request signatures, `ecdh_partial`, seed hashes, hedge stream, a list in each change event, lifetime classes, order-free approvers, duplicate-key adds, kind 5 skew, list-hash order, recovery changes co-signed only by the holder).
- 2026-11-03 · Review, modules round 3: Server profile 6, Device policy 6, Doors 5, Backup 4 (heir record pinned in the paper change; "alive" rounds cut, cancel on next visible use), Account admin 3. Core 13.13–13.15 (heir lookups, per-key destruction, delete tombstone and paper approval of non-list requests).
- 2026-11-03 · Open for the user (Q6, sent to hub): lockless "Not now" keeps the backup secret until a second device or paper exists (recommended), or destroys it as now.
- 2026-11-03 · User ("yes to all five"): helper-led rounds co-signed only for posting kinds (core 14 §5.7 item 8); any device stops the helper at once with no approval (`helper_stop`); the helper has a host, and no host holds both the helper and a server seat; no helper co-signing; scheduled posts are pre-signed notes.
- 2026-11-03 · User, **reversal**: the key-family window counts from a **NIP-03 Bitcoin timestamp**, replacing "counted from first seen" (2026-11-02). Reason: with "first seen", every new viewer or reinstall restarts the clock, so a leaked child key could still dispute a family that had settled for everyone else.
- 2026-11-03 · User: one family event signed by both keys, timestamped; the earliest anchored family wins; two anchored within 14 days of each other are a dispute; no contest events; app passwords are plain keys with no special role (replaces "app-password children have no contest rights"); settled families still ignore the child. An imported 0.12 account may be a child of a new master (core 14 §6.8).
- 2026-11-03 · User (Q6, (a)): on a **lockless device, "Not now" postpones**: the device keeps the backup secret sealed until a second device joins or a paper is read back (core 14 §4.3 step 4). The app suggests a phone quietly, no hard push.
- 2026-11-03 · Spec (Key families draft 3): a family first seen more than 2016 blocks after another settled, but anchored earlier, is a **dispute for that viewer, never a win**. This local "first seen" rule only downgrades; it doesn't bring back the reversed rule (a later leak still can't anchor earlier). The onboarding card says plainly that an earlier copy of the key may already hold a claim.
- 2026-11-03 · Spec (core 14, from the Helper review): `helper_stop` names the helper's key, travels in seat welcomes and is fetched before helper rounds; `helper_resume` needs an approval; devices never co-sign helper rounds; §10 says a helper plus one dishonest server is the whole key.
- 2026-11-03 · Hub (Q7, on the user's Q6 reasoning; the user may overrule): a lockless account's **kept backup secret lasts until any device has a lock or a paper is read back**, not merely until a second device joins; meanwhile **every lockless device holds a sealed copy** (carried in welcomes), and `kept_done` destroys all copies. Core 14.5.
- 2026-11-03 · Hub (Q8; the user may overrule): Device policy's **"others' content" rule is cut, at the bar, for convergence** (four rounds of highs came from it). Lists, profile, relays and wallet stay guarded; §8 states that a site with `post` can overwrite another app's articles or listings as with a pasted nsec, and device Undo still restores kept versions. It may come back as an optional module.
- 2026-11-03 · Spec: core 14.8–14.10 pin the implementation's batch 3 (helper-list check, `repair_ok`, paper challenge per list) and close core review 17 (the paper as repair helper with a device under a `paper` approval, hedge per event position, the host rule by approval time, named helper stops as account state, `kept_new`).
- 2026-11-03 · Hub (Q9, as for Q8; the user may overrule): in Doors and grants, **a device restored from an old copy, while most relays are unreachable, may answer a site it had signed out of** until it reaches most relays or is reported. Stated as a limit at the bar (a pasted nsec can never be signed out), for convergence.
- 2026-11-03 · Spec: the reference implementation's batches 4 and 5 pinned (enrol-key vector, DKG bodies, Backup TLV, even-y; and a real high in Account admin §3: a relayed `deleted` is accepted only if its carried approval checks at the receiver). Core 14.13.
- 2026-11-03 · Process: **every module passed its own loop** (Server profile 7, Device policy 18, Doors and grants 19, Backup 5, Account admin 8, Helper 8, Key families 7) and the **final cross-module seam review found 0 critical, 0 high**; its mediums and lows are folded into core 14.14 and the modules.
- 2026-11-03 · Spec: core 14.15 adds **§9.5, a strict JSON profile**, from the implementation's batch 6 (a differential run that split 115 of 161 hostile inputs). It is stricter than the batch on the red team's advice: integers spelled one way and checked at parse (`1.0` is refused, not read as 1), lone surrogates and stray control characters refused so that NIP-01 ids agree, depth 32, and the rules cover the event objects too. A malformed `change` object is "not a change", never "void".
- 2026-11-03 · Spec: core 14.16 answers the implementation's item 46: **an add always carries `lock`** (`null` when none). Both implementations already refuse an add without it, so the stricter reading needs no parser change. The 300 differential cases are now `vectors/negative.json`.
- 2026-11-03 · Spec: Server profile draft 8 pins item 47 (eight red-team rounds; the last found no forgery or replay path). A shutdown notice counts only through the host's live `notice_get` answer, which is bound to the request and sealed by the seat's member key. Only the pick's refusal of `enroll` is host-signed. `refused: expired` is dropped: a server that has lost its enrol secret can't answer, so the 7-day quiet rule replaces it. Core 14.17–14.18 add pointers, and the signpost guard now matches any `a` value containing `g` and a signpost `d` (item 48 b). Item 48 (a), a server that answers but won't co-sign, goes to the hub as a question.
- 2026-11-03 · Hub (Q10 (b); the user may overrule): **a server that answers but won't co-sign is not detected automatically.** There is no probe kind and no new core mechanism. The person moves it by hand (F4). Core §6.7.9 adds a quiet Backup line, "S3 hasn't helped sign this week", shown only for requests the server left unanswered, never for its `error` answers; it can be hidden and is never a card or dot. §10 states the limit, including that paper recovery then relies on the other two servers. Item 48 (a) is closed.
