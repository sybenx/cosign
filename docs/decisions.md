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
- 2026-10-25 · User: never silently drop a server the user added, nor one on a two-server account; say once, calmly, after a week quiet.
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
