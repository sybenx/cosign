# Keykin Core: where the red teams keep finding problems, and what to cut

2026-11-02 · Proposal only. Draft 4 (`core.md`) stays as written until the user answers.

## Plain summary for the user

Four independent reviews each found serious problems. Every fix added new machinery, and the next
review broke the new machinery. Almost all of the serious problems come from two features:

1. **Re-dealing the shares after a device is lost, and monthly** ("refresh"), together with
   keeping the paper backup up to date through it: 2 of the 5 critical problems and 6 of the 18
   high ones.
2. **Changes made from a phone with no face or fingerprint**: reporting your other devices lost
   straight away, the "both get removed" counter-rule built to contain it, and the waits and
   cancels around them: the other 2 critical problems that were not simple slips, and 7 high ones.

The proposal is to take both out of the core, and say plainly what that costs:

- When you report a device lost, the servers **block** it at once and for good. But its pieces
  are not destroyed. A thief who has that device would also need a server that ignores the block
  (a hacked or misbehaving server) to sign as you. Today, one person runs all three servers.
- The paper backup is made once, checked by you when it's printed, and never changes. A thief who
  has both an old removed device *and* your paper could sign as you without any server.
- Reporting a device lost needs your face or fingerprint (as you decided on 2026-10-23), or two of
  your devices together, or your paper. A phone with only a passcode can't report another device
  alone.

That still beats an nsec in a password manager. A copied nsec is your account for ever, at once.
Here a thief always needs a second thing: a misbehaving server, or your paper as well. The
"change my leaked password" fix becomes "start fresh with a new key" (key families, later), not a
silent re-deal.

Two questions for you are at the end.

## Rounds so far

| Round | Over | Critical | High | Medium | Low |
|---|---|---|---|---|---|
| 1 | draft 1 | 2 | 7 | 10 | 8 |
| 2 | draft 2's new parts | 0 | 3 | 13 | 5 |
| 3 | all of draft 3 | 2 | 4 | 7 | 7 |
| 4 | all of draft 4 | 1 | 4 | 10 | 8 |

The reports are `keykin-core-redteam-1.md` … `-4.md` in the shared notes folder.

## Which mechanisms keep producing findings

Only critical and high findings are counted. Medium findings are listed where they show the same
root.

| Mechanism | Findings (round·ID) | Root cause | Beats the bar enough to keep? |
|---|---|---|---|
| **Refresh and the backup kept current through it**: dealers, `pending_ok`, delta checks, backup contributions re-made every epoch, the release key per epoch, the previous-epoch fallback, the second-device check | 1·H4, 2·F1 F2 F6 (H), 3·**C1** H4, 4·**C1** H1 H2; mediums 1·M5 M6 M7, 2·F13 F14, 3·M6, 4·M6 | Every refresh, an online member re-makes the paper's shares and wraps them so nobody online can open them. So nobody can check them, and a dishonest dealer can silently kill the paper. Each fix (a sum check, a second-device check, a fallback epoch) moved the blind spot instead of removing it. | **No, not in the core.** What refresh buys over "block at every server": a removed device's shares become worthless even against a server that later misbehaves. That matters, but today one operator runs every server, so the gain is small, and the cost has been 3 criticals and stuck refreshes. |
| **Lockless report-lost, and mutual removal** | 1·C1 H3, 2·F3 F11 F12, 3·(C1 path), 4·**C1 path** M4 M5 M10 | Any device, with no lock, removes another at once. So a thief who reports first wins unless the owner fights back. Mutual removal, 7-day windows, notices to removed phones and `remove` as a delivery all exist to contain that. Round 4 notes it contradicts the user's 2026-10-23 decision (report lost needs the lock or a passkey). | **No.** Requiring the lock (or two devices, or the paper) removes the race, and with it mutual removal, the 7-day window and notices to removed phones. Instant report-lost from a locked phone stays. |
| **Waits, cancels and the recovery freeze** (lockless changes) | 1·C1, 2·F4 F5 F7 F8, 3·**C2** M1 M3 M7, 4·H3 H4 M3 | Many actors (locked device, lockless device, two devices, paper, helper) with different rights over many kinds of wait. Every pair was a seam. | **Keep, simplified.** The 3-day wait for lockless changes is the user's decision and beats the bar. Simplify the rights: any device or the paper may cancel a lockless change; only a locked device, or two devices, may cancel a recovery; a recovery ends every lockless wait. That is three rules instead of six. |
| **Several changes at once, and forks** | 1·H4, 2·F16 F19, 3·M2, 4·M1 | Concurrent drafts and refreshes at different servers. | **Keep, simplified.** With no refresh, a fork is only two membership changes. A draft needs a majority of the account's servers to hold it (2 of 3) before anyone co-signs it, so two drafts can't both win. |
| **`deposit`** (members leaving messages for each other) | 3·H3 | A flooding channel aimed at the owner's notices. | **No.** It served device-to-device signing, which is a module (MAY). Drop it from the core. |
| **The join check** | 1·H1, 3·H2; 4 found it sound | Grinding and racing the 6-digit number. | **Keep.** It has converged. |
| Signing round, nonces, decryption with proofs, the group record, invariants, lock format, lifetimes, push and inbox, migration | none in rounds 3–4 | | **Keep.** Reviewers have found these sound twice. |

## The cut, concretely (what draft 5 would be)

**Removed from the core:**

- Refresh in all its forms: §7.2, `refresh_plan`, `refresh_deal`, `pending_ok`, `bad_delta`, the
  named dealers, the 48-hour drop, the 25-day periodic rule, and §7.3's update deliveries for deltas.
- The per-epoch backup re-making, the previous-epoch fallback and the second-device check (§7.5).
- Mutual removal, the 7-day window, notices to removed phones, and `remove` as a delivery (§6.5).
- `deposit` (§8.2).
- The fork merge rules (§3.4), replaced by "a majority of servers hold the draft".

**Changed:**

- **Report lost** = a `remove` with a lock assertion, or from two devices, or from the paper
  (through the recovery path). Servers block the device at once and for good. Removal is final and
  needs no refresh.
- **The paper** is made once, at setup or when replaced: its shares are made by repair, wrapped to
  the backup key and then the release key, and **checked by the device that prints it** (which
  holds the backup secret for that moment, then forgets it). The wrapped material goes to every
  server and every device. Replacing the paper adds a new backup member and removes the old one.
- **The release key and data key** change only when a device is removed or the paper is replaced:
  the reporting device sends new ones to the remaining devices and servers.
- **Epochs** stay in the record (a counter for membership versions) but no longer mean new shares.

**Kept as written:** the group record and its checks, I1–I5, the join handshake with its check and
nonce, typed-check vouching, the signing rounds, nonces, decryption, locks, the stateless
destructive rule, lifetimes, push and inbox (without `deposit`), transport, versions, migration and
the rename.

**Refresh moves to a later module**, to be designed only when it can be checked. One way it could
be checked: the person re-prints the paper each time, so the new backup is checked at print time.

## Limits draft 5 would state plainly

1. A removed device's pieces stay mathematically valid. The protection is that every server
   refuses it. A server that ignores the block, now or later (hacked, buggy, restored from an old
   backup), plus that device, is the key. Today one person runs every server.
2. A removed device plus the paper (current or old) is the key with no server. That needs two
   thefts.
3. A phone with only a passcode cannot report another device lost alone. It needs a second device
   or the paper (3-day recovery).
4. "Change my password after a leak" means a new key and key families, not a silent re-deal.

Each still beats an nsec in a password manager: there, one copy is the account, at once and for
ever.

## Questions for the user

1. **Drop the automatic re-dealing ("refresh") from the core?** Losing a device would then block
   it at every server rather than destroy its pieces. A thief with that device would also need a
   misbehaving server. Recommended: yes.
2. **Reporting a device lost needs your face or fingerprint** (or two of your devices, or your
   paper), as you decided on 2026-10-23. A passcode-only phone can't report another device lost
   by itself. Recommended: yes.

If both are yes, draft 5 is the cut above, then round 5 of the red team, then the test-vectors
file. The interop test plan (`interop-plan.md`) is already written and does not depend on this.

---

# After round 5 (draft 5)

Round 5 found **0 critical, 4 high, 9 medium, 5 low** (`keykin-core-redteam-5.md`). The cut worked
on what it targeted: nothing in refresh or report-lost came back. Patching stops again under the
rule, so this section maps the four high findings and proposes the cut.

## Plain summary for the user

One feature is still producing serious problems: **letting a phone with no face or fingerprint make
account changes by waiting 3 days**. If your only phone is stolen and you don't act within those 3
days, the thief can add their own device and keep the account for good. The thief also gets 3 days
of cover, because nothing reliably tells a one-phone owner. That has come up in every round.

The proposal: **account changes need a face or fingerprint, a second device of yours, or your
paper.** No "wait 3 days instead". The 3-day wait stays only where it protects you: when someone
uses the paper to recover, and before a mass deletion from a phone without a lock.

The other three high findings are slips with one-line fixes, not new machinery.

## Round 5's high findings

| ID | What | Kind | Proposal |
|---|---|---|---|
| F2 | One stolen phone, nobody acts for 3 days: the thief's waited "add device" or "register lock" goes through, and the account is theirs for good. | The same mechanism as rounds 1–4: lockless account changes by waiting | **Cut** (below) |
| F1 | In the join-code direction, the inviter never checks that the hello comes from the key in the code it scanned, so a watcher can grind both checks. | Slip | Fix: the hello must be sealed by the code's `n`, and that key is the one added. |
| F3 | Nothing authenticates the backup material, so any member could swap in junk and the paper would fail only at recovery. | Slip | Fix: the backup key signs the material when the paper is made; members pin its hash and refuse any other copy. |
| F4 | On a 2-server account, one dead server blocks every change and recovery. | Slip in the minimums | Fix: accounts MUST have at least 3 servers; replacing a dead server is one record (remove + add). |

## The cut

**Every account change needs one of: the asking device's lock, two devices together, or the paper.**
That covers adding a device, server, helper or backup, registering or replacing a lock, removing a
server or the backup, removing or replacing a notice channel, and replacing the paper. Two devices
(6 points) or a device plus the paper (5) already hold the key, so asking them for more adds nothing
(round 5 F9).

**Removed:** the "else `W` waited" column for every change, waited statements for changes, the
cancel table except for recoveries, and most of the freeze. Waits remain only for:

- **paper recovery** (`W`, cancelled by a locked device or two devices), which is what stops a stolen
  paper; and
- **held mass deletions and vanishing** from a device without a lock (§5.8), which only delay one
  event.

**What it costs:** a phone with only a passcode cannot, by itself, add a new device or a server,
or turn on a face lock after the fact. Its owner uses a second device or the paper. Most phones have
a face or fingerprint; a passcode-only owner has the paper.

**What it fixes:** round 5 F2 (the 3-day takeover), F12 (wait spam), F15 (an uncancellable `w`), F16
(missed cancels), and most of rounds 1–4's wait findings, by removing the thing they attacked.

## Smaller changes alongside the cut

- **The data key never changes in the core.** A lost device could read private data written later.
  That is the same as a stolen nsec, which is the bar. Re-keying moves to the optional refresh module.
  This also makes the paper's copy of the data key complete (F7).
- The mediums and lows that are slips (F5 one `draft_held` per record number, F6 one
  `replace_backup` change, F8 the person re-enters the paper before its secret is forgotten, F10 the
  release key rotation tied to the record, F11 devices act on `remove` too, F13 0.12 traffic stops
  once migrated, F14, F17, F18 text) are fixed in the same draft.

## Questions for the user

1. **Account changes need your face or fingerprint, a second device, or your paper. No "wait 3 days
   instead".** A passcode-only phone can't add a new device by itself. Recommended: yes, because it
   closes the "thief waits out 3 days" takeover.
2. **The private-data key doesn't change when you report a device lost.** The lost device could
   still read private notes written later, the same as a stolen nsec. Re-keying would come with the
   optional refresh. Recommended: yes.
3. **Accounts must have at least 3 servers**, so one dead server never blocks you. You have 3 today.
   Recommended: yes.

If all three are yes: draft 6, round 6 under the same rule, then the test vectors and the optional
"Refresh now" module (its own red team).

---

# After round 6 (draft 6)

Round 6 found **1 critical, 6 high, 4 medium, 4 low** (`keykin-core-redteam-6.md`). The second
cut held where it aimed: nobody found a lockless takeover. But two things surfaced that are
structural, not slips, so patching stops again.

## Plain summary for the user

Two problems are now clear:

1. **Without re-dealing, a server can never be safely replaced.** The old server's piece still fits
   the key. Swap one server and the server side holds 4 points, which is the key. Today one person
   runs every server. So replacing a dead server must re-deal, which is your "Refresh now".
2. **The machinery for ordering account changes keeps breaking.** That is the numbered chain of
   member lists, drafts, and "majority of servers holds the draft". It has produced a serious
   finding in every round: forks, deadlocks, devices that fall behind and never catch up. It exists
   only because changes can happen at the same time from different places.

The proposal splits account changes in two.

- **Everyday, instant changes stay in the core:** add a device, report a device lost, and paper
  recovery. These are safe to happen in any order. Each is its own signed approval, members keep the
  whole set, and a device that was off for a month simply catches up. There is no chain, no drafts
  and no forks.
- **Structural changes move into "Refresh now":** adding, swapping or removing a server, adding a
  helper, and replacing the paper. This is the ceremony you asked for. Every member that stays is
  online together, everyone confirms, the paper is reprinted and checked, and the shares are re-dealt
  so the old pieces stop working. It runs one at a time by nature, so it needs no ordering machinery,
  and it fixes problem 1.

## Round 6's critical and high findings

| ID | What | Proposal |
|---|---|---|
| C1 | The paper-recovery approval can be copied by a thief's device in the account and reused for its own changes. | Fix: during recovery, the backup key signs **each** change, and only the backup holder may submit it. |
| H1 | One interrupted change can freeze all changes for good (`draft_held` once per number). | **Cut:** no chain and no drafts. Everyday changes form a set (order doesn't matter); structural ones happen only in "Refresh now". |
| H2 | A device off for more than 7 days never catches up and may co-sign with a reported thief. | **Cut:** members keep the whole set of signed changes, which never expire and are small. Catching up means fetching the set. |
| H3 | Swapping a server without re-dealing gives the server side 4 points. | **Move:** server changes only in "Refresh now", which re-deals. |
| H4 | Replacing the paper can never finish (circular hash). | **Move:** paper replacement only in "Refresh now". Drop the hash; the backup key's signature is enough. |
| H5 | A "lock" can be a passcode (WebAuthn user verification and the Android default accept a PIN). | Fix: a lock is **biometric-only** and dies when enrollment changes: Android `BIOMETRIC_STRONG` with enrollment invalidation, and iOS `biometryCurrentSet`. A browser passkey can't promise that, so it doesn't count as a lock. |
| H6 | Two-device approvals other than adds are one tap each. | Fix: every two-device approval has the person type a 6-digit code from one device into the other. |

The mediums (lockless holds during recovery, inbox addressing, migration order, the draft id) are
fixed or disappear with the cut. In particular, recovery ends lockless holds, and deliveries name
their recipient in the gift wrap's `p` tag.

## What the core would keep

Joining, signing, decryption, the record's commitment and the check on it, the invariants, report
lost, recovery with its wait and freeze, the paper's double wrap, push and inbox, transport and
migration. Five reviews found these sound.

## Questions for the user

1. **Server changes, adding a helper, and replacing the paper happen only in "Refresh now"** (every
   staying device and server online together, paper reprinted). The reason: without re-dealing,
   swapping a server would hand the server side the whole key. Adding a device and reporting one lost
   stay instant. Recommended: yes.
2. **A face/fingerprint lock must be biometric-only.** If it falls back to a passcode, it doesn't
   count. Browser passkeys don't count as locks, because they can fall back to a PIN. Recommended:
   yes.
3. **Every two-device approval asks you to type a 6-digit code** shown on one device into the other,
   not just tap Yes. It is rare (adding a device without a lock, reporting a device lost from two
   lockless devices). Recommended: yes.

If yes: draft 7 (core) plus `refresh.md` (the ceremony) together, then round 7 over both under the
same rule, then the test vectors.
