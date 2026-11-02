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
