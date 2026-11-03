# Keykin: status

2026-11-03 · branch `claude/keykin-spec-0b883d` · docs only, nothing built, nothing pushed

**The bar:** an nsec kept in a password manager. Every rule must beat it on security *and* ease of use.

Keykin is the new working name of the Cosign protocol: one Nostr key for life, split with FROST so that
no device, server or company holds it. The bar every rule is held to is an nsec kept in a password
manager. Every rule must beat that on security **and** on ease of use.

## What is here

| File | What it is | Status |
|---|---|---|
| [core.md](core.md) | **Keykin Core, draft 14.15**: the core spec, including the strict JSON profile (§9.5), including Upkeep (§6.7: replacing servers, the helper and the paper), one member per machine (§4.6), the helper's limits (§5.7 item 8) and the encodings the reference implementation pinned (§6.7.10) | Core round 13 was clean; the later changes were reviewed in core rounds 14–18 (18 clean). The final seam review across core and modules found **no critical or high** problems. |
| [modules/server-profile.md](modules/server-profile.md) | Running and listing a server: duties, abuse limits, enrol replies and per-seat keys, the signed public list, closing and moving | **Done**, draft 7 (round 6 clean) |
| [modules/device-policy.md](modules/device-policy.md) | How a device judges what it signs: lists, profile, relays, wallet, deletions and media, Undo, drafts | **Done**, draft 18 (round 16 clean) |
| [modules/doors-and-grants.md](modules/doors-and-grants.md) | NIP-07, NIP-55, NIP-46 and QRST; site grants and scopes; syncing, ending and watching; borrowed computers | **Done**, draft 19 (round 18 clean) |
| [modules/backup.md](modules/backup.md) | The QR code and 24 words, recovery contacts (friends), and an heir | **Done**, draft 5 (round 4 clean) |
| [modules/account-admin.md](modules/account-admin.md) | Creating an account (DKG, import), devices, leaving, deleting, taking data out | **Done**, draft 8 (round 6 clean) |
| [modules/helper.md](modules/helper.md) | A friend's always-on box that may post for chosen sites, stoppable from any device | **Done**, draft 8 (round 7 clean) |
| [modules/key-families.md](modules/key-families.md) | Linking a master key to child keys so followers can move after a leak (off the 1.0 path) | **Done**, draft 7 (round 6 clean) |
| [vectors/](vectors/) | Test vectors: `gen_vectors.py` produces `vectors.json` (computed, now including `enrol_keys`); `vectors.md` lists the behaviour cases | The reference implementation passes every computed vector and cross-checked `enrol_keys`. |
| [interop-plan.md](interop-plan.md) | Compatibility tests: nak must pass, plus a top set chosen by use (Primal, Amethyst, nostr-tools/NDK, Damus), and the Upkeep events a site must never notice | Plan only. |
| [simplification.md](simplification.md) | Why and how the core was cut, round by round, with the user's answers | Record. |
| [../decisions.md](../decisions.md) | Every decision, one dated line each, including the user's answers Q1–Q9 | Current. |

The red-team reports are in the shared notes folder for this group of sessions, not in the repo:
`keykin-core-redteam-1.md` … `-18.md`, `keykin-module-<name>-redteam-N.md` for each module,
`keykin-seam-review-1.md`, and the reference implementation's `keykin-impl-spec-issues.md` (batches 1–5,
all pinned). `refresh.md` was replaced by Upkeep and is in git history.

## Red-team rounds

**Core**

| Round | Reviewed | Critical | High |
|---|---|---|---|
| 1–8 | core drafts 1–8 (and refresh) | 7 | 33 |
| 9–12 | core 9–12 (Upkeep) | 0 | 10 |
| 13 | core 13 | 0 | 0 |
| 14–17 | core changes since 13.1 (modules, the implementation's pins, the helper rules) | 0 | 1 each |
| **18** | **core 14.8–14.11** | **0** | **0** |

**Modules** (critical / high per round, last round clean)

| Module | Rounds | Last |
|---|---|---|
| Server profile | 6 | 0 / 0 |
| Device policy | 16 | 0 / 0 |
| Doors and grants | 18 | 0 / 0 |
| Backup | 4 | 0 / 0 |
| Account admin | 6 | 0 / 0 |
| Helper | 7 | 0 / 0 |
| Key families | 6 | 0 / 0 |
| **Seam review (all)** | 1 | **0 / 0** |

The reference implementation's own code reviews found two real holes the red teams had missed (a fourth
point through an unchecked repair helper list, and a relayed account delete accepted without checking its
approval). Both are fixed in the core and Account admin.

## Decided limits, at the bar

These are stated in the modules on purpose, by the user's answers (Q8, Q9) or as the bar itself:

- A site with `post` access can overwrite another app's articles or listings, as with a pasted nsec (Device
  policy §8).
- A device restored from an old copy, while most relays are unreachable, may answer a site it had signed
  out of until it reaches most relays or is reported (Doors and grants §6).
- On a lockless account, every lockless device holds the backup secret until a lock or a paper exists, like
  an nsec kept in each extension (core §4.3 step 4).

## Open by design

- **Outside reviewer** sign-off on the core.
- **Formal check** of the one-call signing round and the one-request list (core §5.1, §6.7.10).
- **Reference implementation**: the core and parts of Server profile, Account admin and Backup are built
  (TypeScript, `claude/keykin-impl-738c41`); behaviour vectors' expected outputs come from it. Kotlin should
  pass them too.
- **Interop runs** against a prototype (`interop-plan.md`).
- **Kind numbers** (24301, 24302, 30242, 30243, 10243, 1244–1247) are provisional and must be pinned before
  1.0.

`../COSIGN.md`, `../NIP-XX.md`, `../servers.md` and `../choosing-servers.md` still describe Cosign 0.12 as
built, and stay until the Keykin build replaces it.
