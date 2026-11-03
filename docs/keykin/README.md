# Keykin: status

2026-11-02 · branch `claude/keykin-spec-0b883d` · docs only, nothing built, nothing pushed

Keykin is the new working name of the Cosign protocol: one Nostr key for life, split with FROST so
that no device, server or company holds it. The bar every rule is held to is an nsec kept in a
password manager. Every rule must beat that on security **and** on ease of use.

## What is here

| File | What it is | Status |
|---|---|---|
| [core.md](core.md) | Keykin Core, draft 8.4: the short core spec | **Passed red-team round 8** (no critical or high problems), but **not the deliverable without structural change** (user, 2026-11-02). |
| [core.md §4.6](core.md) | One member per machine (a desktop app is the machine's member; extensions relay to it) | Reviewed: 0 critical, 2 high (handover gaps), verdict keep. Fixes applied in 8.4; quick re-check below. |
| [refresh.md](refresh.md) | "Refresh now", the ceremony for changing servers, helper and paper | **Required; redesign in progress.** Draft 3's red team found 1 critical and 2 high problems. The user unparked it: structural change must work. The hub's design panel is choosing the approach. |
| [vectors/](vectors/) | Test vectors: `gen_vectors.py` produces `vectors.json` (computed); `vectors.md` lists the behaviour cases | Computed vectors done. Behaviour cases need a reference implementation to fill in expected outputs. |
| [interop-plan.md](interop-plan.md) | How to test compatibility: nak must pass, plus a top set chosen by use (Primal, Amethyst, nostr-tools/NDK, Damus) | Plan only. |
| [simplification.md](simplification.md) | Why the design was cut five times, with the user's answers | Record. |
| [../decisions.md](../decisions.md) | Every decision, one dated line each | Current. |

The red-team reports (rounds 1–8, refresh, machine rule) are in the shared notes folder for this group
of sessions, not in the repo.

## Red-team rounds

| Round | Reviewed | Critical | High |
|---|---|---|---|
| 1 | core draft 1 | 2 | 7 |
| 2 | draft 2's new parts | 0 | 3 |
| 3 | draft 3 | 2 | 4 |
| 4 | draft 4 | 1 | 4 |
| 5 | draft 5 | 0 | 4 |
| 6 | draft 6 | 1 | 6 |
| 7 | core 7 + refresh 1 | 1 | 5 |
| 8 | core 8 + refresh 2 | 0 | 0 in the core (3 in refresh) |
| refresh only | refresh 3 | 1 | 2 → redesign |
| machine rule | core 8.3 §4.6 | 0 | 2 → fixed in 8.4 |

## Open by design

- **Outside reviewer** sign-off on the core.
- **Formal check** of the one-call signing round (core §5.1).
- **Reference implementation**, to produce the behaviour vectors' expected outputs. TypeScript and
  Kotlin should both pass them.
- **Interop runs** against a prototype (`interop-plan.md`).
- **Structural change** (refresh or its replacement): required, redesign in progress.
- **Modules** not yet written: Account admin, Server profile, Device policy, Doors and grants, Backup,
  Helper, Key families.

`../COSIGN.md`, `../NIP-XX.md`, `../servers.md` and `../choosing-servers.md` still describe Cosign
0.12 as built, and stay until the Keykin build replaces it.
