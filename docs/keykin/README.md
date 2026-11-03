# Keykin: status

2026-11-03 · branch `claude/keykin-spec-0b883d` · docs only, nothing built, nothing pushed

**Focus:** one Nostr account for life. Sign in anywhere, trusted devices ask less, and no single website, server, app or company can stop you. Cover what people actually need from an account, without fighting the platforms for the last few percent.

**The bar:** an nsec kept in a password manager. Every rule must beat it on security *and* ease of use.

Keykin is the new working name of the Cosign protocol: one Nostr key for life, split with FROST so that
no device, server or company holds it. The bar every rule is held to is an nsec kept in a password
manager. Every rule must beat that on security **and** on ease of use.

## What is here

| File | What it is | Status |
|---|---|---|
| [core.md](core.md) | **Keykin Core, draft 13.1**: the core spec, including Upkeep (§6.7, replacing servers, the helper and the paper) and one member per machine (§4.6) | **Red-team round 13 found no critical or high problems.** Its mediums and lows are folded in. |
| [vectors/](vectors/) | Test vectors: `gen_vectors.py` produces `vectors.json` (computed, for draft 13.1); `vectors.md` lists the behaviour cases | Computed vectors regenerated for 13.1. Behaviour cases need a reference implementation to fill in expected outputs. |
| [interop-plan.md](interop-plan.md) | Compatibility tests: nak must pass, plus a top set chosen by use (Primal, Amethyst, nostr-tools/NDK, Damus), and the Upkeep events a site must never notice | Plan only. |
| [simplification.md](simplification.md) | Why and how the design was cut, round by round, with the user's answers | Record. |
| [../decisions.md](../decisions.md) | Every decision, one dated line each | Current. |

The red-team reports (`keykin-core-redteam-1.md` … `-13.md`, `keykin-refresh-redteam-2.md`,
`keykin-machine-rule-*.md`) are in the shared notes folder for this group of sessions, not in the repo.
The design panel's Upkeep proposal is `~/igloo/keykin-upkeep-design.md`. `refresh.md` was replaced by
Upkeep and is in git history.

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
| refresh only | refresh 3 | 1 | 2 → replaced by Upkeep |
| machine rule | core 8.3 §4.6 | 0 | 2 → fixed |
| machine re-check | core 8.4 §4.6 | 0 | 0 |
| 9 | core 9 (Upkeep) | 0 | 6 |
| 10 | core 10 | 0 | 2 |
| 11 | core 11 | 0 | 1 |
| 12 | core 12 | 0 | 1 (local) |
| **13** | **core 13** | **0** | **0** |

## Open by design

- **Outside reviewer** sign-off on the core.
- **Formal check** of the one-call signing round (core §5.1).
- **Reference implementation**, to produce the behaviour vectors' expected outputs; TypeScript and
  Kotlin should both pass them.
- **Interop runs** against a prototype (`interop-plan.md`).
- **Modules** not yet written: Account admin, Server profile, Device policy, Doors and grants, Backup,
  Helper, Key families.

`../COSIGN.md`, `../NIP-XX.md`, `../servers.md` and `../choosing-servers.md` still describe Cosign 0.12 as
built, and stay until the Keykin build replaces it.
