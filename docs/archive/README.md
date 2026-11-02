# Archive

Drafts that a later document replaced. They are kept for their reasoning and their red-team
verdicts, not as current text. Git history is intact (`git log --follow`).

| File | Moved | Why | Replaced by |
|---|---|---|---|
| [device-evidence.md](device-evidence.md) | 2026-11-02 | Its red team found the mechanism cannot be built (forgeable evidence, nothing binding a key to its share indices). The problem and its §1 rule survive. | The group record and share proofs in [Keykin Core](../keykin/core.md) §3, which bind keys to indices through the polynomial commitment the user's own device saw. |

## Drafts on unmerged branches that Keykin Core also replaces

These were never on `main`, so there is nothing to move. Do not merge them as they stand.

| Branch | File | Replaced by |
|---|---|---|
| `claude/pinned-members` | `docs/pinned-members.md` (draft 2 and its red team) | Core §3 (group record, pinned commitment, pinned kinds) and §4 (join handshake). Its finding about the join became live finding #17, which Core §4 closes. |
| `claude/no-server-history` | `docs/no-server-history.md` | Core §2 (what a server keeps) and §6.4 (the stateless destructive rule). |

## Still current, not archived

- [COSIGN.md](../COSIGN.md), [NIP-XX.md](../NIP-XX.md), [servers.md](../servers.md) and
  [choosing-servers.md](../choosing-servers.md) describe **Cosign 0.12 as built**. Code, tests and
  cosign.aaro.cc link to them, and the feature freeze keeps them matching the code. They become
  archive material when the Keykin Core build replaces that code (plan Phase 4), not before.
- [faster-messages.md](../faster-messages.md) is an open proposal (batching decryptions), not
  superseded. It belongs to the DMs module later.
