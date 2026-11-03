# Behaviour cases: expected outputs from the reference implementation

The behaviour cases in `docs/keykin/vectors/vectors.md`, with the outcome this implementation
gives. "refuse `x`" is the stable error code (`{type: "error", code: "x"}` on the wire). Each row
names the test that checks it. A second implementation (Kotlin) should give the same accept or
refuse result. The codes are proposals until the spec pins them.

| # | Case | Expected | Test |
|---|---|---|---|
| 1 | One-call round, device (3) + server (1); even key, R of either parity | accept: plain BIP-340 under `g` | `frost.test.ts` (24 rounds, so both R parities occur), `cosigner.test.ts` |
| 1 | Two-call round, backup + two servers, with `after` | accept, only in a recovery session and only for a `recovery`-approved change | `cosigner.test.ts`, `sim.test.ts` (paper recovery) |
| 1 | A bad partial | refuse `bad_partial: member <key>` at the coordinator | `cosigner.test.ts` |
| 1 | `signers` not exactly the participants | refuse `bad_signers` | `cosigner.test.ts` |
| 1 | Commitments miss an index | refuse `bad_commitments` | `cosigner.test.ts` |
| 1 | Commitments contain the identity (or any non-point) | refuse `malformed` (the identity has no 33-byte encoding) | `cosigner.test.ts` |
| 1 | Byte-identical retry | the cached answer, identical | `cosigner.test.ts` |
| 1 | Same id, different body | refuse `id_reused` | `cosigner.test.ts` |
| 1 | Second `sign` for the same `after` | refuse `after_used` | `cosigner.test.ts` |
| 1 | Co-signer's own commitment altered in the two-call list | refuse `bad_commitments` | `cosigner.test.ts` |
| 1 | State mismatch | `stale {ids}` | `cosigner.test.ts` |
| 2 | Same OS randomness, two requests: nonces (co-signer and coordinator) | different nonces; `D ≠ E` | `frost.test.ts` |
| 2 | Same for the DLEQ `k` | different `k` (the request hash is an input) | `ecdh.ts` by construction; `vectors.test.ts` |
| 3 | Record of the wrong kind, or wrong `d` | refuse `not_a_record` | `membership.test.ts` |
| 3 | Tags disagree with the content | refuse `bad_record` | `membership.test.ts` |
| 3 | A kind 1 that looks like a record | refuse `not_a_record` | `membership.test.ts` |
| 3 | `d` = `cosign` (old name) | accept (read-only) | `membership.test.ts` |
| 3 | Record for another group | refuse `wrong_group` | `membership.test.ts`, `join.test.ts` |
| 3 | Commitment the device can't rebuild | refuse `bad_share` / `bad_commitment` | `membership.test.ts` |
| 3 | I1 / I2 / I3 / I5 / I6 broken; not exactly 3 server seats | refuse `invariant` (message names the rule) | `membership.test.ts` |
| 3 | Change approved by a helper | refuse `approver_not_device` | `membership.test.ts` |
| 3 | Change naming the previous epoch | refuse `wrong_epoch` (Core 1.x has one epoch; the case's 7-day rule is stale, spec issue 15) | `membership.ts` |
| 3 | Two adds claiming one index | both void (the key is no member) | `membership.test.ts` |
| 3 | Two lock changes replacing one lock | both void, the device is lockless; a `void:<id>` change restores a lock | `membership.test.ts` |
| 3 | Catch-up union; one server omits a removal | the removal holds | `membership.test.ts` |
| 4 | Honest join, both directions | accept; shares on their points | `join.test.ts` |
| 4 | Racer's hello | the honest hello gets `already_accepted`; the typed check does not match | `join.test.ts` |
| 4 | Join-code hello not sealed by `n` | refuse `not_sealed_by_n` | `join.test.ts` |
| 4 | Welcome from a stranger | refuse `not_sealed_by_m` | `join.test.ts` |
| 4 | Record for another group | refuse `wrong_group` | `join.test.ts` |
| 4 | Inviter's (or the server's) sigma missing | refuse `sigma_missing` | `join.test.ts` |
| 4 | Summed share misses the commitment | refuse `repair_failed` | `join.test.ts` |
| 5 | Valid assertion for `sign`, `change`, `cancel` | accept | `membership.test.ts` |
| 5 | UV flag missing | refuse `lock_flags` | `membership.test.ts` |
| 5 | Wrong `rp` | refuse `lock_rp` | `membership.test.ts` |
| 5 | Challenge over a different body | refuse `lock_challenge` | `membership.test.ts` |
| 5 | A destructive approval reused at a second co-signer | accept | `cosigner.test.ts` |
| 6 | Approval table rows met / not met | accept / refuse `approval_not_allowed`, `approver_not_device`, `pair_same_device`, `not_backup_key`, `no_lock` | `membership.test.ts` |
| 6 | `pair` signed by a non-device | refuse `approver_not_device` | `membership.test.ts` |
| 6 | `paper` approval with a stale or foreign challenge at the co-signer | refuse `stale_challenge` / `wrong_challenge_server` | `cosigner.ts` |
| 6 | `recovery` approval from a connection other than the holder's | refuse `not_holder` | `cosigner.ts` |
| 6 | Waited statement shorter than `W` | not counted; with fewer than two, refuse `waited_missing` | `approval.ts`, `sim.test.ts` |
| 6 | Hold cancelled by a locked device | no statement; `sign` with the hold refused `hold_not_passed` | `cosigner.test.ts` |
| 6 | A recovery ends running holds and refuses new ones | refuse `frozen` | `cosigner.test.ts` |
| 6 | Recovery wait cancelled by a locked device | the holder gets no release (`waited_missing`) | `sim.test.ts` |
| 6 | Missed `cancel`; dead peer skipped after an hour | a server fetches peers' cancels before a waited statement or release, so the recovery is not released; a quiet peer is skipped for an hour | `sim.test.ts` (missed cancel); skipping is in `sim/nodes.ts` (`quiet`) |
| 7 | Removal by `lock`, `pair`, `paper` | accept | `membership.test.ts`, `sim.test.ts` |
| 7 | Lockless single device reporting another | refuse `no_lock` | `membership.test.ts`, `sim.test.ts` |
| 7 | Rounds with a removed member | refuse `removed` | `cosigner.test.ts`, `sim.test.ts` |
| 7 | `deliver` from a removed member | refuse `removed` | `transport.test.ts` |
| 8 | Full recovery flow | accept, ending in `[remove, redeal]` (F9) | `sim.test.ts` |
| 8 | Material whose base doesn't match the pin | refuse `bad_material` | `upkeep.test.ts` |
| 8 | Ordinary event in a session | refuse `recovery_session` | `cosigner.test.ts` |
| 9 | Destructive table and lifetimes, through a server | as `vectors.json`; refusals `needs_approval`, `expired`, `dated_ahead`, `bad_class` | `cosigner.test.ts` |
| 10 | Push padding and size | every payload the same length (2,297 plaintext bytes for a 2,400-byte body); `wrap` dropped when it doesn't fit | `transport.test.ts` |
| 10 | Server signature | refuse `bad_signature` / `unknown_server` | `transport.test.ts` |
| 10 | One address per class; dropped on removal or 404/410 | yes | `transport.test.ts` |
| 10 | `deliver` with a `p` tag that isn't `to` | refuse `bad_p` | `transport.test.ts` |
| 10 | Inbox caps never drop deliveries or wait notices | yes | `transport.test.ts` |
| 11 | Chunking and reassembly by sender | reassembled per `(sender, of)` | `transport.test.ts` |
| 11 | 513 KB message | refuse `too_large` | `transport.test.ts` |
| 11 | Expired part | dropped | `transport.test.ts` |
| 11 | Share-bearing message as kind 1059 | refuse `never_stored` | `transport.test.ts`, `sim.test.ts` (whole wire) |
| 12 | Seat replacement: same index, same value at that state | yes; after the redeal, the dead server's old point is useless | `frost.test.ts`, `sim.test.ts` |
| 12 | Redeal: delta check, `C_S` rebuilt from a device's points, old share destroyed, `stale` and catch-up | yes; a bad delta is refused `bad_delta`; never applied twice or once abandoned (`cannot_apply`) | `sim.test.ts`, `upkeep.test.ts` |
| 12 | `[seat]` or `[remove]` without a redeal | refuse `mandatory_redeal` | `membership.test.ts` |
| 12 | `self` remove | accept with `self`, dealt by the app; refused `self_redeal_dealer` otherwise | `membership.test.ts` |
| 12 | Seat conflicts | same `new` counts once; different `new` voids both; one host in two seats voids both | `membership.test.ts` |
| 12 | Two paper changes | lowest list hash wins; the loser's key is removed | `membership.test.ts` |
| 12 | `rerepair` allowed / forged proof | accept / refuse `bad_proof` | `sim.test.ts` |
| 12 | `need_repair` for the backup seat; for an unassigned index | refuse `backup_seat` / `not_assigned` | `sim.test.ts` |
| 12 | Signpost sign or delete on a site's request | refuse `machinery`, `signpost_n`, `signpost_h` | `cosigner.test.ts` |
| 12 | Dealer upload without a valid approval; inert uploads expire | refuse `bad_approval` / `approval_expired`; inert uploads expire after 7 days | `upkeep.test.ts`, `sim.test.ts` |
| 12 | Concurrent redeals | both apply (additive); every member reaches the same state | `sim.test.ts` |
| 12 | Dealer dies before the co-sign | nothing changes; signing goes on at the old state | `sim.test.ts` |

Not yet covered: the paper (F7) flow and paper re-issue, F3 (every server dead), the helper,
`need_seeds`, the signpost's publication, forwarding notes and `seated?`, passive servers, and a
recovery whose state includes a stranded redeal.
