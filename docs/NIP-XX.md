NIP-XX
======

Threshold Co-Signing
--------------------

`draft` `optional`

A user's key is split with FROST into weighted pieces held by their own devices and by
**co-signers**: always-on services, typically relays, ideally run by different operators.
Signing takes 4 points: each device holds 3, each co-signer 1, a paper backup 2. So a
device plus any one co-signer signs, two devices sign, and all the co-signers together
never can. Sites keep using NIP-07, NIP-46 and NIP-55 unchanged; this NIP defines
only the traffic between the pieces and what a co-signer must do.

The design, the user experience and the reasoning are in
[COSIGN.md](COSIGN.md). This document is the wire format and the obligations.

## Terms

- **Group** — one user's key. Its public key is the user's pubkey.
- **Member** — anything holding a piece: a **device** (an app on hardware the user owns)
  or a **co-signer** (a service). Each member has a stable keypair, its **member key**,
  used only to address and authenticate member traffic.
- **Epoch** — one version of the set of pieces. Pieces of different epochs never
  combine.
- **Operator** — whoever runs a member. The user operates their own devices.

## Cryptography

- FROST as in RFC 9591, ciphersuite `FROST(secp256k1, SHA-256)` with the BIP-340
  challenge (as `frost-secp256k1-tr`). Odd-y group keys are negated as in BIP-340.
  Resulting signatures are ordinary BIP-340 signatures.
- Threshold `t = 4`. A device holds 3 shares, a co-signer exactly 1, the backup always
  2; every share has a unique index `i ≥ 1`. A member with several shares acts as
  several FROST participants. A group starts with at least two co-signers.
- The **device coordinates** every round it takes part in. Rounds sent to several
  co-signers at once are independent, each with fresh coordinator nonces; the
  coordinator completes the first and discards the rest.
- Threshold ECDH for NIP-04, NIP-44 and NIP-59: members return `λ_i · s_i · P` for
  shares worth 4 points; the coordinator adds them.
- Each round uses fresh nonces, used once and never persisted where a restore could
  replay them.

## Events

### Group record (`kind:30242`, `d = "frost"`)

Signed by the group key. Content is NIP-44 encrypted under a random **group secret**
that every member holds and that changes on every refresh. Tags: `["d","frost"]`,
`["epoch","<counter>"]` (plaintext).

```jsonc
{
  "epoch": { "counter": 7, "id": "<128-bit hex>" },
  "group_pub": "<hex>",
  "commitments": ["<a_1·G>", "<a_2·G>", "<a_3·G>"],
  "members": [
    { "shares": [1, 2, 3],  "pubkey": "<member key>", "kind": "device",   "label": "Pixel 9" },
    { "shares": [4, 5, 6],  "pubkey": "<member key>", "kind": "device",   "label": "Chrome on Mac" },
    { "shares": [7],        "pubkey": "<member key>", "kind": "cosigner", "label": "syb.lol",  "operator": "<operator pubkey>" },
    { "shares": [8],        "pubkey": "<member key>", "kind": "cosigner", "label": "…",        "operator": "<another>" },
    { "shares": [9],        "pubkey": "<member key>", "kind": "cosigner", "label": "…",        "operator": "<a third>" },
    { "shares": [10, 11],   "pubkey": "<backup key>", "kind": "backup" }
  ],
  "removed": ["<member key>", "..."]
}
```

Members verify each of their shares against the commitments (Feldman, degree 3).

### Member messages (`kind:24301` rumor)

All member traffic is a `kind:24301` rumor, sealed (`kind:13`) by the sender's member
key and gift-wrapped (NIP-59) to the recipient's member key:

- **live** messages in an ephemeral wrap, `kind:21059`, re-sent until answered;
- messages that must wait for an offline member in a `kind:1059` wrap with NIP-40
  `expiration` 30 days;
- backup contributions in a `kind:1059` wrap with no expiration.

Rumor content is JSON with a `type`, the group pubkey `g`, the `epoch` counter and a
request `id`. A message larger than 24 KB of plaintext is split into parts
`{"part": n, "of": m, "id": ...}` and reassembled by `id`.

| `type` | From → to | Body |
|---|---|---|
| `sign` | coordinator → member | full unsigned event, coordinator's commitments, origin (site grant or member) |
| `partial` | member → coordinator | commitments and signature shares for each of its shares, or `refused` with a reason |
| `asking` | device → coordinator | the user is being asked; wait (≤ 60 s) |
| `declined` | device → coordinator | the user said no; the round ends, no one else is asked |
| `ecdh` / `ecdh_partial` | coordinator ↔ member | points `P[]` / partials `λ·s·P[]` |
| `hold` / `approve` | member → devices / device → members | a destructive event and its plain-words reason / an approval for its id |
| `history` | signer → members | a signed event of an archived kind, signed without a co-signer |
| `presence` | device → user's devices | `awake` or `asleep`; never sent to a co-signer |
| `repair` | member → new member or backup key | blinded, Lagrange-weighted contributions to each new share |
| `refresh` | dealer → member | the member's delta of a zero-constant polynomial, with commitments |
| `ack` | member → dealer | the new piece verified |
| `remove` | member → members | a member key, and that the sender confirmed with its device lock |
| `wait` / `cancel` | co-signer → members / device → co-signers | a pending addition or backup use, and when it completes / cancel, confirmed with the device's lock |
| `finalized` | initiator → members | the epoch is complete; old pieces may be destroyed |
| `take_out` / `released` / `noted` | device → co-signers / co-signer → device | take the account out: after the wait, the co-signer's shares sealed to the device; with the paper, `noted` before the device shows the key |
| `forget` | device → co-signers | stop at once; delete this co-signer's pieces after the wait |

A signing round MAY be collapsed into one request and one answer: the coordinator sends
its commitment in `sign`, and the co-signer generates a fresh nonce and returns its
commitment and share together in `partial`. *(Security of this one-round form is to be
confirmed in review before 1.0.)*

## Co-signer obligations

A co-signer MUST:

1. Refuse every round from a member key that is not in the current group record, or is
   listed in `removed`, from the moment a valid `remove` arrives.
2. Hash the full event itself (NIP-01); never sign a bare digest.
3. Refuse requests from a site without a live grant, and site requests it has already
   answered or whose `created_at` is older than 30 s.
4. MAY judge each event against the version it replaces and refuse one that would
   destroy something (COSIGN.md §5.3) without an approval; the device's own check is the
   gate. Holding MUST NOT be the default for ordinary events.
5. Keep the recent versions of the user's replaceable lists (kinds 0, 3, 10000–10030,
   30000–30030; reference 25 each), built only from events validly signed by the group.
6. Never finish a decryption for a user it does not belong to (it returns partials
   only), and never hold a NIP-46 signer key for such a user. Give decryption partials
   only to active member devices: never to the backup key or a removed member. Until
   per-site signer keys exist, a co-signer that still holds a NIP-46 signer key for a
   user it does not belong to refuses NIP-46 encrypt and decrypt requests.
7. Destroy its old piece once a refresh verifies, with no copy kept anywhere.
8. Enforce waits: refuse to take part in a `repair` for a new device vouched for by one
   device without its lock, or in any round using the backup's shares without a
   surviving device, until 3 days after sending `wait` to every member, unless a
   member device sends `cancel`.
9. Hold exactly one share per group, and never delete a finished group's share for
   inactivity; only the guarded `forget` (after its wait) deletes it.
10. Never connect to private, loopback, carrier-grade NAT or cloud-metadata addresses
    because a relay or push address in a group record, a site's request or a new device
    names one; resolve and check at every connect. Push only to `https://` hosts the
    operator allows, without following redirects.

A co-signer that is a relay SHOULD accept `kind:21059` and `kind:1059` wraps addressed
to its member keys from any connection, and deliver wraps addressed to the group's
devices, so that devices need only add it to their relay list.

## Device obligations

A device MUST:

- coordinate its own rounds, judge every event against its own archive (COSIGN.md
  §5.3), and ask the user before signing one that would destroy something;
- ask for its own lock (biometric or passcode) at the moment it vouches for a new
  device, reports a device lost, cancels a wait, or approves a held event. Today this
  is a claim co-signers cannot check; a hardware-bound user-verification key is planned;
- carry the epoch in every round with no co-signer, refuse any round below the newest
  epoch it has seen, and fetch the latest group record after coming online before
  taking part in such a round;
- rebuild the key without first telling the co-signers only through the escape hatch:
  no co-signer has answered for 7 days, and a device with the paper backup, or two
  devices, confirm with the lock after a plain warning (COSIGN.md §8.4);
- prefer another of the user's own awake devices over a co-signer it does not operate,
  and otherwise ask its fastest co-signer first, without adding delay (COSIGN.md §5.1);
- send `history` for every archived-kind event it signs without a co-signer.

## Server discovery

- **Server announcement** (`kind:30243`, `d = "cosign-server"`), signed by the co-signer's
  host key. Content `{"relays":[...],"https":"<url>"|null,"enroll":"open"|"invite","version":"<string>"}`.
  Tags `["p", <operator pubkey>, "", "operator"]`, optionally `["nip05", "<name@domain>"]`.
- **Operator's server list** (`kind:10243`), signed by the operator: one
  `["p", <co-signer host key>]` per server. A co-signer belongs to an operator only when
  each names the other.
- Clients SHOULD pick co-signers with distinct operator pubkeys, and among those prefer
  the best measured answer times. When fewer operators exist, a client MAY fill from
  one operator's co-signers, MUST show that to the user, and SHOULD replace them by
  refresh as other operators appear. Clients ship a seed list so a fresh install works.

## Site access

Sites use NIP-07, NIP-46 or NIP-55 as they do today. A site's access is a grant held by
the members, never a piece. For NIP-46, the signer key of each site is held only by the
user's devices and by co-signers the user operates.

## Security considerations

- One piece signs nothing, and all co-signers together (3 points) sign nothing. A
  breached co-signer cannot sign and cannot get a held event signed: the device gates
  those.
- A co-signer sees every event it co-signs, the user's sites, and the peers of
  decryptions, never their plaintext.
- Two of the user's devices (6 points) can sign without any co-signer and its checks.
- A stolen unlocked device plus one cooperating co-signer is 4 points; reporting the
  device blocks it at every honest co-signer.
- A Nostr key cannot be replaced. 4 points of one epoch in a thief's hands is the
  identity, permanently; removal plus refresh exists to stop that from happening.
- `kind:24301`, `kind:30242`, `kind:30243` and `kind:10243` are provisional. None
  appears in the NIPs registry, its pull requests or its issues as of 2026-10-24.
