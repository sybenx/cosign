# Keykin minimum

What an app needs to work with Keykin accounts, and nothing more. [Keykin Core](core.md) is the
normative text; this page only points into it. Anything not listed here is optional, including every
module. The reference libraries (TypeScript and Kotlin) are a convenience: an app that meets these
sections and passes the [vectors](vectors/) works with every other Keykin app, with or without them.

## 1. A site or Nostr client (a door's other side)

Nothing new. A Keykin account is an ordinary npub. A site uses the NIPs it already uses:

- NIP-07 (`window.nostr`), NIP-46 (`bunker://`, `nostrconnect://`) or NIP-55, and optionally a QRST
  `signer-ticket` through the neutral `qrst:` hand-off (Doors and grants §3.4);
- events signed by a Keykin account verify like any other (BIP-340, NIP-01).

Label the sign-in button plainly, **Sign in**. Optional extras, such as `window.nostr.vaults`, are
feature-detected: a site that doesn't use them loses nothing.

## 2. A member device (a signer app that holds pieces)

It MUST implement these Core sections, and pass the computed and negative vectors for them:

| What | Core |
|---|---|
| The ciphersuite (FROST secp256k1-tr, even y) and shares | §1 |
| Epoch records, changes, invariants and every check | §3 |
| Joining (welcome, checks), the paper at creation, the data key, one member per machine | §4 |
| The signing round, nonces, retries, never a bare digest, decryption, lifetimes, co-signer checks it relies on, holds | §5.1–5.8 |
| Approvals (lock, pair, paper, recovery), waits, recovery, report lost, Upkeep: applying redeals and the paper rules | §6 |
| Keeping what it holds | §7 |
| Transport: the envelope, relays (HTTPS optional), message types it sends, the strict JSON profile | §9 |
| Versions | §11.1 |
| Creating an account, if it offers that (key generation, import) | Account admin §1 |
| Picking a replacement server: the server-list format and the pick | Server profile §4 |

SHOULD: push (§8). MAY: the rest of every module (Device policy, Doors and grants, Backup's friends and
heir, Account admin's screens, Helper, Key families), the app-facing device API (`dataKeys` in §4.5,
§5.9), and any UI. An app that skips account creation can still join accounts other apps made. A member
device answers sites through whichever doors it chooses; Doors and grants says how to do that safely,
and is strongly recommended for any app that answers sites.

## 3. A server

It MUST meet Core §2 (its duties), §3 (every check), §4 as it applies to seat holders, §5 (the round
as a co-signer, nonces, retries, decryption, lifetimes, checks, holds), §6.3–6.7 as they apply to
servers, §7.1, §8.1–8.2, §9 and §11.1, and the Server profile module's duty, enrol and list rules (§2–§4). Being on any server list is optional and up to
each list's publisher; a server can serve accounts that seat it directly.

## 4. Lists, hosts and names

- **Server lists and app lists** are open: any app maker, operator or community may publish one, no list
  is special, and apps pin the ones they trust (Core §5.9, §6.7.7).
- **No host is a default.** QRST hosts, push gateways and list publishers named anywhere in these docs
  are examples. An app that offers push runs its own gateway (Core §8.3).
- **Names.** Wire names use the spec's own name (`keykin-…`) or neutral Nostr names (`window.nostr.*`,
  `nostr-vault/…`). No app's name appears in the wire format or in a MUST.
- **Tests.** Interop with nak and standard NIPs is a gate for every implementation, the reference ones
  included ([interop-plan.md](interop-plan.md)).
