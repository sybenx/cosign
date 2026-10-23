# Cosign

A Nostr key split three ways — **two servers and your phone** — where any two can sign
and no one can sign alone.

- Everyday things (notes, reactions, reposts, logins, app settings) are signed by the two
  servers between them. The phone never hears about them.
- Everything else (profile, follow list, deletions, DMs, relay list, …) needs the phone:
  it buzzes, you tap Approve or Deny.
- Any one of the three can be off, lost or compromised. Lose the phone: the servers still
  sign everyday things. Lose a server: the other one and the phone still sign everything.
  A compromised server can't sign alone, and the other server won't co-sign anything
  sensitive with it.

Nostr apps talk to it through one ordinary NIP-46 **bunker** link. If server A goes down,
server B answers that same link after 30 s.

**This is a prototype to see how it feels.** Unaudited, hand-rolled FROST, provisional
wire format. Use the throwaway key setup makes, not your real one.

## Run it

```sh
cd server
npm install
node setup.ts              # makes a throwaway key and splits it 2-of-3
node server.ts data/a      # http://localhost:8711 — shows the phone's pairing code and the bunker link
node server.ts data/b      # http://localhost:8712
```

Install the app (`android/app/build/outputs/apk/release/app-release.apk`), tap **Scan your
server's code**, scan the code on server A's page, tap **Join**. Then log in to any Nostr
app that supports a remote signer / bunker with the link on the same page.

`node setup.ts --nsec nsec1…` splits a key you already have. `--force` replaces the group
(the old key is gone for good).

## How it works

```
 Nostr app ──NIP-46──▶ server A ─┬─ "sign this note" ──▶ server B   (auto: routine kind)
                                 └─ "sign this profile" ▶ phone     (asks you)
```

- **Transport.** Everything is relays (syb.lol, nos.lol, relay.primal.net). No member opens
  a port to another. Member messages are ephemeral events (kind 28001), NIP-44 encrypted to
  the recipient and signed by the sender.
- **Signing.** The server that got the request picks a co-signer, sends its nonce
  commitments with the event; the co-signer checks the event really hashes to what it's
  asked to sign, applies its policy, and answers with its commitments and partial in one
  message. The coordinator verifies the partial, adds its own, and checks the result is a
  valid BIP-340 signature before handing it to the app.
- **Encryption** (NIP-04 / NIP-44 for DMs and encrypted lists) uses threshold ECDH: each of
  two members contributes λᵢ·sᵢ·P; the shared point is their sum. Servers do this between
  themselves; the phone helps only when a server is down. Shared secrets are cached in
  server memory for 10 minutes.
- **Pairing** is shaped like QRST at its lowest level: the QR carries server A's public key,
  a one-time token and the relays — not the share. The phone answers with the token, gets
  the share sealed to a key it just made, checks it against the group, asks you, and
  confirms. Then server A deletes its copy. It is *not* QRST-wire-compatible yet.

## Layout

```
server/
  frost.ts        dealing, nonces, partial signatures, aggregation, threshold ECDH
  policy.ts       which kinds are routine; who must be in the pair for the rest
  net.ts          relay pool, sealed member messages
  server.ts       coordinator, co-signer, NIP-46 bunker, pairing, failover, status page
  setup.ts        trusted dealer: key → three shares → two state files
  test/           fake-phone.ts, client.ts (a NIP-46 app), e2e.sh, vectors.ts
android/          the Cosign app (Kotlin, Compose)
  core/Frost.kt   the phone's half of frost.ts, pinned to it by src/test/resources/frost.json
  Phone.kt        joining, answering, asking the user
  CosignService   keeps the relay connection open; request notifications
```

## Tests

```sh
cd server && node test/vectors.ts && ./test/e2e.sh          # over public relays
cd android && ./gradlew :app:testDebugUnitTest               # Kotlin FROST vs the server's
```

## What's rough

- **The FROST is hand-rolled** (binding factors by tagged SHA-256, not RFC 9591's
  hash-to-scalar), so it interoperates with nothing else. Final signatures are plain BIP-340.
- **Trusted dealer.** `setup.ts` sees the whole key once.
- **A lost phone can't be replaced** without a new key: server A forgets the phone's share
  once it's delivered, and there's no re-sharing yet.
- **No phone unlock to sign in the background**: the share is Keystore-encrypted but
  usable while locked, so routine signing works with the screen off. Approving a sensitive
  request from the lock screen does require unlocking.
- **Battery**: the phone holds a relay connection and pings every 10 s.
- **Both servers on one machine** is a demo, not two servers. Nothing in the code cares
  where they run; put `data/b` on another box.
- **Kind 28001** for member traffic is made up.
