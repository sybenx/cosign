# Cosign

Your Nostr key split three ways — **two servers and your phone** — where any two can
sign and none can alone. Sites sign through your servers. Your phone is the remote
control: it connects sites, removes them, approves anything destructive, and undoes
changes.

- **Connecting a site** is QRST at its lowest level: the site shows a code, you scan
  it with Cosign, tap *Connect*, and the site is signed in. What crosses is a one-time
  ticket, not your key; the site redeems it with your servers for access of its own.
- **About 95% of things sign at once**, by the two servers, without asking you.
- **Destructive things wait for your phone**: most of your follows gone, your profile
  wiped, your relay list emptied, a pile of deletions, a request to vanish. Judged by
  what the event does compared with the version it replaces — adding one follow is
  routine, replacing your whole follow list isn't.
- **Every change to your lists is archived**, with Undo on the phone.
- **Remove a site** on the phone or on either server's page; it stops immediately.
- **Any one of the three can be down.** Server B takes over from A after 30 s; with a
  server down, the phone co-signs routine things in the background.

Everything travels over public relays (syb.lol, nos.lol, relay.primal.net): your servers
need no public address and your phone needs nothing but a connection.

**A prototype to see how it feels.** Unaudited, hand-rolled FROST, provisional message
kinds. Use the throwaway key `setup.ts` makes.

## Try it

```sh
cd server && npm install
node setup.ts               # a throwaway key, split 2 of 3
node server.ts data/a       # http://localhost:8711 — the code to add your phone
node server.ts data/b       # http://localhost:8712
cd ../site && npm install && node build.mjs && node serve.mjs   # http://localhost:8790 — a demo site
```

1. Install `Cosign-0.2.0.apk` on your phone. Tap **Scan your server's code** and scan the
   code on http://localhost:8711. Tap **Add this phone**.
2. Open http://localhost:8790. In Cosign tap **Connect a site**, scan the demo's code,
   tap **Connect**. On the demo, tap **Sign in**.
3. Press buttons. Everyday ones sign in about 0.4 s. *Follow 30 people*, then *Unfollow
   everyone*: your phone buzzes.

For push when Android has put Cosign to sleep, install **ntfy** on the phone (it becomes
the UnifiedPush distributor); without it, approvals still arrive while Cosign's
background service is running.

## How it works

```
 site ──NIP-46 over relays──▶ your servers ─┬─ routine ─────▶ the other server
   ▲                                        └─ destructive ─▶ your phone (asks you)
   └── one-time ticket, by QRST ◀── your phone scanned the site's code
```

- **Sign-in** (`site/src/pair.ts`, `site/src/ticket.ts`, `android/.../core/SignerTicket.kt`):
  QRST profile `signer-ticket`, a §5.2-shaped ticket: `{pubkey, signer, relays, t,
  expires}`. The site shows the code (Flow A, check `none`); the phone tells both servers
  about the ticket and hands it over; the site redeems it as the NIP-46 `connect` secret
  and keeps a key of its own, which is what removing it revokes. QRST itself is the
  reference implementation (vendored in `site/vendor`, ported in `android/.../core`).
- **Signing** (`server/server.ts`, `site/src/client.ts`): NIP-46 over relays to a signer
  key both servers hold. The site re-sends each request until answered; the servers keep
  their answers and send them again to a repeat (freshly wrapped — strfry refuses a
  repeated event id). Member-to-member requests are re-sent the same way, and a repeated
  request gets the same answer, never a second partial.
- **Policy** (`server/policy.ts`): `assess(event, previousVersion)`. Each co-signing server
  judges an event against its own archive, so one compromised server can't talk the
  other into co-signing something destructive without the phone.
- **FROST** (`server/frost.ts`, `android/.../core/Frost.kt`): two nonces per signer,
  binding factors over the commitment list, BIP-340 challenge. Final signatures are plain
  BIP-340. `android/app/src/test/resources/frost.json` pins the two implementations.
- **Push**: the servers POST "cosign:approve" to the phone's ntfy endpoint — nothing
  else; the request itself comes over relays, sealed.

## Tests

```sh
cd server && node test/vectors.ts                       # FROST vectors for the phone
cd android && ./gradlew :app:testDebugUnitTest          # Kotlin FROST against them
# with both servers running and test/fake-phone.ts paired:
cd site && node test/server.e2e.ts                      # tickets, signing, hold, undo, removal
cd site && node --experimental-transform-types test/pair.e2e.ts   # QRST sign-in, end to end
```

## What's rough

- **The FROST is hand-rolled**, not RFC 9591's hashing, so it interoperates with nothing
  else. Trusted dealer: `setup.ts` sees the whole key once.
- **A lost phone can't be replaced** without a new key yet: there's no re-sharing.
- **The phone trusts the coordinating server's "this is destructive"** when it co-signs
  because the *other* server is down. A compromised server plus the other one down is a
  double failure this doesn't cover.
- **One tap to connect a site.** QRST §9.1 says a web origin SHOULD get a deliberate act
  beyond one tap; this deliberately doesn't, per "no more complex than lowest-level QRST".
- **ntfy is wired but untested end to end**: the test emulator has no distributor.
- **Both servers on one machine** is a demo; put `data/b` on another box. Nothing cares.
- **Kinds 28001 (member traffic) and the `signer-ticket` profile are made up here.**
- **Sites need this client library.** No real site shows a `signer-ticket` code yet;
  the nostrconnect fallback (next) is what makes existing sites work.
