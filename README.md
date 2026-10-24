# Cosign (beta)

Your Nostr account, without your key sitting in any one place. **Each of your devices
holds 3 shares of your key, each server 1, and it takes 4 to sign.** The device you're
using plus any one server signs; all the servers together never can. Lose a device and
you report it; lose every device and a paper backup gets you back in, after a wait your
other devices can stop.

Cosign is also a home screen for Nostr on your phone: search, a Discover feed, and a
bell for replies, mentions and anything that needs you. Your account, devices, sites and
backups are behind your picture.

**Beta.** Signing uses the Zcash Foundation's audited FROST library
(`frost-secp256k1-tr`). Cosign's own protocol around it — making keys, adding devices,
refresh, recovery, the sign-in codes — hasn't had an outside review yet.

## What it does

- **Create an account nobody ever holds**: your phone and your servers make the key
  together (DKG). Or **move the key you have** out of a web app in one scan.
- **Sign in to sites** by scanning their code and tapping *Connect*. Sites that only
  know remote signers (`nostrconnect://`) work the same way. Each site gets access of its
  own, which you remove with one tap.
- **Apps on your phone sign through Cosign** (Android signer, NIP-55), the way they use
  Amber.
- **Everyday things sign at once.** Destructive ones — most of your follows gone, your
  profile wiped, your relay list emptied, a pile of deletions, a request to vanish —
  ask you first, judged by what the event does compared with the version it replaces.
- **Undo.** Every change to your lists is archived, with Undo. You can undo everything
  one site did in one go. Deletions are held for 10 seconds, and Cosign keeps a copy
  with *Post again*.
- **Nothing dated in the future** gets signed if it's a list or profile, so one bad clock
  can't block every later change.
- **Add your other devices** (a second phone, a tablet) by scanning a code and
  confirming with your phone's lock. Nobody ever holds the new device's share but the
  new device.
- **Report a device lost**, with your lock: every server blocks it at once, and your
  remaining pieces are refreshed so its shares are worthless. Removal is final; a device
  removed by mistake is simply added again.
- **Paper backup**: a QR to print, save as a PDF or copy into a password manager. It's
  worth 2 shares: with any device it signs; with two servers it restores your account
  after a 3-day wait that any of your devices can cancel.
- **Take your account out** whenever you like, as an ordinary nsec, or remove the
  servers' pieces. Both are announced to all your devices and can be cancelled.

## Servers

Every account starts with at least two servers; at launch the app picks three. **All of
today's public servers are run by Cosign's author** (syb.lol and a Cloudflare Worker,
with a third to come), and **they see everything you sign through them**. More operators
are wanted, and running your own server, public or private, is encouraged but not
required. The live list is at [cosign.aaro.cc/servers](https://cosign.aaro.cc/servers).

- [Running a Cosign server](docs/servers.md): what a server must do, what it can see,
  and how to run one in Docker.
- [How apps choose servers](docs/choosing-servers.md).
- [The design](docs/COSIGN.md) and [the wire format](docs/NIP-XX.md).

Everything travels over public relays: servers need no public address, and your phone
needs nothing but a connection.

## Getting the app

Releases are on GitHub (github.com/sybenx/cosign/releases), so Obtainium can follow
them: add `https://github.com/sybenx/cosign` as an app. The newest build is also at
https://cosign.aaro.cc/cosign.apk. `./release.sh` publishes both.

For approvals while Android has put Cosign to sleep, install **ntfy** (it becomes the
UnifiedPush distributor). Without it, approvals arrive while Cosign's background service
is running.

## What's not done yet

- **Sites connected by `nostrconnect://`** share one signer key on the servers, so they
  can sign but can't read or send your DMs. Messages go through the app or the extension.
  Per-site signer keys are designed but not built.
- **Signing with two of your devices and no server** is designed but not built.
- **Rebuilding the key on your devices when no server has answered for a week** (the
  escape hatch) is designed but not built.
- **The device lock is the device's word**: servers can't check it yet. A hardware-bound
  key that proves it is planned.
- **Swapping a dead server automatically**, the 24-word paper backup, and a library for
  other apps to hold a share are planned (see [ROADMAP.md](ROADMAP.md)).
- **ntfy push** is wired but hasn't been tested end to end.

## How it works

For developers. The spec is [docs/COSIGN.md](docs/COSIGN.md).

- **Shares and signing** (`frost/`, Rust): the Zcash Foundation's `frost-secp256k1-tr`
  (RFC 9591, BIP-340 signatures), built to WebAssembly for the server
  (`server/frost-wasm`, `server/sign.ts`) and to a native library for the phone
  (`core/FrostNative.kt`). A device holds 3 shares, a server 1, the paper 2; threshold 4.
  Only FROST is accepted; the earlier hand-rolled math is refused.
- **Making a key** (`server/dkg.ts`, `core/Dkg.kt`): DKG between the device and its
  servers, with no dealer. Enrolling on a running server (`server/core/enroll.ts`):
  `how: 'dkg'` (Create account) or `how: 'dealt'` (a key moved in).
- **Moving a key in** (`site/src/import.ts`, `site/src/member.ts`,
  `core/CosignMember.kt`): a web app holding an nsec deals it, enrolls each server, and
  hands the phone its shares by QRST (`cosign-member`, checked at `type`).
- **Sign-in** (`site/src/pair.ts`, `site/src/ticket.ts`, `core/SignerTicket.kt`): QRST
  profile [`signer-ticket`](https://github.com/sybenx/qr-secret-transfer/pull/14). The
  site shows a code; the phone hands over a one-time ticket that the site redeems as its
  NIP-46 `connect` secret. A combined code also carries a `nostrconnect://` fallback
  (`nc`).
- **Signing for sites** (`server/core/group.ts`, `site/src/client.ts`): NIP-46 over
  relays; sites re-send until answered, and a repeated request gets the same answer.
- **Policy** (`server/policy.ts`, `core/Policy.kt`, kept in step by
  `server/test/policy-vectors.ts`): `assess(event, previousVersion)`. The phone judges
  against its own copy of your lists and asks you; servers check too. A decline ends the
  round.
- **Decryption**: done in parts and finished on the device. A server answers only a
  device (or a server running the round) with enough shares taking part to sign —
  never a paper or a removed device — and never for sites connected by code.
- **Android signer** (`Nip55Provider.kt`, `Nip55Activity.kt`): the app asks the phone,
  which runs the round with a server. `android/nip55tester` exercises it on an
  emulator.
- **History** (`server/history.ts`): everything signed, by which site or app, with the
  version each list change replaced, and copies of everything deleted.
- **Guarded actions** (`server/core/group.ts`, COSIGN.md §7.2, §7.6): report lost (at
  once), take out and forget (after the wait, or announced first with the paper). Each
  needs the lock of a live device; every device is told and woken; any device can
  cancel a waiting one.
- **Refresh** (`server/refresh.ts`): after a report, the reporting device and a server
  each deal a zero-constant polynomial; every remaining share adds its deltas. A device
  that was away gets its parts from the servers (`mail`).
- **Paper backup** (`server/backup.ts`, COSIGN.md §8): made by repair, each helper sealing
  its pieces to the paper's key. Restoring reads the paper, collects the pieces and every
  refresh since, and asks to `recover`; after the 3-day wait the restored phone grows a
  device's 3 shares by repair with two servers.
- **Finding servers** (`site/src/servers.ts`, COSIGN.md §9.5): servers announce
  themselves (kind 30243); operators list them back (kind 10243). Devices ping each and
  prefer the fastest from different operators.
- **Egress**: relays, queries, publishing and push connect to the exact address that
  was checked, so a stranger can't point a public server at a private one
  ([docs/servers.md](docs/servers.md)).
- **Time** (`server/clock.ts`, `core/Clock.kt`): the median `Date` header of a few HTTPS
  sites. **Big messages** go in 24 KB parts (`sealParts`).

## Tests

End-to-end tests are in `site/test/` (each starts what it needs; see the comment at the
top of each file), unit tests in `server/test/` and `android/app/src/test/`:

```sh
cd server && node test/vectors.ts && node test/policy-vectors.ts
cd android && ./gradlew :app:testDebugUnitTest
cd site && node test/guards.e2e.ts      # report lost, take out, forget; what a paper and a removed device get
cd site && node test/paper.e2e.ts       # paper backup through a refresh; cancelled and finished recovery
```

## License

MIT. The QRST code in `site/vendor` and `android/.../core` is MIT too
(`site/vendor/QRST-LICENSE`).
