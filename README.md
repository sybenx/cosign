# Cosign (beta)

A protocol and library for Nostr accounts that no one place holds whole. **A key is split
into FROST shares: each of your devices holds 3, each server 1, a paper backup 2, and it
takes 4 to sign.** A device plus any one server can sign; the servers on their own never
can. Lose a device and you report it, and the remaining shares are refreshed; lose every
device and the paper backup gets you back in, after a wait your other devices can stop.

**Beta.** The signing maths is the Zcash Foundation's audited FROST library. Cosign's own
protocol around it hasn't had an outside review yet.

This repository is the protocol: the spec, the server, the Cloudflare Worker, the web
pieces sites use, and the Android library apps build on. It has no app of its own.

- [The design](docs/COSIGN.md) and [the wire format](docs/NIP-XX.md).
- `frost/`: FROST shares and signing (Rust), for the server (WebAssembly) and the phone (JNI).
- `server/`: the Cosign server; `worker/`: the same as a Cloudflare Worker; `deploy/`:
  running one beside popular relays.
- `site/`: what a site uses to sign people in (and cosign.aaro.cc/servers); `link/`: cosign.aaro.cc.
- `android/cosign`: the Android library. `android/nip55tester`: a stand-in for another
  app, for testing NIP-55 on an emulator.

## Apps

**Any app can build Cosign in.** Apps that do will be featured above Marble wherever a
site suggests a sign-in app.

[Marble](https://github.com/sybenx/marble) is one app built on the library, for Android,
with a browser extension. It uses Cosign only through the library, the way any other app
would.

## The Android library

`android/cosign` (Gradle `cc.aaro.cosign:cosign`) holds the whole signing side of an
Android app: the shares (sealed with the Android Keystore), FROST, making and joining a
key, the member logic and its relays, refresh, the paper backup, site sign-in (NIP-46),
and NIP-55 for other apps on the phone. It draws nothing: what needs the person's answer
reaches the app through callbacks, and the app draws it.

Everything that holds or uses a share runs in a process of its own, `:signer` (the
library's manifest puts its components there). The app's own process, which shows
strangers' posts and pictures, only ever asks it, through `SignerService`, and never sees
a share.

- **Setting up:** call `Cosign.init(application, host)` from your `Application.onCreate`
  (it runs in both processes). In the app's process, `Cosign.accounts` is the list of
  accounts on the phone; each one (`Phone`) has its state as a `StateFlow<Ui>` with the
  secrets taken out, and actions by name (`createAccount`, `scanned`, `accept`, `signOwn`,
  …). In `:signer`, `Cosign.signers` holds the keys themselves (`Signer`).
- **What the library asks of the app:**
  - `Cosign.Host.reveal(context, slot)`: show the paper backup's code or a taken-out key,
    from an activity of the app's in `:signer`.
  - `Signer.Listener`: a request that waits for the person's OK (`onAsk`, `onBatch`), a
    deletion in its few seconds (`onDeleting`), something to say (`onNotice`), the
    connection (`onStatus`). The app answers with `decide`, `decideBatch` and
    `cancelDeletion`, and shows these as notifications, from a foreground service of its
    own in `:signer` if it wants to stay reachable.
  - `Nip55Request`: the app's activity for `nostrsigner:` (in `:signer`) hands it each
    intent, draws its `stage`, and calls `connect`, `allowDms`, `approve` or `reject`.
    The library's `Nip55Provider` answers connected apps in the background.
- **Using it:** no Maven package yet. Add this repository as a git submodule and
  `includeBuild("<submodule>/android")` in your `settings.gradle.kts`; Gradle then
  resolves `implementation("cc.aaro.cosign:cosign")` from it. Marble does exactly this.

## Servers

Every account starts with at least two servers; at launch an app picks three. **All of
today's public servers are run by Cosign's author** (syb.lol and a Cloudflare Worker,
with a third to come), and **they see everything you do through them**. More operators
are wanted, and running your own server, public or private, is encouraged but not
required. The live list is at [cosign.aaro.cc/servers](https://cosign.aaro.cc/servers).

- [Running a Cosign server](docs/servers.md): what a server must do, what it can see,
  and how to run one in Docker.
- [How apps choose servers](docs/choosing-servers.md).

## Privacy

- **A server sees what you sign through it**, and nothing else: never your messages, and
  never enough of your account to act as you. Your servers are yours to choose, and one
  you run yourself is preferred over anyone else's.

## What's not done yet

- **Sites with their own older-style sign-in code** can act for you but can't read or
  send your messages.
- **Your devices working together with no server** is designed but not built.
- **Getting your account onto your own devices when no server has answered for a week**
  is designed but not built.
- **Your phone's lock is taken on trust**: servers can't check it yet. A way for them to
  check is planned.
- **Replacing a dead server automatically**, periodic refresh and a 24-word paper backup
  are planned (see [ROADMAP.md](ROADMAP.md)).
- **ntfy push** is wired but hasn't been tested end to end.

## How it works

The spec is
[docs/COSIGN.md](docs/COSIGN.md). Everything travels over public relays: servers need no
public address, and a phone needs nothing but a connection.

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
- **Android signer** (`Nip55Provider.kt`, `Nip55Request.kt`): the app asks the phone,
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
top of each file), unit tests in `server/test/` and `android/cosign/src/test/`:

```sh
cd server && node test/vectors.ts && node test/policy-vectors.ts
cd frost && cargo build --release --features android   # the desktop FROST the Android tests load
cd android && ./gradlew :cosign:testDebugUnitTest
cd site && node test/guards.e2e.ts      # report lost, take out, forget; what a paper and a removed device get
cd site && node test/paper.e2e.ts       # paper backup through a refresh; cancelled and finished recovery
cd site && node test/member.e2e.ts      # the member library (src/member) joining, signing and refreshing
cd site && node test/device2.e2e.ts     # two devices signing with every server killed (§5.1, §5.5)
```

## License

MIT. The QRST code in `site/vendor` and `android/.../core` is MIT too
(`site/vendor/QRST-LICENSE`).
