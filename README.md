# Cosign (beta)

Sign in to apps and sites with your phone, without your account sitting whole in any one
place. **It's split into pieces: each of your devices holds 3, each server 1, and it
takes 4 to act for you.** The device you're using plus any one server can; the servers
on their own never can. Lose a device and you report it; lose every device and a paper
backup gets you back in, after a wait your other devices can stop.

**Beta.** The signing maths is the Zcash Foundation's audited FROST library. Cosign's own
protocol around it hasn't had an outside review yet.

## Marble, and any other app

**Marble is Cosign's reference app**, for Android, and a proof of concept. It's a sign-in
app with a home screen: search, a Discover feed, and a bell for replies, mentions and
anything that needs you. Your account, devices, sites and backups are behind your
picture.

**Any app can implement Cosign.** The protocol is open: see [the design](docs/COSIGN.md)
and [the wire format](docs/NIP-XX.md). Apps that build it in will be featured above
Marble wherever a site suggests a sign-in app.

## What it does

- **Create an account that no one ever holds whole**: your phone and your servers make
  it together. Or **bring an account you already have** over from a web app in one scan.
- **Sign in to sites** by scanning their code and tapping *Connect*. Sites with their own
  older style of sign-in code work the same way. Each site gets access of its own, which
  you remove with one tap.
- **Other apps on your phone sign in through Marble.**
- **Everyday things go through at once.** Destructive ones — most of the people you
  follow gone, your profile wiped, one of your lists emptied, a pile of deletions, a
  request to erase everything — ask you first, judged by what they do, not what they are.
- **Undo.** Every change to your lists is kept, with Undo. You can undo everything one
  site did in one go. Deletions wait 10 seconds, and Marble keeps a copy with *Post
  again*.
- **Nothing dated in the future** goes out if it's a list or your profile, so one wrong
  clock can't block every later change.
- **Add your other devices** (a second phone, a tablet) by scanning a code and
  confirming with your phone's lock. Only the new device ever holds its pieces.
- **Report a device lost**, with your lock: every server blocks it at once, and your
  remaining pieces are renewed so its pieces are worthless. It's final; a device removed
  by mistake is simply added again.
- **Paper backup**: a code to print, save as a PDF or keep in a password manager. With
  any one of your devices it works at once; with two servers it gets your account back
  after a 3-day wait that any of your devices can cancel.
- **Take your account out** whenever you like, to use without Cosign, or have the
  servers delete their pieces. Both are announced to all your devices and can be
  cancelled.

## Servers

Every account starts with at least two servers; at launch the app picks three. **All of
today's public servers are run by Cosign's author** (syb.lol and a Cloudflare Worker,
with a third to come), and **they see everything you do through them**. More operators
are wanted, and running your own server, public or private, is encouraged but not
required. The live list is at [cosign.aaro.cc/servers](https://cosign.aaro.cc/servers).

- [Running a Cosign server](docs/servers.md): what a server must do, what it can see,
  and how to run one in Docker.
- [How apps choose servers](docs/choosing-servers.md).

## Getting Marble

Releases are on GitHub (github.com/sybenx/cosign/releases), so Obtainium can follow
them: add `https://github.com/sybenx/cosign` as an app. The newest build is also at
https://cosign.aaro.cc/cosign.apk. `./release.sh` publishes both.

For approvals while Android has put Marble to sleep, install **ntfy**. Without it,
approvals arrive while Marble is running in the background.

## Privacy

- **A server sees what you sign through it**, and nothing else: never your messages, and
  never enough of your account to act as you. Your servers are yours to choose, and one
  you run yourself is preferred over anyone else's.
- **Searching for people** sends what you type to the servers Marble searches. When a
  result shows an address like `name@example.com`, Marble asks that site whether the
  address really belongs to the person shown. That site can see your IP address while it
  answers.
- **The feed loads pictures and videos from wherever they are kept**, which is usually
  not the place the post came from. Those places can see your IP address, as they can in
  any app that shows you a picture.

## What's not done yet

- **Sites with their own older-style sign-in code** can act for you but can't read or
  send your messages; use Marble or the browser extension for messages.
- **Your devices working together with no server** is designed but not built.
- **Getting your account onto your own devices when no server has answered for a week**
  is designed but not built.
- **Your phone's lock is taken on trust**: servers can't check it yet. A way for them to
  check is planned.
- **Replacing a dead server automatically**, a 24-word paper backup, and a library so
  other apps can hold pieces are planned (see [ROADMAP.md](ROADMAP.md)).
- **ntfy push** is wired but hasn't been tested end to end.

## How it works

For developers; from here on the usual Nostr terms apply. The spec is
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
