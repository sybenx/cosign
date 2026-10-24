# Cosign

Your Nostr key, split so no one place ever holds it: **your phone holds 3 shares, each
of your servers 1, and it takes 4 to sign**. Your phone and any one server sign; the
servers together can't. Sites sign through your servers with your phone co-signing
quietly in the background, and your phone is also the remote control: it connects sites,
removes them, approves anything destructive, and undoes changes. Lose the phone and a
paper backup gets your key back, after a wait your other devices can stop.

- **Create a key with nobody ever holding it** (DKG with your servers), or **move the one
  you have** out of a web app in one scan.
- **Connecting a site** is QRST at its lowest level: the site shows a code, you scan
  it with Cosign, tap *Connect*, and the site is signed in. What crosses is a one-time
  ticket, not your key; the site redeems it with your servers for access of its own.
- **Apps on your phone sign through Cosign** (Android signer, NIP-55), the way they use
  Amber: connect once, everyday signing is silent, destructive things and the first use
  of your messages ask you. Each app shows in your list with Remove.
- **Sites that only know NIP-46 work too**: scan their `nostrconnect://` code the same
  way. Same one tap, same access of its own, removed the same way.
- **About 95% of things sign at once**, by your server and your phone, without asking you.
- **Destructive things wait for your phone**: most of your follows gone, your profile
  wiped, your relay list emptied, a pile of deletions, a request to vanish. Judged by
  what the event does compared with the version it replaces — adding one follow is
  routine, replacing your whole follow list isn't.
- **Every change to your lists is archived**, with Undo on the phone, and every version is
  kept on your phone too.
- **Undo everything a site did**, in one go: its access goes, every list it changed goes
  back to how it was before it touched it, and everything else it posted is deleted.
- **Deletions can't be taken back on Nostr, so Cosign keeps a copy first**, holds each one
  for 10 seconds with Undo on your phone, asks once for a batch (5 or more, or one that
  touches a list), and keeps the copies with **Post again**.
- **Nothing is ever signed dated in the future** if it's a list or profile: on a relay
  that took it, it would beat every later change. "Now" is the network's time, so a phone
  or server with its clock set ahead doesn't change that. A future-dated version already
  out there is flagged on your phone with a one-tap fix.
- **Remove a site** on the phone or on either server's page; it stops immediately.
- **Add your other devices** (a second phone, a tablet): the new one shows a code, your
  phone scans it and asks for its own lock, and your phone and server make the new
  device's share between them — neither ever has it.
- **Any one of the three can be down.** If your phone doesn't answer within 3 s, the
  backup server signs instead (never for anything destructive). If your server is down,
  the backup takes over from it after 30 s. With neither phone nor backup, the site gets
  an error after about 15 s rather than hanging.
- **Your phone judges for itself.** It keeps the latest signed version of each of your
  lists and asks you about anything destructive even if the server didn't flag it.

**Servers.** Public servers today: syb.lol, which its author runs and will keep running,
listed live at [cosign.aaro.cc/servers](https://cosign.aaro.cc/servers). More operators
wanted: running your own (public or private) is encouraged, not required.
[Running a server](docs/servers.md) · [How servers work](docs/COSIGN.md#9-servers) ·
[How Cosign picks servers](docs/choosing-servers.md)

Everything travels over public relays (syb.lol, nos.lol, relay.primal.net): your servers
need no public address and your phone needs nothing but a connection.

**Early.** The FROST is the Zcash Foundation's audited `frost-secp256k1-tr` (refresh came
after the audit); Cosign's own protocol and message kinds are provisional and unaudited.

## Try it

```sh
cd server && npm install
node setup.ts               # a throwaway key, split 2 of 3
node server.ts data/a       # http://localhost:8711 — the code to add your phone
node server.ts data/b       # http://localhost:8712
cd ../site && npm install && node build.mjs && node serve.mjs   # http://localhost:8790 — a demo site
```

1. Install Cosign on your phone (see "Getting the app" below). Tap **Scan your server's code** and scan the
   code on http://localhost:8711. Tap **Add this phone**.
2. Open http://localhost:8790. In Cosign tap **Connect a site**, scan the demo's code,
   tap **Connect**. On the demo, tap **Sign in**.
3. Press buttons. Everyday ones sign in about 0.4 s. *Follow 30 people*, then *Unfollow
   everyone*: your phone buzzes.
4. Sign out, tap **Show a nostrconnect code instead**, and do it again: that's an ordinary
   NIP-46 site (nostr-tools, nothing of Cosign's). Real sites work the same way; Jumble's
   *Remote signer* login has been tried.

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
- **nostrconnect** (`connectByUri` in `server/core/group.ts`, `scannedNostrConnect` in `Phone.kt`):
  the phone passes the site's code to both servers; both add the site and listen on its
  relays, and the one answering sites sends the site's secret back from the signer key.
  When the site asks `switch_relays`, the servers move it onto their own relays.
- **Signing** (`server/core/group.ts`, `site/src/client.ts`): NIP-46 over relays to a signer
  key both servers hold. The site re-sends each request until answered; the servers keep
  their answers and send them again to a repeat (freshly wrapped — strfry refuses a
  repeated event id). Member-to-member requests are re-sent the same way, and a repeated
  request gets the same answer, never a second partial.
- **Policy** (`server/policy.ts`, and its copy `android/.../core/Policy.kt`, kept in step
  by `server/test/policy-vectors.ts`): `assess(event, previousVersion)`. Every co-signer
  judges an event against its own copy of your lists, so one compromised member can't
  talk another into co-signing something destructive. When the phone asks you, it tells
  the server to wait the full minute; a decline ends it, and nobody else is asked.
- **Android signer** (`Nip55Provider.kt`, `Nip55Activity.kt`, the apps section of `Phone.kt`;
  `onCosignReq` in `server/core/group.ts`): the app asks the phone, so the phone runs the round
  and a server gives the other half after checking the app's grant and judging the event
  itself. Decryption is done in two halves and finished on the phone. `android/nip55tester`
  is a stand-in app that runs through all of it on an emulator.
- **History** (`server/history.ts`): everything signed, for which site or app, with the
  version a list change replaced, and copies of everything deleted. Shared between the
  servers and with the phone (`signed.jsonl`), so undoing a site never depends on how
  many list versions the archive keeps.
- **Time** (`server/clock.ts`, `core/Clock.kt`): the median Date header of a few HTTPS sites.
- **Big messages** go between members in 24 KB parts (`sealParts` in `server/core/seal.ts`,
  `send` in `Phone.kt`): NIP-44 stops at 64 KB, and a large follow list is bigger.
- **FROST** (`frost/`, Rust): the Zcash Foundation's `frost-secp256k1-tr` (RFC 9591,
  BIP-340 signatures), built to WebAssembly for the server (`server/frost-wasm`, used by
  `server/sign.ts`) and to a native library for the phone (`core/FrostNative.kt`). Requests
  say `frost: 2`; the earlier hand-rolled math (`server/frost.ts`, `core/Frost.kt`) is
  kept only so members not updated yet keep working — a coordinator finishes each round
  in whichever math its partner used.
- **Weighted keys** (`server/dkg.ts`, `core/Dkg.kt`; `setup.ts --weighted`): no dealer.
  Your phone holds 3 shares and each server 1, and it takes 4 to sign: the phone and either
  server can, the two servers can't. The key is made by DKG when the phone scans server A's
  code: A sends `pair_offer {weighted, plan}` (the session, threshold, and which member
  key holds each share index) and `dkg_start {plan}` to B; every holder sends `dkg1`
  (its part-1 packages) to all and `dkg2` (part-2 packages, `[from, to, package]`) to each
  share's holder, re-sent every 4 s until done. The phone then sends `pair_ack {groupX}`.
  A round is every share of the members taking part (`commits`/`zs` lists in `sign_req`,
  `cosign_req`, and their answers; `points` in `ecdh_res`).
- **Push**: the servers POST "cosign:approve" to the phone's ntfy endpoint — nothing
  else; the request itself comes over relays, sealed.
- **Shared servers** (`server/core/`, `server/server.ts`, `server/HOSTS.md`): the member
  logic is a core with no I/O, one group per instance; the Node host runs any number of
  them in one process with one relay subscription. `node server.ts --root data data/a`
  adds a host key, and a device can enroll a new group on a running server by writing
  to it (`server/core/enroll.ts`): the group record and this server's share, checked
  against the group's share points (`how: 'dealt'`), or the record and a key plan, the
  key then made by DKG with the device (`how: 'dkg'`, "Create account": no code, no
  setup step on the server).
- **Moving a key in** (`site/src/import.ts`, `site/src/member.ts`, `core/CosignMember.kt`):
  a web app holding an nsec deals it (the phone 3 shares, each server 1, any 4 sign),
  enrolls each server with its share, a claim token for the phone and a ticket for the
  page, and hands the phone its shares by QRST (`cosign-member`, checked at `type`: the
  phone shows five digits, you type them on the page). The phone claims its place with
  `pair_ack {token}`; the page is signed in by the same move.
- **Report lost and refresh** (`server/refresh.ts`, `onRemove` in `server/core/group.ts`,
  COSIGN.md §7.2–7.3): a device, with its own lock, sends `remove_member {idx, plan}`;
  every server blocks that device at once and tells it. The plan is the next epoch,
  dealt by the reporting device and a server: each picks a zero-constant polynomial and
  sends every remaining share its delta (`refresh_part`, checked against commitments to
  the coefficients). Everyone adds its deltas, the key stays the same, and the lost
  device's pieces stop combining. A device that was away gets its parts from the
  servers when it's back (`mail`). The lost device can answer `not_me`, which blocks the
  device that reported it too, until it's settled.
- **Paper backup** (`backupPiece`… in `server/core/group.ts`, `server/backup.ts`, COSIGN.md §8):
  a key printed on paper with share indices of its own (3 while there's one server,
  else 2) whose shares nobody online holds. Made by repair like adding a device
  (`add_device {backup: true}`), except each helper seals its pieces to the paper's key
  and every server keeps them; each later refresh's part for the paper is kept sealed to
  it too. Restoring: a new phone reads the paper, asks the servers as the paper
  (`backup_get`), adds the pieces up and every refresh since, then asks to `recover`;
  after a wait every server enforces (3 days; `COSIGN_RECOVERY_WAIT`) and any device can
  cancel, the paper's shares are that phone's. With two servers the paper holds 2: the
  restored phone then grows a device's 3 (`add_device {grow}`, by repair with both
  servers: a server short of the threshold with the vouching device brings in another,
  `repair_help`/`repair_finish`) and asks for a refresh (`refresh_request`).
- **Finding servers** (`site/src/servers.ts`, COSIGN.md §9.5): a shared server with an
  `operator` in `host.json` (or `COSIGN_OPERATOR`) announces itself, kind 30243 signed by
  its host key; the operator lists it back, kind 10243 (`operatorServers`). Devices
  `findServers` (plus a seed list), `pingHost` each, and `pickServers` takes the fastest
  of each operator, never two from one.

## Tests

```sh
cd server && node test/vectors.ts                       # FROST vectors for the phone
cd android && ./gradlew :app:testDebugUnitTest          # Kotlin FROST against them
# with both servers running and test/fake-phone.ts paired:
cd site && node test/server.e2e.ts                      # tickets, signing, hold, undo, removal
cd site && node --experimental-transform-types test/pair.e2e.ts   # QRST sign-in, end to end
cd site && node test/nostrconnect.e2e.ts [relay]         # a plain nostr-tools site, by nostrconnect
cd site && node test/shared.e2e.ts                       # two keys in one process; enroll a third (starts its own servers)
cd site && node test/create.e2e.ts                       # create account: a device and one shared server make a key
cd site && node --experimental-transform-types test/import.e2e.ts   # move a key from a page into Cosign
cd site && node test/lost.e2e.ts                         # report a device lost; refresh; one that was away catches up
cd site && node test/paper.e2e.ts                        # paper backup through a refresh; a cancelled and a finished recovery
cd site && node test/paper2.e2e.ts                       # two servers: the restored phone grows its shares with both
cd site && node test/servers.e2e.ts                      # finding and picking servers; a live one announces itself
cd site && node test/single.e2e.ts                       # phone co-signs; backup steps in; big lists
cd site && node test/deletion.e2e.ts                     # copies kept, 10 s Undo, one approval per batch
cd site && node test/undo-site.e2e.ts                    # undo everything one site did
cd site && NSEC=… node test/future.e2e.ts                # dated ahead: refused, held, found and removed
cd site && node test/devices.e2e.ts                      # add a device by repair; it co-signs
cd site && node test/weighted.e2e.ts                     # a key nobody held: phone 3 + server 1 sign
cd server && node test/policy-vectors.ts                 # policy cases for the phone's copy
# a second group beside yours for these: node setup.ts --dir test-data --port 8721
```

## What's rough

- **Trusted dealer:** `setup.ts` sees the whole key once. (Signing now uses the Zcash
  Foundation's audited FROST library; its DKG would remove the dealer.)
- **A lost phone can't be replaced** without a new key yet: there's no re-sharing.
- **The phone only knows the lists it has seen signed** (from your servers, or on your
  relays). If it missed the latest version, it judges against an older one.
- **The two servers are one key share each, not one server and a spare.** The backup can
  co-sign with the main server when the phone is quiet, for everyday things only.
- **One tap to connect a site.** QRST §9.1 says a web origin SHOULD get a deliberate act
  beyond one tap; this deliberately doesn't, per "no more complex than lowest-level QRST".
- **ntfy is wired but untested end to end**: the test emulator has no distributor.
- **Both servers on one machine** is a demo; put `data/b` on another box. Nothing cares.
- **Kinds 28001 (member traffic) and the `signer-ticket` profile are made up here.**
- **No real site shows a `signer-ticket` code yet**; existing sites come in by nostrconnect.
- **nostrconnect is less sure-footed than the QRST sign-in.** Ordinary sites send each
  request once and wait forever; if every relay drops it, the site hangs. The servers
  answer twice and move sites onto relays known to work, which covers lost answers, not
  lost requests. A site waiting for your phone just looks busy: it can't say why.
- **Phone cameras open QRST codes in whichever app owns the link's host**, so the demo's
  codes point at cosign.aaro.cc (`link/`, deployed with `wrangler deploy`), whose App
  Links file names Cosign. Android checks that file when the app is installed.

## Getting the app

Releases are on GitHub (github.com/sybenx/cosign/releases), so Obtainium can follow them:
add `https://github.com/sybenx/cosign` as an app. The newest build is also at
https://cosign.aaro.cc/cosign.apk. `./release.sh` publishes both.

## License

MIT. The QRST code in `site/vendor` and `android/.../core` is MIT too (`site/vendor/QRST-LICENSE`).
