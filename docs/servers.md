# Running a Cosign server

Cosign splits your Nostr key into pieces. Your devices each hold a big piece (3 points),
servers each hold a small one (1 point), and signing takes 4 points. So **a device plus
any one server signs**, and **all the servers together can never sign without you**.

A server's job is to be the always-on fourth point: it adds its share to what your
device signs, keeps a history of your lists so you can undo, enforces the safety waits,
and wakes your devices when something needs you. It never holds enough to act alone.

This page says what a server must do, what it can see, and how to run the reference
server. The full design is [COSIGN.md](COSIGN.md) (servers: §9), and the wire format is
[NIP-XX.md](NIP-XX.md). How apps choose servers is [choosing-servers.md](choosing-servers.md).

## How many servers exist today

**One public server, as of 24 October 2026: syb.lol, run by Cosign's author.** Its
host key starts `040e022d…`, its operator key `f5073ea2…`, and anyone can enroll. The live
list is on [cosign.aaro.cc](https://cosign.aaro.cc/), so this number goes out of date.

> I run syb.lol and will keep running it. I'd love others to run public servers too;
> here's how. If you already run a relay, sidecar packages for popular relay software are
> on the way, so adding a Cosign server beside it will take a few lines.

What that means for you:

- With only one server, your **paper backup counts 3 points instead of 2**, so the
  paper plus that one server can still recover your account if you lose every device.
- **More operators are wanted.** Three servers run by three different people is the
  design. Until then, everything still works, but one operator is doing a job meant for
  three.
- **The app adds servers on its own** as new ones announce themselves. You don't need to
  do anything.

## Do I need my own server?

No. Cosign works with public servers alone. Running your own is encouraged, though:

- **Privacy.** A server sees what it signs. Your own server counts as one of your own
  devices, so the app asks it first and public servers see less.
- **Redundancy.** One more server that answers, and that you control.

## What every server must do

These come from [COSIGN.md](COSIGN.md); the section is given for each.

**Must:**

- **Be always on and reachable over relays** (§4.2, §9.1). A server needs no public
  address: it connects out to relays like any app. An HTTPS address is optional.
- **Hold exactly one share per account** (§3). Never more, whoever runs it.
- **Run as one operator per account.** No one but the user may run two of the same
  account's servers (§3, §9.3). Two servers from one operator plus a stolen paper backup
  would be 4 points, with only that operator enforcing the wait.
- **Destroy old shares after a refresh** (§7.3). When a device is reported lost, every
  piece is renewed and the old ones must be gone for good: no snapshots, backups,
  version history or log lines that keep them. Some hosts keep history you can't turn
  off. Cloudflare's SQLite-backed Durable Objects, for example, keep 30 days of
  point-in-time recovery, so a share must never be stored there in a form that history
  could bring back.
- **Enforce the 3-day wait** (§7.4, §8.3). When someone uses a paper backup without any
  surviving device, or adds a device without that device's lock, the server tells every
  device and refuses to take part for 3 days unless one of them cancels.
- **Give only its half of a decryption, and never finish one** (§5.6). The device
  finishes it, so a server never sees what your messages say.
- **Never hold a site's NIP-46 signer key if it's a public server** (§6.1, §9.2). Only
  your devices, and servers you run yourself, may hold it, because whoever holds it can
  read what those sites send.
- **Refuse a device the moment it's reported lost** (§7.2).
- **Drop replayed requests**: one already answered, or older than 30 seconds (§5.2).

**Should:**

- **Announce itself** (§9.5) with a kind 30243 event signed by its host key, naming its
  relays, its HTTPS address if any, its enrollment policy and its version. Its operator
  should list it back with a kind 10243 event. Apps only count a server as an operator's
  when both sides name each other.
- **State its enrollment policy**: `open` (anyone can create an account with it) or
  `invite` (only devices on its list).
- **Check events itself** and refuse destructive ones without your approval (§5.2). Your
  device is the real gate; the server is a second opinion.
- **Keep list history for Undo** (§5.4), from properly signed events only.

## What a server can see

- **Everything it co-signs**: your posts, reactions, follows, profile, with exact times.
  Most of this is public on relays anyway.
- **Which sites and apps you use**, and when.
- **Who you DM and when**, from its half of each decryption. Never what you say.
- **Your list history**, kept for Undo.

It **cannot** see your DM text, your IP address (everything goes through relays), or
anything two of your own devices sign without it. Your app asks its fastest server first
and the others only if that one is slow, so most of what you sign is seen by one server.

## Where the reference server falls short today

As of 24 October 2026 the reference server (Cosign 0.11) does not yet meet two of the
musts above:

- **It holds a NIP-46 signer key** for the accounts it serves, so it can read requests
  from sites that connect by a `nostrconnect://` code. Per-site signer keys held only by
  your devices are designed but not built.
- **It finishes decryptions for those NIP-46 sites.** Sites that use the browser
  extension or the Android app are not affected.

Until both are fixed, use NIP-46 sites with a public server only if you're fine with
its operator seeing those requests.

## Running the reference server

The reference server is Node, in [`server/`](../server/). It runs in Docker.

1. **Build and start it** with a data directory owned by uid 1000:

   ```sh
   docker build -t cosign-server server/
   docker run -d --name cosign --restart unless-stopped \
     -u 1000:1000 -v /srv/cosign:/data -p 8711:8711 \
     -e COSIGN_RELAYS=wss://relay.example,wss://relay2.example \
     -e COSIGN_ENROLL=invite \
     -e COSIGN_PERSONAL=0 \
     cosign-server
   ```

2. **Pick its relays** (`COSIGN_RELAYS`, comma-separated): relays your users' devices
   also use. A server
   beside a relay can reach it over the local network while telling devices its public
   address; see [`deploy/README.md`](../deploy/README.md).
3. **Choose who may enroll**: `COSIGN_ENROLL=open` for anyone, or `invite` with
   `COSIGN_INVITES` listing device pubkeys (hex, comma-separated). The list is read again for each enrollment,
   so you can change it without a restart.
4. **Say who runs it**: `COSIGN_OPERATOR` is your npub, and `COSIGN_HTTPS` its public
   page, if it has one. Then publish your own kind 10243 list naming the server's host
   key, so apps count it as yours.
5. **Keep port 8711 private** unless it's behind a login. It's the server's own page
   and lists every account it serves.

`COSIGN_PERSONAL=0` skips the throwaway test account a fresh server otherwise makes for
itself. Leave it out to try the server with your own phone.

**Look after its storage like a key store**: no snapshots or backups that keep old
shares after a refresh (see "Destroy old shares" above).

The [deployment notes](../deploy/README.md) cover running beside a Ditto relay, one
server for many accounts, and a local rehearsal.
