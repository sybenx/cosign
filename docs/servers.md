# Running a Cosign server

Cosign splits your Nostr key into pieces. Your devices each hold a big piece (3 points),
servers each hold a small one (1 point), and signing takes 4 points. So **a device plus
any one server signs**, and **all the servers together can never sign without you**.

A server's job is to be the always-on fourth point: it adds its share to what your
device signs, keeps a history of your lists so you can undo, enforces the safety waits,
and wakes your devices when something needs you. It never holds enough to act alone.

> **Beta.** Cosign signs with an audited FROST library, but the protocol built around
> it — how pieces are made, refreshed, recovered and moved — hasn't had an outside
> review yet.

This page says what a server must do, what it can see, and how to run the reference
server. The full design is [COSIGN.md](COSIGN.md) (servers: §9), and the wire format is
[NIP-XX.md](NIP-XX.md). How apps choose servers is [choosing-servers.md](choosing-servers.md).

## How many servers exist today

**Cosign launches with three public servers, all run by its author, on different
hardware:** syb.lol, a Cloudflare Worker, and a third still to be announced. As of 24
October 2026, syb.lol is live (host key `040e022d…`, operator key `f5073ea2…`, anyone can
enroll). The live list is on [cosign.aaro.cc/servers](https://cosign.aaro.cc/servers), so
this paragraph goes out of date.

> I run syb.lol and will keep running it. I'd love others to run public servers too;
> here's how. If you already run a relay, sidecar packages for popular relay software are
> on the way, so adding a Cosign server beside it will take a few lines.

What that means for you:

- **All launch servers are run by one person, and they see everything you sign through
  them** (see "What a server can see" below).
- **One operator, for now.** The design wants three servers from three different
  people. Until other operators exist, the Marble app and extension fill your three
  places from one operator's servers and **say so** in setup and settings. When other operators
  appear, you can add their servers from Home → **Add a server**. Swapping them in
  automatically is planned.
- **What one operator can and can't do.** All of one operator's servers together are
  3 points and can never sign without you. The risk is that operator plus someone who
  stole your paper backup: 2 + 2 = 4, with the 3-day wait in that operator's hands.
- **Why three servers anyway.** If one server loses its data or disappears, your device
  and another server still sign, even if you have no paper backup.
- **If that one operator disappears entirely**, every server goes at once and nothing
  signs. After 7 days with no server answering, a device plus your paper backup, or two
  devices, can rebuild your key on one device (the *escape hatch*, [COSIGN.md](COSIGN.md)
  §8.4): you then hold a whole nsec, as with any other app, and can split it again with
  new servers. **With one device and no paper backup, the account is lost.** Print the
  paper backup.

### What different operators don't protect against

While the person who runs the servers also publishes the app, spreading servers across
operators buys little: a malicious app update would be a bigger lever than any server.
That's why the **outside review** behind the beta label matters more than server
diversity right now. The mitigations for the app itself are **reproducible builds**, so
anyone can check a release matches the source, and **Zapstore pinning the release
certificate**, so an update signed by anyone else won't install.

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
- **Say who runs it.** Its announcement names its operator (§9.5), so apps can prefer
  servers from different people for each account and show users when they can't (§3,
  §9.3).
- **Destroy old shares after a refresh** (§7.3). When a device is reported lost, every
  piece is renewed and the old ones must be gone for good: no snapshots, backups,
  version history or log lines that keep them. Some hosts keep history you can't turn
  off. Cloudflare's SQLite-backed Durable Objects, for example, keep 30 days of
  point-in-time recovery, so a share must never be stored there in a form that history
  could bring back.
- **Enforce the 3-day wait** (§7.4, §8.3). When someone uses a paper backup without any
  surviving device, or adds a device without that device's lock, the server tells every
  device and refuses to take part for 3 days unless one of them cancels, confirmed with
  its lock.
- **Give only its half of a decryption, and never finish one** (§5.6), and give it only
  to your active devices: never to a paper backup key or a removed device.
- **Never hold a site's NIP-46 signer key if it's a public server** (§6.1, §9.2). Only
  your devices, and servers you run yourself, may hold it, because whoever holds it can
  read what those sites send.
- **Refuse a device the moment it's reported lost** (§7.2).
- **Drop replayed requests**: one already answered, or older than 30 seconds (§5.2).
- **Never delete a finished account's share for inactivity** (§9.2). Only an enrollment a
  stranger never finished may be dropped. A share goes only when one of the user's
  devices asks, through the guarded, cancellable "remove the servers' pieces" (§7.6).
- **Never connect where a stranger points it.** Accounts, sites and new devices name
  relays and push addresses, and anyone can create an account on an open server. A
  public server must not connect to private, loopback, tailnet/CGNAT or cloud-metadata
  addresses because of one, and should check every address each time it connects
  (§9.1).
- **Limit what one stranger can use**: how many accounts it takes, how fast new ones
  arrive, how many messages an account may send, and how many relays it connects to.

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

As of 24 October 2026 the reference server does not yet meet one of the musts above:

- **It holds a NIP-46 signer key** for the accounts it serves, so it can read the
  signing requests of sites that connect by a `nostrconnect://` code. Per-site signer
  keys held only by your devices are designed but not built.

Until they are, a public server **refuses NIP-46 encrypt and decrypt requests**, so
those sites can sign through it but can't read or send your DMs. Sites that use the
browser extension or the Android app are not affected. A server that holds no signer
key, such as the Cloudflare Worker server, never answers NIP-46 sites at all.

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
   also use. A server beside a relay can reach it over the local network while telling
   devices its public address; see [`deploy/README.md`](../deploy/README.md).
3. **Choose who may enroll**: `COSIGN_ENROLL=open` for anyone, or `invite` with
   `COSIGN_INVITES` listing device pubkeys (hex, comma-separated). The list is read
   again for each enrollment, so you can change it without a restart.
4. **Say who runs it**: `COSIGN_OPERATOR` is your npub, and `COSIGN_HTTPS` its public
   page, if it has one. Then publish your own kind 10243 list naming the server's host
   key, so apps count it as yours.
5. **Keep port 8711 private** unless it's behind a login. It's the server's own page
   and lists every account it serves.

On first start a fresh server also makes a key of your own: its page shows an "Add your
phone" code, and your phone and this server make the key together, so neither can sign
alone. `COSIGN_PERSONAL=0` skips it, for a server meant only for others. (Before 0.11.2
the default was a throwaway 2-of-3 that left two shares on the same box; that's now
only `COSIGN_PERSONAL=dealt`, and it says so in the log.)

### Limits and reach (all optional, Cosign 0.11.2)

| Setting | Default | What it does |
|---|---|---|
| `COSIGN_MAX_GROUPS` | 5000 | Accounts this server takes at most. One a stranger started and never finished setting up is let go after a day (`COSIGN_UNFINISHED_AFTER`, in seconds); a finished account is never let go for being idle. |
| `COSIGN_ENROLL_PER_HOUR` | 30 | New accounts per hour. |
| `COSIGN_GROUP_PER_MINUTE` | 600 | Messages per account per minute; the rest are dropped. |
| `COSIGN_MAX_RELAYS` | 300 | Relay connections at most. |
| `COSIGN_RELAY_ALLOW` | none | Relay URLs (comma-separated) this server may reach even if they aren't public. Normally it reaches only `wss://` relays whose names resolve to public addresses, checked at every connect. A sidecar relay mapped with `COSIGN_RELAY_MAP` is always allowed. |
| `COSIGN_PUSH_HOSTS` | ntfy.sh only | Extra push hosts. Push is `https://` only, with no redirects. |

Fixed: at most 8 relays per account, 4 per site's nostrconnect code, and 4 per new
device.

### Adding a server to existing accounts

A device can add a new server to an account it already has (on Home, **Add a server** under the device list):
the device and an existing server make the new server's share together by repair,
without anyone seeing the whole key. So when your server appears, people can move to it
without starting over.

### The Cloudflare Worker server

[`worker/`](../worker/) is a reference server that runs on Cloudflare's free tier. It
holds no NIP-46 signer key, so it never answers NIP-46 sites. It keeps its shares in
Workers KV and everything else in its Durable Object's SQLite, so Cloudflare's 30-day
point-in-time history never holds a share.

**Look after its storage like a key store**: no snapshots or backups that keep old
shares after a refresh (see "Destroy old shares" above).

The [deployment notes](../deploy/README.md) cover running beside a Ditto relay, one
server for many accounts, and a local rehearsal.
