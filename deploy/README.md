# Deploying the Cosign server

Run a Cosign server next to the Nostr relay you already run, with one compose file: copy
a folder, set your npub, `docker compose up -d`.

A Cosign server holds one small share of each user's key (1 point of the 4 it takes to
sign), so **a user's device plus any one server signs, and the servers together never
can**. It's the always-on piece that lets people sign in to Nostr apps without handing
an nsec to anyone. Apps pick three servers from three different operators, so every new
operator makes everyone safer. What a server must do and what it can see:
[Running a Cosign server](../docs/servers.md).

## Pick your relay

| Your relay | Folder | Its traffic goes through your relay |
| --- | --- | --- |
| [strfry](https://github.com/hoytech/strfry) | [`strfry/`](strfry/) | yes (tested) |
| [nostr-rs-relay](https://sr.ht/~gheartsfield/nostr-rs-relay/) | [`nostr-rs-relay/`](nostr-rs-relay/) | yes (tested) |
| [Haven](https://github.com/bitvora/haven), [Pyramid](https://github.com/fiatjaf/pyramid), [WoT relay](https://github.com/bitvora/wot-relay), or no relay | [`haven/`](haven/) | no: they only take their owner's, members' or WoT's events, so it uses public relays |
| [nostream](https://github.com/cameri/nostream) | [`nostream/`](nostream/) | yes, once you exempt it from rate limits |
| [Ditto](https://gitlab.com/soapbox-pub/ditto) | [`ditto/`](ditto/) (syb.lol's own: [`beside-ditto/`](#beside-a-ditto-relay-as-its-own-dockge-stack)) | yes |
| Anything else in Docker (khatru relays, Chorus, rnostr, zooid…) | [`other-relay/`](other-relay/) | yes, if it takes events from any key |
| Any relay not in Docker (systemd), on Linux | [`other-relay/compose.host.yaml`](other-relay/compose.host.yaml) | yes, if it takes events from any key |
| Umbrel | the [Cosign for Umbrel](https://github.com/sybenx/cosign-umbrel) community app store | no: Umbrel's relay is only reachable at home, so it uses public relays |

Why these: on 24 October 2026 we read the NIP-11 `software` field of the 1,059 public
relays that answered, out of 1,186 listed by NIP-66 monitors and relay lists. strfry ran
316 of them (30%), nostr-rs-relay 192 (18%), Haven 151 (14%), Pyramid 55 (5%), khatru
itself 35, nostream 32, WoT relay 26, rnostr and zooid 12 each, Ditto 6, and a long
tail. Umbrel's and StartOS's relay apps are nostr-rs-relay too.

## Start it

```sh
cd deploy/strfry         # or your relay's folder
cp .env.example .env     # set COSIGN_OPERATOR (your npub) and RELAY_URL
docker compose up -d
```

It runs in a compose project of its own (`cosign`), joined to the relay's Docker network
only. Nothing you do to it can stop or recreate your relay, and the reverse is true too.
It only connects out, so it needs no open port, no domain and no TLS of its own.

| Setting (`.env`) | What it is |
| --- | --- |
| `COSIGN_OPERATOR` | your npub. The server names you in its announcement (kind 30243). |
| `RELAY_URL` | your relay's public `wss://` address, as phones and sites reach it |
| `RELAY_INTERNAL`, `RELAY_NETWORK` | where this container reaches the relay inside Docker, and that network's name |
| `COSIGN_ENROLL` | `open` (the default beside a relay): anyone can create an account with it. `invite`: only `COSIGN_INVITES`. Open means strangers' key pieces on that machine: it belongs on a VPS, with its outbound connections limited, not at home. |
| `COSIGN_INVITES` | device pubkeys (hex, comma separated) allowed when `invite` |
| `EXTRA_RELAYS` | other relays it uses besides yours (default `wss://nos.lol,wss://relay.primal.net`) |
| `COSIGN_HTTPS` | its public page, if you put one behind a login (optional) |
| `COSIGN_VERSION` | image tag, default `0.12` (`ghcr.io/sybenx/cosign-server`) |

Change any of them in `.env` and run `docker compose up -d` again: the server reads them
at every start (0.11.2 and later).

## Check it

```sh
docker compose logs cosign          # "[relays] relay up: wss://your.relay", and no errors
curl -s localhost:8711/status       # "host": the server's host key, "enroll": "open"
```

## Make it count as yours

Apps only count a server as yours when you name it back: a kind 10243 event, signed by
**your** key, with a `p` tag for each server's host key (the `host` from `/status`). With
[nak](https://github.com/fiatjaf/nak), for example:

```sh
nak event -k 10243 --tag p=<host key> --sec <your bunker:// URL or nsec> wss://your.relay wss://nos.lol wss://relay.primal.net
```

It's a replaceable event: if you run more than one server, list them all in one event.

## Look after it

- **Port 8711 is its own page, with no login.** It lists every account it serves. The
  compose files publish it on `127.0.0.1` only. Keep it that way, or put a login in front.
- **No snapshots or backups of its volume.** After a refresh, old shares must be gone for
  good. A backup that keeps them defeats that.
- **Upgrade:** `docker compose pull && docker compose up -d`. The tag follows the
  `0.12` line; set `COSIGN_VERSION` for another.
- **A public server today holds each account's NIP-46 signer key**, so it can read what
  `nostrconnect://` sites ask. See
  ["Where the reference server falls short"](../docs/servers.md#where-the-reference-server-falls-short-today).

## App stores

**Umbrel.** [Cosign for Umbrel](https://github.com/sybenx/cosign-umbrel) is a community
app store with one app, Cosign Server: a private server (`invite`) with an "Add your
phone" code on its page, behind the Umbrel login, its shares left out of Umbrel backups.
It runs on public relays: Umbrel's own Nostr Relay app is only reachable at home.

**StartOS** (planned, not built). A StartOS package is an `.s9pk` built with Start9's SDK:
a manifest, the same image, a config with the operator npub and enroll policy, a health
check on `/status`, and backups turned off for the shares. Its "Nostr RS Relay" is
reachable only over Tor or LAN, so like Umbrel it would use public relays. Worth doing
once there's demand.

## Tests

`test/e2e.ts` runs a relay and the sidecar in Docker on this machine. The server
announces itself, a device enrolls a 2-of-3 key (this server, a second one, a phone), a
site signs in with a ticket and signs a note and a follow list, then it restarts and
signs again. The relay's network is internal, so the servers can't reach the internet,
and nothing is posted to a public relay.

```sh
(cd server && npm ci) && (cd site && npm ci)    # the stand-in phone and site
node deploy/test/e2e.ts strfry
node deploy/test/e2e.ts nostr-rs-relay
node deploy/test/e2e.ts strfry other-relay      # another folder's compose.yaml, beside strfry
```

**Tested** (24 Oct 2026, Docker on an arm64 Mac), all passing: `strfry/` with strfry 1.1.2
(`ghcr.io/hoytech/strfry`), `nostr-rs-relay/` with `scsibug/nostr-rs-relay` (amd64,
under emulation), and `other-relay/compose.yaml` beside that strfry.

**Not tested:** `nostream/`, `ditto/`, `other-relay/compose.host.yaml`, `haven/` (it
would post to public relays), the Umbrel app, the `nak` command above, and any relay
behind a real domain and TLS.

## Beside a Ditto relay, as its own Dockge stack

`beside-ditto/compose.yaml` is a Dockge stack of its own that joins the relay stack's
network (`ditto-relay_default`) and reaches Ditto at `ws://relay:13131`, while telling
phones and sites the relay's public address. No button on either stack can touch the
other. Don't add Cosign to the relay's own stack: Dockge's Update downloads every image
in a stack, and a Ditto image built from its Dockerfile can't be downloaded, so the
stack is left stopped.

1. Copy it to the host, beside the relay's stack, and make its data directory, owned by
   uid 1000 (`/data/cosign` as Dockge's Docker sees it):

   ```sh
   rsync -a --delete --exclude node_modules --exclude data --exclude 'test*' --exclude logs \
     server/ <host>:<dockge-stacks>/cosign/server/
   scp deploy/beside-ditto/compose.yaml <host>:<dockge-stacks>/cosign/compose.yaml
   ```

2. Reload Dockge (its editor keeps the files it loaded, and saves them back when you
   press Start). Open the `cosign` stack and press **Start** (or Edit, then Deploy). It
   builds the image and starts it. After copying new code, press Update: the image is
   `pull_policy: build`, so Update rebuilds it instead of downloading.

3. On first start it makes its own host key and a key of your own (`/data/a`): no key
   yet, and your phone and this server make it together, so neither can sign alone.
   Port 8711 lists every group it serves; open yours (`/g/<id>/`) and scan "Add your
   phone" with Cosign. (Before 0.11.2 this was a throwaway 2-of-3 with server B's share
   in `/data/b` on the same box; that's gone.)

**On the relay's own stack, only ever press Edit → Deploy.** Update can't work there,
and Stop/Restart take the relay down. To upgrade Ditto: new binary in `bin/`, bump the
ARGs in its Dockerfile *and* the `image:` tag in its compose file, then Edit → Deploy.

## One server, many groups

The container is a shared server (`node server.ts --root /data /data/a`): one process,
one relay subscription, for your group in `a/` and for every group a device enrolls,
each in `groups/<id>/` with a member key and share of its own. `host.json` holds the
server's host key (its identity to devices, and where they write to enroll), the port
of its page, its relays, and who may enroll:

```json
{ "enroll": "invite", "invites": ["<device pubkey hex>"] }
```

`"invite"` (the default, with nobody invited) takes on groups only for the devices
listed; `"open"` takes anyone's. The list is read again for each enrollment, so it can
change without a restart. `COSIGN_ENROLL` and `COSIGN_INVITES` override the file.

Upgrading a server that ran one group: nothing to do. An existing `/data/a` is served as
it is, with the same key and share; the first start adds `host.json` and `groups/`.
`COSIGN_PERSONAL=0` skips that key of your own on a fresh server meant only for others.

Outside a container: `node server.ts data/a` still runs one group on its own port, and
`node server.ts --root data data/a` is the shared server.

## Local rehearsal

`local/compose.yaml` runs the same image as servers A and B on this Mac, with
wss://syb.lol as the only relay. (Ditto itself can't run here: its LMDB doesn't work
under x86 emulation.)
