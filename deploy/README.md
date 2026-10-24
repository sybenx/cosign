# Deploying the Cosign server

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
