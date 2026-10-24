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

3. On first start it makes a throwaway key (2-of-3: this server, server B, your phone).
   Open its page on port 8711 and scan "Add your phone" with Cosign.

Server B's share is in `/data/cosign/b`. Run it anywhere else (`node server.ts <dir>`
with a copy of that directory) to have a backup; without it, your phone and this
server sign everything, and a site gets an error when your phone doesn't answer.

**On the relay's own stack, only ever press Edit → Deploy.** Update can't work there,
and Stop/Restart take the relay down. To upgrade Ditto: new binary in `bin/`, bump the
ARGs in its Dockerfile *and* the `image:` tag in its compose file, then Edit → Deploy.

## Local rehearsal

`local/compose.yaml` runs the same image as servers A and B on this Mac, with
wss://syb.lol as the only relay. (Ditto itself can't run here: its LMDB doesn't work
under x86 emulation.)
