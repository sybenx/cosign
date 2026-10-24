# Deploying the Cosign server

## Beside syb.lol's Ditto relay (xumbrel): its own Dockge stack `cosign`

`xumbrel-stack/compose.yaml` is a stack of its own that joins the relay stack's network
(`ditto-relay_default`) and reaches Ditto at `ws://relay:13131`. No button on either
stack can touch the other. (An earlier attempt added Cosign to the `ditto-relay` stack
itself; Stop + Update there took syb.lol down for a minute, because Update downloads
every image and the relay's is built locally. That file is kept as
`xumbrel/ditto-relay-with-cosign.DO-NOT-USE.yaml`.)

1. Copy the stack and make its data directory (uid 1000):

   ```sh
   ST=umbrel/app-data/dockge/data/dockge-stacks
   ssh umbrel@xumbrel mkdir -p $ST/cosign/server umbrel/app-data/dockge/data/docker/cosign
   rsync -a --delete --exclude node_modules --exclude data --exclude 'test*' --exclude logs \
     ~/cosign/server/ umbrel@xumbrel:$ST/cosign/server/
   scp ~/cosign/deploy/xumbrel-stack/compose.yaml umbrel@xumbrel:$ST/cosign/compose.yaml
   ```

2. In Dockge, open the `cosign` stack and press **Deploy**. It builds the image and
   starts it. To update after copying new code, press Deploy again (or Update: the
   image is `pull_policy: build`, so Update rebuilds instead of downloading).

3. On first start it makes a throwaway key (2-of-3: this server, server B, your phone) in
   `/data/cosign`. Open http://xumbrel:8711 and scan "Add your phone" with Cosign.

Server B's share is in `/data/cosign/b`. Run it anywhere else (`node server.ts <dir>`
with a copy of that directory) to have a backup; without it, your phone and this
server sign everything, and a site gets an error when your phone doesn't answer.

**On the relay's own stack (`ditto-relay`), only ever press Deploy.** Update can't work
there (its image is built on xumbrel, not downloadable), and Stop/Restart take syb.lol
down. To upgrade Ditto: new binary in `bin/`, bump the ARGs in its Dockerfile *and* the
`image:` tag in its compose file, then Deploy.

## Local rehearsal

`local/compose.yaml` runs the same image as servers A and B on this Mac, with
wss://syb.lol as the only relay. (Ditto itself can't run here: its LMDB doesn't work
under x86 emulation.)
