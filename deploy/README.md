# Deploying the Cosign server

## Beside syb.lol's Ditto relay (xumbrel) — DON'T deploy it this way

**This took syb.lol down on 2026-10-23.** `xumbrel/compose.yaml` adds `cosign` to the
live `ditto-relay` stack. Pressing Deploy in Dockge stopped the relay and Caddy, then
tried to pull every image from Docker Hub; the locally built images can't be pulled,
so it gave up with the relay stopped. The stack was restored by hand.

Next time: a separate Dockge stack for Cosign that joins `ditto-relay`'s network as an
external network, so deploying it can never touch the relay. Check what Dockge runs
before pressing anything. The steps below are kept for reference only.

1. Copy the server into the stack, and make its data directory (uid 1000):

   ```sh
   rsync -a --delete --exclude node_modules --exclude data --exclude 'test*' --exclude logs \
     ~/cosign/server/ umbrel@xumbrel:umbrel/app-data/dockge/data/dockge-stacks/ditto-relay/cosign/
   ssh umbrel@xumbrel mkdir -p umbrel/app-data/dockge/data/docker/cosign
   scp ~/cosign/deploy/xumbrel/compose.yaml umbrel@xumbrel:umbrel/app-data/dockge/data/dockge-stacks/ditto-relay/compose.yaml
   ```

2. In Dockge, open `ditto-relay` and press **Deploy**. It builds `cosign` and starts it.

3. On first start it makes a throwaway key (2-of-3: this server, server B, your phone) in
   `/data/cosign`. Open http://10.0.0.10:8711 (or the tailnet address) and scan
   "Add your phone" with Cosign.

Server B's share is in `/data/cosign/b`. Run it anywhere else (`node server.ts <dir>`
with a copy of that directory) to have a backup; without it, your phone and this
server sign everything, and a site gets an error when your phone doesn't answer.

To undo: remove the `cosign` service from the compose file and deploy again.

## Local rehearsal

`local/compose.yaml` runs the same image as servers A and B on this Mac, with
wss://syb.lol as the only relay. (Ditto itself can't run here: its LMDB doesn't work
under x86 emulation.)
