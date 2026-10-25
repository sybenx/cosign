# Cosign beside Ditto

A Cosign server next to your Ditto relay, in its own compose project. The public Cosign
server at syb.lol runs exactly this way, beside Ditto 2.0.

```sh
cp .env.example .env     # set COSIGN_OPERATOR (your npub) and RELAY_URL (wss://…)
docker compose up -d
```

`.env` assumes Ditto's service is `ditto` on port 4036 (Ditto's default `PORT`), in a
project whose network is `ditto_default`. Set `RELAY_INTERNAL` and `RELAY_NETWORK` to
yours. Most Ditto installs run under systemd, not Docker: then use
[`../other-relay/compose.host.yaml`](../other-relay/compose.host.yaml) with
`RELAY_INTERNAL=ws://127.0.0.1:4036`.

**Keep it in its own stack** (Dockge, Portainer…), not in Ditto's: an Update there pulls
every image in the stack, and a Ditto built from its Dockerfile can't be pulled, so
the whole stack, relay included, is left stopped.

Then [check it and list it as yours](../README.md#check-it).

Not tested from this folder. syb.lol's deploy is
[`../beside-ditto/`](../beside-ditto/).
