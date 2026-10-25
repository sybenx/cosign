# Cosign beside strfry

A Cosign server next to your strfry relay, in its own compose project. It reaches strfry
on its Docker network and tells phones and sites your relay's public address.

```sh
cp .env.example .env     # set COSIGN_OPERATOR (your npub) and RELAY_URL (wss://…)
docker compose up -d
```

`.env` assumes strfry's service is `strfry` on port 7777, in a project whose network is
`strfry_default`. If yours differ, `docker network ls` and `docker ps` show the right
`RELAY_NETWORK` and `RELAY_INTERNAL`. If strfry isn't in Docker, use
[`../other-relay/compose.host.yaml`](../other-relay/compose.host.yaml) with
`RELAY_INTERNAL=ws://127.0.0.1:7777`.

Then [check it and list it as yours](../README.md#check-it).

## strfry settings

Nothing to change with strfry's defaults. If you run a **write policy plugin**, let these
through from any pubkey: kind **28001** (Cosign's messages between devices and servers),
**24133** (NIP-46, for sites) and **30243** (server announcements). The first two are
ephemeral, so strfry doesn't keep them.

Cosign splits its own messages into parts under 32 KB, well inside the default
`events.maxEventSize` (64 KB). A NIP-46 reply carrying a big follow list can be larger,
so raise `maxEventSize` and `relay.maxWebsocketPayloadSize` if you want those to go
through your relay too (they also go through the other relays).

Tested with strfry 1.1.2 (`ghcr.io/hoytech/strfry`): see [`../test/`](../test/).
