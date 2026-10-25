# Cosign beside nostr-rs-relay

A Cosign server next to your nostr-rs-relay, in its own compose project. It reaches the
relay on its Docker network and tells phones and sites your relay's public address.

```sh
cp .env.example .env     # set COSIGN_OPERATOR (your npub) and RELAY_URL (wss://…)
docker compose up -d
```

`.env` assumes the relay's service is `nostr-rs-relay` on port 8080, in a project whose
network is `nostr-rs-relay_default`. If yours differ, `docker network ls` and
`docker ps` show the right `RELAY_NETWORK` and `RELAY_INTERNAL`. If it isn't in Docker,
use [`../other-relay/compose.host.yaml`](../other-relay/compose.host.yaml) with
`RELAY_INTERNAL=ws://127.0.0.1:8080` (or the `port` in your `config.toml`).

On **Umbrel**, its "Nostr Relay" app is nostr-rs-relay, but it's only reachable at home
(or over Tor or Tailscale), so phones elsewhere can't use it. See
[the Umbrel app](../README.md#app-stores).

Then [check it and list it as yours](../README.md#check-it).

## config.toml

Nothing to change with the defaults. Watch these if you set them:

- `[authorization] pubkey_whitelist`: Cosign's messages come from keys made per device
  and per account, so a whitelist turns them away. Use [`../haven/`](../haven/) instead.
- `nip42_auth` with `nip42_dms`: fine. Cosign doesn't use kind 4 or 1059.
- `[limits] max_event_bytes`: Cosign's own messages stay under 32 KB. A NIP-46 reply
  carrying a big follow list can be larger.
- `[limits] messages_per_sec`: a server pings each partner every 10 s per account it
  serves. Leave room for that if you set one.

Tested with `scsibug/nostr-rs-relay:latest`: see [`../test/`](../test/).
