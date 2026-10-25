# Cosign beside any other relay

For relays with no folder of their own: khatru-based relays, Chorus, rnostr, zooid and
the rest. The relay must take events from keys it has never seen (Cosign makes keys per
device and per account). If it only takes its owner's, members' or web of trust's
events, use [`../haven/`](../haven/) instead.

## Relay in Docker

```sh
cp .env.example .env     # COSIGN_OPERATOR, RELAY_URL, RELAY_INTERNAL, RELAY_NETWORK
docker compose up -d
```

`docker network ls` shows the relay's network (`RELAY_NETWORK`). `docker ps` shows its
service name and port, which make `RELAY_INTERNAL`, e.g. `ws://relay:3334`.

## Relay not in Docker (Linux)

```sh
cp .env.example .env     # COSIGN_OPERATOR, RELAY_URL, RELAY_INTERNAL=ws://127.0.0.1:<port>
docker compose -f compose.host.yaml up -d
```

This shares the machine's network, so the server reaches the relay on localhost. It
starts as `invite` (private): a box like this is often at home. `COSIGN_ENROLL=open`
lets strangers store pieces of their keys there, from your home IP; a public server
belongs on a VPS, with its outbound connections limited. Its page
listens on `127.0.0.1:8711` only. It needs Linux: Docker Desktop on macOS and Windows
doesn't share the machine's network this way.

Then [check it and list it as yours](../README.md#check-it).

## What the relay must let through

From any pubkey: kind **28001** (Cosign's messages between devices and servers),
**24133** (NIP-46, for sites), both ephemeral, and kind **30243** (server
announcements). Cosign's own messages stay under 32 KB. It doesn't do NIP-42 AUTH.

Not tested yet.
