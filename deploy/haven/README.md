# Cosign beside Haven, Pyramid or WoT relay (or no relay at all)

These relays only take events from their owner, their members, or their web of trust,
and ask anyone else to AUTH. Cosign's messages come from keys made per device and per
account, which no such relay knows, and Cosign doesn't AUTH. So the server can't use
your relay. It runs beside it on public relays instead, and is just as useful: it only
connects out, so it needs no port, domain or TLS.

```sh
cp .env.example .env     # set COSIGN_OPERATOR (your npub)
docker compose up -d
```

`COSIGN_RELAYS` picks the relays (default `wss://syb.lol,wss://nos.lol,wss://relay.primal.net`).
Pick ones that take short-lived events from any key.

This also works on any machine with Docker and no relay at all: a home server, a VPS.

Then [check it and list it as yours](../README.md#check-it).

Not tested yet.
