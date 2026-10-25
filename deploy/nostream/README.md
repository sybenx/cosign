# Cosign beside nostream

A Cosign server next to your nostream relay, in its own compose project. It joins
nostream's network (`nostream`, 10.10.10.0/24) at a fixed address, 10.10.10.10, outside
the range Docker hands out there.

```sh
cp .env.example .env     # set COSIGN_OPERATOR (your npub) and RELAY_URL (wss://…)
docker compose up -d
```

## Exempt it from rate limits

nostream's default limits are 720 events an hour per key, and a server pings each
partner every 10 s for each account it serves. Add its address to the whitelists in
`.nostr/settings.yaml`, beside the ones already there:

```yaml
limits:
  connection:
    ipWhitelist:
      - "10.10.10.10"
      - "::ffff:10.10.10.10"
  event:
    whitelists:
      ipAddresses:
        - "10.10.10.10"
        - "::ffff:10.10.10.10"
```

Phones talk to your relay from outside, so the same limits apply to them: one phone is
well inside them. Make the event limit for kinds 20000–29999 generous if your relay
gets many Cosign users.

**If payments are on** (`payments.enabled`), unpaid keys can't post, and every Cosign
key is new. Use [`../haven/`](../haven/) instead, which runs on public relays.

Then [check it and list it as yours](../README.md#check-it).

Not tested yet.
