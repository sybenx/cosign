# Keykin dry-run test stack (throwaway, test only)

This folder holds a **test** Keykin stack for a dry run with a throwaway account. It is not the main npub and not
a live server.

## What runs

- two Nostr relays (`bin/nak serve`, in memory);
- three Keykin servers (`node keykin/server/main.ts`);
- a push stub;
- one TLS front door, `proxy.mjs`.

All of them run as plain processes from this folder. The relays, servers and push stub listen on 127.0.0.1 only. The front door listens on this machine's **tailnet address only**, with this machine's Tailscale certificate:

- `wss://<name>/r1` and `wss://<name>/r2` are the relays;
- `https://<name>/s1` … `/s3` are the servers' front doors.

Nothing was installed. No launchd job, login item or setting was added. Nothing outside this folder was touched. The certificate files live in `run/`.

## Start, stop, delete

    ./start.sh mini.ghost-dragon.ts.net 100.106.68.2   # prints the servers' host keys
    ./stop.sh                                          # stops every process start.sh began
    ./stop.sh && cd ~ && rm -rf ~/keykin-dryrun        # removes it all

A reboot simply stops the stack. The relays keep nothing across a stop, and neither does the account's test data; a dry run starts again from a new throwaway account.
