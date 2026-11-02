# Keykin interop test plan

Plan only, nothing built. This is the plan for the last item of Phase 1's finish line: "nak,
Grimoire, nostr-tools, NDK and Amethyst pass a scripted sign-in, post, held delete and NIP-44
test against a prototype." It says what the script does, against what, and what counts as a
pass, so whoever builds the Keykin prototype can write it in a day.

The bar comes from the user (2026-10-27): an account that only works in our own apps is not a
real Nostr account. Sites change nothing (Core, introduction); this test is how we know.

## What it runs against

- **A throwaway Keykin account** on a prototype that implements Core: one device (a headless
  member process standing in for the phone, holding 3 shares and coordinating), two local servers
  (1 share each), and one public relay plus one local relay. Never the main npub.
- **The device auto-answers the person** with a scripted policy, so the run needs nobody at a
  screen: approve the first held event, decline the second.
- The starting point already exists: `site/test/nip46.e2e.ts` (Cosign 0.12) builds a group, runs a
  spec-written NIP-46 client and `nak`, and checks every standard method. The Keykin version keeps
  its shape and swaps the account under it.

## Clients and how each is driven

| Client | Door | Driven by | Notes |
|---|---|---|---|
| `nak` (pinned version) | NIP-46, `bunker://` | shell: `nak event --sec bunker://… -k 1 -c …`, `nak decrypt`/`encrypt --sec bunker://…` | needs the device to hand out a `bunker://` (Doors module) |
| nostr-tools `BunkerSigner` | NIP-46, both `bunker://` and `nostrconnect://` | a Node script | what most web clients are built on |
| NDK `NDKNip46Signer` | NIP-46 | a Node script | second web library |
| Grimoire | NIP-46 | **to identify** | the 2026-10-26 audit could not find a NIP-46 tool by that name. Ask the user which Grimoire is meant (open question below); until then, run `nkcli` in its place and say so |
| Amethyst (pinned APK) | NIP-55 on Android, NIP-46 as fallback | an Android emulator, UI Automator script | the one GUI client; run on its own emulator, one emulator at a time |
| A browser site | NIP-07 | Playwright with the extension loaded | the extension is the device |

## The four checks, for every client

1. **Sign in.** Connect (ticket, `bunker://` or `nostrconnect://`), then `get_public_key` returns
   the group key. Pass: connected within 10 s, the key matches.
2. **Post.** `sign_event` for a kind 1, then publish it. Pass: a valid BIP-340 signature by the
   group key within 5 s on the local relay, and the event appears on the relay.
3. **Held delete.** `sign_event` for a kind 5 with 5 targets (a mass deletion, Core §5.8), twice.
   Pass: the first comes back signed after the device approves it, the second comes back as a
   refusal with a stable error code after the device declines. The client must not hang or crash.
   Also a single-target kind 5: signed after the device's 10-second Undo hold. Record how each
   client treats a 10-second answer (a timeout looks like a failure to the person; Doors module).
4. **NIP-44.** `nip44_encrypt` to a test peer, then `nip44_decrypt` of the peer's reply. Pass: the
   round trip gives the original text, and the decrypt went through the device (a server alone
   never finishes a decryption, Core §5.5). Run nip04 the same way for clients that still send it.

Plus, for each client, the failure cases that matter in real use:

- one dead relay in the `bunker://` relay list (the client must still connect; seen hanging nak on
  2026-10-26);
- a revoked grant: the next request gets the not-connected error and the client shows its own
  sign-in;
- the device asleep for 30 s before answering (iPhone-like): the client waits or retries, rather
  than failing silently.

## Output

One line per client per check, `ok` / `FAIL` / `skip (reason)`, timings, and the error codes seen,
written to a dated file. A run passes when every non-skipped line is `ok`. Skips are allowed only
for a client that cannot do a check at all (for example nak has no held-event UI), and are listed.

## When it runs

- Against the prototype before Phase 1 is called done.
- Again before each Phase 4 build step reaches the user's daily account.
- The NIP-46 part (nak, nostr-tools, NDK) runs headless in CI-like fashion; Amethyst and the
  browser run on request, because they need an emulator or a browser.

## Open

- Which "Grimoire" the user means.
- `bunker://` from the device and `auth_url` belong to the Doors module; this plan assumes they
  exist. Without them, nak can only be tested through a hand-built URL, as in the 0.12 audit.
