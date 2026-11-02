# Companion B: Keeping versions, and Undo

*Companion to [COSIGN.md](COSIGN.md). Moved out of the core on 2026-11-01 (the devices and
co-signers cut). The core keeps one sentence — every device keeps the latest version of each list
it judges against — because that is what the destructive check needs. How many versions are kept,
the history screen and Undo are a product of the clients and live here.*

## Today

Each co-signer, and each device, keeps the recent versions of the user's replaceable lists (profile, follows,
mutes, relays, bookmarks, sets; reference: the last 25 per list). Every change shows in
every device's history in plain words, with **Undo**, which republishes the archived
version (a routine signature).

**Being revised.** Whether a co-signer keeps any of this is under review: the author decided on
2026-10-27 that co-signers should keep no history, and the spec for it
(`no-server-history.md`) came back from its red team with the finding that the archive is also
what forces a device into a destructive signing, and that the account's write-relay list lives
in it. Until that is settled, what a co-signer keeps is what it keeps today.
