# Roadmap

Cosign is in a feature freeze from 2026-10-24 (0.11.2): only fixes for what people hit in
real use, until what's here has been lived with. The spec (docs/COSIGN.md) marks the
items below "Planned, not yet specified".

## Next, in this order

1. **Silent periodic refresh** (COSIGN.md §7.7): about every 30 days while a device is
   online, the shares move to a new epoch with the servers that answer; a server silent
   for 7+ days (seen by two others) is swapped for a fresh pick. Two-phase, with commit
   spread between servers; nothing visible. Needs server removal (below).
2. **The member library split**: the signing member as a library, the prerequisite for
   an iOS Marble app (the first iOS step is a small TestFlight app around the Safari
   extension).
3. **Per-site activity and grant expiry**: tap a site for what it did, with Undo per item
   (from this phone's history for now); expired sign-ins stay listed, greyed.
4. **A hardware-bound lock**: a Keystore (StrongBox) key that servers verify on guarded
   requests; WebAuthn in the extension. A plan goes to the user first.
5. **The escape hatch** (COSIGN.md §8.4): after 7 days with no server answering, device +
   paper or two devices rebuild the key locally, after the lock and a warning.

Smaller, any 0.12.x: **Report** in Discover's ⋯ menu (hide at once, report to the feed's
curation); **search** in Marble, led by the NIP-50 relays that answer fastest (syb.lol,
relay.ditto.pub), follows first, pasted npub/nevent/NIP-05 resolved, ranked by exact name,
a checked NIP-05 and the social graph — taking what works from the user's Wisp fork.

## Paused

- **The paper backup as 24 words.** BIP-39 English of the backup secret, labelled as a
  Cosign backup (not a NIP-06 or wallet seed). Restoring from the words alone asks the
  seed and announced servers' host keys `backup_find`, signed by the backup key over a
  nonce the server chose, rate-limited; when every server in a key is private or
  unannounced, the phone says at backup time that the words alone won't be enough. Today
  the paper is the QR, or the code copied to a password manager.
- **Swapping servers automatically.** When an operator's server is gone or slow, add a
  new one by repair and refresh the old one out, staggered across accounts; never swap a
  server the user runs themselves; cap accounts per operator. Today a person adds a
  server themselves (Home → Add a server).
- **Removing a server from a key** (outside a periodic refresh). The account's own
  "Remove my servers' pieces" is built.
- **A private Worker,** from the same code as the public one.
- **Google Play,** and **publishing on Zapstore** (zapstore.yaml and zapstore.sh, now in
  the Marble repository, are ready; publishing is a separate step).
- **Running the server beside popular relays** (strfry, nostr-rs-relay, haven, nostream,
  ditto) as ready-made `deploy/` setups, and an Umbrel app: built and tested, not
  published yet.
- **Listing a server as yours from cosign.aaro.cc/servers** (kind 10243, with NIP-07),
  so running one beside a relay takes no extra tool.

## Built in 0.12: Marble as a home screen

Agreed with the user, and built (0.12.0 on). Cosign is one app, and its reason to be on an ordinary
phone is a home screen like a search app's. One screen, no tabs:

- **Top:** a big search box for people, notes and hashtags (NIP-50 search relays). Top
  right: a bell (replies, mentions and reactions to you, and Cosign's approvals) and
  your picture, which opens everything about the signer: devices, sites and apps,
  backups, servers.
- **Under the search:** at most one "needs you" card (Approve?, your paper backup is
  being used, make your paper backup), gone once handled.
- **Below:** a scrolling Discover feed of notes from curated or trending feed relays
  (discover.syb.lol, trending.relays.land, …), pluggable with fallbacks. A card opens
  its thread.
- **Actions:** react (kind 7) and follow, from a card or a profile; that's the only
  follow management. No posting or replies. Reposts and showing zaps: to be decided.

Before building it: a short screen-by-screen plan, checked with the user.

## Done, for reference

**Who can join a server** (built, in the next release): its page sets one of four — only me, people I follow,
people I invite, anyone — and lists the accounts it serves, with a way to stop serving
one. Someone bringing an account they already have proves whose it is with a signed kind
27235; a code from the page still works in every mode, and is the only way in for a
brand-new account.

Several keys on one phone (0.11.1); adding a device with two or three parties (repair
with extra servers); Add a server (0.11.2).
