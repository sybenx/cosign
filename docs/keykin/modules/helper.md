# Keykin module: Helper

Draft 1 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.12 · not built

A **helper** is a family member's or friend's always-on box that holds the helper seat (3 shares, core
§3.1, I6). With one server it can sign everyday events for the account while every one of the person's
devices sleeps. It exists only if the person opts in. This module says what it is for, how it is added and
removed, what it may sign, and what its owner can see. The core wins any disagreement, and nothing here
may weaken it.

The bar is the core's: an nsec in a password manager. A helper is like giving a trusted friend a copy of
the nsec that can only post, never change the account, and can be taken back. It is only worth having
if the person wants their account answered while their phone is off.

## 1. What a helper is for

Two jobs, and only these:

- **Answering sites while devices sleep.** For a site the person chooses, the helper answers NIP-46
  requests when no device has answered within 3 seconds (Doors and grants §3.3).
- **Scheduled posts.** A device hands the helper an unsigned event and a time; the helper signs and
  publishes it then.

A helper:

- never approves an account change and never cancels a wait (core §6.2, §6.3);
- never gets decryption answers, the data key or release seeds (core §2's table, §7.2), so it can't read
  messages, private lists or wallets;
- has no screen for the account, so it never shows a card.

## 2. What it may sign

The helper coordinates rounds with one server (3 + 1 = 4 points, core I4 satisfied as a device-class
member). It applies Device policy as a coordinator with nobody to ask:

- it signs only events Device policy rates **Silent**, and never a deletion (it can't offer the
  10-second Undo);
- anything rated Confirm or Held it refuses with `needs-confirm`, and the site is told to ask on the
  person's phone;
- for a site it answers, only the `sign-in` and `post` scopes apply, whatever the grant says;
- as a co-signer for a device, it enforces Held like any co-signer (Device policy §2).

The helper has no data key, so it keeps no account history. It sends every event it signs to every device
as a delivery (`helper_signed {event, site}`, core §7.1, signed by its member key). Devices add it to
their history (Device policy §1) and show it quietly: "*Helper* signed 2 notes for *Primal*".

## 3. Adding a helper

1. The friend installs a Keykin app on an always-on machine (a desktop app left running, or a home-server
   package) and picks **Be a helper**. It shows a join code (core §4.1).
2. On a device, the person picks **Add a helper**. The opt-in screen says, once and plainly: "*Name*'s
   box will be able to post as you, together with one of your servers, whenever it wants. It can't change
   your account, read your messages or spend from your wallet. Only add someone you'd trust with your
   password."
3. The typed join check (core §4.1), then the approval (a lock, a second device, or the paper), then
   `[seat helper→H, redeal]`. The device and one server repair the helper seat (core §6.7.6 F6).
4. The person picks which sites the helper may answer (none by default) and whether it takes scheduled
   posts. For each chosen site, the home device sends the helper that grant's signer key (only `post`-only
   grants qualify, Doors and grants §3.3) sealed to its member key.

The helper's member entry is `{"key", "kind": "helper", "shares": <the helper seat>, "operator": <the
friend's npub>}`. There is at most one helper (core I5).

## 4. Scheduled posts

- A device sends `schedule {id, event, at}`, sealed, where `event` is unsigned, `pubkey = g`. The helper
  keeps it until `at`, then judges it (§2), coordinates the round with one server, and publishes it to the
  account's write relays.
- A device may send `unschedule {id}` at any time. Each device lists what is scheduled from its own record
  of what it sent.
- If the helper is offline at `at`, it signs when it returns only within 1 hour of `at`; later it drops the
  post and tells the devices.

## 5. Removing or moving the helper

- **Remove the helper**: `[seat helper→null, redeal]` with an approval (core F6). The helper's pieces stop
  combining with anything current, and every signer key it was given is revoked (Doors and grants §2).
- **Moving to another box** is a seat change to the new box's member key, with the same approval.
- A helper that is offline needs nothing: no seat depends on it, and the person loses only its two jobs.
- A helper that has been unreachable for 30 days is shown once, calmly: "*Name*'s helper has been off for a
  month." The person may remove it; nothing is done for them.

## 6. What the friend can see

The friend runs the box, so they can see what it holds:

- the account's membership (its devices, servers, helper and backup key), from its welcome;
- the events it signs, and the requests of the sites it answers;
- the backup material, wrapped under release seeds it never gets.

They can't read messages, private lists or wallet content. The opt-in screen links to this list.

## 7. Limits, said plainly

- **The helper plus one server signs**, by design: a dishonest helper and any one server can post as the
  person, silently, until it is removed (core §10).
- **The helper alone signs nothing**, and the helper plus the paper is worth nothing without a server's
  wait (core §7.2, I5).
- **A dishonest helper at a redeal** learns `δ`, and with a retired server is the key (core §10).
- **The friend's box can be stolen.** Its shares are stored as core §7.3 says, but the friend's machine
  is not the person's.
- **A lone device with no lock** needs the paper to add or remove a helper.

## Changes

- Draft 1.
