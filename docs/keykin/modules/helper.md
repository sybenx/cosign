# Keykin module: Helper

Draft 2 · 2026-11-03 · module of [Keykin Core](../core.md) draft 14 · not built

A **helper** is a family member's or friend's always-on box that holds the helper seat (3 shares, core
§3.1, I6). With one server it can post for the account while every one of the person's devices sleeps.
It exists only if the person opts in. This module says what it is for, how it is added, stopped and
removed, what it may sign, and what its owner can see. The core wins any disagreement, and nothing here
may weaken it.

The bar is the core's: an nsec in a password manager. A helper is like giving a trusted friend a key that
can only post, never change the account, and can be taken back with one tap. It is only worth having if
the person wants some sites answered while their phone is off.

## 1. What a helper is for

One job: **answering chosen sites while devices sleep.** Bots, cross-posters, schedulers and other
post-only clients connect to the helper instead of to a phone, and the helper signs for them with one
server.

What the core lets a helper do, and nothing more (core §5.7 item 8):

- coordinate a round with one server only for kinds 1 (notes and replies), 1111 (comments), 7
  (reactions), 6 and 16 (reposts), 9734 (zap requests), 20, 21 and 22 (media posts) and 22242 (relay
  auth). Servers refuse anything else, so even a stolen helper box can't change the profile, lists,
  relays or wallet, delete anything, or log in to other services;
- never co-sign for anyone, approve an account change, or cancel a wait (core §2, §6.2, §6.3);
- never get decryption answers, the data key or release seeds, so it can't read or write messages,
  private lists or wallets;
- never send `hold`, `cancel`, `push_register`, `notify_register`, `need_seeds`, `take_out` or `ecdh`;
  servers refuse them from a helper.

**Scheduled posts** need no helper: a device signs a future-dated note with the person present (core
§5.7 item 4 allows it for these kinds) and hands the signed event to any always-on publisher, the helper
included, to publish at its time.

## 2. Sites the helper answers

- **A site is either the phone's or the helper's.** On the connect screen the person may pick "Let
  *helper* answer for this site". The device then asks the helper to mint a `bunker://` link (Doors and
  grants §3.3), so the helper is the grant's **home**: it holds the signer key and answers, and no device
  does.
- A helper grant has only the kinds of §1. It never widens: for more, the person connects the site to a
  phone instead, which is a new grant.
- Requests outside those kinds get `declined: ask on your phone`. Encrypt and decrypt requests get
  `unsupported:`, since the helper can't do them.
- **Signing out reaches the helper.** The helper reports its grants to devices (§4), and every device
  lists them. A sign-out, End, expiry or `logout` is a tombstone delivered to the helper (Doors and grants
  §2), which ends the grant and answers `revoked:` for 30 days.

## 3. Adding, stopping and removing

### 3.1 Adding

1. The friend installs a Keykin app on an always-on machine (a desktop app left running, or a home-server
   package) and picks **Be a helper**. It refuses if a Keykin member of this account is already on that
   machine. It shows a join code (core §4.1) carrying its host key, and tells the friend: "Your npub will
   be listed in *name*'s account."
2. On a device, the person picks **Add a helper**. The opt-in screen says, once and plainly: "*Name*'s
   box will be able to post notes, replies, reactions, reposts and media as you, together with one of your
   servers, for the sites you choose. It can't change your profile, lists or wallet, read your messages or
   delete anything. Any of your devices can stop it at once."
3. The typed join check (core §4.1), then the approval (a lock, a second device, or the paper), then
   `[seat helper→H, redeal]`. The device and one server repair the helper seat (core §6.7.6 F6).

The helper's member entry is `{"key", "kind": "helper", "shares": <the helper seat>, "host": <its host
key>, "operator": <the friend's npub>}`. No host holds both the helper seat and a server seat (core I6),
and replacement picks skip the helper's operator. There is at most one helper (core I5).

### 3.2 Stopping, at once

**Stop helper** is on every device, with no approval (core §5.7, `helper_stop`): every server refuses
the helper's rounds from then on, and every device is told. It only takes power away, so a lone device
with no lock can do it too. A stopped helper stays in its seat until it is removed or replaced.

### 3.3 Removing or moving

- **Remove the helper**: `[seat helper→null, redeal]` with an approval (core F6). It also clears the stop.
- **Moving to another box** is a seat change to the new box's member key, with the same approval.
- Either way every grant the helper was home to ends, and the screen says so: "*3* sites will ask you to
  sign in again."
- A helper that is offline needs nothing: no seat depends on it.
- A helper that has been unreachable for 30 days is shown once, calmly: "*Name*'s helper has been off for a
  month." The person may stop or remove it; nothing is done for them.

## 4. What devices see

- **Reports.** The helper sends each device `helper_report {events, grants, last_used, logouts}`, sealed,
  as a delivery, once an hour or every 50 events. The first device to receive it checks each event
  (`pubkey == g`, the signature) and writes Device policy's metadata for them (Device policy §1), marking
  the attribution as the helper's. Devices show it quietly: "*Helper* signed 12 notes for *Bot*."
- **Signing nobody reported.** A device that fetches account events no device's metadata and no helper
  report accounts for, after an hour's grace, shows one quiet line: "Posts you didn't make from any device
  appeared. Stop your helper?", with **Stop** (§3.2).
- After an heir takes over (Backup module §4), the app offers to remove the helper. Helper rounds never
  count as a sign of life for an heir wait.

## 5. What the friend can see

The friend runs the box, so they can see what it holds:

- the account's membership (its devices, servers, helper and backup key), from its welcome;
- the events it signs, and the requests of the sites it answers;
- the backup material, wrapped under release seeds it never gets.

They can't read messages, private lists or wallet content. The opt-in screen links to this list.

## 6. Messages

| `type` | From → to | `cls` |
|---|---|---|
| `helper_mint {site}` / `helper_link {bunker}` | device → helper / back | `ask` |
| `helper_report {events, grants, last_used, logouts}` | helper → devices (delivery) | `member` |

## 7. Limits, said plainly

- **The helper plus one server** can post notes, replies, reactions, reposts and media as the person,
  silently, until any device stops it (core §10). A dishonest friend or a stolen box can post spam or
  worse in the person's name.
- **The helper alone signs nothing**, and the helper plus the paper is worth nothing without a server's
  wait (core §7.2, I5).
- **A dishonest helper at a redeal** learns `δ`, and with a retired server is the key (core §10).
- **The friend's box can be stolen.** Its shares are stored as core §7.3 says, but the friend's machine
  is not the person's.
- **Removing or moving a helper** needs the paper on a lone device with no lock; stopping it never does.

## Changes

- **Draft 2**, from its first red team (1 critical, 6 high) and the user's answers:
  - servers co-sign helper rounds only for posting kinds (C1, core 14);
  - sites are the helper's or the phone's, with sign-outs delivered to it (H1, H6, M5, M7);
  - helper grants never widen (H2, M6);
  - **Stop helper** on any device, no approval (H3, core 14);
  - no helper co-signing for devices (H4, core 14);
  - a host field, and no host with both the helper and a server seat (H5, core 14);
  - scheduled posts are pre-signed notes (M1, M2);
  - batched reports that feed Device policy's metadata (M3, L3);
  - unreported signing noticed (M4);
  - sites reconnect on remove or move, heirs, messages refused from a helper, the friend told about
    the npub, a message table (L1, L2, L5, L6, L7).
- Draft 1.
