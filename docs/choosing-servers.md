# How apps choose Cosign servers

Each Cosign account uses several servers, ideally three, each run by a different person.
Your device plus any one of them signs, so one server being down, slow or gone changes
nothing you can see. This page explains how the Marble app and extension find and pick
them. The precise
rules are in [COSIGN.md](COSIGN.md) §9.5 and [NIP-XX.md](NIP-XX.md).

## Finding servers

The list of servers lives on Nostr, not on any one website.

- **Each server announces itself** with a kind 30243 event (`d` tag `cosign-server`),
  signed by its host key. The event names the server's relays, its HTTPS address if it
  has one, whether anyone can enroll or only invited devices, and its version. It also
  names the operator's pubkey.
- **Each operator lists their servers** with a kind 10243 event, signed with their own
  key.
- **Both must agree.** An app counts a server as an operator's only when the server
  names the operator and the operator names the server back. Anyone can claim to run
  a server; this makes them prove it from both sides.
- **Apps ship with a starter list** of known servers, so a fresh install works before it
  has found anything. They add whatever announcements they find on your relays and the
  starter relays.

The live list is on [cosign.aaro.cc/servers](https://cosign.aaro.cc/servers). Cosign
launches with three public servers run by its author on different hardware (syb.lol, a
Cloudflare Worker and a third to be announced); as of 24 October 2026, syb.lol is
live.

## Picking three

When you create an account, the app:

1. **Pings each candidate once** and keeps the ones that answer.
2. **Prefers three different operators.** When there aren't enough, it fills the rest
   from one operator's servers and **tells you so**. When other operators appear, you
   can add their servers yourself (Home → **Add a server**); swapping them in
   automatically is planned. One operator's servers together still can't sign. The
   cost is that this operator plus someone who stole your paper backup would be enough,
   with the 3-day wait in their hands. Three servers are still worth it: if one loses
   its data, your device and another server still sign. If that operator disappears
   entirely, an account with one device and no paper backup is lost; with a second
   device or the paper, the escape hatch ([COSIGN.md](COSIGN.md) §8.4) lets you rebuild
   the key after 7 days and set up new servers.
3. **Prefers your own server** if you run one. It counts as one of your own devices,
   so it costs no privacy.
4. **Shows each server's operator by name** in settings, so you can see who you're
   trusting.

Every account starts with at least two servers (at launch, three), so your paper
backup plus two of them can always recover it.

## Signing

For each everyday thing you sign:

- The app asks **its fastest server first**. It keeps a running record of how quickly
  and reliably each server has answered.
- If no answer comes within about **300 ms**, it asks the others too, and takes
  whichever answers first.
- If another of your own devices is awake, those two sign together and **no server sees
  it at all**.

So most of what you sign is seen by one server, and a slow server costs you a third of
a second, not a failure.

## Adding and replacing servers

You can add a server to your account at any time from Home → **Add a server**. Your
device and an existing server make the new server's share together, without anyone
seeing your whole key, and your npub stays the same.

Swapping out a server that's gone or keeps failing, automatically, is planned. Until
then, a dead server simply never answers, and your device signs with the others.

## The known limit

An operator is just a pubkey, so **one person with two npubs can pose as two
operators** — the same exposure as one operator openly running two of your servers,
which is how every account starts at launch.
Everyday signing stays safe, because all three servers together still can't sign without
you. But that person could then run two of your three servers, and with a
stolen paper backup they would have enough to recover your account, with the 3-day wait
in their own hands. Their two servers could also fail together.

The defence is the starter list and the operator names in settings: apps should only
seed operators known to be different people, and you can see and change who runs your
servers.
