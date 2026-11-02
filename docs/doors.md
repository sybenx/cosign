# Companion A: Doors

*Companion to [COSIGN.md](COSIGN.md). Moved out of the core on 2026-11-01 (the devices and
co-signers cut): the core keeps only the three rules a member must enforce about a grant; how a
site connects, which doors exist and what each may ask for lives here. Normative where it says
MUST; section numbers are this document's own, and COSIGN.md §6 points here.*

The core's three rules, repeated so this document stands on its own:

- A **grant** is a site's own key, its origin or package name, an optional expiry and the device
  that admitted it. Every member refuses a request from a key with no live grant.
- A NIP-46 **signer key** is copied to every one of the user's devices and never to a co-signer
  (COSIGN.md §4.2's transition applies while co-signers still hold the keys they hold today).
- Removing a grant is immediate at every member.

---

## The doors

## 1. Connecting

- **By code (primary).** The site shows a QRST code for the published profile
  [`signer-ticket`](https://github.com/sybenx/qr-secret-transfer/pull/14) (QRST §5.2
  shape: `{pubkey, signer, relays, t, expires}`). The user scans it with a member
  device and taps **Connect**. The device tells the holders of the signer key about the
  ticket; the site redeems it as a NIP-46 `connect` secret and keeps a key of its own,
  which is its grant. QRST check level `none` is allowed for a camera scan or a verified
  App Link; `compare` for a pasted link, the `qrst:` handoff or any custom scheme. How
  the code reaches an app is §6.4.
- **By nostrconnect (fallback).** A `nostrconnect://` code is scanned the same way and
  ends in the same kind of grant, removed the same way. Ordinary NIP-46 sites send each
  request once; members SHOULD answer twice and move the site onto relays known to work.
  Such sites stay less reliable than QRST ones: they cannot re-send, and some client
  libraries' relay connections go stale after a few idle minutes until the page is
  reloaded (non-normative, seen with nostr-tools).

  NIP-46 is unchanged; this document only decides which of the user's pieces answers
  it. A NIP-46 site encrypts its requests to a **signer key** — a mailbox address, not
  the user's key, and unable to sign anything. Whoever holds it can read those requests,
  DM text included. So:

  - The signer key for each site is copied to **every one of the user's devices**,
    attended or not, and **never to a co-signer** (§4.2's transition applies until
    co-signers drop the keys they hold today). Whichever holder is awake answers, and gets
    the rest of a signature as usual (§5.1): another device's 3, or one co-signer's point.
  - With only the phone holding it, NIP-46 sites work while the phone is awake or can be
    woken by push (§10).
  - The first time a NIP-46 site asks to encrypt or decrypt, the phone asks once: **"Let
    *site* read and send your DMs?"** The answer is part of the grant.

## 2. Grants

A grant holds the site's key, its origin (or Android package name), when it was made,
and an optional expiry. Members refuse every request from a key without a live grant.

- **Remove**: from the phone, any member device, or any co-signer's web page. Immediate.
- **Expiry**: by default a grant **never expires while it is used, and expires after 90
  days unused** — the pattern of OAuth refresh tokens with an inactivity limit. The user
  MAY instead pick a fixed 30, 60 or 90 days, or never. When a grant expires, the site
  gets the usual not-connected error and shows its own sign-in; nothing else is shown
  anywhere.
  - An expired grant **stays listed**, below the active ones, marked "Expired · last
    used *date*", and still offers Remove and Undo all. Signing in again from that site
    reactivates the same entry rather than adding a second.
  - Entries expired for more than a year fold under "Show older": hidden, never deleted.
  - *(Not built yet.)*
- **One entry per site, each connection inside it.** Grants with the same origin are
  grouped under one site, whichever door they came through (§6.3). Inside, each grant is
  listed by where it lives — "Chrome on *Work PC*", "*Laptop* extension", "*Phone*" —
  with when it was last used. The user can **sign out one connection** (the work
  computer) or **sign the whole site out everywhere** (a site misbehaving). Both are
  immediate.
- A grant gives the site nothing to keep: removing it leaves the site holding a key that
  no member will answer.

## 3. Doors sites already use

Sites MUST NOT need to change to work with this. A conforming device SHOULD offer the
doors that already exist:

- **Android: NIP-55.** The phone app is a NIP-55 signer. An app's request reaches the
  phone app directly (Android starts it to answer), and the phone app is the
  coordinator of §5.1. Each app is a grant.
- **Desktop: NIP-07.** A browser extension is a member device. A site calls
  `window.nostr`; the extension is the coordinator of §5.1. Each website is a grant
  of its own, merged with any other grant for the same origin (§6.2).
- **Everything else: NIP-46** via §6.1.

## 4. Open to any app

The doors are a protocol, not a product. No app, website or host is required:

- **The code.** A site's QR is the `https` form of QRST §11.2 on **any bounce host**
  (QRST §11.2a) — the site's own, or a neutral one. Its fragment carries the
  `signer-ticket` parameters and MAY carry `nc`, a `nostrconnect:` fallback (the
  profile's "`nc` fallback"). A bounce host only explains itself to someone with no
  member app; `cosign.aaro.cc` is one such host and is never required.
- **Suggesting an app.** A bounce host or a site MAY suggest member apps to someone
  without one, from a list it keeps (for example `/apps.json`). It SHOULD list apps that
  people already use for other things before a dedicated reference app.
- **Words people see.** What a site or bounce host shows a person SHOULD say "sign-in
  app" and "your phone", not "signer", "key", "relay" or "Nostr"; those terms are for
  developers.
- **Handing the code to an app.** On the same device the site hands the code over
  either by the neutral `qrst:` handoff (QRST §11.2c), which **any member app may
  claim**, or by a verified `https` App Link to one app it knows.
- **No host needed.** An installed member app MUST work with no bounce host reachable:
  scanning the code with the app, or receiving it by `qrst:`, involves no request to the
  host. Every parameter is in the fragment.
- **Same-phone shortcut.** A site MAY skip its own "Sign in as …?" only when it handed
  the code over by a verified `https` App Link to one specific app. Through `qrst:` or
  any custom scheme, which any app can claim, the site MUST ask before redeeming (the
  profile's "Same-phone sign-in").
