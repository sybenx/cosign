# Keykin module: Backup

Draft 1 · 2026-11-03 · module of [Keykin Core](../core.md) draft 13.3 · not built

The core has one backup: the **paper**, a backup key pair whose shares exist only as wrapped material
(core §4.3, §7.2), recovered with two servers after a 3-day wait (§6.5). This module says how that key is
written down (a QR code, or 24 words), how friends can hold it instead of paper (**recovery contacts**),
and how an heir can inherit the account after a long wait. It adds no new way to sign. The core wins any
disagreement, and nothing here may weaken it.

The bar is the core's: an nsec in a password manager. A backup must be easier to keep than an nsec and
harder to steal, and nothing here is ever forced. Most people won't print a paper, and the app only
suggests it quietly.

## 1. Writing the backup key down

The backup key's secret is 32 bytes. It can be written as either or both of:

- **A QR code**: `keykin:backup?k=<bech32 "kkbak" of the secret>&g=<group key>&e=<epoch id>&h=<host>&h=…`,
  where `h` is each current server's host key. Readers also accept `cosign:`.
- **24 words**: BIP-39 (English list) of the 32-byte secret, with its checksum, under the heading
  "**Keykin backup — not a wallet seed**". It MUST be labelled so nobody types it into a wallet, and a
  member app MUST refuse to treat these words as a NIP-06 seed.

The words alone are enough. The app derives the backup key from them and finds the account's servers
by the `seated?` lookup over the public list (core §6.7.5, which needs only the backup key). It then
learns `g` and the epoch id from the release (§6.5). The QR's extra fields only make that faster.

Making a paper (core §4.3, F7) always ends with the read-back, where the person scans the QR or types
the words back (core §1.1). The app never keeps the secret after that.

## 2. Recovery contacts

Instead of paper, or as well as it, the backup secret can be **split among friends**: Shamir 2-of-3 over
the 32-byte secret (SLIP-39 style, one group, threshold 2). No friend ever holds a FROST share.

- **Setup.** The device that makes the backup key (core §4.3) splits it, and sends each friend their piece
  sealed to the friend's own Nostr key, through the friend's app (any app that implements this module).
  The friend's app stores the piece encrypted at rest and shows only "You're holding a recovery piece for
  *name*". The device then destroys the secret and the pieces, as for paper.
  - Optionally, one of the three pieces is printed instead (paper + 2 friends, any 2 recover).
- **A phrase.** At setup the person chooses a short phrase only they would know ("the blue boat"). It is
  stored in each friend's piece and shown to the friend when a recovery is asked for. A friend is told to
  hand over their piece only if the requester says the phrase.
- **Recovering.**
  1. The person, on a new device, asks two friends.
  2. Each friend's app shows "*Name* asks for their recovery piece" and the phrase question, and the
     friend taps Give once satisfied.
  3. Each piece is sealed to the new device's member key.
  4. The new device combines the two pieces into the backup secret and runs the ordinary paper recovery
     (core §6.5): two servers, the 3-day wait, every device and channel told, and any locked device (or
     two devices) can stop it.
- **After a recovery** (or any use), the app makes a new backup key and new pieces (core §6.5 step 6, F9).
  The old pieces are then for a removed key (core §6.7.2) and worthless.
- **Changing contacts** is a new backup key (F7), split again.

## 3. An heir

The person can name an **heir** who can take over, or post a last note, after a long silence.

- **What the heir holds.** The heir key is the heir's own Nostr key. At setup the device makes an **heir
  envelope**: the backup secret, encrypted under `K = SHA-256("keykin-heir/1" ‖ ECDH(heir key, e) ‖
  r_combined)`. Here `e` is an ephemeral key whose public half is stored with the envelope, and
  `r_combined` is a 32-byte value split Shamir 2-of-3 among the account's three servers.
  - Each server stores its piece of `r_combined` and a copy of the envelope (a few hundred bytes).
  - Neither the heir alone nor any two servers alone can open the envelope.
- **The long wait.**
  1. The heir sends `heir_request`, signed by the heir key, to each server.
  2. Each server starts a wait of **H** days (default **180**, chosen at setup) on its own clock, and
     tells every member and every notice channel at the start and every 30 days: "Your heir has asked to
     take over. It happens on *date* unless you stop it."
  3. **Any current device**, with or without a lock, cancels with one tap. An heir is for when nobody is
     left, so any sign of life stops it.
  4. When its own wait has passed with no cancel, a server seals its piece of `r_combined` to the heir key.
- **Then.** The heir combines two pieces with their own key, opens the envelope, and holds the backup
  secret. From there it is an ordinary paper recovery: the core's 3-day wait, devices told. The person
  chooses at setup what the heir may do:
  - **"Final note, then delete"**: the heir's app posts one note the person wrote in advance and then
    runs Account admin's delete.
  - **"Take over"**: the heir joins as a device by the recovery join (core §4.4).
- **Servers keep** the envelope, their `r_combined` piece and the heir's public key, and nothing else for
  this. An heir setup is a change approved like a new paper (`lock`, `pair` or `paper`). Replacing a
  server re-splits `r_combined` at the next new paper or heir change (the app prompts quietly).
- Inactivity is measured only by the wait. No server tracks when the person was last seen.

## 4. When every server is gone

Core F3 covers it: with a device and the paper (or two devices), the app moves all three seats to new
servers. The app offers it calmly, after 7 days with every server unreachable from 2 or more networks
(core §6.7.9).

## 5. What the app shows

- One quiet suggestion at setup ("Write down a backup, or ask two friends to hold it"), and the quiet dot
  on Backup after a report-lost or a server swap (core §6.7.9). Never a banner, never a gate.
- A plain comparison, on request:

  | Case | An nsec in a password manager | Keykin, no backup | Keykin with paper or friends |
  |---|---|---|---|
  | Phone stolen | the thief may have the key | report it from another device; the key is safe | the same, or recover with the paper |
  | Password manager breached | the key is gone | not affected | not affected |
  | A server hacked | — | can't sign | can't sign |
  | The app maker shuts down | the key is in the manager | any Keykin app keeps working | the same |
  | Every device lost | the key is in the manager | the account is lost | recover in 3 days |

## 6. Limits, said plainly

- **Two friends together** hold the backup key. Two friends who collude, plus two servers' waits that
  nobody cancels, take the account. The phrase and the notices are the protection.
- **A friend can be tricked** ("it's me, I lost my phone") if they don't check the phrase.
- **An heir plus two dishonest servers** skip the heir's wait. Today one operator runs every server.
- **24 words in the wrong place** (a photo, a cloud note) are as dangerous as the paper.
- With no paper, no friends and every device lost, the account is gone. That is the likeliest loss.

## Changes

- Draft 1.
