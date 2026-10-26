# The device lock, as evidence — proposal

**Status: proposal, for review. Nothing here is built.** It is the normative text for
COSIGN.md §7.1's planned *hardware-bound user-verification key*, written so it can be
attacked before it is written. A companion to
[progressive-accounts.md](progressive-accounts.md); §9 lists what it would change in
COSIGN.md.

## 1. What is wrong today

COSIGN.md §7.1 says it plainly: **the lock is a claim the device makes.** A device
vouching for a new device says "I asked the user and they unlocked me", and every other
member takes its word. The claim is honest in the reference app — Marble asks through
`KeyguardManager` at the moment of vouching, refuses when there is no screen lock, and
never reuses an earlier unlock — but nothing a server or another device receives
distinguishes that from a message that says so and asked nobody.

Against a thief that is already a real gate: the shares live in the device's keystore
inside the app's sandbox, so a thief cannot carry them to a build that skips the prompt,
and the OS asks. Against a modified app, a rooted device, or anything running with that
device's keys and network identity, it is not a gate at all. The consequence is specific:
one device plus a silent helper can grow a third device (progressive-accounts.md §10), and
after that the attacker holds 6 points, which is the identity for good.

The fix is for the lock to produce something **other members can check**: a signature
from a key that the hardware will not use until the user has authenticated, over a
statement naming exactly the action being authorised.

## 2. The user-verification key

Every member device SHOULD hold a **UV key**: an asymmetric key whose private half is
held by the platform's secure hardware and whose use requires user authentication at the
moment of use.

- It is **not** a share. It signs statements about actions; it has no part in the group
  key, it is worth no points, and losing it loses nothing but the ability to prove a lock.
- It is **per device**, generated on that device, and never leaves it.
- Its public half is recorded in the member list as
  `uv: { kind, pub, attested, since }` and in the epoch record (§3, kind 30242), where
  `kind` is one of the three in §4, `pub` is the raw public key, `attested` is whether
  the platform's own evidence for it was verified (§5), and `since` is when it was
  registered.
- A member with no UV key has `uv: null`, which is today's behaviour and MUST keep
  working (§7).

## 3. What it signs

A UV assertion is over the SHA-256 of a **statement**, which is a byte string with no
JSON and therefore no canonicalisation to get wrong:

```
uv-v1 \n
<groupX>           the account, in hex
<epoch>            decimal, the epoch the action belongs to
<action>           one of the names in §6, lowercase ASCII
<body-hash>        sha256 of the exact message body being authorised, in hex
<asked-by>         the member public key that issued the challenge, in hex
<challenge>        32 bytes of that member's randomness, in hex
```
one field per line, each lowercase hex or decimal, no trailing newline.

- **The action and the body are bound.** An assertion for one action MUST NOT verify for
  another, and an assertion for one body (this new device, this member index, this event)
  MUST NOT verify for another. This is what stops a modified app from collecting a lock
  the user gave for signing a note and spending it on a vouch.
- **The challenge is the verifier's.** A member asked to take part in a locked action
  MUST first send a fresh 32-byte challenge and MUST accept an assertion only over its
  own. One extra round trip is acceptable: these actions already have a human in them.
- A verifier MUST reject an assertion it has already seen, and one whose round it did not
  start.
- Where several members must each take part (a repair's helpers, the servers in a wait),
  **each** issues its own challenge and checks its own assertion. There is no shared
  assertion to replay from one member to another.

## 4. Per platform

### 4.1 Android — `kind: "keystore-p256"`

- A P-256 key in the Keystore, generated with `setUserAuthenticationRequired(true)` and
  `setUserAuthenticationParameters(0, …)`, where a timeout of 0 means **per use**: the
  key cannot be used at all without an authentication bound to that operation.
- Per-use keys are used through a `BiometricPrompt` with a `CryptoObject` wrapping the
  `Signature`. **This is a change for the reference app**, which today confirms through
  `KeyguardManager.createConfirmDeviceCredentialIntent`; that is the time-window path and
  does not authorise a per-use key. The app MUST move the vouching prompt to
  `BiometricPrompt` with a crypto object, which also removes any question of a cached
  unlock.
- *To confirm against the current API before building:* whether a per-use key may accept
  `AUTH_DEVICE_CREDENTIAL` as well as `AUTH_BIOMETRIC_STRONG`. If it may not, a user with
  a PIN and no enrolled biometric cannot have a per-use key, and MUST fall back to the
  shortest allowed timeout with device credential — recorded as `attested: false` if that
  weakens the evidence, never as a refusal to work.
- `setInvalidatedByBiometricEnrollment(true)` (the default) is correct here: see §8.
- Evidence: **key attestation**. The generated key's certificate chain carries the
  attestation extension, which states the security level (TEE or StrongBox), the key's
  purposes, and that authentication is required and per use.

### 4.2 Apple — `kind: "secure-enclave-p256"`

- A P-256 key in the Secure Enclave, created with an access control requiring biometry or
  the device passcode at use time, and used through `LocalAuthentication`.
- **This needs a signed app, and in practice an Apple developer certificate.** Secure
  Enclave keys live in the data-protection keychain, which an unsigned or ad-hoc-signed
  macOS binary cannot use: that is the `-34018` (`errSecMissingEntitlement`) already seen
  on the Mac app. A Developer ID certificate and the keychain entitlements are therefore
  a prerequisite, not a detail — and the author does not have one yet.
  *To confirm on the machine:* whether an ad-hoc-signed build can create a Secure Enclave
  key with no keychain access group, which would make a local build testable without a
  certificate even if a distributed one still needs it.
- Evidence: the Secure Enclave offers no attestation chain comparable to Android's on
  macOS. `kind: "secure-enclave-p256"` is therefore registered as `attested: false`
  unless and until something better exists, which §7's policy already accounts for. An
  unattested UV key is still worth having: it is a real second factor against a thief, and
  it is checkable evidence that *something* that holds that key authorised the action.
- Until there is a certificate, the Mac registers no UV key at all and is a member with
  `uv: null` (§7). It signs, it reads, it follows refreshes; it does not vouch instantly.

### 4.3 Browser and extension — `kind: "webauthn"`

- A WebAuthn **platform** credential created with `residentKey: "required"` and
  `userVerification: "required"`, so the authenticator is the machine's own and the user
  is verified at use.
- The assertion signs `authenticatorData ‖ SHA-256(clientDataJSON)`, and the only place
  our statement can go is the challenge: the challenge presented to `navigator.credentials.get`
  MUST be `SHA-256(statement)` from §3.
- A verifier MUST check, in this order: the signature over the assertion's own bytes with
  the registered public key; that `clientDataJSON.type` is `webauthn.get`; that
  `clientDataJSON.challenge` is base64url of `SHA-256(statement)`; that
  `clientDataJSON.origin` is the one recorded at registration; that `authenticatorData`'s
  `rpIdHash` matches; and that the **UV bit (0x04) of the flags byte is set**. An
  assertion without UV MUST be refused, whatever else it carries.
- To keep verifiers simple, **the registering device publishes its public key as a raw
  P-256 point**, which it extracts from its own attestation object at registration. No
  verifier parses CBOR; `authenticatorData` is read only for its fixed prefix (32-byte
  rpIdHash, 1 flags byte, 4-byte counter).
- Evidence: attestation of a platform credential is uneven across browsers and often
  anonymised. A WebAuthn UV key is registered `attested: false` unless the platform
  provides something a verifier can actually check.

## 5. Registration

- A device generates its UV key **as it joins** (§7.1) and sends
  `{ kind, pub, attestation? }` with the `joined` message it already sends. Members record
  it with the new member.
- A member verifying an Android attestation MUST check the chain to a known hardware
  attestation root, that the extension says authentication is required and per use, and
  the security level. It MUST record `attested: true` only if all of that holds, and MUST
  NOT treat a chain it cannot verify as a failure of the join — the device joins with
  `attested: false`.
- **Attestation verification lives in one place.** The servers verify it (TypeScript, where
  chain and ASN.1 handling is cheapest) and publish the result; a device MAY verify for
  itself and MUST NOT accept a server's `attested: true` as a reason to skip its own check
  if it has one. A device that cannot verify treats the flag as a hint and nothing more.
- A UV key is registered against the account and the device, so re-joining the same
  account with the same key is the same member; joining a different account generates a
  different key.

## 6. The actions

| Action name | What it authorises | UV |
|---|---|---|
| `vouch` | adding a device or a server (§7.1) | **MUST** |
| `export` | taking the account out, or removing the servers' pieces (§7.6) | **MUST** |
| `paper` | using the paper backup without a surviving device (§8.3) | **MUST** |
| `approve` | a destructive event (§5.3) | SHOULD |
| `remove` | reporting a device lost (§7.2) | SHOULD NOT be required |
| `cancel` | cancelling a wait (§7.4) | SHOULD NOT be required |

**Fail closed for granting, fail open for revoking.** The actions that hand out authority
must be provable, because that is where an attacker gains ground. The actions that take
authority away must stay available to a user whose fingerprint reader has died, whose
biometric enrolment has just invalidated their key, or who is holding a borrowed phone and
watching their own account being taken: refusing those fails in the dangerous direction.
A member MUST accept `remove` and `cancel` on the device's claimed lock alone, exactly as
today.

## 7. When a platform cannot do it, and the policy

COSIGN.md §7.1 already says what happens, and this proposal keeps it: *a device without
one will then count as vouching without its lock, so the wait applies.*

- A device with `uv: null`, or whose assertion is missing or bad, is a device vouching
  **without** its lock: adding a device on its word alone is a wait (§7.4), not instant.
- An account where **no** device has a UV key behaves exactly as accounts do today. There
  is no stage, no badge and no nagging (progressive-accounts.md §0a). A client MAY show,
  in settings, that a device's lock is hardware-backed — as a fact about the device, not a
  score.
- Whether `attested: false` is enough to vouch instantly is the policy question this
  document deliberately leaves to one line that an implementation may tighten: **the
  reference policy is that a verified UV assertion suffices, attested or not, and an
  implementation MAY require `attested: true` for `vouch` and `export`.** The argument for
  the looser default is that an unattested UV key still stops the attack in §1 (a message
  that asked nobody); the argument for the stricter one is that an unattested key may have
  been generated by the very software that would lie about the lock.

## 8. When the key dies

UV keys are meant to die. On Android a new or removed fingerprint invalidates them (and
should: `setInvalidatedByBiometricEnrollment(true)`), removing the screen lock invalidates
them, and a factory reset takes them with it. On Apple, `biometryCurrentSet` does the
same. A WebAuthn credential goes with its browser profile.

- **Losing a UV key MUST NOT cost the user anything but proof.** The device goes on
  signing, reading, following refreshes, reporting another device lost and cancelling
  waits. What it loses is the ability to vouch instantly.
- A device whose UV key is gone registers a new one by itself, as `uv_replace`, carrying
  the same evidence a join carries. Members replace the recorded key, set `attested`
  from the new evidence, and **reset `since`**.
- **A replacement MUST carry attestation of the same kind or stronger to keep
  `attested: true`.** Otherwise it is recorded `attested: false`. This is what stops a
  modified app from replacing a hardware key with one it made up and keeping the standing
  of the old one.
- A client SHOULD tell every member when a UV key is replaced — it is exactly the event a
  compromise would produce — and a member MAY treat a replacement younger than a short
  age (reference: 24 h) as not yet good enough for `vouch`, which is the wait of §7.4
  again rather than a new mechanism.
- A device that is reset and restored is a new device: it has no shares (§4.1's
  "unreadable" case) and must join again, at which point it registers a UV key as any
  newcomer does.

## 9. What this would change in COSIGN.md

- **§3**: the member entry of the epoch record gains `uv: { kind, pub, attested, since }`.
- **§7.1**: "Today the lock is a claim the device makes" is replaced by §§2–6 above, and
  the existing sentence about a device without one counting as vouching without its lock
  becomes §7.
- **§7.2, §7.4**: a note that `remove` and `cancel` are deliberately not gated on UV.
- **§11**: three message names — `UV_CHALLENGE`, `UV_ASSERTION`, `UV_REPLACE`.
- **§12**: "the device lock is a claim the device makes" becomes "a locked action carries
  a signature other members check, where the platform can produce one".

## 10. Threat model

1. **A modified app on the user's own device.** The threat this exists for. With an
   attested per-use key, the app cannot produce an assertion without the user's finger at
   that moment, so it cannot vouch itself a second device silently. Without attestation it
   can register a key it controls and assert at will — which is why §7's stricter policy
   exists and why §8's replacement rule matters.
2. **A stolen unlocked device.** Unchanged and still the accepted baseline (§12): the
   thief has the device's shares and, with the user's biometric absent, cannot vouch. A
   per-use key is strictly better than today here, because "unlocked" stops being enough.
3. **Collecting an assertion for one thing and spending it on another.** Closed by
   binding the action and the body hash (§3), and by the verifier's own challenge.
4. **Replay from one member to another.** Closed by `asked-by` and each verifier issuing
   its own challenge.
5. **Downgrade.** An attacker who can suppress the UV assertion gets the unlocked-vouch
   path, which is the wait (§7). A client MUST NOT let a missing assertion silently become
   an instant vouch, and the wait MUST be enforced by someone other than the device that
   is vouching.
6. **Lockout.** The failure mode of getting this wrong is a user who cannot act on their
   own account. §6's asymmetry and §8's rules exist for that, and they are the parts most
   worth attacking: if there is a path where a dead fingerprint reader leaves someone
   unable to remove a stolen device, it is a bug in this document.
7. **Attestation as theatre.** A chain nobody verifies is worse than no chain, because it
   reads as evidence. If attestation verification is not actually implemented, members MUST
   record `attested: false` rather than `true` on an unchecked chain.

## 11. Build order, if it is agreed

1. **Android**, where it is free and where most of the threat is: generate the key, register
   it, verify assertions in the servers and on the phone, and move the vouching prompt to
   `BiometricPrompt` with a crypto object. Attestation verified on the servers first.
2. **The extension**, via WebAuthn, which needs the verifier work from step 1 plus the
   envelope checks of §4.3.
3. **The Mac**, once there is an Apple developer certificate. Until then it is a member
   with `uv: null` and vouching from it is a wait.

Steps 1 and 2 need no new cryptography and no epoch change: a UV key is registered into
the member list the same way a name is.
