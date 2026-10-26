# The device lock, as evidence — proposal, second draft

**Status: proposal, for review. Nothing here is built.** The normative text for COSIGN.md
§7.1's planned hardware-bound user-verification key. A companion to
[progressive-accounts.md](progressive-accounts.md); §13 lists what it would change in
COSIGN.md.

This draft answers an independent red-team review of the first one
(`~/igloo/cosign-uv-redteam-findings.md`, verdict: *good idea, don't build as written*;
two critical findings, six high). All of it is resolved here.

**What changed from the first draft:**

- **"Revoking is always free" is gone.** It was a takeover path: a thief reports your other
  devices lost, then cancels every recovery you start. Removing another device and
  cancelling a recovery change who controls the account, so they are handled in §7 with
  mutual removal and a contest rule, not by an asymmetry that waved them through.
- **An unattested key no longer buys an instant add.** The first draft's reference policy
  accepted a key the asserting device made up, which is exactly what a tampered app would
  do, so the mechanism didn't stop the attack it was written for.
- **`vouch` now means every repair that creates or enlarges a share-holding member** —
  device, server, **paper**, grow. The first draft left making a paper out, and a paper
  handed to a key the device keeps is 2 points: with its own 3, the key.
- **Every server sees its own challenge in one assertion**, so the gate is not the laxest
  server; and one touch covers all of them, instead of one prompt per verifier.
- **The attestation check list is written out**, including the things that actually matter
  against root — revocation, key origin, the app's own identity, boot state — with the
  honest note that leaked attestation keyboxes exist and this raises cost rather than
  proving anything.
- **`paper` no longer requires an assertion** (there is no device to hold a key), and every
  MUST in the table means *or the wait*, never a refusal, so no path ends in "no".
- **Replacing a key** is pinned down: the youth rule is a MUST, a downgrade is a wait, the
  order of kinds is defined, and a removed device's key is burned.

---

## 1. What is wrong today

COSIGN.md §7.1 says it plainly: **the lock is a claim the device makes.** A device vouching
for a new one says "I asked the user and they unlocked me", and every other member takes
its word. The claim is honest in the reference app — Marble asks through `KeyguardManager`
at the moment of vouching, refuses when there is no screen lock, and never reuses an
earlier unlock — but nothing a verifier receives tells that apart from a message that asked
nobody.

Against a thief that is a real gate on Android, where the shares are in a keystore inside
the app's sandbox. It is **not** a gate on the browser extension or the Tauri Mac, whose
shares are files in a profile (verified), and not against a tampered or hooked app
anywhere. The consequence is specific: one device plus a silent helper can grow a second
device, and 6 points of one epoch is the identity for good.

The fix is for the lock to produce something a verifier can check: a signature from a key
the hardware will not use until the user authenticates, over a statement naming exactly the
action being authorised and exactly who is being asked.

## 2. The user-verification key

Every member device SHOULD hold a **UV key**: an asymmetric key whose private half is held
by the platform's secure hardware and whose use requires user authentication at the moment
of use.

- It is **not** a share: no points, no part in the group key. Losing it costs proof and
  nothing else (§11).
- One per device per account, generated on that device, never leaving it.
- Recorded in the signed member record (progressive-accounts.md §4.1) as
  `uv: { kind, pub, attested, synced, since }`. It MUST NOT be accepted from a server's
  member list: a server that can write `uv.pub` or `attested` owns the mechanism.
- `kind` is one of §4's three. `pub` is a raw P-256 point. `attested` is what **this
  verifier** computed (§5.3), not what anyone published. `synced` is set when the platform
  says the key can leave the machine (§4.3). `since` is when this verifier first accepted it.
- A member with no UV key has `uv: null`, which is today's behaviour and MUST keep working
  (§10).

## 3. What it signs

A UV assertion is over the SHA-256 of a **statement**: a byte string, so there is no JSON
and nothing to canonicalise wrong.

```
uv-v1
<groupX>             the account, hex
<epoch>              decimal, the committed epoch at challenge time
<action>             a name from §6, lowercase ASCII
<asserter>           the asserting member's E public key, hex
<body-hash>          sha256 of the action's fields from §3.1, hex
<n>                  decimal, how many challenge lines follow
<pk>:<challenge>     one line per verifier, sorted by pk, each challenge 32 bytes hex
```

one field per line, no trailing newline.

- **One statement, every verifier.** A verifier MUST find its own `pk:challenge` line,
  MUST have issued that challenge itself, and MUST NOT accept an assertion that omits it.
  One assertion therefore satisfies every server at once, which is why §8 can demand that
  all of them check it — and it costs the user **one** touch, not one per verifier.
- **The action and the body are bound**, so a touch given for one thing cannot be spent on
  another by anything downstream of the prompt. (What the user *saw* is §9; this binding is
  between members.)
- **Challenges**: 32 bytes from the verifier's own randomness, single use, with a life
  (reference: 2 minutes) and a cap on how many may be outstanding per member. A verifier
  remembers spent challenges, not signature bytes: ECDSA signatures are malleable, so
  deduplicating on them is not deduplicating.
- **Epoch**: the committed epoch at challenge time. If the account commits a new epoch
  before the action completes, the action fails and is asked again (COSIGN.md §7.7's two
  phases make this reachable).

### 3.1 The body of each action

The verifier acts only on these fields, and hashes exactly them:

| Action | Body fields, in this order |
|---|---|
| `vouch` | kind (`device` \| `server` \| `paper` \| `grow`), the newcomer's `E.pub`, the share indices, the label, the newcomer's `uv.pub` or `none` |
| `export` | the requesting member's `E.pub`, the route (`take_out` \| `escape`), whether the servers' pieces are being removed |
| `approve` | the event id, its kind, and the one-line description shown to the user |
| `register` | the `uv.pub` being registered, its `kind`, and the member's `E.pub` (§5.1) |
| `cancel` | what is being cancelled: the guard or recovery id |

"The exact message body" is not good enough: it invites hashing one JSON and acting on
another.

## 4. Per platform

### 4.1 Android — `kind: "keystore-p256"`

- A P-256 key in the Keystore, `setUserAuthenticationRequired(true)` and
  `setUserAuthenticationParameters(0, …)` — a timeout of 0 means **per use**, so the key
  cannot be used without an authentication bound to that operation.
- Used through `BiometricPrompt` with a `CryptoObject` wrapping the `Signature`. **This is a
  change for the reference app**, which confirms through
  `KeyguardManager.createConfirmDeviceCredentialIntent`: that is the time-window path and
  does not authorise a per-use key. The change also removes any remaining question of a
  cached unlock.
- Marble's minimum is API 30, where a per-use key may accept `AUTH_DEVICE_CREDENTIAL`
  alongside `AUTH_BIOMETRIC_STRONG`, so a PIN-only user is fine and the first draft's
  "shortest allowed timeout" fallback is **dropped**: it was never needed and a time window
  is a hole.
- But the PIN is the common theft: watched, then the phone taken. So a key used for `vouch`
  and `export` MUST allow **strong biometric only, when a strong biometric is enrolled**,
  and the device credential only when none is. Other actions may take either. (Android's own
  Identity Check makes the same split.) Pair this with §9's notices, because a thief who
  knows the PIN can enrol their own finger — which invalidates the key and lands in §11.
- `setInvalidatedByBiometricEnrollment(true)`: yes. An enrolment the user did not make must
  break the key, not inherit it.
- Evidence: **key attestation** (§5.2).

### 4.2 Apple — `kind: "secure-enclave-p256"`

- A P-256 key in the Secure Enclave with an access control requiring biometry or the
  passcode at use, through `LocalAuthentication`.
- **The Mac can have a UV key today, through the Chrome extension**, which gets Touch ID
  from Chrome's own signed authenticator (§4.3). That needs no Apple certificate.
- **The Tauri app cannot.** WebAuthn in `WKWebView` needs Apple's browser entitlement, and
  the data-protection keychain needs a signed app — the `-34018` already seen. Worth
  testing before accepting: CryptoKit's `SecureEnclave.P256` returns an encrypted blob the
  app stores itself rather than a keychain item, so an ad-hoc-signed build may manage it.
  Until then the Tauri Mac is `uv: null` (§10).
- Evidence: no attestation chain a verifier can check on macOS, so `attested: false` unless
  something better appears. It is still worth having: it is a real second factor against a
  thief.
- The unsigned Mac app is the softest member in any account — its shares are readable by
  any process running as the user — which is a reason for §7, not an argument about keys.

### 4.3 Browser and extension — `kind: "webauthn"`

- A **platform** credential, `userVerification: "required"`, and
  `residentKey: "discouraged"` — *not* "required" as the first draft said. Discoverable
  credentials are the ones password managers sync and intercept, and a synced key is not a
  device key.
- Read the **BE and BS flags** (0x08, 0x10) of `authenticatorData` at registration and at
  every assertion. `BE = 1` means the key can leave the machine: record `synced: true`, and
  §8 never lets a synced key make an instant `vouch`.
- `alg: -7` only. RSA (`-257`, which Windows Hello may choose) breaks the raw-P-256-point
  rule and MUST be refused at registration.
- The assertion signs `authenticatorData ‖ SHA-256(clientDataJSON)`, and the statement can
  only ride in the challenge: present `SHA-256(statement)` to `navigator.credentials.get`.
- A verifier MUST check, in order: the signature with the registered key; `type` is
  `webauthn.get`; `challenge` is base64url of `SHA-256(statement)`; `origin` is the one
  recorded at registration; `crossOrigin` is absent or false and `topOrigin` is absent;
  `rpIdHash` matches; and the **UV flag (0x04)** is set. No UV, no assertion.
- The rpId MUST be the extension's own id (`chrome-extension://<id>`), never a website's
  domain. A member page served from a server's domain MUST NOT use WebAuthn for this: that
  operator, or an XSS there, could harvest touches over any challenge.
- Signature counters are 0 on most platform authenticators. Do not use them.
- Firefox and Safari extension origins very likely cannot make platform credentials for
  themselves; those devices are `uv: null`, which is fine.
- Registration publishes the raw P-256 point, which the registering device extracts from
  its own attestation object, so no verifier parses CBOR.

## 5. Registration

### 5.1 Possession, uniqueness, and where it is recorded

- A device registers its UV key as it joins (COSIGN.md §7.1), or later by `uv_replace`
  (§11), with `{ kind, pub, attestation? }` **and an assertion over the `register`
  statement of §3.1** — proof that it holds the key it is registering. The first draft
  registered unattested keys with no signature at all.
- A verifier MUST refuse a `uv.pub` already registered to any member of this account.
- The entry enters the **signed member record** (progressive-accounts.md §4.1). A verifier
  MUST NOT take it, or change it, from a server's `members` message.

### 5.2 What an Android attestation must actually be checked for

A verifier that records `attested: true` MUST check all of:

- the certificate chain to a known hardware attestation root, **and the current revocation
  list**, re-checked periodically rather than once;
- the attestation challenge, bound to this registration, so the chain is fresh;
- `origin = GENERATED` — an imported key was outside the chip, so its owner knows it;
- `attestationApplicationId`: the package name **and the signing-certificate digest**. This
  is the only field that answers "is this the real app, not a repackaged one";
- `noAuthRequired` absent, `userAuthType` and `authTimeout` exactly as §4.1 requires, and
  purpose SIGN only;
- the security level (TEE or StrongBox), preferring StrongBox and RKP-provisioned chains
  (Android 12+, short-lived Google-issued certificates, much harder to forge with a leaked
  keybox);
- boot state: accept `VERIFIED`, and `SELF_SIGNED` when `deviceLocked` is true — this
  project's users run their own builds — and treat `UNVERIFIED` as `attested: false`.

**Attestation raises cost; it is not proof against root.** Leaked OEM keyboxes are used to
forge chains that claim TEE and per-use authentication, and some stay unrevoked for months.
That is why §8 pairs an attested instant add with §9's notices, and why §12.2 says what
remains open.

### 5.3 Every verifier computes `attested` for itself

- A verifier keeps the chain and computes the flag itself. A published flag is a **display
  hint** and MUST NOT be the basis of a decision: three operators with different roots and
  revocation lists will disagree, and the flag would otherwise live in a list servers write.
- Devices verify Android attestations themselves (an X.509 chain plus the KeyDescription
  extension; Google publishes a reference verifier). Without this, a two-device account has
  no verifier at all, and §8's policy would be empty exactly where the proposal is aimed.
- A chain a verifier cannot check is not a failed join. The device joins with
  `attested: false`.

## 6. The actions

| Action | What it authorises | Assertion |
|---|---|---|
| `vouch` | **every repair that creates or enlarges a share-holding member**: a device, a server, a paper, or `grow` | MUST, **or the wait** |
| `export` | taking the account out, the escape hatch, removing the servers' pieces | MUST, **or the wait** |
| `approve` | a destructive event (COSIGN.md §5.3) | SHOULD, from a device that has a UV key |
| `register` | registering or replacing this device's own UV key | MUST (§5.1, §11) |
| `cancel` | cancelling a wait, or a paper recovery | §7.2 |
| `remove` | reporting a device lost | never required (§7.1) |
| `paper` (using it) | recovery with the paper and no surviving device | **not required** (§7.3) |

**"MUST, or the wait" means no path ends in a refusal.** A missing or unverifiable
assertion never blocks an action the user is entitled to; it costs the instant path and
falls back to COSIGN.md §7.4's wait, which every other member enforces and any device can
cancel. A member that *has* a registered UV key and sends a granting message **without** an
assertion gets the wait — never the old `lock: true` path. Every verifier checks this.

Making a paper is a `vouch`: today's servers hand its 2 shares to whatever key the device
names, on the device's word, which with the device's own 3 is the whole key.

## 7. Taking authority away

The first draft's axis — fail closed for granting, fail open for revoking — was wrong.
Removing another device and cancelling a recovery do not merely stop the bleeding: they
decide who controls the account. A thief reports every other device lost, then cancels each
recovery the owner starts, and the owner can never get back in.

### 7.1 Reporting a device lost stays free, and mutual reports take both out

- `remove` MUST NOT require an assertion. A dead fingerprint reader, a just-invalidated key
  or a borrowed phone cannot be what stops someone protecting themselves.
- A device that has been reported lost keeps, for a window (reference: 7 days),
  **revoke-only rights**: it may report *its remover* lost, and cancel a wait or a recovery.
  It may not sign, decrypt, vouch, deal or help a repair.
- **Two devices that report each other are both out.** The account falls to the remaining
  holders or the paper. A thief can then deny service; it can never take over by reporting
  first.

### 7.2 Cancelling

- Cancelling a wait or a recovery MUST carry a `cancel` assertion from a device that has a
  UV key — of any age, a just-replaced key included, so it is never a lockout. A device with
  `uv: null` cancels on its claimed lock, as today.
- A device under a pending report cannot be the only canceller.

### 7.3 While a recovery is pending

No member may `vouch` or `export`, or add a server or paper, instantly while a paper
recovery is pending: neither side of a contest may escalate during it. `paper` itself
carries no assertion — the whole case is that no device survives, so there is no registered
key to check; a key made on the spot would prove nothing, and requiring one would mean the
last-resort recovery never works. Its protection is the wait, the notices, and §7.1.

The recovered device registers a new UV key with `since = now`.

## 8. When an add is instant

- **Instant `vouch` and `export` require `attested: true` as this verifier computed it,
  and `synced: false`.** Anything else is the wait. This is the stricter of the two options
  the first draft offered, and it is the only one that stops a tampered app registering a
  key it made up and then vouching for itself at will.
- An unattested or synced key still counts for `approve`, for `cancel` (§7.2), and as
  evidence in the log. Its vouches are the wait.
- **Taking part in a repair is never vouching.** COSIGN.md §7.1's "two member devices vouch"
  means **two assertions**, one from each device, over the same `vouch` body. A helper that
  contributes shares without asking its user has helped, not vouched.
- **Rollout.** An account becomes UV-required only when every one of its always-on members
  advertises support; until then the old rule holds and the client says nothing. A verifier
  that did not see its own challenge in an assertion it checked itself treats the new member
  as **pending**: it will not co-sign with it, or help anything involving it, until the wait
  has passed.
- No path where `attested: true` skips a notice (§9).

## 9. What the user sees

A per-use key signs whatever bytes the app passes after the user authenticates, and the
prompt's wording belongs to the app. A hooked app can show "Confirm it's you" for something
innocuous and spend that touch on a `vouch`. Nothing in the protocol can bind a signature to
what the user saw; what it can do is make the touch rare and the outcome loud.

- The UV prompt MUST be shown **only** for granting actions, with fixed wording that names
  the action and the newcomer: *"Add Pixel 7 (code 4-81) to your account"*. The newcomer
  shows the same short code, derived from its `E.pub`, so the two can be compared.
- A client SHOULD teach this once: a fingerprint here always means adding something or
  taking the key out.
- After every instant add, every member MUST show, and be woken for, *"Phone added Pixel 7.
  Not you? Report it."*
- A new member is on probation (progressive-accounts.md §11): it may sign, and may not
  vouch, help a repair, report another member lost, deal a refresh or cancel anything, for
  a window (reference: 72 h).

## 10. When a platform cannot do it

COSIGN.md §7.1 already says what happens, and this keeps it: *a device without one counts
as vouching without its lock, so the wait applies.*

- `uv: null`, or a missing or bad assertion, means the wait — not a refusal, and not the
  old claimed-lock path for a device that has a key (§6).
- An account where no device has a UV key behaves exactly as accounts do today: no stage, no
  badge, no nagging. A client MAY show in settings that a device's lock is hardware-backed,
  as a fact about the device rather than a score.
- At progressive-accounts §3.1 and §3.2 the whole key is on one device and UV protects
  nothing; a client MUST NOT present it there as protection.
- Guests hold no UV key and are never verifiers. A guest's request may lead to an `approve`
  assertion with the event as its body, and never to a `vouch`.
- In a two-device account the helper device is the verifier and the wait-keeper: it issues
  the challenge and MUST keep the pending add across restarts until the wait ends.

## 11. When the key dies

UV keys are meant to die: a new or removed fingerprint invalidates them, removing the screen
lock invalidates them, a factory reset takes them, and a WebAuthn credential goes with its
browser profile.

- **Losing one MUST cost nothing but proof.** The device goes on signing, reading, following
  refreshes, reporting another device lost and cancelling. What it loses is the instant path.
- Replacement is `uv_replace`, carrying `{ kind, pub, attestation? }` and a `register`
  assertion (§5.1). Members replace the entry in the signed record and set `since = now`.
- **A replacement MUST be of the same kind or stronger to keep standing**, and the order is:
  attested StrongBox > attested TEE > attested other > unattested hardware claim. Replacing
  an attested key with an unattested one is itself **a wait**, cancellable, because
  `kind` is self-declared and a tampered app's first move is a downgrade. Replacing to
  `null` is not a replacement; that is removing the device.
- Where the old key still works — a voluntary rotation — the request MUST also carry an
  assertion **by the old key** over the new one.
- **The youth rule is a MUST, not a MAY:** a key younger than 24 h MUST NOT make an instant
  `vouch` or `export`. A PIN-knowing thief can enrol a finger, which invalidates the old key,
  and register a genuine attested key of their own; the day's delay and the notice are what
  stand between that and the account.
- Every member MUST be told: *"Phone's lock changed. If you didn't add a fingerprint or
  reset it, report it lost."*
- **A removed device's UV key is burned**: never accepted again, for any member, in this
  account. A device that re-joins is a new member with `since = now`. The first draft's
  "re-joining with the same key is the same member" is deleted.

## 12. Threat model

1. **A tampered or hooked app on the user's own device.** The threat this exists for. With
   an attested per-use key it cannot vouch without a touch at that moment. §8 is what makes
   that true: with the first draft's policy it would simply have registered its own key.
   It can still spend one touch the user gives for something else (§9), so the mechanism
   raises the cost from zero touches to one and makes the result loud.
2. **Forged attestation.** Leaked keyboxes exist and §5.2's list is the mitigation, not a
   cure. Attestation only ever upgrades an add from wait to instant, and a registration
   still needs a member to vouch first, so a forgery buys speed rather than authority.
3. **A stolen unlocked device.** A per-use key is strictly better than today: "unlocked" is
   no longer enough. A watched PIN is answered by §4.1's biometric-only rule for granting
   actions, and by §11's youth rule when the thief enrols their own finger.
4. **Collecting an assertion for one action and spending it on another.** Closed by the
   action and body binding (§3) and the verifier's own challenge.
5. **Replay between verifiers.** Closed by the asserter and the per-verifier challenge
   lines (§3), which also give one touch for all of them.
6. **The laxest server.** Closed by §8's rollout rule: a verifier that did not see its own
   challenge treats the member as pending.
7. **A server rewriting `uv` or `attested`.** Closed by §2 and §5.3: the entry lives in the
   signed member record and every verifier computes the flag itself.
8. **Downgrade by suppression.** A missing assertion is the wait, never the old path, and
   the wait is enforced by members other than the one vouching.
9. **Downgrade by replacement.** §11: same kind or stronger, a wait otherwise, the youth
   rule, notices, and the old key signing over the new one when it can.
10. **Synced passkeys.** A credential the platform can move is not a device key: `synced`
    is read from the BE flag and never makes an instant add (§4.3).
11. **Lockout.** The failure this mechanism could cause. With §6's "or the wait", §7.1's
    free `remove`, §7.3's assertion-free `paper` and §11's "costs nothing but proof", there is
    no path where a dead reader, a new fingerprint, a PIN-only phone, a reset or losing every
    device leaves the user unable to act. That is the property most worth attacking again.
12. **What it does not do.** A compromised OS can still sign everyday events, read DMs and
    connect sites — the accepted baseline, which an nsec on a phone already allows. The UV
    key guards only the growing of power.

## 13. What it would change in COSIGN.md

- **§3**: the member record gains `uv: { kind, pub, attested, synced, since }`, in the
  signed record of progressive-accounts.md §4.1.
- **§7.1**: "Today the lock is a claim the device makes" is replaced by §§2–6; "two devices
  vouch" is defined as two assertions; taking part in a repair is not vouching.
- **§7.2**: `remove` is never gated, and mutual reports take both devices out (§7.1).
- **§7.4**: a wait means the newcomer gets no pieces until it ends; cancelling carries an
  assertion where the device has a key.
- **§8.3**: using the paper carries no assertion, and nothing may escalate while a recovery
  is pending.
- **§11**: `UV_CHALLENGE`, `UV_ASSERTION`, `UV_REGISTER`, `UV_REPLACE`.
- **§12**: "the device lock is a claim" becomes "a granting action carries a signature every
  verifier checks, where the platform can produce one".

## 14. Build order, if it is agreed

1. **Android**, where it is free and where most of the threat is: generate the key, register
   it with possession and attestation, verify assertions in the servers **and on devices**
   (§5.3), and move the vouching prompt to `BiometricPrompt` with a crypto object. Pin the
   exact signed bytes and publish test vectors — Android signs the statement bytes with
   `SHA256withECDSA`, WebAuthn signs its own envelope over `SHA-256(statement)` — because a
   mismatch here refuses honest users.
2. **The extension**, via WebAuthn, which also gives the Mac a UV key with no Apple
   certificate (§4.2).
3. **The Tauri Mac**, once there is a certificate, or once CryptoKit in an ad-hoc-signed
   build is shown to work.

None of it needs new cryptography or an epoch change. All of it needs the signed member
record of progressive-accounts.md §4.1 first: a `uv` entry in a list servers can write is
not evidence of anything.
