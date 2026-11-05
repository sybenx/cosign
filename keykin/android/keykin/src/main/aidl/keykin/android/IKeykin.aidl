package keykin.android;

import keykin.android.IKeykinClient;

/**
 * The signer process, as the main process sees it (KeykinService). What goes in is a slot, a code or a
 * string; what comes out is a result or public state. No call hands back a share, a secret key, the data
 * key or a seed.
 */
interface IKeykin {
    /** Send [client] every membership's state now, and again whenever it changes. */
    void listen(IKeykinClient client);
    /** A new slot for a membership; its state follows. */
    String add();
    /** Join by an invite code over [relays] (comma-separated); the check digits arrive in the slot's state. */
    oneway void join(String slot, String code, String relays);
    /** Sign the app's own event (JSON without id, pubkey, sig): {"event": …} or {"error": code}. */
    String signOwn(String slot, String event);
    /** NIP-44 with the account itself (to-self data) for content of an event of `kind`: the other side is always
     *  this account, and only for the kinds the app declares in its manifest (meta-data `keykin.ownKinds`, a
     *  comma-separated list; absent: NIP-51 lists and NIP-78 app data, never NIP-60 wallet kinds). This reads every
     *  to-self payload of those kinds, so the app calls it only for its own data. Null on failure or refusal. */
    String nip44Own(String slot, int kind, String text, boolean encrypt);
    /** Catch up with every server (changes, inbox); the state follows. */
    oneway void fetch(String slot);
    /** Catch up and answer with the slot's fresh state (JSON, as the listener's), waiting up to a minute: what a
     *  screen that lists or acts on the devices shows first. {"error": code} on failure. A slot still opening is sent
     *  to listeners as {"slot", "opening": true} at once. */
    String refresh(String slot);
    /** Invite a device from this phone (core §4.1): {"invite": code} to show as a QR, over `relaysCsv` (empty: the
     *  slot's relays). The slot's state carries "invite": {"status": "waiting" | "typed" | "mismatch"}. */
    String invite(String slot, String relaysCsv);
    /** The person typed the new device's 6 digits: true if they match. Then the app starts KeykinApprove with action
     *  "add_invited" (KeykinClient.approve), where the person approves the add with the lock or the paper. */
    boolean inviteTyped(String slot, String digits);
    /** The other direction: this phone scanned the new device's hello code (the extension shows one as a QR). The
     *  offer goes, the hello comes back; the new device then shows the 6 digits, typed here with `inviteTyped`, and the
     *  add is approved on KeykinApprove ("add_invited") as for an invite. {"ok": true} or {"error": code}. */
    String inviteScanned(String slot, String helloCode);
    /** The membership's end on this phone: its sealed state and key go. */
    oneway void forget(String slot);

    /** Every live grant on the account (Doors §1–§2), from every device, for listing: JSON
     *  [{by, id, says, site, door, connection, scopes, made, last_used}]. Public data only. */
    String grants(String slot);
    /** Sign one out, anywhere: an own one ends here, another device's gets a tombstone, published and delivered to
     *  its home with an `ask` push (a helper grant's to the helper) (Doors §2). */
    oneway void endGrant(String slot, String by, String id);

    /** Pair requests this phone was asked to approve (core §6.2): JSON [{id, from, list, expiry}]. */
    String pairAsks(String slot);
    /** The person typed `code` for pair request `id`: true if it matched and this phone signed. */
    boolean pairApprove(String slot, String id, String code);
    /** Remove device `key` with a pair: asks device `with` and returns the 6-digit code to show; once the person
     *  typed it there, the list is dealt and submitted, and the slot's state says how it went ("pair"). */
    String removeWithPair(String slot, String key, String with);

    /** "Sign out of every site" (Doors §1): every own grant ends, and every other home, the helper included, gets a
     *  wildcard for every grant it made before now. */
    oneway void signOutEverywhere(String slot);
    /** The person took back a vault app's grant, or a "Don't allow" (Doors 20 §3.7): the slot's state lists them as
     *  "vault_apps" and "vault_declined". Granting is only ever on the signer process's own screen. */
    oneway void revokeVaultApp(String slot, String app);
    /** "Let the helper answer for this site" (Helper module §2): the bunker:// link the helper minted, or null. */
    String helperSite(String slot, String site, String relaysCsv);

    // --- Device policy (§2, §3, §6): what the person answers. The slot's state carries "cards" ({id, site, row,
    // reason, media?}), "undos" ({id, site}: a deletion waiting its 10 seconds) and "held" (events held for the lock
    // or a 3-day hold: {id, signer, site, kind, content, at, wait}).
    /** The person's answer to a card: Allow or Decline (a decline counts towards §6's auto-declines). */
    oneway void answerCard(String slot, int id, boolean allow);
    /** Undo a deletion still waiting its 10 seconds (and its twins from that site); a decline of that site. */
    oneway void undoPending(String slot, int id);
    /** Undo a list or the profile to an earlier version (§3): {"event": …}, {"needs": "confirm"|"held"}, or {"error"}. */
    String undoTo(String slot, String versionId, boolean confirmed);
    /** Undo everything a site did since it connected (§3): {"lists": [...], "posts": [ids offered for deletion]}. */
    String undoSite(String slot, String owner, boolean confirmed);
    /** "Post again" (§3): a deleted post's content as a new event: {"event": …} or {"error"}. */
    String postAgain(String slot, String id);
    /** Lockless: start a 3-day hold at every server for held event `id`: {"wait": …} or {"error"}. With a lock the
     *  app approves it from a signer-process activity instead (LockPrompt.approveSign, then approveHeld there). */
    String holdHeld(String slot, String id);
    /** Sign a held event once its hold's wait has passed: {"event": …} or {"error"}. */
    String releaseHeld(String slot, String id);
    /** The person declined a held event (a decline of that site). */
    oneway void declineHeld(String slot, String id);

    // --- the NIP-46 home on this phone (Doors §3.3): the slot's state carries "sites" asks ({signer, scopes}).
    /** A bunker:// link for a site, over these relays, offering these scopes (comma-separated); null on failure. */
    String bunker(String slot, String relaysCsv, String scopesCsv);
    /** Connect a scanned nostrconnect:// code: the new grant's signer key, or null. */
    String nostrconnect(String slot, String uri, String scopesCsv);
    /** The person allowed `scope` for a site (asked the first time it was needed). */
    oneway void allowScope(String slot, String signer, String scope);

    // --- UnifiedPush, forwarded by the app's receiver (core §8.2): one instance per server and wake class.
    /** The UnifiedPush instances to register, as JSON ["<server>:<cls>", ...]. */
    String pushInstances(String slot);
    /** UnifiedPush gave `endpoint` for `instance`; once every instance has one, the device registers them. */
    oneway void pushEndpoint(String slot, String instance, String endpoint);
    /** A UnifiedPush message for `instance`: decrypted and checked, a carried delivery taken, a wake. */
    oneway void pushMessage(String slot, String instance, in byte[] body);
}
