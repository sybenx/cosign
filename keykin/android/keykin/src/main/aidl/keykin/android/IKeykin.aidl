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
    /** The membership's end on this phone: its sealed state and key go. */
    oneway void forget(String slot);
}
