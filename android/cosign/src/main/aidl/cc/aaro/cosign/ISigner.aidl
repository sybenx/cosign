package cc.aaro.cosign;

import cc.aaro.cosign.ISignerClient;

/**
 * The signer process, as the main process sees it (SignerService). Everything that goes in
 * is a slot, a word or a string; everything that comes out is a result or public state.
 * No call hands back a share, a secret key or a paper backup's code.
 */
interface ISigner {
    /** Send [client] every account's state now, and again whenever it changes. */
    void listen(ISignerClient client);

    /** One of the UI's actions on an account (SignerService.act lists them all). */
    oneway void act(String slot, String action, String text, boolean flag);

    /** "I already have an account": the nsec typed in, as characters, wiped once read. */
    oneway void importKey(String slot, in char[] secret);

    /** Sign the app's own event (a like, a follow, a reply, a mute): "event", or "approval" (what needs you), or "error". */
    Bundle signOwn(String slot, String event, boolean approved);

    /**
     * Encrypt or decrypt the app's own data with the account itself (NIP-44 to self, for
     * NIP-78 app data). The other side is always this account's own key: no peer goes in,
     * so this can never read anyone else's messages. Null if it couldn't be done.
     */
    String nip44Own(String slot, String text, boolean encrypt);

    /** The newest signed version of one of your lists ("3": follows), as JSON, or null. */
    String latest(String slot, String key);

    /** A place for another account, shown: its slot. */
    String add();
    oneway void show(String slot);
    oneway void forget(String slot);
}
