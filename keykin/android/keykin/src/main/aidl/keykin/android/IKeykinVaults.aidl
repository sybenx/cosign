// The door for vault apps on the same phone (Doors 20 §3.7): exported from the signer process, answered only for an
// app the person granted all three open vault domains (one question for the set), and only the narrow vault calls,
// never a general encrypt. The app is who Android says is calling (its package and signing certificate). Every call
// answers JSON: {"result": …} or {"error": "<code>: <why>"}. Bytes are lowercase hex.
package keykin.android;

import android.app.PendingIntent;

interface IKeykinVaults {
    /** The accounts (npub hex) this app was granted on this phone, as JSON ["<g>", ...]. */
    String accounts();
    /** The one question for the set, as a screen the app starts ("Let Notes use all your vaults, in every app, on
     *  this device?"), for the account `account`, or any account on the phone when it is empty. */
    PendingIntent askGrant(String account);
    /** {"mk", "ksig"}: the device's member key and its signature over nostr-vault/ksig/1 and the root's 32 bytes. */
    String ksig(String account, String rootHex);
    /** {"key"}: dataKeys.derive under nostr-vault/owner/1 or nostr-vault/keyring/1, for `idsJson` (sorted redeal ids). */
    String derive(String account, String idsJson, String domain, String bytesHex);
    /** {"ids", "state"}: the state to write under. */
    String current(String account);
    /** [{"ids", "state"}, ...]: the states this device has held, newest first. */
    String states(String account);
    /** A signed kind 4810, 4811 or 30811; a kind 5 only of those, by the account, through Device policy. */
    String sign(String account, String eventJson);
    /** A kind-1059 gift wrap of the kind-4812 rumor `rumorJson` (by the account, unsigned), sealed by the account. */
    String invite(String account, String rumorJson, String recipient);
    /** {"rumor", "seal"}: a gift wrap's kind-4812 rumor whose seal signer is its pubkey, and that pubkey. */
    String unwrap(String account, String wrapJson);
    /** {"plain"}: NIP-44 as the account with `peer`, only when the plaintext is a vault payload. */
    String decrypt(String account, String peer, String payload);
}
