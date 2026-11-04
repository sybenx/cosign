// One Keykin membership on the phone, in the signer process: loaded from its sealed state, saved after every
// change, joined by an invite code, woken by the app's UnifiedPush. The app owns the UnifiedPush receiver (as
// Marble does for Cosign) and hands this class the endpoints and messages; it draws nothing.
package keykin.android

import android.content.Context
import keykin.Device
import keykin.KeykinException
import keykin.RelayNet
import org.json.JSONObject

class KeykinSigner(private val context: Context, val name: String = "default") {
    private val store = SealedStore(context, name)
    @Volatile private var net: RelayNet? = null
    @Volatile var device: Device? = null; private set
    init { KeykinAndroid.init(); Proc.signerOnly("KeykinSigner") }

    private fun netFor(relays: List<String>) = net ?: RelayNet(relays, wire = KeykinAndroid.wire).connect().also { net = it }
    private fun adopt(d: Device): Device { d.persist = { store.save(it) }; store.save(d.snapshot()); device = d; return d }

    /** The stored membership, if any, over `relays` (the account's own once known; the app's defaults before). */
    fun open(relays: List<String>): Device? = device ?: store.load()?.let { s ->
        try { adopt(Device.fromSnapshot(s, netFor(relays))) } catch (e: KeykinException) { if (e.code == "malformed") null else throw e }
    }
    /** Join by an invite code (core §4.1–§4.2); `onCheck` shows the 6 digits the inviter types. Blocks until the
     *  welcome is checked: call it off the main thread. */
    fun join(code: String, relays: List<String>, onCheck: (String) -> Unit): Device = adopt(Device.join(code, netFor(relays), onCheck))

    /** UnifiedPush gave the app `endpoint` for `instance` ("<server>:<cls>", one per server and wake class). */
    // Kept across restarts (endpoints aren't secret; the address keys are in the sealed device state).
    private val prefs = context.getSharedPreferences("keykin-push-$name", Context.MODE_PRIVATE)
    private val endpoints = HashMap<String, String>(prefs.all.mapNotNull { (k, v) -> (v as? String)?.let { k to it } }.toMap())
    fun onEndpoint(instance: String, endpoint: String) { synchronized(endpoints) { endpoints[instance] = endpoint; prefs.edit().putString(instance, endpoint).apply() } }
    /** Register this device's push addresses with every server, once the app holds an endpoint for each instance
     *  (`instances()` says which to ask UnifiedPush for). Returns how many servers took them. */
    fun registerPush(): Int {
        val d = device ?: return 0
        val missing = instances().filter { synchronized(endpoints) { it !in endpoints } }
        if (missing.isNotEmpty()) return 0
        return d.registerPush { server, cls -> synchronized(endpoints) { endpoints["$server:$cls"]!! } }
    }
    fun instances(): List<String> = device?.servers()?.flatMap { s -> listOf("sign", "ask", "notice").map { "${s.key}:$it" } } ?: emptyList()
    /** A UnifiedPush message for `instance`: decrypted and checked, a carried delivery taken, then a fetch. */
    fun onMessage(instance: String, body: ByteArray): JSONObject? {
        val d = device ?: return null
        val url = synchronized(endpoints) { endpoints[instance] } ?: return null
        val p = d.onPush(url, body) ?: return null
        if (!p.has("wrap")) d.fetch()
        return p
    }
    /** The membership's end on this phone: the sealed state and its key go (core §7.3). */
    fun forget() { device?.wipe(); device = null; store.destroy(); synchronized(endpoints) { endpoints.clear(); prefs.edit().clear().apply() } }
}
