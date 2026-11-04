// One Keykin membership on the phone, in the signer process: loaded from its sealed state, saved after every
// change, joined by an invite code (with the phone's lock when it has a strong biometric), woken by the app's
// UnifiedPush. The app owns the UnifiedPush receiver (as Marble does for Cosign) and hands this class the
// endpoints and messages; it draws nothing. Removed by the others, it destroys its state and its key (§7.3).
package keykin.android

import android.content.Context
import keykin.Device
import keykin.KeykinException
import keykin.RelayNet
import org.json.JSONObject

class KeykinSigner(private val context: Context, val name: String = "default") {
    private val store = SealedStore(context, name)
    private val extra = NoBackup(context, "signer-$name")
    @Volatile private var net: RelayNet? = null
    @Volatile var device: Device? = null; private set
    /** Called once when the others removed this device and its state is gone. */
    @Volatile var onRemoved: (() -> Unit)? = null
    private val lockAlias = "keykin-lock-$name"
    init { KeykinAndroid.init(); Proc.signerOnly("KeykinSigner") }

    private fun netFor(relays: List<String>) = net ?: RelayNet(relays, wire = KeykinAndroid.wire).connect().also { net = it }
    private fun adopt(d: Device): Device {
        // A wipe (this device removed) stores nothing: the sealed state and its key go (core §7.3, review 15 M7).
        d.persist = { s -> if (JSONObject(s).optBoolean("wiped")) store.destroy() else store.save(s) }
        d.onGone { store.destroy(); onRemoved?.invoke() }
        if (!d.wiped) store.save(d.snapshot())
        device = d; return d
    }
    /** The stored membership, if any, over `relays`. Throws if it is there but can't be opened: the caller keeps
     *  the error, and nothing overwrites the stored shares. */
    fun open(relays: List<String>): Device? = device ?: store.load()?.let { s ->
        adopt(Device.fromSnapshot(s, netFor(relays))).also { d -> if (KeystoreLock.exists(lockAlias)) d.lock = KeystoreLock.open(lockAlias) }
    }
    /** Join by an invite code (core §4.1–§4.2); `onCheck` shows the 6 digits the inviter types. With `withLock`
     *  and a strong biometric enrolled, the device joins with a Keystore lock (§6.1); a passcode-only phone joins
     *  lockless. Refuses on a slot that holds a membership already. Blocks: call it off the main thread. */
    fun join(code: String, relays: List<String>, withLock: Boolean = true, onCheck: (String) -> Unit): Device {
        if (device != null || store.exists()) throw KeykinException("already_joined", "this slot holds a membership")
        val lock = if (withLock) try { KeystoreLock.open(lockAlias) } catch (_: Exception) { null } else null
        return try { adopt(Device.join(code, netFor(relays), onCheck, lock = lock)) }
        catch (e: Exception) { if (lock != null) KeystoreLock.destroy(lockAlias); throw e }
    }

    /** UnifiedPush gave the app `endpoint` for `instance` ("<server>:<cls>", one per server and wake class). */
    fun onEndpoint(instance: String, endpoint: String) = extra.update { it.put("endpoints", (it.optJSONObject("endpoints") ?: JSONObject()).put(instance, endpoint)) }
    private fun endpoint(instance: String): String? = extra.get().optJSONObject("endpoints")?.optString(instance)?.ifEmpty { null }
    /** Register this device's push addresses with every server, once the app holds an endpoint for each instance
     *  (`instances()` says which to ask UnifiedPush for). Returns how many servers took them. */
    fun registerPush(): Int {
        val d = device ?: return 0
        if (instances().any { endpoint(it) == null }) return 0
        return d.registerPush { server, cls -> endpoint("$server:$cls")!! }
    }
    fun instances(): List<String> = device?.servers()?.flatMap { s -> listOf("sign", "ask", "notice").map { "${s.key}:$it" } } ?: emptyList()
    /** A UnifiedPush message for `instance`: decrypted and checked, a carried delivery taken, then a fetch. */
    fun onMessage(instance: String, body: ByteArray): JSONObject? {
        val d = device ?: return null
        val p = d.onPush(endpoint(instance) ?: return null, body) ?: return null
        if (!p.has("wrap")) d.fetch()
        return p
    }
    /** The membership's end on this phone: the sealed state, its key, the lock and the relays go (core §7.3). */
    fun forget() {
        device?.wipe(); device = null; store.destroy(); KeystoreLock.destroy(lockAlias)
        extra.update { for (k in it.keys().asSequence().toList()) it.remove(k) }
        net?.close(); net = null
    }
}
