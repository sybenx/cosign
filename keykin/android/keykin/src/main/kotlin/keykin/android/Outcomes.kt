// What the person last did on a library screen (KeykinApprove), per membership, for the slot's public state
// ("last_action": {action, ok, detail?, key?, at}). Kept in the signer process; never words, codes or keys beyond a
// device key's prefix.
package keykin.android

import org.json.JSONObject

object Outcomes {
    private val last = HashMap<String, JSONObject>()
    /** KeykinService publishes the slot's state again whenever an outcome lands. */
    @Volatile var onChange: ((String) -> Unit)? = null
    fun put(slot: String, action: String, ok: Boolean, detail: String? = null, key: String? = null) {
        val o = JSONObject().put("action", action).put("ok", ok).put("at", System.currentTimeMillis() / 1000)
        detail?.let { o.put("detail", it.take(160)) }; key?.let { o.put("key", it.take(12)) }
        synchronized(this) { last[slot] = o }
        onChange?.invoke(slot)
    }
    fun get(slot: String): JSONObject? = synchronized(this) { last[slot]?.let { JSONObject(it.toString()) } }
}
