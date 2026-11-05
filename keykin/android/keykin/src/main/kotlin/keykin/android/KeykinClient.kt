// The main process's side of KeykinService (as Cosign's SignerClient): it binds the signer, hears each
// membership's public state, and passes the app's calls through. It never holds key material.
package keykin.android

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import org.json.JSONObject
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit

class KeykinClient(private val context: Context) {
    interface Listener { fun slots(slots: List<String>) {}; fun state(slot: String, state: JSONObject) {} }
    private val listeners = CopyOnWriteArrayList<Listener>()
    /** The signer as last bound: replaced when its process died and Android bound it again (review 15 M5). */
    @Volatile private var bound = CompletableFuture<IKeykin>()
    @Volatile var states: Map<String, JSONObject> = emptyMap(); private set

    private val callback = object : IKeykinClient.Stub() {
        override fun slots(slots: Array<out String>) { val l = slots.toList(); listeners.forEach { it.slots(l) } }
        override fun state(slot: String, json: String) { val s = JSONObject(json); states = states + (slot to s); listeners.forEach { it.state(slot, s) } }
    }
    private val conn = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder) {
            val k = IKeykin.Stub.asInterface(service); k.listen(callback)
            if (!bound.complete(k)) bound = CompletableFuture.completedFuture(k)
        }
        // The signer process died: calls wait for the new binding (BIND_AUTO_CREATE restarts it).
        override fun onServiceDisconnected(name: ComponentName?) { bound = CompletableFuture() }
        override fun onBindingDied(name: ComponentName?) { bound = CompletableFuture(); unbind(); bind() }
    }
    fun bind(): KeykinClient { context.bindService(Intent(context, KeykinService::class.java), conn, Context.BIND_AUTO_CREATE); return this }
    fun unbind() { try { context.unbindService(conn) } catch (_: IllegalArgumentException) {} }
    fun listen(l: Listener) { listeners += l }
    /** Open the library's approval screen (KeykinApprove, in the signer process) for `action`: "report_lost" (key),
     *  "paper_check", "add_invited", "pair_approve" (id), "pair_remove" (key, with). The lock prompt or the paper's
     *  words stay in that process; the outcome arrives in the slot's state as "last_action". */
    /** Create a new account on this phone (KeykinApprove "create"): the account's `relays` and the three servers' front
     *  keys `fronts`; the paper is shown and checked on the library's screen only. Call `add()` first for the slot. */
    fun create(slot: String, relays: List<String>, fronts: List<String>) {
        context.startActivity(Intent(context, KeykinApprove::class.java).putExtra(KeykinApprove.SLOT, slot).putExtra(KeykinApprove.ACTION, "create")
            .putExtra(KeykinApprove.RELAYS, relays.joinToString(",")).putExtra(KeykinApprove.FRONTS, fronts.joinToString(","))
            .apply { if (context !is android.app.Activity) addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) })
    }
    fun approve(slot: String, action: String, key: String? = null, id: String? = null, with: String? = null) {
        require(action in KeykinApprove.ACTIONS) { "unknown action $action" }
        context.startActivity(Intent(context, KeykinApprove::class.java).putExtra(KeykinApprove.SLOT, slot).putExtra(KeykinApprove.ACTION, action)
            .apply { key?.let { putExtra(KeykinApprove.KEY, it) }; id?.let { putExtra(KeykinApprove.ID, it) }; with?.let { putExtra(KeykinApprove.WITH, it) }
                if (context !is android.app.Activity) addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) })
    }
    /** The signer, once bound (a call made from a background thread may wait for it). */
    fun signer(timeoutS: Long = 10): IKeykin = bound.get(timeoutS, TimeUnit.SECONDS)
}
