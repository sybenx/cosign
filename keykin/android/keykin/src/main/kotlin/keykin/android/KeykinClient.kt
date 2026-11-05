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
    /** The signer, once bound (a call made from a background thread may wait for it). */
    fun signer(timeoutS: Long = 10): IKeykin = bound.get(timeoutS, TimeUnit.SECONDS)
}
