// The signer process's door, and its only one for the main process (bound, not exported), as Cosign's
// SignerService: memberships by slot, each a KeykinSigner; calls run on one background thread in order; each
// membership's state goes out as public JSON (stateOf), never a share, a key or a seed.
package keykin.android

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.RemoteCallbackList
import android.util.Log
import keykin.Doors
import keykin.KeykinException
import keykin.Nip44
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.Executors

class KeykinService : Service() {
    private val clients = RemoteCallbackList<IKeykinClient>()
    /** Every call that touches a membership runs here, in order; every message to the UI goes out from `out`. */
    private val work = Executors.newSingleThreadExecutor { r -> Thread(r, "keykin-signer").also { it.isDaemon = true } }
    private val out = Executors.newSingleThreadExecutor()
    /** What the UI shows while a join runs, by slot (the check digits, an error). */
    private val joining = HashMap<String, JSONObject>()

    override fun onCreate() {
        super.onCreate()
        Proc.signerOnly("KeykinService")
        Memberships.init(this)
        work.execute { for (slot in slots()) open(slot) }
    }
    override fun onDestroy() { clients.kill(); work.shutdown(); out.shutdown(); super.onDestroy() }
    override fun onBind(intent: Intent?): IBinder = binder

    private fun slots() = Memberships.slots()
    private fun open(slot: String): KeykinSigner = Memberships.signer(slot)

    /** One membership's public state: its device key, the account, the state it is at, the devices, notices. */
    private fun stateOf(slot: String): JSONObject {
        val x = JSONObject().put("slot", slot)
        joining[slot]?.let { j -> for (k in j.keys()) x.put(k, j.get(k)) }
        val d = Memberships.signer(slot).device ?: return x.put("joined", false)
        val (self, asOf, keys) = d.members.devices()
        return x.put("joined", true).put("device", self).put("account", d.g).put("state", asOf).put("wiped", d.wiped)
            .put("devices", JSONArray(keys.map { JSONObject().put("key", it.key).put("flagged", it.flagged) }))
            .put("removed", JSONArray(d.members.removed(0).map { it.json() })).put("notices", JSONArray(d.notices.toList()))
    }
    private fun send(f: (IKeykinClient) -> Unit) = out.execute {
        val n = clients.beginBroadcast()
        try { for (i in 0 until n) try { f(clients.getBroadcastItem(i)) } catch (e: Exception) { Log.w(TAG, "client: $e") } } finally { clients.finishBroadcast() }
    }
    private fun publish(slot: String) { val s = stateOf(slot).toString(); send { it.state(slot, s) } }
    private fun <T> onWork(f: () -> T): T = work.submit(f).get()

    private val binder = object : IKeykin.Stub() {
        override fun listen(client: IKeykinClient) {
            clients.register(client)
            work.execute { val ss = slots(); send { it.slots(ss.toTypedArray()) }; for (s in ss) publish(s) }
        }
        override fun add(): String = onWork {
            val slot = Memberships.addSlot(); val ss = slots(); send { it.slots(ss.toTypedArray()) }
            slot
        }
        override fun join(slot: String, code: String, relays: String) = work.execute {
            val rs = relays.split(",").filter { it.isNotBlank() }
            Memberships.setRelays(slot, rs)
            joining[slot] = JSONObject().put("joining", true); publish(slot)
            try {
                open(slot).join(code, rs) { check -> joining[slot] = JSONObject().put("joining", true).put("check", check); publish(slot) }
                joining.remove(slot)
            } catch (e: KeykinException) { joining[slot] = JSONObject().put("error", e.code) } catch (e: Exception) { joining[slot] = JSONObject().put("error", "internal") }
            publish(slot)
        }
        override fun signOwn(slot: String, event: String): String = onWork {
            try {
                val d = Memberships.signer(slot).device ?: throw KeykinException("no_membership")
                val e = JSONObject(event)
                val kind = e.getInt("kind"); val tags = e.optJSONArray("tags")?.let { a -> (0 until a.length()).map { i -> a.getJSONArray(i).let { t -> (0 until t.length()).map { t.getString(it) } } } } ?: emptyList()
                // The main process draws strangers' content: its events pass the same guard a site's do (Doors §2).
                Doors.siteGuard(d, kind, tags)
                JSONObject().put("event", d.sign(kind, e.optString("content"), tags, e.optLong("created_at", System.currentTimeMillis() / 1000))).toString()
            } catch (x: KeykinException) { JSONObject().put("error", x.code).toString() } catch (x: Exception) { JSONObject().put("error", "malformed").toString() }
        }
        override fun nip44Own(slot: String, text: String, encrypt: Boolean): String? = onWork {
            try { Memberships.signer(slot).device?.let { d -> d.nip44(d.g, text, encrypt) } } catch (_: Exception) { null }
        }
        override fun fetch(slot: String) = work.execute { try { Memberships.signer(slot).device?.fetch() } catch (e: Exception) { Log.w(TAG, "fetch: $e") }; publish(slot) }
        override fun forget(slot: String) = work.execute {
            Memberships.forget(slot); joining.remove(slot)
            val ss = slots(); send { it.slots(ss.toTypedArray()) }
        }
    }
    companion object { private const val TAG = "KeykinService" }
}
