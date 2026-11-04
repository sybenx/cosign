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
    /** A join waits up to two minutes for the welcome: on its own thread, so other calls go on (review 15 L5). */
    private val joins = Executors.newSingleThreadExecutor { r -> Thread(r, "keykin-join").also { it.isDaemon = true } }
    /** What the UI shows while a join runs, by slot (the check digits, an error). */
    private val joining = HashMap<String, JSONObject>()

    override fun onCreate() {
        super.onCreate()
        Proc.signerOnly("KeykinService")
        Memberships.init(this)
        work.execute { for (slot in slots()) open(slot) }
    }
    override fun onDestroy() { clients.kill(); work.shutdown(); joins.shutdown(); out.shutdown(); super.onDestroy() }
    override fun onBind(intent: Intent?): IBinder = binder

    private fun slots() = Memberships.slots()
    private fun open(slot: String): KeykinSigner = Memberships.signer(slot)

    /** One membership's public state: its device key, the account, the state it is at, the devices, notices. */
    private fun stateOf(slot: String): JSONObject {
        val x = JSONObject().put("slot", slot)
        joining[slot]?.let { j -> for (k in j.keys()) x.put(k, j.get(k)) }
        Memberships.signer(slot)
        Memberships.openError(slot)?.let { x.put("open_error", it) }
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
    /** The kinds the app declares its own process reads of the account's to-self data (manifest meta-data
     *  `keykin.ownKinds`), read here in the signer process, so the main process can't widen them. */
    private val ownKinds: Set<Int>? by lazy {
        try { packageManager.getApplicationInfo(packageName, android.content.pm.PackageManager.GET_META_DATA).metaData?.getString("keykin.ownKinds")
            ?.split(",")?.mapNotNull { it.trim().toIntOrNull() }?.toSet() } catch (_: Exception) { null }
    }

    private val binder = object : IKeykin.Stub() {
        override fun listen(client: IKeykinClient) {
            clients.register(client)
            work.execute { val ss = slots(); send { it.slots(ss.toTypedArray()) }; for (s in ss) publish(s) }
        }
        override fun add(): String = onWork {
            val slot = Memberships.addSlot(); val ss = slots(); send { it.slots(ss.toTypedArray()) }
            slot
        }
        override fun join(slot: String, code: String, relays: String) = joins.execute {
            val rs = relays.split(",").filter { it.isNotBlank() }
            try {
                Memberships.checkSlot(slot)
                val s = onWork { open(slot) }
                // Never over a membership this slot holds, opened or not (review 15 M4).
                if (s.device != null || Memberships.openError(slot) != null) throw KeykinException("already_joined")
                onWork { joining[slot] = JSONObject().put("joining", true); publish(slot) }
                s.join(code, rs) { check -> work.execute { joining[slot] = JSONObject().put("joining", true).put("check", check); publish(slot) } }
                onWork { Memberships.setRelays(slot, rs); Memberships.joined(slot); joining.remove(slot) }
            } catch (e: KeykinException) { onWork { joining[slot] = JSONObject().put("error", e.code) } } catch (e: Exception) { onWork { joining[slot] = JSONObject().put("error", "internal") } }
            work.execute { publish(slot) }
        }
        override fun signOwn(slot: String, event: String): String = onWork {
            try {
                val d = Memberships.signer(slot).device ?: throw KeykinException("no_membership")
                // The main process draws strangers' content: its events pass the same guard a site's do (Doors §2).
                JSONObject().put("event", Nip55.sign(d, event)).toString()
            } catch (x: KeykinException) { JSONObject().put("error", x.code).toString() } catch (x: Exception) { JSONObject().put("error", "malformed").toString() }
        }
        override fun nip44Own(slot: String, kind: Int, text: String, encrypt: Boolean): String? = onWork {
            if (!Doors.ownMay(kind, ownKinds)) return@onWork null
            try { Memberships.signer(slot).device?.let { d -> d.nip44(d.g, text, encrypt) } } catch (_: Exception) { null }
        }
        override fun fetch(slot: String) = work.execute { try { Memberships.signer(slot).device?.fetch() } catch (e: Exception) { Log.w(TAG, "fetch: $e") }; publish(slot) }
        override fun grants(slot: String): String = onWork {
            val d = Memberships.signer(slot).device ?: return@onWork "[]"
            JSONArray(d.grants.all().map { e -> JSONObject().also { o -> for (k in listOf("by", "id", "says", "site", "door", "connection", "scopes", "made", "last_used")) e.opt(k)?.let { o.put(k, it) } } }).toString()
        }
        override fun endGrant(slot: String, by: String, id: String) = work.execute {
            Memberships.signer(slot).device?.let { d -> d.grants.end(by, id); d.publishGrantsSoon() }; publish(slot)
        }
        override fun pairAsks(slot: String): String = onWork {
            val d = Memberships.signer(slot).device ?: return@onWork "[]"
            JSONArray(d.pairAsks.values.map { JSONObject().put("id", it.getString("id")).put("from", it.getString("from")).put("list", it.getJSONArray("list")).put("expiry", it.getLong("expiry")) }).toString()
        }
        override fun pairApprove(slot: String, id: String, code: String): Boolean = onWork {
            try { Memberships.signer(slot).device?.pairApprove(id, code) ?: false } catch (_: Exception) { false }
        }
        override fun removeWithPair(slot: String, key: String, with: String): String? = onWork {
            val d = Memberships.signer(slot).device ?: return@onWork null
            val list = JSONArray().put(JSONObject().put("remove", key)).put(JSONObject().put("redeal", JSONObject().put("dealer", d.pub)))
            val (code, approval) = try { d.pairStart(list, with) } catch (_: Exception) { return@onWork null }
            joining[slot] = JSONObject().put("pair", JSONObject().put("status", "waiting").put("code", code)); publish(slot)
            // Waiting for the other device off the work thread; the list goes once it signed (or the wait ends).
            joins.execute {
                val status = try {
                    val a = approval.get(10, java.util.concurrent.TimeUnit.MINUTES) ?: throw KeykinException("refused")
                    onWork { d.submit(list, a) }; "done"
                } catch (e: KeykinException) { e.code } catch (_: Exception) { "expired" }
                work.execute { joining[slot] = JSONObject().put("pair", JSONObject().put("status", status)); publish(slot) }
            }
            code
        }
        override fun forget(slot: String) = work.execute {
            Memberships.forget(slot); joining.remove(slot)
            val ss = slots(); send { it.slots(ss.toTypedArray()) }
        }
    }
    companion object { private const val TAG = "KeykinService" }
}
