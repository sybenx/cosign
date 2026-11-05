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
    companion object {
        /** Scopes the main process may offer or allow for a NIP-46 site; the rest are the person's on a signer screen. */
        val APP_SCOPES = setOf("sign-in", "post", "lists")
        private const val TAG = "KeykinService"
    }
    private val clients = RemoteCallbackList<IKeykinClient>()
    /** Every call that touches a membership runs here, in order; every message to the UI goes out from `out`. */
    private val work = Executors.newSingleThreadExecutor { r -> Thread(r, "keykin-signer").also { it.isDaemon = true } }
    private val out = Executors.newSingleThreadExecutor()
    /** A join waits up to two minutes for the welcome: on its own thread, so other calls go on (review 15 L5). */
    private val joins = Executors.newSingleThreadExecutor { r -> Thread(r, "keykin-join").also { it.isDaemon = true } }
    /** Calls that sign or wait on servers and sites (Undo, holds, push wakes): their own thread, never the join's or
     *  the membership queue's, so a binder call never waits two minutes behind a join (review 20 M10). */
    private val slow = Executors.newSingleThreadExecutor { r -> Thread(r, "keykin-slow").also { it.isDaemon = true } }
    private val wakes = Executors.newSingleThreadExecutor { r -> Thread(r, "keykin-wake").also { it.isDaemon = true } }
    /** What the UI shows while a join runs, by slot (the check digits, an error). */
    private val joining = HashMap<String, JSONObject>()
    /** An invite from this phone, by slot: "waiting" for the new device's digits, then "typed" or "mismatch". */
    private val invites = HashMap<String, JSONObject>()

    override fun onCreate() {
        super.onCreate()
        Proc.signerOnly("KeykinService")
        Memberships.init(this)
        // Diagnostics in a debuggable build only: each request to a member, timed, to logcat (tag KeykinTrace).
        if (applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0) keykin.Keykin.trace = { Log.d("KeykinTrace", it) }
        Outcomes.onChange = { slot -> work.execute { if (Outcomes.get(slot)?.optString("action") == "add_invited") invites.remove(slot); publish(slot) } }
        work.execute { for (slot in slots()) open(slot) }
    }
    override fun onDestroy() { clients.kill(); work.shutdown(); joins.shutdown(); slow.shutdown(); wakes.shutdown(); out.shutdown(); super.onDestroy() }
    override fun onBind(intent: Intent?): IBinder = binder

    private fun slots() = Memberships.slots()
    private fun open(slot: String): KeykinSigner = Memberships.signer(slot)

    /** One membership's public state: its device key, the account, the state it is at, the devices, notices. */
    private fun stateOf(slot: String): JSONObject {
        val x = JSONObject().put("slot", slot)
        joining[slot]?.let { j -> for (k in j.keys()) x.put(k, j.get(k)) }
        Outcomes.get(slot)?.let { x.put("last_action", it) }
        invites[slot]?.let { x.put("invite", it) }
        Memberships.signer(slot)
        Memberships.openError(slot)?.let { x.put("open_error", it) }
        val d = Memberships.signer(slot).device ?: return x.put("joined", false)
        // Once joined, a join's leftovers (an extra Join or scan's "already_joined", the check digits) aren't this
        // membership's state (dry-run bug 5).
        for (k in listOf("error", "check", "joining")) x.remove(k)
        val (self, asOf, keys) = d.members.devices()
        return x.put("joined", true).put("device", self).put("account", d.g).put("state", asOf).put("wiped", d.wiped)
            // Core 14.25: the data-key state an app's own records are sealed under; re-seal when it changes.
            .put("data_state", try { d.currentState().second } catch (_: Exception) { JSONObject.NULL })
            .put("devices", JSONArray(keys.map { k -> d.nameOf(k.key).put("key", k.key).put("flagged", k.flagged) }))
            .put("removed", JSONArray(d.members.removed(0).map { it.json() })).put("notices", JSONArray(d.notices.toList()))
            .also { o -> hooked(slot, d); val v = d.guard.view { owner -> d.grants.own[owner.substringAfter(':')]?.optString("says") }
                o.put("cards", v.getJSONArray("cards")).put("undos", v.getJSONArray("undos")).put("held", d.nip46.heldList())
                .put("sites", JSONArray(d.nip46.asks.map { (k, sc) -> JSONObject().put("signer", k).put("scopes", JSONArray(sc.toList())) }))
                .put("vault_apps", JSONArray(vaultApps(d))).put("vault_declined", JSONArray(d.vault.declinedApps())) }
    }
    /** The vault apps granted on this device (Doors 20 §3.7), listed for the person (review 22 M3). A grant whose package
     *  is uninstalled or now signed by someone else is dropped here. */
    private fun vaultApps(d: keykin.Device): List<String> {
        for (app in d.vault.allowed()) {
            val uid = try { packageManager.getPackageUid(app.substringBefore('@'), 0) } catch (_: Exception) { -1 }
            if (uid < 0 || VaultService.appOf(this, uid) != app) d.vault.revoke(app)
        }
        return d.vault.allowed()
    }
    /** Cards and Undo waits change outside any call: each change goes out as the slot's state at once. */
    // Per device, not per slot: a membership forgotten and joined again gets its hooks again (review 20 M9).
    private fun hooked(slot: String, d: keykin.Device) {
        if (d.guard.onChange == null) d.guard.onChange = { work.execute { publish(slot) } }
        if (d.nip46.onChange == null) d.nip46.onChange = { work.execute { publish(slot) } }
    }
    private fun <T> withDevice(slot: String, f: (keykin.Device) -> T): T? = Memberships.signer(slot).device?.let(f)
    private fun errorJson(e: Exception) = JSONObject().put("error", (e as? KeykinException)?.code ?: "internal").toString()
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

    /** Core 14.25's Android identity for the app calling as `uid`: its one package, and the SHA-256 of its original
     *  signing certificate (the first of a v3 lineage). A uid shared by several packages, or an APK with several
     *  signers, gets no identity domain. */
    private fun callerIdentity(uid: Int): String {
        val pkgs = packageManager.getPackagesForUid(uid)?.toList() ?: emptyList()
        if (pkgs.size != 1) throw KeykinException("bad_caller")
        val info = packageManager.getPackageInfo(pkgs[0], android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
        val si = info.signingInfo ?: throw KeykinException("bad_caller")
        if (si.hasMultipleSigners()) throw KeykinException("bad_caller")
        val original = si.signingCertificateHistory?.firstOrNull() ?: throw KeykinException("bad_caller")
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(original.toByteArray())
        return keykin.AppDomains.androidIdentity(pkgs[0], digest.joinToString("") { "%02x".format(it) })
    }
    private fun csv(x: String) = x.split(",").map { it.trim() }.filter { it.isNotEmpty() }
    private fun appScopes(x: String) = csv(x).filter { it in APP_SCOPES }.ifEmpty { listOf("sign-in", "post") }
    private val binder = object : IKeykin.Stub() {
        override fun listen(client: IKeykinClient) {
            clients.register(client)
            // A slot still being opened (storage read, relays reached) says so at once, instead of nothing for a few
            // seconds (dry-run bug 3); its full state follows once it is open.
            val ss = slots()
            send { it.slots(ss.toTypedArray()) }
            for (s in ss) if (!Memberships.isOpen(s)) { val o = JSONObject().put("slot", s).put("opening", true).toString(); send { it.state(s, o) } }
            work.execute { for (s in ss) publish(s) }
        }
        override fun refresh(slot: String): String? = try {
            val d = onWork { Memberships.signer(slot).device } ?: throw KeykinException("no_membership")
            // Off the membership queue: a fetch waits on servers.
            slow.submit<String> { d.fetch(); onWork { stateOf(slot).also { s -> send { it.state(slot, s.toString()) } }.toString() } }.get(60, java.util.concurrent.TimeUnit.SECONDS)
        } catch (e: Exception) { errorJson(e) }
        override fun invite(slot: String, relays: String): String? = try {
            onWork {
                val d = Memberships.signer(slot).device ?: throw KeykinException("no_membership")
                val rs = csv(relays).ifEmpty { Memberships.relays(slot) ?: emptyList() }
                val code = d.invite(rs)
                invites[slot] = JSONObject().put("status", "waiting"); publish(slot)
                JSONObject().put("invite", code).toString()
            }
        } catch (e: Exception) { errorJson(e) }
        override fun inviteScanned(slot: String, helloCode: String): String? = try {
            val d = onWork { Memberships.signer(slot).device } ?: throw KeykinException("no_membership")
            // Off the membership queue: the offer and the hello wait on the relays.
            // Core 14.24: this phone shows the digits; the new device's confirm moves the invite on.
            val check = slow.submit<String> { d.inviteScanned(helloCode) { work.execute { invites[slot] = JSONObject().put("status", "confirmed"); publish(slot) } } }.get(60, java.util.concurrent.TimeUnit.SECONDS)
            onWork { if (invites[slot]?.optString("status") != "confirmed") invites[slot] = JSONObject().put("status", "show").put("check", check); publish(slot) }
            JSONObject().put("ok", true).put("check", check).toString()
        } catch (e: java.util.concurrent.ExecutionException) { errorJson((e.cause as? Exception) ?: e) } catch (e: Exception) { errorJson(e) }
        override fun inviteTyped(slot: String, digits: String): Boolean = onWork {
            val d = Memberships.signer(slot).device ?: return@onWork false
            val ok = try { d.inviter?.typed(digits.trim()) == true } catch (_: Exception) { false }
            // The join-code direction types nothing here (core 14.24): its status stays the confirm's.
            if (d.inviter?.expectN != null) return@onWork false
            invites[slot] = JSONObject().put("status", if (ok) "typed" else if (d.inviter?.contested == true) "contested" else "mismatch"); publish(slot)
            ok
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
        override fun latest(slot: String, kind: Int, d: String?, maxAgeS: Long): String = try {
            val dev = onWork { Memberships.signer(slot).device } ?: throw KeykinException("no_membership")
            // Off the membership queue: an ask waits on the relays.
            if (maxAgeS < 0) dev.latest(kind, d, -1).toString()
            else slow.submit<String> { dev.latest(kind, d, maxAgeS).toString() }.get(15, java.util.concurrent.TimeUnit.SECONDS)
        } catch (e: java.util.concurrent.ExecutionException) { errorJson((e.cause as? Exception) ?: e) } catch (e: Exception) { errorJson(e) }
        override fun fetch(slot: String) = work.execute { try { Memberships.signer(slot).device?.fetch() } catch (e: Exception) { Log.w(TAG, "fetch: $e") }; publish(slot) }
        override fun grants(slot: String): String = onWork {
            val d = Memberships.signer(slot).device ?: return@onWork "[]"
            JSONArray(d.grants.all().map { e -> JSONObject().also { o -> for (k in listOf("by", "id", "says", "site", "door", "connection", "scopes", "made", "last_used")) e.opt(k)?.let { o.put(k, it) } } }).toString()
        }
        override fun endGrant(slot: String, by: String, id: String) = work.execute {
            try { Memberships.signer(slot).device?.signOut(listOf(by to id)) } catch (e: Exception) { Log.w(TAG, "endGrant: $e") }; publish(slot)
        }
        override fun signOutEverywhere(slot: String) = work.execute {
            try { Memberships.signer(slot).device?.signOutEverywhere() } catch (e: Exception) { Log.w(TAG, "signOutEverywhere: $e") }; publish(slot)
        }
        override fun helperSite(slot: String, site: String, relaysCsv: String): String? = onWork {
            try { Memberships.signer(slot).device?.helperSite(site, relaysCsv.split(",").map { it.trim() }.filter { it.isNotEmpty() }) } catch (_: Exception) { null }
        }
        // --- Device policy: cards, Undo, held events -----------------------------------------------------------
        override fun answerCard(slot: String, id: Int, allow: Boolean) = work.execute { withDevice(slot) { it.guard.answer(id, if (allow) "allow" else "decline") }; publish(slot) }
        override fun undoPending(slot: String, id: Int) = work.execute { withDevice(slot) { it.guard.undoPending(id) }; publish(slot) }
        // These sign: off the call thread a card or a server can't block, as the join is.
        override fun undoTo(slot: String, versionId: String, confirmed: Boolean): String = slow.submit<String> {
            try { withDevice(slot) { d -> when (val r = d.undoTo(versionId, confirmed)) { is String -> JSONObject().put("needs", r).toString(); is JSONObject -> JSONObject().put("event", r).toString(); else -> JSONObject().put("error", "internal").toString() } } ?: JSONObject().put("error", "no_membership").toString() }
            catch (e: Exception) { errorJson(e) }
        }.get()
        override fun undoSite(slot: String, owner: String, confirmed: Boolean): String = slow.submit<String> {
            try { withDevice(slot) { d -> val (lists, posts) = d.undoSite(owner, confirmed)
                JSONObject().put("lists", JSONArray(lists.map { if (it is JSONObject) JSONObject().put("event", it) else JSONObject().put("needs", it.toString()) })).put("posts", JSONArray(posts)).toString() } ?: JSONObject().put("error", "no_membership").toString() }
            catch (e: Exception) { errorJson(e) }
        }.get()
        override fun postAgain(slot: String, id: String): String = slow.submit<String> {
            try { withDevice(slot) { d -> JSONObject().put("event", d.postAgain(id)).toString() } ?: JSONObject().put("error", "no_membership").toString() } catch (e: Exception) { errorJson(e) }
        }.get()
        override fun holdHeld(slot: String, id: String): String = slow.submit<String> {
            try { withDevice(slot) { d -> JSONObject().put("wait", d.nip46.holdHeld(id)).toString() } ?: JSONObject().put("error", "no_membership").toString() } catch (e: Exception) { errorJson(e) } finally { work.execute { publish(slot) } }
        }.get()
        override fun releaseHeld(slot: String, id: String): String = slow.submit<String> {
            try { withDevice(slot) { d -> JSONObject().put("event", d.nip46.releaseHeld(id)).toString() } ?: JSONObject().put("error", "no_membership").toString() } catch (e: Exception) { errorJson(e) } finally { work.execute { publish(slot) } }
        }.get()
        override fun declineHeld(slot: String, id: String) = work.execute { withDevice(slot) { it.nip46.declineHeld(id) }; publish(slot) }

        // --- the NIP-46 home ----------------------------------------------------------------------------------
        // The main process may offer and allow only what it could do itself (sign-in, posting, lists, which nip44Own's
        // default kinds already read): messages, private data and the wallet are allowed only on a signer-process
        // screen (Nip46Asks), so a compromised app can't grant itself the account's DMs (review 20 H2).
        override fun bunker(slot: String, relaysCsv: String, scopesCsv: String): String? = slow.submit<String?> {
            try { withDevice(slot) { d -> d.nip46.mintBunker(csv(relaysCsv), "", appScopes(scopesCsv)) } } catch (_: Exception) { null }
        }.get()
        override fun nostrconnect(slot: String, uri: String, scopesCsv: String): String? = slow.submit<String?> {
            try { withDevice(slot) { d -> d.nip46.acceptNostrconnect(uri, appScopes(scopesCsv)).signer } } catch (_: Exception) { null }
        }.get()
        override fun allowScope(slot: String, signer: String, scope: String) = work.execute {
            if (scope !in APP_SCOPES) { Log.w(TAG, "allowScope: $scope is the person's to allow on a signer-process screen"); return@execute }
            try { withDevice(slot) { it.nip46.allowScope(signer, scope) } } catch (e: Exception) { Log.w(TAG, "allowScope: $e") }; publish(slot)
        }

        // --- UnifiedPush -----------------------------------------------------------------------------------------
        // Core 14.25: the calling app's own key, under its identity domain, worked out here from the binder's caller.
        override fun ownKey(slot: String, label: String): String = ownKeyFor(slot, label, null)
        override fun ownKeyAt(slot: String, label: String, state: String): String = ownKeyFor(slot, label, state)
        private fun ownKeyFor(slot: String, label: String, state: String?): String = try {
            val identity = callerIdentity(android.os.Binder.getCallingUid())
            val d = onWork { Memberships.signer(slot).device } ?: throw KeykinException("no_membership")
            val (st, key) = d.ownKey(identity, label, state)
            JSONObject().put("key", keykin.hex(key)).put("state", st).toString().also { key.fill(0) }
        } catch (e: Exception) { errorJson(e) }
        // F1 (core §6.7.6–§6.7.7): ask every seated server, and answer the card's seats [{seat, host, why}] (empty while
        // all count as alive). The app then picks a replacement from its server list and starts KeykinApprove "move_seat".
        override fun checkServers(slot: String): String = try {
            val d = onWork { Memberships.signer(slot).device } ?: throw KeykinException("no_membership")
            slow.submit<String> { JSONArray(d.checkServers()).toString() }.get(60, java.util.concurrent.TimeUnit.SECONDS)
        } catch (e: java.util.concurrent.ExecutionException) { errorJson((e.cause as? Exception) ?: e) } catch (e: Exception) { errorJson(e) }
        override fun setLabel(slot: String, name: String): String = try {
            val d = onWork { Memberships.signer(slot).device } ?: throw KeykinException("no_membership")
            // The model is this phone's own, read here: a stolen phone can rename itself, never pass for another model.
            val model = "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}".trim()
            slow.submit<String> { d.setLabel(name, model); onWork { publish(slot) }; JSONObject().put("ok", true).toString() }.get(60, java.util.concurrent.TimeUnit.SECONDS)
        } catch (e: java.util.concurrent.ExecutionException) { errorJson((e.cause as? Exception) ?: e) } catch (e: Exception) { errorJson(e) }
        override fun pushInstances(slot: String): String = onWork { JSONArray(Memberships.signer(slot).instances()).toString() }
        override fun pushEndpoint(slot: String, instance: String, endpoint: String) = work.execute {
            try { val s = Memberships.signer(slot); s.onEndpoint(instance, endpoint); s.registerPush() } catch (e: Exception) { Log.w(TAG, "pushEndpoint: $e") }
        }
        override fun pushEndpointKeys(slot: String, instance: String, endpoint: String, p256dh: String, auth: String) = work.execute {
            try { val s = Memberships.signer(slot); s.onEndpoint(instance, endpoint, p256dh, auth); s.registerPush() } catch (e: Exception) { Log.w(TAG, "pushEndpointKeys: $e") }
        }
        override fun pushDecrypted(slot: String, instance: String, plaintext: ByteArray) = wakes.execute {
            try { Memberships.signer(slot).onDecrypted(instance, plaintext) } catch (e: Exception) { Log.w(TAG, "pushDecrypted: $e") }
            work.execute { publish(slot) }
        }
        // A wake can wait on servers and sites: on its own thread, as the join is; the state follows.
        override fun pushMessage(slot: String, instance: String, body: ByteArray) = wakes.execute {
            try { Memberships.signer(slot).onMessage(instance, body) } catch (e: Exception) { Log.w(TAG, "pushMessage: $e") }
            work.execute { publish(slot) }
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
        override fun revokeVaultApp(slot: String, app: String) = work.execute {
            Memberships.signer(slot).device?.vault?.revoke(app); publish(slot)
        }
        override fun forget(slot: String) = work.execute {
            Memberships.forget(slot); joining.remove(slot)
            val ss = slots(); send { it.slots(ss.toTypedArray()) }
        }
    }
}
