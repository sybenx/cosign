package cc.aaro.cosign

import android.content.Context
import android.net.Uri
import cc.aaro.cosign.core.CodeCheck
import cc.aaro.cosign.core.Event
import cc.aaro.cosign.core.Frost
import cc.aaro.cosign.core.FrostNative
import cc.aaro.cosign.core.Json
import cc.aaro.cosign.core.Mode
import cc.aaro.cosign.core.Nip44
import cc.aaro.cosign.core.Outcome
import cc.aaro.cosign.core.PairingParams
import cc.aaro.cosign.core.PairingUri
import cc.aaro.cosign.core.Phase
import cc.aaro.cosign.core.Policy
import cc.aaro.cosign.core.SignerTicket
import cc.aaro.cosign.core.SignerTicketProfile
import cc.aaro.cosign.core.SystemEnv
import cc.aaro.cosign.core.generateSecretKey
import cc.aaro.cosign.core.hexToBytes
import cc.aaro.cosign.core.isHex32
import cc.aaro.cosign.core.publicKeyHex
import cc.aaro.cosign.core.toHex
import cc.aaro.cosign.net.KeyValue
import cc.aaro.cosign.net.Relays
import cc.aaro.cosign.net.Store
import cc.aaro.cosign.net.Transfer
import cc.aaro.cosign.net.TransferDeps
import cc.aaro.cosign.net.TransferView
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import fr.acinq.secp256k1.Secp256k1
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

data class Member(val idx: Int, val name: String, val role: String, val pk: String?, val sharePub: String)
data class Group(val groupX: String, val npub: String, val threshold: Int, val relays: List<String>, val members: List<Member>)
data class Membership(val sk: String, val idx: Int, val share: String, val signer: String, val group: Group)
data class Offer(val fromPk: String, val token: String, val idx: Int, val share: String, val signer: String, val group: Group)
/** Something destructive, waiting for you. */
/** [frost]: which signing math the server asked for (2 = the library, 1 = the earlier one). */
data class Ask(val id: String, val fromPk: String, val via: String, val app: String, val event: Event, val msg: String, val commit: Frost.Commit, val hold: String, val expiresAt: Long, val frost: Int = 1)
/** A grant. [parent]: the connected site (the extension) that added it; [via]: what connected it. */
data class Site(val pk: String, val origin: String, val added: Long, val lastUsed: Long, val parent: String? = null, val via: String? = null)
data class Change(val id: String, val text: String, val by: String, val at: Long, val held: Boolean, val undone: Boolean)
data class Connect(val origin: String, val stage: Stage, val message: String? = null) { enum class Stage { CONFIRM, WORKING, DONE, FAILED } }
data class Line(val ts: Long, val text: String, val kind: String = "info")
/** An app on this phone that may sign as you (Android signer, NIP-55). [pk] names its grant on your servers. */
data class AppGrant(val pkg: String, val pk: String, val label: String, val dm: Boolean)
/** Destructive: the app has to open Cosign so you can approve it. */
class NeedsApproval(val what: String) : Exception(what)
/** You removed this app; it must connect again. */
class Revoked : Exception("revoked")

data class Ui(
    val member: Membership? = null,
    val joining: String? = null,
    val offer: Offer? = null,
    val error: String? = null,
    val asks: List<Ask> = emptyList(),
    val online: Map<Int, Boolean> = emptyMap(),
    val relaysUp: Int = 0,
    val log: List<Line> = emptyList(),
    val sites: List<Site> = emptyList(),
    val changes: List<Change> = emptyList(),
    val connect: Connect? = null,
    val push: String? = null,
)

/**
 * The phone's part: your remote control, and one share of your key.
 *
 * It connects sites (scan a site's code; your servers give it access of its own), shows
 * and removes what's connected, approves anything destructive, and undoes changes. It
 * co-signs routine things itself only while one of your servers is down.
 */
class Phone(private val context: Context) {
    interface Listener { fun onAsk(ask: Ask); fun onAskGone(id: String); fun onStatus() }

    private val secrets = Secrets(context)
    private val lists = Lists(context)
    /** Big messages arrive in parts (NIP-44 stops at 64 KB); these are the ones still coming in. */
    private val parts = ConcurrentHashMap<String, Pair<Long, Array<String?>>>()
    private val env = SystemEnv
    val ui = MutableStateFlow(Ui())
    @Volatile var listener: Listener? = null

    private var relays: Relays? = null
    private var sk: String? = null
    private var pairing: Uri? = null
    private val lastSeen = ConcurrentHashMap<Int, Long>()
    private val timer = Executors.newSingleThreadScheduledExecutor()
    private var pinger: ScheduledFuture<*>? = null
    private var helloer: ScheduledFuture<*>? = null
    /** Answers already given, by request id: a repeat gets the same answer, never a second partial. */
    private val answered = ConcurrentHashMap<String, Map<String, Any?>>()
    private val asking = ConcurrentHashMap.newKeySet<String>()
    private val pendingReplies = ConcurrentHashMap<String, (Map<String, Any?>) -> Unit>()
    private val myUndos = ConcurrentHashMap<String, Long>()
    private var lastEcdhNote = 0L

    private val qrstStore = Store(object : KeyValue {
        private val prefs = context.getSharedPreferences("qrst", Context.MODE_PRIVATE)
        override fun get(key: String): String? = prefs.getString(key, null)
        override fun put(key: String, value: String) { prefs.edit().putString(key, value).apply() }
    })
    private var transfer: Transfer<SignerTicket>? = null
    private var connecting: PairingParams? = null
    /** A nostrconnect:// code being connected: the raw code, and the site's key in it. */
    private var nostrConnect: Pair<String, String>? = null
    private var nostrConnectTries: ScheduledFuture<*>? = null

    init {
        secrets.loadMembership()?.let { parseMembership(Json.parse(it)) }?.let { m -> ui.update { it.copy(member = m) } }
        secrets.loadLog()?.let { Json.parse(it) as? List<*> }?.let { lines ->
            ui.update { u -> u.copy(log = lines.mapNotNull { (it as? Map<*, *>)?.let { m -> Line(m["ts"] as Long, m["text"] as String, m["kind"] as? String ?: "info") } }) }
        }
        ui.update { it.copy(push = context.getSharedPreferences("cosign", Context.MODE_PRIVATE).getString("push", null)) }
    }

    val isMember get() = ui.value.member != null
    private fun servers() = ui.value.member?.group?.members?.filter { it.role == "server" && it.pk != null } ?: emptyList()

    /** Start answering, if this phone is in a group. Called by the service. */
    fun start() {
        val m = ui.value.member ?: return
        if (relays == null || sk != m.sk) connect(m.group.relays, m.sk)
        relays?.watch(mapOf("kinds" to Policy.ARCHIVED.toList(), "authors" to listOf(m.group.groupX)))
        if (pinger?.isCancelled != false) pinger = timer.scheduleWithFixedDelay({ pingServers(); status() }, 0, 10, TimeUnit.SECONDS)
        timer.schedule({ requestState(); ui.value.push?.let { tellPush(it) } }, 2, TimeUnit.SECONDS)
    }

    fun stop() { pinger?.cancel(false); pinger = null; relays?.stop(); relays = null; sk = null }

    // --- Joining your servers ------------------------------------------------

    private fun joinGroup(text: String) {
        val uri = Uri.parse(text.trim().replace("cosign:pair?", "cosign://pair?"))
        val pk = uri.getQueryParameter("pk")
        val token = uri.getQueryParameter("t")
        val urls = uri.getQueryParameters("r").filter { it.startsWith("wss://") || it.startsWith("ws://") }
        if (!isHex32(pk) || token.isNullOrBlank() || urls.isEmpty()) { ui.update { it.copy(error = "That code is damaged. Try scanning it again.") }; return }
        pairing = uri
        connect(urls, generateSecretKey(env).toHex())
        ui.update { it.copy(joining = "Reaching your server…", error = null, offer = null) }
        val started = System.currentTimeMillis()
        helloer?.cancel(false)
        helloer = timer.scheduleWithFixedDelay({
            if (ui.value.offer != null || pairing == null) { helloer?.cancel(false); return@scheduleWithFixedDelay }
            if (System.currentTimeMillis() - started > 20_000) {
                helloer?.cancel(false); relays?.stop(); relays = null
                ui.update { it.copy(joining = null, error = "Your server didn't answer. Is it running, and is the code still on its page?") }
                return@scheduleWithFixedDelay
            }
            if ((relays?.up() ?: 0) > 0) send(pk!!, mapOf("type" to "pair_hello", "token" to token))
        }, 1500, 3000, TimeUnit.MILLISECONDS)
    }

    private fun onOffer(msg: Map<*, *>, fromPk: String) {
        val p = pairing ?: return
        if (fromPk != p.getQueryParameter("pk") || msg["token"] != p.getQueryParameter("t") || ui.value.offer != null) return
        val group = parseGroup(msg["group"]) ?: return
        val idx = (msg["idx"] as? Long)?.toInt() ?: return
        val share = msg["share"] as? String ?: return
        val signer = msg["signer"] as? String ?: return
        if (group.members.firstOrNull { it.idx == idx }?.sharePub != Frost.sharePub(share)) {
            ui.update { it.copy(joining = null, error = "Your server sent a share that doesn't match its group. Nothing was kept.") }
            return
        }
        helloer?.cancel(false)
        ui.update { it.copy(joining = null, offer = Offer(fromPk, msg["token"] as String, idx, share, signer, group)) }
    }

    fun accept() {
        val o = ui.value.offer ?: return
        val mySk = sk ?: return
        val me = publicKeyHex(mySk.hexToBytes())
        val group = o.group.copy(members = o.group.members.map { if (it.idx == o.idx) it.copy(pk = me) else it })
        val m = Membership(mySk, o.idx, o.share, o.signer, group)
        secrets.saveMembership(Json.stringify(membershipToMap(m)))
        send(o.fromPk, mapOf("type" to "pair_ack", "token" to o.token))
        pairing = null
        ui.update { it.copy(member = m, offer = null) }
        note("Joined. This phone holds 1 of ${group.members.size} shares.")
        lastSeen[group.members.first { it.pk == o.fromPk }.idx] = System.currentTimeMillis()
        start()
    }

    fun decline() {
        pairing = null; helloer?.cancel(false)
        if (!isMember) { relays?.stop(); relays = null; sk = null }
        ui.update { it.copy(offer = null, joining = null) }
    }

    fun clearError() = ui.update { it.copy(error = null) }

    fun leave() {
        stop(); secrets.clear(); lists.clear(); lastSeen.clear()
        context.getSharedPreferences("cosign", Context.MODE_PRIVATE).edit().clear().apply()
        ui.value = Ui()
    }

    // --- Scanning ------------------------------------------------------------

    /** Whatever the camera read: your server's code, or a site's. */
    fun scanned(text: String) {
        val t = text.trim()
        if (t.startsWith("cosign:pair")) {
            if (isMember) ui.update { it.copy(error = "This phone is already part of your key. That code is for adding a phone.") } else joinGroup(t)
            return
        }
        if (t.startsWith("nostrconnect:")) return scannedNostrConnect(t)
        val params = try { PairingUri.parse(t) } catch (_: Exception) { null }
        // A sign-in code that carries a nostrconnect:// fallback (`nc`, site/src/pair.ts):
        // use the ticket if it's one for us, the fallback if not.
        val nc = t.substringAfter('#', "").split('&').firstOrNull { it.startsWith("nc=") }?.let { Uri.decode(it.removePrefix("nc=")) }
        if (nc != null && nc.startsWith("nostrconnect:") && (params == null || params.profile != SignerTicketProfile.id || params.mode != Mode.OFFER))
            return scannedNostrConnect(nc)
        when {
            params == null -> ui.update { it.copy(error = "That isn't a code Cosign understands.") }
            !isMember -> ui.update { it.copy(error = "Add this phone to your servers first: scan the code on your server's page.") }
            params.profile != SignerTicketProfile.id -> ui.update { it.copy(error = "That code is for something else (${params.profile}).") }
            params.mode != Mode.OFFER -> ui.update { it.copy(error = "That code isn't asking to sign in.") }
            else -> {
                connecting = params; nostrConnect = null
                ui.update { it.copy(error = null, connect = Connect(params.origin ?: "This site", Connect.Stage.CONFIRM)) }
            }
        }
    }

    // --- Connecting a site ----------------------------------------------------
    //
    // A one-time ticket, handed over by QRST at its lowest check: this phone's own camera
    // read the code, the ticket is sealed to that code's burner, and the site can't use
    // it without your servers, who take it once and only for 15 minutes.

    fun confirmConnect() {
        if (nostrConnect != null) return confirmNostrConnect()
        val params = connecting ?: return
        val m = ui.value.member ?: return
        val origin = params.origin ?: "a site"
        val ticket = SignerTicket(m.group.groupX, m.signer, m.group.relays, env.random(16).toHex(), env.now() + 900)
        for (s in servers()) send(s.pk!!, mapOf("type" to "ticket", "t" to ticket.t, "origin" to origin, "expires" to ticket.expires))
        ui.update { it.copy(connect = Connect(origin, Connect.Stage.WORKING, "Sending to $origin…")) }
        var released = false
        val deps = TransferDeps(SignerTicketProfile, qrstStore, env, "https://qrst.aaro.cc/", CodeCheck.NONE)
        val t = Transfer.join(deps, params, true, ticket)
        transfer = t
        t.onChange = {
            val v: TransferView<SignerTicket> = t.view()
            if (v.session.phase == Phase.RELEASE && !released) { released = true; t.release(ticket) }
            if (v.stage == TransferView.Stage.ENDED) finishConnect(origin, v.session.outcome)
        }
    }

    private fun finishConnect(origin: String, outcome: Outcome?) {
        if (ui.value.connect?.stage != Connect.Stage.WORKING) return
        val (stage, message) = when (outcome) {
            Outcome.DELIVERED, Outcome.SENT_UNCONFIRMED -> Connect.Stage.DONE to "$origin can sign as you now. Remove it below any time."
            Outcome.SECOND_RESPONDER -> Connect.Stage.FAILED to "Two devices answered that code, so nothing was sent. Ask the site for a new code."
            Outcome.PEER_ABORTED, Outcome.DECLINED -> Connect.Stage.FAILED to "$origin cancelled."
            Outcome.EXPIRED -> Connect.Stage.FAILED to "That code expired. Ask the site for a new one."
            else -> Connect.Stage.FAILED to "Couldn't connect $origin (${outcome?.wire ?: "unknown"})."
        }
        if (stage == Connect.Stage.DONE) note("Connected $origin", "approved")
        ui.update { it.copy(connect = Connect(origin, stage, message)) }
        // A success needs no tap to dismiss, and mustn't sit over an approval that arrives next.
        if (stage == Connect.Stage.DONE) timer.schedule({ ui.update { u -> if (u.connect?.stage == Connect.Stage.DONE) u.copy(connect = null) else u } }, 2500, TimeUnit.MILLISECONDS)
        connecting = null
        timer.schedule({ requestState() }, 3, TimeUnit.SECONDS)
    }

    fun closeConnect() {
        val stage = ui.value.connect?.stage
        if (stage == Connect.Stage.CONFIRM || stage == Connect.Stage.WORKING) transfer?.cancel()
        connecting = null; nostrConnect = null; nostrConnectTries?.cancel(false)
        ui.update { it.copy(connect = null) }
    }

    // --- Connecting a site by nostrconnect ----------------------------------------
    //
    // For a site that only knows NIP-46: its nostrconnect:// code names its own key, its
    // relays and a secret. This phone passes the code to your servers, they give the site
    // access of its own, and the one answering sites sends the secret back to say hello.
    // Same access as a QRST sign-in, removed the same way.

    private fun scannedNostrConnect(text: String) {
        val uri = Uri.parse(text.replaceFirst(Regex("^nostrconnect:(?!//)"), "nostrconnect://"))
        val client = uri.host?.lowercase()
        val relayList = uri.getQueryParameters("relay").filter { it.startsWith("wss://") || it.startsWith("ws://") }
        when {
            !isMember -> ui.update { it.copy(error = "Add this phone to your servers first: scan the code on your server's page.") }
            !isHex32(client) || relayList.isEmpty() || uri.getQueryParameter("secret").isNullOrBlank() ->
                ui.update { it.copy(error = "That nostrconnect code is incomplete. Ask the site for a new one.") }
            else -> {
                // What the site says it is: its web address if it gave one, else its name.
                val site = uri.getQueryParameter("url")?.let { Uri.parse(it).let { u -> u.host?.let { h -> if (u.port > 0) "$h:${u.port}" else h } } }
                    ?: uri.getQueryParameter("name")?.take(40)?.trim()?.ifBlank { null } ?: "This app"
                nostrConnect = text to client!!; connecting = null
                ui.update { it.copy(error = null, connect = Connect(site, Connect.Stage.CONFIRM)) }
            }
        }
    }

    private fun confirmNostrConnect() {
        val (code, client) = nostrConnect ?: return
        val origin = ui.value.connect?.origin ?: "a site"
        ui.update { it.copy(connect = Connect(origin, Connect.Stage.WORKING, "Telling your servers…")) }
        val started = System.currentTimeMillis()
        nostrConnectTries?.cancel(false)
        // Say it again until a server answers: relays drop things.
        nostrConnectTries = timer.scheduleWithFixedDelay({
            if (nostrConnect?.second != client) { nostrConnectTries?.cancel(false); return@scheduleWithFixedDelay }
            if (System.currentTimeMillis() - started > 20_000) {
                nostrConnectTries?.cancel(false); nostrConnect = null
                ui.update { it.copy(connect = Connect(origin, Connect.Stage.FAILED, "Your servers didn't answer. Are they running?")) }
                return@scheduleWithFixedDelay
            }
            for (s in servers()) send(s.pk!!, mapOf("type" to "nostrconnect", "uri" to code, "origin" to origin))
        }, 0, 4, TimeUnit.SECONDS)
    }

    private fun onConnected(msg: Map<*, *>) {
        val (_, client) = nostrConnect ?: return
        if (msg["pk"] != client) return
        nostrConnectTries?.cancel(false); nostrConnect = null
        finishConnect(ui.value.connect?.origin ?: "The site", Outcome.DELIVERED)
    }

    // --- What's connected, and what changed --------------------------------------

    fun removeSite(site: Site) {
        for (s in servers()) send(s.pk!!, mapOf("type" to "revoke", "pk" to site.pk))
        appByPk(site.pk)?.let { apps.edit().remove(it.pkg).apply() }
        // Removing the extension removes every site it added; your servers do the same.
        ui.update { it.copy(sites = it.sites.filter { x -> x.pk != site.pk && x.parent != site.pk }) }
        note("Removed ${site.origin}", "denied")
    }

    fun undo(change: Change) {
        // One server does it: the first one that's online.
        val target = servers().sortedBy { if (ui.value.online[it.idx] == true) 0 else 1 }.firstOrNull() ?: return
        myUndos[change.id] = System.currentTimeMillis()
        send(target.pk!!, mapOf("type" to "undo", "id" to change.id))
        note("Undoing: ${change.text}")
    }

    fun requestState() { for (s in servers()) send(s.pk!!, mapOf("type" to "state_req")) }

    // --- Push (ntfy, by UnifiedPush) ---------------------------------------------

    fun setPushEndpoint(url: String?) {
        context.getSharedPreferences("cosign", Context.MODE_PRIVATE).edit().putString("push", url).apply()
        ui.update { it.copy(push = url) }
        tellPush(url)
    }

    private fun tellPush(url: String?) { for (s in servers()) send(s.pk!!, mapOf("type" to "push", "endpoint" to (url ?: ""))) }

    // --- Apps on this phone (Android signer, NIP-55) ---------------------------------
    //
    // An app asks this phone, so this phone runs the round and asks one of your servers
    // for the other half, the way a site asks a server. Both judge the event: something
    // destructive needs you to approve it here first, and the server checks the app still
    // has access. Decrypting is done in two halves and finished here, never on a server.

    private val apps = context.getSharedPreferences("apps", Context.MODE_PRIVATE)
    private val waiting = ConcurrentHashMap<String, CompletableFuture<Map<*, *>>>()
    private val sharedXs = ConcurrentHashMap<String, Pair<Long, ByteArray>>()

    fun appGrant(pkg: String): AppGrant? = apps.getString(pkg, null)?.let { j ->
        (Json.parse(j) as? Map<*, *>)?.let { AppGrant(pkg, it["pk"] as String, it["label"] as String, it["dm"] == true) }
    }
    private fun appByPk(pk: String) = apps.all.keys.mapNotNull { appGrant(it) }.firstOrNull { it.pk == pk }
    private fun store(g: AppGrant) = apps.edit().putString(g.pkg, Json.stringify(mapOf("pk" to g.pk, "label" to g.label, "dm" to g.dm))).apply()

    fun connectApp(pkg: String, label: String): AppGrant {
        val g = appGrant(pkg) ?: AppGrant(pkg, env.random(32).toHex(), label, false).also(::store)
        for (s in servers()) send(s.pk!!, mapOf("type" to "app_grant", "pk" to g.pk, "origin" to g.label))
        note("Connected ${g.label}", "approved")
        timer.schedule({ requestState() }, 2, TimeUnit.SECONDS)
        return g
    }

    fun allowDms(g: AppGrant): AppGrant = g.copy(dm = true).also { store(it); note("${g.label} may read and send your messages", "approved") }

    /** What would be destroyed, if this needs you to approve it; else null. */
    fun holdFor(ev: Event): String? = Policy.hold(ev, lists.latest(Policy.keyOf(ev)))

    /** The event an app sent, as it will be signed: under your key, with its id. */
    fun appEvent(json: String): Event {
        val m = ui.value.member ?: error("Cosign isn't set up yet")
        val raw = Json.parse(json) as? Map<*, *> ?: throw IllegalArgumentException("not an event")
        val tags = (raw["tags"] as? List<*>)?.map { t -> (t as List<*>).map { it.toString() } } ?: emptyList()
        return Event(m.group.groupX, raw["created_at"] as? Long ?: env.now(), (raw["kind"] as Long).toInt(), tags, raw["content"] as? String ?: "").withId()
    }

    /** Sign for an app, with one of your servers. Blocks for up to a few seconds; never call on the main thread. */
    fun signForApp(g: AppGrant, ev: Event, approved: Boolean): Event {
        val m = ui.value.member ?: error("Cosign isn't set up yet")
        if (!approved) holdFor(ev)?.let { throw NeedsApproval(it) }
        awake()
        val group = groupJson(m)
        val tried = mutableListOf<String>()
        for (srv in servers().sortedBy { if (ui.value.online[it.idx] == true) 0 else 1 }) {
            val c = Json.parse(FrostNative.commit(group, m.idx, m.share)) as Map<*, *>
            val mine = c["commit"] as Map<*, *>
            val res = askServer(srv, mapOf("type" to "cosign_req", "id" to env.random(8).toHex(), "event" to ev.toMap(), "msg" to ev.id,
                "participants" to listOf(m.idx, srv.idx).sorted(), "commit" to mine, "frost" to 2, "grant" to g.pk, "approved" to approved))
                ?: run { tried += "${srv.name}: no answer"; null } ?: continue
            if (res["ok"] != true) {
                val why = res["reason"] as? String ?: "refused"
                if (why.startsWith("revoked")) { apps.edit().remove(g.pkg).apply(); throw Revoked() }
                if (why.startsWith("needs-approval:")) throw NeedsApproval(why.removePrefix("needs-approval:").trim())
                tried += "${srv.name}: $why"; continue
            }
            val theirs = res["commit"] as Map<*, *>
            val z2 = res["z"] as String
            val commits = Json.stringify(listOf(mine, theirs))
            if (!FrostNative.verifyPartial(group, ev.id, commits, srv.idx, z2)) { tried += "${srv.name}: bad partial"; continue }
            val z = FrostNative.sign(group, m.idx, m.share, c["nonces"] as String, ev.id, commits)
            val signed = ev.copy(sig = FrostNative.aggregate(group, ev.id, commits, Json.stringify(listOf(listOf(m.idx, z), listOf(srv.idx, z2)))))
            send(srv.pk!!, mapOf("type" to "phone_signed", "event" to signed.toMap(), "grant" to g.pk, "approved" to approved))
            note("Signed ${Describe.kind(ev.kind)} for ${g.label}", if (approved) "approved" else "auto")
            return signed
        }
        throw IllegalStateException("Couldn't reach your servers (${tried.joinToString("; ")})")
    }

    /** The shared x with [peerX], from this phone's half and a server's. Kept ten minutes, in memory. */
    private fun sharedX(g: AppGrant, peerX: String): ByteArray {
        sharedXs[peerX]?.let { (at, x) -> if (System.currentTimeMillis() - at < 600_000) return x }
        val m = ui.value.member ?: error("Cosign isn't set up yet")
        awake()
        for (srv in servers().sortedBy { if (ui.value.online[it.idx] == true) 0 else 1 }) {
            val participants = listOf(m.idx, srv.idx).sorted()
            val res = askServer(srv, mapOf("type" to "ecdh_req", "id" to env.random(8).toHex(), "peerX" to peerX, "participants" to participants, "grant" to g.pk)) ?: continue
            if (res["ok"] != true) { if ((res["reason"] as? String)?.startsWith("revoked") == true) throw Revoked(); continue }
            val mine = Frost.ecdhPartial(m.idx, m.share, participants, peerX).hexToBytes()
            val x = Secp256k1.pubKeyCombine(arrayOf(mine, (res["point"] as String).hexToBytes())).copyOfRange(1, 33)
            sharedXs[peerX] = System.currentTimeMillis() to x
            return x
        }
        throw IllegalStateException("Couldn't reach your servers")
    }

    fun nip44(g: AppGrant, peer: String, text: String, encrypt: Boolean): String {
        val key = Nip44.conversationKeyFromShared(sharedX(g, peer))
        return if (encrypt) Nip44.encrypt(text, key, env.random(32)) else Nip44.decrypt(text, key)
    }

    fun nip04(g: AppGrant, peer: String, text: String, encrypt: Boolean): String {
        val key = SecretKeySpec(sharedX(g, peer), "AES")
        val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val b64 = Base64.getEncoder()
        if (encrypt) {
            val iv = env.random(16)
            c.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv))
            return b64.encodeToString(c.doFinal(text.toByteArray())) + "?iv=" + b64.encodeToString(iv)
        }
        val (ct, iv) = text.split("?iv=").let { it[0] to it.getOrElse(1) { "" } }
        c.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(Base64.getDecoder().decode(iv)))
        return String(c.doFinal(Base64.getDecoder().decode(ct)))
    }

    private fun groupJson(m: Membership) = Json.stringify(mapOf("groupX" to m.group.groupX, "threshold" to m.group.threshold,
        "members" to m.group.members.map { mapOf("idx" to it.idx, "sharePub" to it.sharePub) }))

    /** Ask a server and wait for its answer, saying it again once in case a relay dropped it. */
    private fun askServer(srv: Member, msg: Map<String, Any?>): Map<*, *>? {
        val id = msg["id"] as String
        val f = CompletableFuture<Map<*, *>>()
        waiting[id] = f
        send(srv.pk!!, msg)
        val again = timer.schedule({ if (!f.isDone) send(srv.pk!!, msg) }, 2, TimeUnit.SECONDS)
        return try { f.get(if (ui.value.online[srv.idx] == true) 6 else 3, TimeUnit.SECONDS) } catch (_: Exception) { null }
            finally { again.cancel(false); waiting.remove(id) }
    }

    /** An app can wake Cosign from nothing: make sure the relays are up before asking. */
    private fun awake() {
        start()
        val until = System.currentTimeMillis() + 5000
        while ((relays?.up() ?: 0) == 0 && System.currentTimeMillis() < until) Thread.sleep(100)
    }

    // --- Answering your servers --------------------------------------------------

    private fun connect(urls: List<String>, secret: String) {
        relays?.stop()
        sk = secret
        relays = Relays(urls, ::onEvent, ::status).also {
            it.start(mapOf("kinds" to listOf(KIND_MEMBER), "#p" to listOf(publicKeyHex(secret.hexToBytes()))))
        }
    }

    private fun onEvent(e: Event) {
        if (e.kind != KIND_MEMBER) { ui.value.member?.let { lists.record(e, it.group.groupX) }; return }
        val msg = whole(e.pubkey, open(e) ?: return) ?: return
        val type = msg["type"] as? String ?: return
        // Relays replay recent ephemeral events to a new subscription; the sender has given up on those.
        if ((type == "sign_req" || type == "ecdh_req") && System.currentTimeMillis() / 1000 - e.createdAt > 30) return
        if (type == "pair_offer") return onOffer(msg, e.pubkey)
        val m = ui.value.member ?: return
        val from = m.group.members.firstOrNull { it.pk == e.pubkey && it.role == "server" } ?: return
        lastSeen[from.idx] = System.currentTimeMillis()
        when (type) {
            "sign_req" -> onSignReq(msg, from, m)
            "ecdh_req" -> onEcdhReq(msg, from, m)
            "state" -> onState(msg)
            "connected" -> onConnected(msg)
            "cosign_res", "ecdh_res" -> (msg["id"] as? String)?.let { waiting.remove(it)?.complete(msg) }
            "signed" -> Event.fromMap(msg["event"])?.let { lists.record(it, m.group.groupX) }
            "undo_failed" -> note("Couldn't undo: ${msg["reason"]}", "denied")
        }
        status()
    }

    private fun onState(msg: Map<*, *>) {
        val sites = (msg["sites"] as? List<*>)?.mapNotNull { x -> (x as? Map<*, *>)?.let {
            Site(it["pk"] as? String ?: return@let null, it["origin"] as? String ?: "a site", it["added"] as? Long ?: 0, it["lastUsed"] as? Long ?: 0,
                it["parent"] as? String, it["via"] as? String) } } ?: return
        val changes = (msg["changes"] as? List<*>)?.mapNotNull { x -> (x as? Map<*, *>)?.let {
            Change(it["id"] as? String ?: return@let null, it["text"] as? String ?: "", it["by"] as? String ?: "", it["at"] as? Long ?: 0, it["held"] == true, it["undone"] == true) } } ?: emptyList()
        ui.update { it.copy(sites = sites.sortedByDescending { s -> s.lastUsed }, changes = changes) }
    }

    private fun onSignReq(msg: Map<*, *>, from: Member, m: Membership) {
        val id = msg["id"] as? String ?: return
        answered[id]?.let { send(from.pk!!, it); return }
        if (id in asking) return
        val reply = { body: Map<String, Any?> -> val full = mapOf("type" to "sign_res", "id" to id) + body; answered[id] = full; send(from.pk!!, full) }
        val ev = Event.fromMap(msg["event"]) ?: return reply(mapOf("ok" to false, "reason" to "malformed event"))
        val participants = (msg["participants"] as? List<*>)?.mapNotNull { (it as? Long)?.toInt() } ?: emptyList()
        val c = msg["commit"] as? Map<*, *>
        val commit = c?.let { Frost.Commit((it["idx"] as Long).toInt(), it["D"] as String, it["E"] as String) }
        val digest = msg["msg"] as? String
        if (commit == null || digest == null || commit.idx != from.idx || participants.sorted() != listOf(from.idx, m.idx).sorted())
            return reply(mapOf("ok" to false, "reason" to "bad participants"))
        // Sign only what we were shown: the digest must be this event's id under your key.
        if (ev.pubkey != m.group.groupX || ev.computeId() != digest) return reply(mapOf("ok" to false, "reason" to "event does not match the message"))
        val app = msg["app"] as? String ?: "a site"
        // Your server's judgement, or this phone's own: either one is enough to ask you.
        val hold = msg["hold"] as? String ?: Policy.hold(ev, lists.latest(Policy.keyOf(ev)))
        val undo = msg["undo"] as? String
        val ask = Ask(id, from.pk!!, from.name, app, ev, digest, commit, hold ?: "", System.currentTimeMillis() + 55_000, if (msg["frost"] == 2L) 2 else 1)
        val myUndo = undo != null && System.currentTimeMillis() - (myUndos[undo] ?: 0) < 120_000
        if (hold == null || myUndo) {
            sign(ask, m, reply)
            if (myUndo) note("Undone", "approved")
            else note("Signed ${Describe.kind(ev.kind)} for $app", "auto")
            return
        }
        asking.add(id)
        send(from.pk!!, mapOf("type" to "asking", "id" to id)) // so the server waits for you, not just a moment
        pendingReplies[id] = reply
        ui.update { it.copy(asks = it.asks + ask, connect = if (it.connect?.stage == Connect.Stage.DONE) null else it.connect) }
        listener?.onAsk(ask)
        timer.schedule({ expire(id) }, 56, TimeUnit.SECONDS)
    }

    fun decide(id: String, approve: Boolean) {
        val ask = ui.value.asks.firstOrNull { it.id == id } ?: return
        val m = ui.value.member ?: return
        val reply = pendingReplies.remove(id) ?: return
        ui.update { it.copy(asks = it.asks.filter { a -> a.id != id }) }
        asking.remove(id)
        listener?.onAskGone(id)
        if (System.currentTimeMillis() > ask.expiresAt) return note("Too late to answer: ${ask.hold}", "denied")
        if (approve) { sign(ask, m, reply); note("You approved: ${ask.hold} (${ask.app})", "approved") }
        else { reply(mapOf("ok" to false, "reason" to "declined on the phone")); note("You declined: ${ask.hold} (${ask.app})", "denied") }
    }

    private fun sign(ask: Ask, m: Membership, reply: (Map<String, Any?>) -> Unit) {
        if (ask.frost == 2) {
            val group = Json.stringify(mapOf("groupX" to m.group.groupX, "threshold" to m.group.threshold,
                "members" to m.group.members.map { mapOf("idx" to it.idx, "sharePub" to it.sharePub) }))
            val c = Json.parse(FrostNative.commit(group, m.idx, m.share)) as Map<*, *>
            val mine = c["commit"] as Map<*, *>
            val theirs = mapOf("idx" to ask.commit.idx, "D" to ask.commit.D, "E" to ask.commit.E)
            val z = FrostNative.sign(group, m.idx, m.share, c["nonces"] as String, ask.msg, Json.stringify(listOf(theirs, mine)))
            return reply(mapOf("ok" to true, "z" to z, "commit" to mine))
        }
        val (nonces, mine) = Frost.commit(m.idx, env)
        val z = Frost.partialSign(m.group.groupX, ask.msg, listOf(ask.commit, mine), m.idx, m.share, nonces)
        reply(mapOf("ok" to true, "z" to z, "commit" to mapOf("idx" to mine.idx, "D" to mine.D, "E" to mine.E)))
    }

    private fun expire(id: String) {
        val ask = ui.value.asks.firstOrNull { it.id == id } ?: return
        pendingReplies.remove(id)
        asking.remove(id)
        ui.update { it.copy(asks = it.asks.filter { a -> a.id != id }) }
        listener?.onAskGone(id)
        note("Not answered in time: ${ask.hold} (${ask.app})", "denied")
    }

    private fun onEcdhReq(msg: Map<*, *>, from: Member, m: Membership) {
        val id = msg["id"] as? String ?: return
        answered[id]?.let { send(from.pk!!, it); return }
        val participants = (msg["participants"] as? List<*>)?.mapNotNull { (it as? Long)?.toInt() } ?: return
        val peerX = msg["peerX"] as? String ?: return
        if (!isHex32(peerX) || participants.sorted() != listOf(from.idx, m.idx).sorted()) return
        val body = mapOf("type" to "ecdh_res", "id" to id, "ok" to true, "point" to Frost.ecdhPartial(m.idx, m.share, participants, peerX))
        answered[id] = body
        send(from.pk!!, body)
        if (System.currentTimeMillis() - lastEcdhNote > 60_000) {
            lastEcdhNote = System.currentTimeMillis()
            note("Helped ${from.name} read your messages", "auto")
        }
    }

    private fun pingServers() {
        val m = ui.value.member ?: return
        for (s in servers()) send(s.pk!!, mapOf("type" to "ping", "idx" to m.idx, "ts" to System.currentTimeMillis()))
        if (answered.size > 300) answered.keys.take(150).forEach { answered.remove(it) }
    }

    private fun status() {
        val m = ui.value.member
        val now = System.currentTimeMillis()
        val online = m?.group?.members?.associate { it.idx to (it.idx == m.idx || now - (lastSeen[it.idx] ?: 0) < 30_000) } ?: emptyMap()
        ui.update { it.copy(online = online, relaysUp = relays?.up() ?: 0) }
        listener?.onStatus()
    }

    private fun note(text: String, kind: String = "info") {
        ui.update { it.copy(log = (listOf(Line(System.currentTimeMillis(), text, kind)) + it.log).take(60)) }
        secrets.saveLog(Json.stringify(ui.value.log.map { mapOf("ts" to it.ts, "text" to it.text, "kind" to it.kind) }))
    }

    // --- Sealed messages ----------------------------------------------------

    private fun send(toPk: String, body: Map<String, Any?>) {
        val text = Json.stringify(body)
        if (text.length <= PART) return seal(toPk, text)
        val id = env.random(8).toHex(); val n = (text.length + PART - 1) / PART
        for (i in 0 until n) seal(toPk, Json.stringify(mapOf("type" to "part", "id" to id, "i" to i, "n" to n, "data" to text.substring(i * PART, minOf(text.length, (i + 1) * PART)))))
    }

    private fun seal(toPk: String, text: String) {
        val secret = sk?.hexToBytes() ?: return
        val content = Nip44.encrypt(text, Nip44.conversationKey(secret, toPk), env.random(32))
        relays?.publish(Event.sign(publicKeyHex(secret), env.now(), KIND_MEMBER, listOf(listOf("p", toPk)), content, secret, env))
    }

    /** The message, once all its parts are in (server/net.ts sealParts is the other half). */
    private fun whole(fromPk: String, msg: Map<*, *>): Map<*, *>? {
        if (msg["type"] != "part") return msg
        val id = msg["id"] as? String ?: return null
        val i = (msg["i"] as? Long)?.toInt() ?: return null
        val n = (msg["n"] as? Long)?.toInt() ?: return null
        if (n !in 1..64 || i !in 0 until n) return null
        val now = System.currentTimeMillis()
        parts.entries.removeIf { now - it.value.first > 120_000 }
        val got = parts.getOrPut("$fromPk:$id") { now to arrayOfNulls(n) }.second
        if (got.size != n) return null
        got[i] = msg["data"] as? String ?: return null
        if (got.any { it == null }) return null
        parts.remove("$fromPk:$id")
        return try { Json.parse(got.joinToString("")) as? Map<*, *> } catch (_: Exception) { null }
    }

    private fun open(e: Event): Map<*, *>? = try {
        val secret = sk?.hexToBytes() ?: throw IllegalStateException()
        Json.parse(Nip44.decrypt(e.content, Nip44.conversationKey(secret, e.pubkey))) as? Map<*, *>
    } catch (_: Exception) { null }

    // --- Serialisation -------------------------------------------------------

    private fun parseGroup(v: Any?): Group? {
        val g = v as? Map<*, *> ?: return null
        val members = (g["members"] as? List<*>)?.mapNotNull { x ->
            val mm = x as? Map<*, *> ?: return@mapNotNull null
            Member((mm["idx"] as Long).toInt(), mm["name"] as String, mm["role"] as String, mm["pk"] as? String, mm["sharePub"] as String)
        } ?: return null
        return Group(g["groupX"] as? String ?: return null, g["npub"] as? String ?: "", (g["threshold"] as? Long)?.toInt() ?: 2,
            (g["relays"] as? List<*>)?.filterIsInstance<String>() ?: return null, members)
    }

    private fun parseMembership(v: Any?): Membership? {
        val m = v as? Map<*, *> ?: return null
        return Membership(m["sk"] as String, (m["idx"] as Long).toInt(), m["share"] as String, m["signer"] as? String ?: return null, parseGroup(m["group"]) ?: return null)
    }

    private fun membershipToMap(m: Membership) = mapOf(
        "sk" to m.sk, "idx" to m.idx, "share" to m.share, "signer" to m.signer,
        "group" to mapOf(
            "groupX" to m.group.groupX, "npub" to m.group.npub, "threshold" to m.group.threshold, "relays" to m.group.relays,
            "members" to m.group.members.map { mapOf("idx" to it.idx, "name" to it.name, "role" to it.role, "pk" to it.pk, "sharePub" to it.sharePub) },
        ),
    )

    companion object { const val KIND_MEMBER = 28001; private const val PART = 24_000 }
}

object Describe {
    private val names = mapOf(
        0 to "profile", 1 to "note", 3 to "follow list", 4 to "DM", 5 to "deletion", 6 to "repost", 7 to "reaction",
        13 to "DM", 14 to "DM", 16 to "repost", 62 to "request to vanish", 1111 to "comment", 9734 to "zap request", 10000 to "mute list",
        10002 to "relay list", 10003 to "bookmarks", 22242 to "relay login", 24242 to "upload login", 27235 to "web login", 30023 to "article", 30078 to "app data",
    )
    fun kind(k: Int) = names[k] ?: "kind $k event"
}
