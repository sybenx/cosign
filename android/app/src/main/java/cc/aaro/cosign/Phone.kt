package cc.aaro.cosign

import android.content.Context
import android.net.Uri
import cc.aaro.cosign.core.Event
import cc.aaro.cosign.core.Frost
import cc.aaro.cosign.core.Json
import cc.aaro.cosign.core.Nip44
import cc.aaro.cosign.core.SystemEnv
import cc.aaro.cosign.core.generateSecretKey
import cc.aaro.cosign.core.hexToBytes
import cc.aaro.cosign.core.isHex32
import cc.aaro.cosign.core.publicKeyHex
import cc.aaro.cosign.core.toHex
import cc.aaro.cosign.net.Relays
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

data class Member(val idx: Int, val name: String, val role: String, val pk: String?, val sharePub: String)
data class Group(val groupX: String, val npub: String, val threshold: Int, val relays: List<String>, val autoKinds: List<Int>, val members: List<Member>)
data class Membership(val sk: String, val idx: Int, val share: String, val group: Group)
data class Offer(val fromPk: String, val token: String, val idx: Int, val share: String, val group: Group)
/** A signing request waiting for the user. */
data class Ask(val id: String, val fromPk: String, val via: String, val app: String, val event: Event, val msg: String, val commit: Frost.Commit, val expiresAt: Long)
data class Line(val ts: Long, val text: String, val kind: String = "info")

data class Ui(
    val member: Membership? = null,
    val joining: String? = null,
    val offer: Offer? = null,
    val error: String? = null,
    val asks: List<Ask> = emptyList(),
    val online: Map<Int, Boolean> = emptyMap(),
    val relaysUp: Int = 0,
    val log: List<Line> = emptyList(),
)

/**
 * Everything the phone does as a member: join by scanning, answer the servers,
 * and ask its user about anything that isn't routine.
 *
 * The phone never starts a signature. A server does, when an app asks it to; the
 * phone is the second signer whenever the event needs one, or whenever the other
 * server is down.
 */
class Phone(context: Context) {
    interface Listener { fun onAsk(ask: Ask); fun onAskGone(id: String); fun onStatus() }

    private val store = Store(context)
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
    private var lastEcdhNote = 0L

    init {
        store.loadMembership()?.let { parseMembership(Json.parse(it)) }?.let { m -> ui.update { it.copy(member = m) } }
        store.loadLog()?.let { Json.parse(it) as? List<*> }?.let { lines ->
            ui.update { u -> u.copy(log = lines.mapNotNull { (it as? Map<*, *>)?.let { m -> Line(m["ts"] as Long, m["text"] as String, m["kind"] as? String ?: "info") } }) }
        }
    }

    val isMember get() = ui.value.member != null

    /** Start answering, if this phone is in a group. Called by the service. */
    fun start() {
        val m = ui.value.member ?: return
        // Joining already opened the relays with this key; reuse them.
        if (relays == null || sk != m.sk) connect(m.group.relays, m.sk)
        if (pinger?.isCancelled != false) pinger = timer.scheduleWithFixedDelay({ pingServers(); status() }, 0, 10, TimeUnit.SECONDS)
    }

    fun stop() { pinger?.cancel(false); pinger = null; relays?.stop(); relays = null; sk = null }

    // --- Joining -------------------------------------------------------------

    fun scanned(text: String) {
        val uri = Uri.parse(text.trim().replace("cosign:pair?", "cosign://pair?"))
        val pk = uri.getQueryParameter("pk")
        val token = uri.getQueryParameter("t")
        val urls = uri.getQueryParameters("r").filter { it.startsWith("wss://") || it.startsWith("ws://") }
        if (uri.scheme != "cosign" || !isHex32(pk) || token.isNullOrBlank() || urls.isEmpty()) {
            ui.update { it.copy(error = "That isn't a Cosign pairing code.") }
            return
        }
        pairing = uri
        val temp = generateSecretKey(env).toHex()
        connect(urls, temp)
        ui.update { it.copy(joining = "Reaching your server…", error = null, offer = null) }
        // Say hello until the server answers, for up to 20 s.
        val started = System.currentTimeMillis()
        helloer?.cancel(false)
        helloer = timer.scheduleWithFixedDelay({
            if (ui.value.offer != null || pairing == null) { helloer?.cancel(false); return@scheduleWithFixedDelay }
            if (System.currentTimeMillis() - started > 20_000) {
                helloer?.cancel(false); relays?.stop(); relays = null
                ui.update { it.copy(joining = null, error = "The server didn't answer. Is it running, and is the code still on its page?") }
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
        // Keep nothing that isn't the share it says it is.
        if (group.members.firstOrNull { it.idx == idx }?.sharePub != Frost.sharePub(share)) {
            ui.update { it.copy(joining = null, error = "The server sent a share that doesn't match its group. Nothing was kept.") }
            return
        }
        helloer?.cancel(false)
        ui.update { it.copy(joining = null, offer = Offer(fromPk, msg["token"] as String, idx, share, group)) }
    }

    fun accept() {
        val o = ui.value.offer ?: return
        val mySk = sk ?: return
        val me = publicKeyHex(mySk.hexToBytes())
        val group = o.group.copy(members = o.group.members.map { if (it.idx == o.idx) it.copy(pk = me) else it })
        val m = Membership(mySk, o.idx, o.share, group)
        store.saveMembership(Json.stringify(membershipToMap(m)))
        send(o.fromPk, mapOf("type" to "pair_ack", "token" to o.token))
        pairing = null
        ui.update { it.copy(member = m, offer = null) }
        note("Joined. This phone holds 1 of ${group.members.size} shares.")
        lastSeen[group.members.first { it.pk == o.fromPk }.idx] = System.currentTimeMillis()
        start()
    }

    fun decline() {
        pairing = null; helloer?.cancel(false); relays?.stop(); relays = null; sk = null
        ui.update { it.copy(offer = null, joining = null) }
    }

    fun clearError() = ui.update { it.copy(error = null) }

    fun leave() {
        stop(); store.clear(); lastSeen.clear()
        ui.value = Ui()
    }

    // --- Answering -----------------------------------------------------------

    private fun connect(urls: List<String>, secret: String) {
        relays?.stop()
        sk = secret
        relays = Relays(urls, ::onEvent, ::status).also {
            it.start(mapOf("kinds" to listOf(KIND_MEMBER), "#p" to listOf(publicKeyHex(secret.hexToBytes()))))
        }
    }

    private fun onEvent(e: Event) {
        if (e.kind != KIND_MEMBER) return
        val msg = open(e) ?: return
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
        }
        status()
    }

    private fun onSignReq(msg: Map<*, *>, from: Member, m: Membership) {
        val id = msg["id"] as? String ?: return
        val reply = { body: Map<String, Any> -> send(from.pk!!, mapOf("type" to "sign_res", "id" to id) + body) }
        val ev = Event.fromMap(msg["event"]) ?: return reply(mapOf("ok" to false, "reason" to "malformed event"))
        val participants = (msg["participants"] as? List<*>)?.mapNotNull { (it as? Long)?.toInt() } ?: emptyList()
        val c = msg["commit"] as? Map<*, *>
        val commit = c?.let { Frost.Commit((it["idx"] as Long).toInt(), it["D"] as String, it["E"] as String) }
        val digest = msg["msg"] as? String
        if (commit == null || commit.idx != from.idx || participants.sorted() != listOf(from.idx, m.idx).sorted())
            return reply(mapOf("ok" to false, "reason" to "bad participants"))
        // Sign only what we were shown: the digest must be this event's id under the group key.
        if (ev.pubkey != m.group.groupX || ev.computeId() != digest)
            return reply(mapOf("ok" to false, "reason" to "event does not match the message"))
        val app = msg["app"] as? String ?: "an app"
        val ask = Ask(id, from.pk!!, from.name, app, ev, digest, commit, System.currentTimeMillis() + 55_000)
        if (ev.kind in m.group.autoKinds) {
            // Routine, and only here because the other server is down.
            sign(ask, m)
            note("Signed ${Kinds.name(ev.kind)} for $app with ${from.name} (routine; the other server was down)", "auto")
            return
        }
        ui.update { it.copy(asks = it.asks + ask) }
        listener?.onAsk(ask)
        timer.schedule({ expire(id) }, 56, TimeUnit.SECONDS)
    }

    fun decide(id: String, approve: Boolean) {
        val ask = ui.value.asks.firstOrNull { it.id == id } ?: return
        val m = ui.value.member ?: return
        ui.update { it.copy(asks = it.asks.filter { a -> a.id != id }) }
        listener?.onAskGone(id)
        if (System.currentTimeMillis() > ask.expiresAt) return note("Too late to answer: ${Kinds.name(ask.event.kind)} for ${ask.app}", "denied")
        if (approve) {
            sign(ask, m)
            note("You approved ${Kinds.name(ask.event.kind)} for ${ask.app}", "approved")
        } else {
            send(ask.fromPk, mapOf("type" to "sign_res", "id" to id, "ok" to false, "reason" to "declined on the phone"))
            note("You declined ${Kinds.name(ask.event.kind)} for ${ask.app}", "denied")
        }
    }

    private fun sign(ask: Ask, m: Membership) {
        val (nonces, mine) = Frost.commit(m.idx, env)
        val z = Frost.partialSign(m.group.groupX, ask.msg, listOf(ask.commit, mine), m.idx, m.share, nonces)
        send(ask.fromPk, mapOf("type" to "sign_res", "id" to ask.id, "ok" to true, "z" to z,
            "commit" to mapOf("idx" to mine.idx, "D" to mine.D, "E" to mine.E)))
    }

    private fun expire(id: String) {
        val ask = ui.value.asks.firstOrNull { it.id == id } ?: return
        ui.update { it.copy(asks = it.asks.filter { a -> a.id != id }) }
        listener?.onAskGone(id)
        note("Nobody answered: ${Kinds.name(ask.event.kind)} for ${ask.app}", "denied")
    }

    private fun onEcdhReq(msg: Map<*, *>, from: Member, m: Membership) {
        val id = msg["id"] as? String ?: return
        val participants = (msg["participants"] as? List<*>)?.mapNotNull { (it as? Long)?.toInt() } ?: return
        val peerX = msg["peerX"] as? String ?: return
        if (!isHex32(peerX) || participants.sorted() != listOf(from.idx, m.idx).sorted()) return
        val point = Frost.ecdhPartial(m.idx, m.share, participants, peerX)
        send(from.pk!!, mapOf("type" to "ecdh_res", "id" to id, "ok" to true, "point" to point))
        if (System.currentTimeMillis() - lastEcdhNote > 60_000) {
            lastEcdhNote = System.currentTimeMillis()
            note("Helped ${from.name} decrypt messages (the other server was down)", "auto")
        }
    }

    private fun pingServers() {
        val m = ui.value.member ?: return
        for (s in m.group.members) if (s.role == "server" && s.pk != null) send(s.pk, mapOf("type" to "ping", "idx" to m.idx, "ts" to System.currentTimeMillis()))
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
        store.saveLog(Json.stringify(ui.value.log.map { mapOf("ts" to it.ts, "text" to it.text, "kind" to it.kind) }))
    }

    // --- Sealed messages ----------------------------------------------------

    private fun send(toPk: String, body: Map<String, Any?>) {
        val secret = sk?.hexToBytes() ?: return
        val content = Nip44.encrypt(Json.stringify(body), Nip44.conversationKey(secret, toPk), env.random(32))
        val e = Event.sign(publicKeyHex(secret), env.now(), KIND_MEMBER, listOf(listOf("p", toPk)), content, secret, env)
        relays?.publish(e)
    }

    private fun open(e: Event): Map<*, *>? = try {
        val secret = sk?.hexToBytes() ?: return null
        Json.parse(Nip44.decrypt(e.content, Nip44.conversationKey(secret, e.pubkey))) as? Map<*, *>
    } catch (_: Exception) { null }

    // --- Serialisation -------------------------------------------------------

    private fun parseGroup(v: Any?): Group? {
        val g = v as? Map<*, *> ?: return null
        val members = (g["members"] as? List<*>)?.mapNotNull { x ->
            val mm = x as? Map<*, *> ?: return@mapNotNull null
            Member((mm["idx"] as Long).toInt(), mm["name"] as String, mm["role"] as String, mm["pk"] as? String, mm["sharePub"] as String)
        } ?: return null
        return Group(
            g["groupX"] as? String ?: return null, g["npub"] as? String ?: "", (g["threshold"] as? Long)?.toInt() ?: 2,
            (g["relays"] as? List<*>)?.filterIsInstance<String>() ?: return null,
            (g["autoKinds"] as? List<*>)?.mapNotNull { (it as? Long)?.toInt() } ?: emptyList(),
            members,
        )
    }

    private fun parseMembership(v: Any?): Membership? {
        val m = v as? Map<*, *> ?: return null
        return Membership(m["sk"] as String, (m["idx"] as Long).toInt(), m["share"] as String, parseGroup(m["group"]) ?: return null)
    }

    private fun membershipToMap(m: Membership) = mapOf(
        "sk" to m.sk, "idx" to m.idx, "share" to m.share,
        "group" to mapOf(
            "groupX" to m.group.groupX, "npub" to m.group.npub, "threshold" to m.group.threshold,
            "relays" to m.group.relays, "autoKinds" to m.group.autoKinds,
            "members" to m.group.members.map { mapOf("idx" to it.idx, "name" to it.name, "role" to it.role, "pk" to it.pk, "sharePub" to it.sharePub) },
        ),
    )

    companion object { const val KIND_MEMBER = 28001 }
}

object Kinds {
    private val names = mapOf(
        0 to "profile", 1 to "note", 3 to "follow list", 4 to "DM", 5 to "deletion", 6 to "repost", 7 to "reaction",
        13 to "DM", 14 to "DM", 16 to "repost", 1111 to "comment", 9734 to "zap request", 10000 to "mute list",
        10002 to "relay list", 22242 to "relay login", 24242 to "upload login", 27235 to "web login", 30023 to "article", 30078 to "app settings",
    )
    fun name(k: Int) = names[k] ?: "kind $k event"

    /** One line saying what an event would do, in plain words. */
    fun describe(e: Event): String = when (e.kind) {
        0 -> (Json.parse(e.content) as? Map<*, *>)?.let { p ->
            listOfNotNull((p["name"] ?: p["display_name"])?.let { "name “$it”" }, p["about"]?.let { "about “${it.toString().take(80)}”" }, p["picture"]?.let { "a new picture" })
                .joinToString(", ").ifEmpty { "an empty profile" }.let { "Change your profile to $it" }
        } ?: "Change your profile"
        3 -> "Replace your follow list with ${e.tags.count { it.firstOrNull() == "p" }} people"
        5 -> "Delete ${e.tags.count { it.firstOrNull() == "e" || it.firstOrNull() == "a" }} of your events"
        10002 -> "Replace your relay list with ${e.tags.count { it.firstOrNull() == "r" }} relays"
        else -> e.content.take(280).ifBlank { "No text" }
    }
}
