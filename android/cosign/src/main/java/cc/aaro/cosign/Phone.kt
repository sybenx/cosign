package cc.aaro.cosign

import android.content.Context
import android.net.Uri
import cc.aaro.cosign.core.Clock
import cc.aaro.cosign.core.CodeCheck
import cc.aaro.cosign.core.Event
import cc.aaro.cosign.core.Frost
import cc.aaro.cosign.core.FrostNative
import cc.aaro.cosign.core.Dkg
import cc.aaro.cosign.core.Nip19
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
import cc.aaro.cosign.core.CosignMemberProfile
import cc.aaro.cosign.core.MemberMove
import cc.aaro.cosign.core.Refresh
import cc.aaro.cosign.core.Backup
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

/** One share point of the key. */
data class Point(val idx: Int, val sharePub: String) : java.io.Serializable
/** A member holds one share (a server) or, in a weighted key, several (a device holds 3). [idx]/[sharePub] are its first. */
data class Member(val idx: Int, val name: String, val role: String, val pk: String?, val sharePub: String, val shares: List<Point>? = null) : java.io.Serializable {
    val points get() = shares ?: listOf(Point(idx, sharePub))
    val idxs get() = points.map { it.idx }
}
data class Group(val groupX: String, val npub: String, val threshold: Int, val relays: List<String>, val members: List<Member>) : java.io.Serializable
/** One of this device's own shares. */
data class Share(val idx: Int, val secret: String) : java.io.Serializable
/** [mirrored]: the key brought in had an odd y, so FROST holds its twin (the same npub); null if not known here. */
data class Membership(val sk: String, val idx: Int, val shares: List<Share>, val signer: String, val group: Group, val epoch: Int = 0, val mirrored: Boolean? = null) : java.io.Serializable {
    /** The first share: what a one-share member signs with, and what repair uses until weighted repair. */
    val share get() = shares.first().secret
    val idxs get() = shares.map { it.idx }
}
/** A server's offer to join. [plan]: a weighted key not made yet, which this phone and the servers make together; then there's no [share]. */
data class Offer(val fromPk: String, val token: String, val idx: Int, val share: String?, val signer: String, val group: Group, val plan: Map<*, *>? = null) : java.io.Serializable
/** Something destructive, waiting for you. */
/** [frost]: which signing math the server asked for (2 = the library, 1 = the earlier one). */
data class Ask(val id: String, val fromPk: String, val via: String, val app: String, val event: Event, val msg: String, val commit: Frost.Commit, val hold: String, val expiresAt: Long, val frost: Int = 1,
    /** The server's commitments, one per share it holds (one, for a server). */
    val commits: List<Frost.Commit> = listOf(commit)) : java.io.Serializable
/** A grant. [parent]: the connected site (the extension) that added it; [via]: what connected it. */
data class Site(val pk: String, val origin: String, val added: Long, val lastUsed: Long, val parent: String? = null, val via: String? = null) : java.io.Serializable
data class Change(val id: String, val text: String, val by: String, val at: Long, val held: Boolean, val undone: Boolean) : java.io.Serializable
/** Deletions held for a few seconds, with Undo. */
data class Deleting(val batch: String, val by: String, val count: Int, val until: Long) : java.io.Serializable
/** One approval for a batch of deletions. */
data class BatchAsk(val batch: String, val text: String, val by: String, val expiresAt: Long) : java.io.Serializable
/** A deleted event a server kept a copy of: it can be posted again. */
data class Deleted(val id: String, val kind: String, val at: Long, val text: String) : java.io.Serializable
/** What undoing a site would do, for you to confirm. */
data class SiteSummary(val pk: String, val origin: String, val total: Int, val counts: Map<String, Int>, val lists: List<String>, val deletable: Int) : java.io.Serializable
/** A new device asking to join your key. */
data class AddingDevice(val pk: String, val name: String, val relays: List<String>) : java.io.Serializable
/** A version of one of your lists dated in the future, found on relays: it blocks every change. */
data class Future(val id: String, val text: String) : java.io.Serializable
data class Connect(val origin: String, val stage: Stage, val message: String? = null) : java.io.Serializable { enum class Stage { CONFIRM, WORKING, DONE, FAILED } }
/** This phone being restored from a paper backup. [until]: when the wait ends, once it's started. */
data class Restoring(val text: String, val until: Long? = null, val failed: Boolean = false) : java.io.Serializable
/** A key moving in from a web page (QRST `cosign-member`): its code, then whether to keep it. */
data class MoveIn(val stage: Stage, val code: String? = null, val text: String? = null) : java.io.Serializable { enum class Stage { WAITING, CODE, ACCEPT, DONE, FAILED } }
data class Line(val ts: Long, val text: String, val kind: String = "info") : java.io.Serializable
/** Taking the account out of Cosign: waiting (until), the key shown, or why not. */
data class TakeOut(val stage: Stage, val text: String = "", val until: Long? = null, val nsec: String? = null, val npub: String? = null, val twinUnknown: Boolean = false) : java.io.Serializable {
    enum class Stage { WAITING, SHOWING, FAILED }
}
/** A guarded action a server told every device about (COSIGN.md §7.6): report lost, take out, removing the servers' pieces. */
data class GuardNote(val id: String, val kind: String, val by: String, val state: String, val until: Long, val paper: Boolean) : java.io.Serializable
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
    val future: List<Future> = emptyList(),
    val deleting: List<Deleting> = emptyList(),
    val batchAsks: List<BatchAsk> = emptyList(),
    val deleted: List<Deleted> = emptyList(),
    val summary: SiteSummary? = null,
    /** A new device's code you scanned: add it? */
    val adding: AddingDevice? = null,
    /** This (new) device's code, while it waits for one of yours to add it. */
    val joinCode: String? = null,
    val connect: Connect? = null,
    val moveIn: MoveIn? = null,
    /** A device you're about to report lost (the sheet asks for this phone's lock). */
    val reporting: Member? = null,
    /** This phone was reported lost, by this device. It can say it wasn't. */
    val removedBy: String? = null,
    /** A paper backup just made: its code, shown once. */
    val paper: String? = null,
    /** Making a paper backup, or restoring from one: what's happening. */
    val paperStatus: String? = null,
    /** Restoring this phone from a paper backup. */
    val restoring: Restoring? = null,
    /** Your paper backup is being used somewhere: for whom, and until when it can be cancelled. */
    val recovery: Pair<String, Long>? = null,
    /** Just made, imported or joined, with one device and no paper: offer the paper now (once; "Later" is fine). */
    val askPaper: Boolean = false,
    /** Adding a server: the ones found that this key doesn't use yet (null while looking). */
    val serverChoice: List<cc.aaro.cosign.net.Servers.Server>? = null,
    /** A one-time code from a server's own page, for the server in [serverChoice]. */
    val addCode: String? = null,
    val takeOut: TakeOut? = null,
    /** Guarded actions on your account, newest first, as the servers announce them. */
    val guards: List<GuardNote> = emptyList(),
    /** Asking for the paper code, to take the account out with it. */
    val takeOutPaper: Boolean = false,
    val push: String? = null,
) : java.io.Serializable

/**
 * The phone's part: your remote control, and one share of your key.
 *
 * It connects sites (scan a site's code; your servers give it access of its own), shows
 * and removes what's connected, approves anything destructive, and undoes changes. It
 * co-signs routine things itself only while one of your servers is down.
 *
 * It lives in the signer process only (Proc); the UI has a stand-in, [Phone], that asks it over [ISigner].
 */
class Signer(private val context: Context, val slot: String = "0") {
    /** This key's own storage names; the first key keeps the ones it always had. */
    private fun named(base: String) = if (slot == "0") base else "$base.$slot"
    interface Listener {
        fun onAsk(ask: Ask); fun onAskGone(id: String); fun onStatus()
        fun onDeleting(d: Deleting) {}; fun onDeletingGone(batch: String) {}
        fun onBatch(b: BatchAsk) {}; fun onBatchGone(batch: String) {}
        /** Something to say while Cosign isn't on screen (a sign-in that didn't go through). */
        fun onNotice(title: String, text: String) {}
    }

    private val secrets = Secrets(context, slot)
    private val lists = Lists(context, slot)
    /** Big messages arrive in parts (NIP-44 stops at 64 KB); these are the ones still coming in. */
    private val parts = ConcurrentHashMap<String, Pair<Long, Array<String?>>>()
    private val env = SystemEnv
    val ui = MutableStateFlow(Ui())
    @Volatile var listener: Listener? = null
    /** Called when this key is left, so the app can forget it (Signers). */
    @Volatile var onLeft: ((Signer) -> Unit)? = null

    /** Which key this is, for a notification or a list: its npub, shortened. */
    val label get() = ui.value.member?.group?.npub?.let { if (it.length > 20) it.take(12) + "…" + it.takeLast(6) else it } ?: "New key"

    private var relays: Relays? = null
    private var sk: String? = null
    private var pairing: Uri? = null
    private val lastSeen = ConcurrentHashMap<Int, Long>()
    private val timer = Executors.newSingleThreadScheduledExecutor()
    private var pinger: ScheduledFuture<*>? = null
    private var clockCheck: ScheduledFuture<*>? = null
    private var helloer: ScheduledFuture<*>? = null
    /** Answers already given, by request id: a repeat gets the same answer, never a second partial. */
    private val answered = ConcurrentHashMap<String, Map<String, Any?>>()
    private val asking = ConcurrentHashMap.newKeySet<String>()
    private val pendingReplies = ConcurrentHashMap<String, (Map<String, Any?>) -> Unit>()
    private val myUndos = ConcurrentHashMap<String, Long>()
    /** What you just removed here (sites, flagged versions, reposted copies). Your two servers each
     *  send their list; the one that hasn't heard yet would bring it back for a moment. */
    private val justRemoved = ConcurrentHashMap<String, Long>()
    private fun removedHere(id: String) = System.currentTimeMillis() - (justRemoved[id] ?: 0) < 60_000
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
        // A restore from paper survives restarts: its wait takes days.
        if (ui.value.member == null) secrets.load("restoring")?.let { Json.parse(it) as? Map<*, *> }?.let { timer.execute { resumeRestore(it) } }
    }

    val isMember get() = ui.value.member != null

    /** One device and no paper backup: lose this phone and the key is gone. */
    val needsPaper get() = ui.value.member?.group?.let { g -> g.threshold >= 4 && g.members.none { it.role == "backup" } && g.members.count { it.role == "phone" || it.role == "device" } <= 1 } ?: false
    private val nudges = context.getSharedPreferences(named("nudges"), Context.MODE_PRIVATE)

    /** Right after the key arrives on this phone: the paper, once, if it's the only device. */
    private fun offerPaper() { if (needsPaper && !nudges.getBoolean("asked", false)) { nudges.edit().putBoolean("asked", true).apply(); ui.update { it.copy(askPaper = true) } } }
    fun laterPaper() = ui.update { it.copy(askPaper = false) }
    private fun servers() = ui.value.member?.group?.members?.filter { it.role == "server" && it.pk != null } ?: emptyList()

    /** Start answering, if this phone is in a group. Called by the service. */
    fun start() {
        val m = ui.value.member ?: return
        // A day on, still one device and no paper: say so once, outside the app too.
        if (!nudges.contains("since")) nudges.edit().putLong("since", System.currentTimeMillis()).apply()
        if (needsPaper && !nudges.getBoolean("told", false) && System.currentTimeMillis() - nudges.getLong("since", 0) > 86_400_000) {
            nudges.edit().putBoolean("told", true).apply()
            listener?.onNotice("Make your paper backup", "If you lose this phone, you can't get your account back without it. Open $appName to make one.")
        }
        if (relays == null || sk != m.sk) connect(m.group.relays, m.sk)
        relays?.watch(mapOf("kinds" to Policy.ARCHIVED.toList(), "authors" to listOf(m.group.groupX)))
        if (pinger?.isCancelled != false) pinger = timer.scheduleWithFixedDelay({ pingServers(); status() }, 0, 10, TimeUnit.SECONDS)
        timer.schedule({ requestState(); ui.value.push?.let { tellPush(it) } }, 2, TimeUnit.SECONDS)
        // Judge "the future" by the network's time, not this phone's clock.
        if (clockCheck?.isCancelled != false) clockCheck = timer.scheduleWithFixedDelay({
            Clock.check()?.let { off -> if (kotlin.math.abs(off) > 60) note("This phone's clock is ${kotlin.math.abs(off)} s ${if (off < 0) "ahead" else "behind"}: using the network's time") }
        }, 0, 30, TimeUnit.MINUTES)
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
        val signer = msg["signer"] as? String ?: return
        if (msg["weighted"] == true) {
            // No key yet: it's made when you say yes. Which member we'll be is in the plan.
            val plan = msg["plan"] as? Map<*, *> ?: return
            val me = publicKeyHex((sk ?: return).hexToBytes())
            val first = (plan["holders"] as? List<*>)?.mapNotNull { it as? Map<*, *> }?.firstOrNull { it["pk"] == me }?.let { (it["idx"] as Long).toInt() } ?: return
            val idx = group.members.firstOrNull { first in it.idxs }?.idx ?: return
            helloer?.cancel(false)
            ui.update { it.copy(joining = null, offer = Offer(fromPk, msg["token"] as String, idx, null, signer, group, plan)) }
            return
        }
        val idx = (msg["idx"] as? Long)?.toInt() ?: return
        val share = msg["share"] as? String ?: return
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
        if (o.plan != null) return makeKey(o, mySk, me)
        val group = o.group.copy(members = o.group.members.map { if (it.idx == o.idx) it.copy(pk = me) else it })
        joined(o, Membership(mySk, o.idx, listOf(Share(o.idx, o.share!!)), o.signer, group), "Joined. This phone holds 1 of ${group.members.size} shares.")
    }

    private fun joined(o: Offer, m: Membership, line: String, ack: Map<String, Any?> = emptyMap()) {
        secrets.saveMembership(Json.stringify(membershipToMap(m)))
        val ackMsg = mapOf("type" to "pair_ack", "token" to o.token) + ack
        send(o.fromPk, ackMsg)
        if (ack.isNotEmpty()) timer.schedule({ send(o.fromPk, ackMsg) }, 4, TimeUnit.SECONDS) // the server may still be finishing the key
        pairing = null
        ui.update { it.copy(member = m, offer = null, joining = null) }
        note(line)
        offerPaper()
        lastSeen[m.group.members.first { it.pk == o.fromPk }.idx] = System.currentTimeMillis()
        start()
    }

    // A weighted key: this phone and both servers make it together (Dkg.kt); nobody ever
    // holds all of it. This phone ends up with 3 shares, each server 1, and it takes 4.
    private var dkg: Dkg? = null
    private var dkgTicker: ScheduledFuture<*>? = null

    private fun makeKey(o: Offer, mySk: String, me: String) {
        ui.update { it.copy(offer = null, joining = "Making your key with your servers…") }
        val started = System.currentTimeMillis()
        val run = try { Dkg(o.plan!!, me, ::send) { r -> timer.execute { keyMade(o, mySk, me, r) } } } catch (e: Exception) {
            return ui.update { it.copy(joining = null, error = "Couldn't start making your key: ${e.message}") }
        }
        dkg = run
        dkgTicker?.cancel(false)
        dkgTicker = timer.scheduleWithFixedDelay({
            val doneFor = run.done?.let { System.currentTimeMillis() - started } ?: 0
            if (dkg !== run || doneFor > 80_000) { dkgTicker?.cancel(false); return@scheduleWithFixedDelay }
            if (run.done == null && System.currentTimeMillis() - started > 60_000) {
                dkgTicker?.cancel(false); dkg = null
                ui.update { it.copy(joining = null, error = "Your servers didn't finish making the key. Scan the code again.") }
                return@scheduleWithFixedDelay
            }
            run.tick()
        }, 0, 4, TimeUnit.SECONDS)
    }

    private fun keyMade(o: Offer, mySk: String, me: String, r: Dkg.Result) {
        val pub = r.members.toMap()
        val members = o.group.members.map { m ->
            val pts = m.idxs.map { Point(it, pub[it] ?: return) }
            m.copy(sharePub = pts[0].sharePub, shares = if (m.shares != null) pts else null, pk = if (m.idx == o.idx) me else m.pk)
        }
        val group = o.group.copy(groupX = r.groupX, npub = Nip19.npub(r.groupX), members = members)
        val m = Membership(mySk, o.idx, r.shares.map { Share(it.first, it.second) }, o.signer, group)
        joined(o, m, "Your key was made. This phone holds ${m.shares.size} of ${pub.size} shares; it and either server can sign.", mapOf("groupX" to r.groupX))
    }

    fun decline() {
        pairing = null; helloer?.cancel(false)
        if (!isMember) { relays?.stop(); relays = null; sk = null }
        ui.update { it.copy(offer = null, joining = null) }
    }

    fun clearError() = ui.update { it.copy(error = null) }
    fun showError(text: String) = ui.update { it.copy(error = text) }

    fun leave() {
        stop(); secrets.clear(); lists.clear(); lastSeen.clear(); signedLog.delete(); apps.edit().clear().apply()
        ui.value = Ui(push = ui.value.push)
        onLeft?.invoke(this)
    }

    // --- Scanning ------------------------------------------------------------

    /** A paper backup's code, pasted from a password manager. */
    fun pastedBackup(text: String) {
        val t = text.trim()
        if (!t.startsWith("cosign:backup")) return ui.update { it.copy(error = "Copy your backup code first (it starts with cosign:backup), then paste it here.") }
        scanned(t)
    }

    /** Whatever the camera read: your server's code, or a site's. */
    fun scanned(text: String) {
        val t = text.trim()
        if (t.startsWith("cosign:pair")) {
            if (isMember) ui.update { it.copy(error = "This phone is already part of your key. That code is for adding a phone.") } else joinGroup(t)
            return
        }
        if (t.startsWith("nostrconnect:")) return scannedNostrConnect(t)
        // Another of your devices (a browser extension, say) invites this phone: ask it to vouch for us.
        if (t.startsWith("cosign:invite")) return if (isMember) ui.update { it.copy(error = "This phone already holds a key. Use Add another key first.") } else joinByInvite(t)
        if (t.startsWith("cosign:join")) {
            if (!isMember) return ui.update { it.copy(error = "That's a new device's code. Scan it with a device that's already part of your key.") }
            val u = Uri.parse(t.replace("cosign:join?", "cosign://join?"))
            val pk = u.getQueryParameter("pk")
            val relays = u.getQueryParameters("r").filter { it.startsWith("wss://") || it.startsWith("ws://") }
            if (!isHex32(pk) || relays.isEmpty()) return ui.update { it.copy(error = "That code is damaged. Try again.") }
            return ui.update { it.copy(error = null, adding = AddingDevice(pk!!, u.getQueryParameter("name")?.take(40) ?: "A device", relays)) }
        }
        // A server's own code, from its page: add it to this account (COSIGN.md §9.6).
        if (t.startsWith("cosign:server")) return scannedServer(t)
        if (t.startsWith("cosign:backup") && isMember && ui.value.takeOutPaper) return takeOutWithPaper(t)
        if (t.startsWith("cosign:backup")) return if (isMember) ui.update { it.copy(error = "This phone already holds a key. Restore a paper backup on a phone that doesn't.") } else startRestore(t)
        val params = try { PairingUri.parse(t) } catch (_: Exception) { null }
        if (params?.profile == CosignMemberProfile.id) return moveIn(params)
        // A sign-in code that carries a nostrconnect:// fallback (`nc`, site/src/pair.ts):
        // use the ticket if it's one for us, the fallback if not.
        val rest = if ('#' in t) t.substringAfter('#') else t.substringAfter('?', "") // an https link, or its qrst: form
        val nc = rest.split('&').firstOrNull { it.startsWith("nc=") }?.let { Uri.decode(it.removePrefix("nc=")) }
        if (nc != null && nc.startsWith("nostrconnect:") && (params == null || params.profile != SignerTicketProfile.id || params.mode != Mode.OFFER))
            return scannedNostrConnect(nc)
        when {
            params == null -> ui.update { it.copy(error = "That isn't a code $appName understands.") }
            !isMember -> ui.update { it.copy(error = "Add this phone to your servers first: scan the code on your server's page.") }
            params.profile != SignerTicketProfile.id -> ui.update { it.copy(error = "That code is for something else (${params.profile}).") }
            params.mode != Mode.OFFER -> ui.update { it.copy(error = "That code isn't asking to sign in.") }
            usedCode(params.token) -> ui.update { it.copy(error = "You've already used that code. Ask the site for a new one.") }
            else -> {
                connecting = params; nostrConnect = null
                ui.update { it.copy(error = null, connect = Connect(params.origin?.let(::siteLabel) ?: "This site", Connect.Stage.CONFIRM)) }
            }
        }
    }

    // --- A device reported lost, and the refresh after it (COSIGN.md §7.2–7.3) -----------------
    //
    // With this phone's lock, you report another device lost: every server blocks it at
    // once. The same message carries a refresh plan, with this phone and a server as
    // dealers (core/Refresh.kt): every remaining share moves to a new epoch of the same
    // key, and the lost device's pieces stop combining. Devices that are away get their
    // parts from the servers when they're back (mail).

    private var refresh: Refresh? = null
    private var refreshTicker: ScheduledFuture<*>? = null

    fun askReportLost(d: Member) = ui.update { it.copy(reporting = d) }
    fun cancelReportLost() = ui.update { it.copy(reporting = null) }

    /** You unlocked this phone: block it everywhere, and refresh. */
    fun confirmReportLost() {
        val d = ui.value.reporting ?: return
        ui.update { it.copy(reporting = null) }
        refreshWithout(d)
        note("Reported ${d.name} lost. It can't sign any more; refreshing your key…", "approved")
    }

    /** Refresh everyone's shares, with this phone and a server dealing; [d], if given, is reported lost first. */
    private fun refreshWithout(d: Member?) {
        val m = ui.value.member ?: return
        val me = publicKeyHex(m.sk.hexToBytes())
        val srv = servers().sortedBy { if (ui.value.online[it.idx] == true) 0 else 1 }.firstOrNull() ?: return
        val left = m.group.members.filter { it.idx != d?.idx }
        val plan = Json.parse(Json.stringify(mapOf(
            "epoch" to m.epoch + 1, "threshold" to m.group.threshold, "dealers" to listOf(me, srv.pk),
            "holders" to left.flatMap { mm -> mm.idxs.map { mapOf("idx" to it, "pk" to (if (mm.idx == m.idx) me else mm.pk)) } },
            "points" to left.flatMap { it.points }.map { listOf(it.idx, it.sharePub) },
        ))) as Map<*, *>
        for (s in servers()) send(s.pk!!, if (d == null) mapOf("type" to "refresh_request", "lock" to true, "plan" to plan)
            else mapOf("type" to "remove_member", "id" to env.random(8).toHex(), "idx" to d.idx, "lock" to true, "plan" to plan))
        val run = startRefresh(plan, m) ?: return
        // Your other devices: the plan and this phone's part, straight to them and kept on the servers for one that's away.
        val parts = run.outgoing().toMap()
        // The paper's part, sealed to it and kept by the servers (COSIGN.md §8.2).
        for (b in left.filter { it.role == "backup" && it.pk != null }) parts[b.pk]?.let { part ->
            val content = Nip44.encrypt(Json.stringify(part), Nip44.conversationKey(m.sk.hexToBytes(), b.pk!!), env.random(32))
            for (s in servers()) send(s.pk!!, mapOf("type" to "backup_store", "epoch" to m.epoch + 1, "content" to content))
        }
        for (o in left.filter { it.role != "server" && it.role != "backup" && it.pk != null && it.idx != m.idx }) {
            send(o.pk!!, mapOf("type" to "refresh_plan", "plan" to plan))
            val key = Nip44.conversationKey(m.sk.hexToBytes(), o.pk)
            for (body in listOfNotNull(mapOf("type" to "refresh_plan", "plan" to plan), parts[o.pk]))
                for (s in servers()) send(s.pk!!, mapOf("type" to "mail_for", "to" to o.pk, "epoch" to m.epoch + 1, "content" to Nip44.encrypt(Json.stringify(body), key, env.random(32))))
        }
    }

    // Growing: restored from a 2-share paper (two servers or more), this phone can't sign
    // with one server, so it asks for a device's full 3 by repair, vouching for itself with
    // the paper's shares and both servers' (three parties), then refreshes the paper's away.
    private var growing: Pair<String, MutableList<List<*>>>? = null
    private var growWelcome: Map<*, *>? = null
    private var growServer: String? = null

    private fun growShares() {
        val m = ui.value.member ?: return
        if (m.shares.size + 1 >= m.group.threshold) return
        val srv = servers().sortedBy { if (ui.value.online[it.idx] == true) 0 else 1 }.firstOrNull() ?: return
        val id = env.random(8).toHex()
        growing = id to java.util.Collections.synchronizedList(mutableListOf()); growWelcome = null
        send(srv.pk!!, mapOf("type" to "add_device", "id" to id, "pk" to publicKeyHex(m.sk.hexToBytes()), "name" to android.os.Build.MODEL.ifBlank { "This phone" }, "lock" to true, "grow" to true))
        note("Getting this phone a device's full share of your key…")
    }

    private fun onGrowPiece(msg: Map<*, *>, from: String) {
        val (id, pieces) = growing ?: return
        val m = ui.value.member ?: return
        if (msg["type"] == "welcome") { growWelcome = msg; growServer = from }
        pieces.addAll((msg["sigmas"] as? List<*>)?.map { it as List<*> } ?: emptyList())
        val w = growWelcome ?: return
        val ks = (w["ks"] as? List<*>)?.mapNotNull { (it as? Long)?.toInt() } ?: return
        val need = (w["helpers"] as? List<*>)?.size ?: return
        val forK = { k: Int -> pieces.toList().filter { (it[0] as? Long)?.toInt() == k }.map { it[2] as String } }
        if (ks.any { forK(it).size < need }) return
        val g = groupJson(m)
        val shares = try { ks.map { k -> Share(k, FrostNative.repairStep3(g, Json.stringify(forK(k)), k)) } } catch (e: Exception) { growing = null; return note("Couldn't grow this phone's shares: ${e.message}", "denied") }
        val points = shares.map { Point(it.idx, Frost.sharePub(it.secret)) }
        send(growServer!!, mapOf("type" to "joined", "id" to id, "sharePubs" to points.map { listOf(it.idx, it.sharePub) }))
        val members = m.group.members.map { if (it.idx == m.idx) it.copy(sharePub = points[0].sharePub, shares = points) else it }
        val updated = m.copy(shares = shares, group = m.group.copy(members = members))
        secrets.saveMembership(Json.stringify(membershipToMap(updated)))
        ui.update { it.copy(member = updated) }
        growing = null
        note("This phone has a device's full share of your key now", "approved")
        // The paper's shares it held stop combining once everyone has moved on.
        timer.schedule({ refreshWithout(null) }, 4, TimeUnit.SECONDS)
    }

    private fun startRefresh(plan: Map<*, *>, m: Membership): Refresh? {
        val epoch = (plan["epoch"] as? Long)?.toInt() ?: return null
        if (epoch <= m.epoch || refresh?.epoch == epoch) return null
        val run = try { Refresh(plan, publicKeyHex(m.sk.hexToBytes()), m.shares.map { it.idx to it.secret }, ::send, { r -> timer.execute { refreshed(r) } }, env) } catch (e: Exception) {
            note("Couldn't refresh: ${e.message}", "denied"); return null
        }
        refresh = run
        refreshTicker?.cancel(false)
        val started = System.currentTimeMillis()
        refreshTicker = timer.scheduleWithFixedDelay({
            if (refresh !== run || System.currentTimeMillis() - started > 120_000) { refreshTicker?.cancel(false); return@scheduleWithFixedDelay }
            run.tick()
        }, 0, 4, TimeUnit.SECONDS)
        return run
    }

    private fun refreshed(r: Refresh.Result) {
        val m = ui.value.member ?: return
        val at = r.points.toMap()
        val members = m.group.members.map { mm ->
            if (!mm.idxs.all { it in at }) return@map mm
            val pts = mm.idxs.map { Point(it, at[it]!!) }
            mm.copy(sharePub = pts[0].sharePub, shares = if (mm.shares != null) pts else null)
        }
        val updated = m.copy(shares = r.shares.map { Share(it.first, it.second) }, group = m.group.copy(members = members), epoch = r.epoch)
        secrets.saveMembership(Json.stringify(membershipToMap(updated)))
        ui.update { it.copy(member = updated) }
        for (s in servers()) send(s.pk!!, mapOf("type" to "refreshed", "epoch" to r.epoch))
        note("Your key moved to a new epoch: a lost device's pieces no longer combine with anything", "approved")
    }

    /** Refresh messages from any member, mail the servers kept, and news of a removal. True if handled. */
    private fun onRefreshMsg(msg: Map<*, *>, from: String, m: Membership): Boolean {
        when (msg["type"]) {
            "mail" -> {
                val sender = msg["from"] as? String ?: return true
                val inner = try { Json.parse(Nip44.decrypt(msg["content"] as String, Nip44.conversationKey(m.sk.hexToBytes(), sender))) as? Map<*, *> } catch (_: Exception) { null } ?: return true
                return onRefreshMsg(inner, sender, m)
            }
            "refresh_plan" -> { (msg["plan"] as? Map<*, *>)?.let { startRefresh(it, m) } }
            "refresh_part" -> refresh?.take(msg, from)
            "removed" -> { ui.update { it.copy(removedBy = msg["by"] as? String ?: "another device") }; note("This phone was reported lost from ${msg["by"]}", "denied") }
            "recovery" -> { ui.update { it.copy(recovery = (msg["name"] as? String ?: "a new phone") to ((msg["until"] as? Long) ?: 0L)) }; note("Your paper backup is being used for ${msg["name"]}", "denied") }
            "recovery_cancelled" -> { ui.update { it.copy(recovery = null) }; note("${msg["by"]} cancelled using your paper backup", "approved") }
            else -> return false
        }
        return true
    }

    /** This phone was reported lost, but it's yours (confirmed with its lock). */

    // --- The paper backup (COSIGN.md §8) ------------------------------------------------
    //
    // Making one: a key for the paper, its shares made by repair with a server, this
    // phone's pieces sealed to the paper and kept by the servers. The paper's code is
    // shown once and never kept here. Restoring: a new phone reads the paper, rebuilds its
    // shares (core/Backup.kt) and asks to recover; after a wait any of your devices can
    // cancel, the paper's shares are this phone's.

    private var making: Pair<String, String>? = null // the paper's secret and public key, until it's shown

    /** You unlocked this phone: make a paper backup. */
    fun makePaper() {
        val m = ui.value.member ?: return
        val srv = servers().sortedBy { if (ui.value.online[it.idx] == true) 0 else 1 }.firstOrNull() ?: return
        val bsk = generateSecretKey(env).toHex()
        making = bsk to publicKeyHex(bsk.hexToBytes())
        send(srv.pk!!, mapOf("type" to "add_device", "id" to env.random(8).toHex(), "pk" to making!!.second, "name" to "Paper backup", "lock" to true, "backup" to true))
        ui.update { it.copy(paperStatus = "Making your paper backup…") }
        timer.schedule({ if (making != null && ui.value.paper == null) { making = null; ui.update { it.copy(paperStatus = null, error = "Your server didn't answer. Try again in a minute.") } } }, 40, TimeUnit.SECONDS)
        if (m.group.members.any { it.role == "backup" }) note("Making a new paper backup: the old one stops working", "approved")
    }

    /** The paper's code, for the screen, a printout or a photo: its key, your servers, their relays. */
    private fun paperCode(bsk: String, m: Membership) = "cosign:backup?k=$bsk&" +
        (servers().map { "s=${it.pk}" } + m.group.relays.map { "r=" + Uri.encode(it) } + listOfNotNull(m.mirrored?.let { "m=${if (it) 1 else 0}" })).joinToString("&")

    private fun onBackupMade() {
        val (bsk, _) = making ?: return
        val m = ui.value.member ?: return
        ui.update { it.copy(paper = paperCode(bsk, m), paperStatus = null) }
        making = null
        note("Made a paper backup", "approved")
    }

    /** You've kept the paper: forget its code here. */
    fun closePaper() = ui.update { it.copy(paper = null) }

    // Restoring, on a phone that isn't in a key yet.

    fun startRestore(code: String) {
        val u = Uri.parse(code.trim().replace("cosign:backup?", "cosign://backup?"))
        val bsk = u.getQueryParameter("k")
        val srvs = u.getQueryParameters("s").filter { isHex32(it) }
        val urls = u.getQueryParameters("r").filter { it.startsWith("wss://") || it.startsWith("ws://") }
        if (!isHex32(bsk) || srvs.isEmpty() || urls.isEmpty()) return ui.update { it.copy(error = "That paper code is damaged. Try scanning it again.") }
        val state = mapOf("paper" to bsk, "sk" to generateSecretKey(env).toHex(), "servers" to srvs, "relays" to urls, "mirrored" to u.getQueryParameter("m")?.let { it == "1" })
        secrets.save("restoring", Json.stringify(state))
        resumeRestore(state)
    }

    private var restoreAsk: ScheduledFuture<*>? = null
    private var restored: Pair<List<Pair<Int, String>>, Map<*, *>>? = null

    private fun resumeRestore(st: Map<*, *>) {
        val bsk = st["paper"] as String
        val bpk = publicKeyHex(bsk.hexToBytes())
        connect((st["relays"] as List<*>).map { it as String }, st["sk"] as String, mapOf(bpk to bsk))
        ui.update { it.copy(restoring = Restoring("Reading your paper…"), error = null) }
        restoreAsk?.cancel(false)
        restoreAsk = timer.scheduleWithFixedDelay({
            if (isMember) { restoreAsk?.cancel(false); return@scheduleWithFixedDelay }
            for (srv in st["servers"] as List<*>) sendAs(bsk, srv as String, mapOf("type" to if (restored == null) "backup_get" else "recover_finish"))
        }, 1, 10, TimeUnit.SECONDS)
    }

    private fun sendAs(secret: String, to: String, msg: Map<String, Any?>) {
        val key = Nip44.conversationKey(secret.hexToBytes(), to)
        relays?.publish(Event.sign(publicKeyHex(secret.hexToBytes()), env.now(), KIND_MEMBER, listOf(listOf("p", to)), Nip44.encrypt(Json.stringify(msg), key, env.random(32)), secret.hexToBytes(), env))
    }

    private fun onRestoreMsg(msg: Map<*, *>, e: Event) {
        val st = secrets.load("restoring")?.let { Json.parse(it) as? Map<*, *> } ?: return
        val bsk = st["paper"] as String
        when (msg["type"]) {
            "backup" -> if (restored == null) {
                val shares = try { Backup.restore(bsk, msg) } catch (x: Exception) {
                    return ui.update { it.copy(restoring = Restoring("Couldn't read the paper: ${x.message}", failed = true)) }
                }
                restored = shares to msg
                for (srv in st["servers"] as List<*>) sendAs(bsk, srv as String, mapOf("type" to "recover", "pk" to publicKeyHex((st["sk"] as String).hexToBytes()), "name" to android.os.Build.MODEL.ifBlank { "A new phone" }))
            }
            "recovering" -> (msg["until"] as? Long)?.let { until -> ui.update { it.copy(restoring = Restoring("Your paper is good. Waiting until your other devices have had time to stop it.", until)) } }
            "recovery_cancelled" -> ui.update { it.copy(restoring = Restoring("${msg["by"]} cancelled it. If that wasn't you, someone else may have your devices: start again.", failed = true)) }
            "recovered" -> {
                val (shares, b) = restored ?: return
                val idx = (msg["idx"] as? Long)?.toInt() ?: return
                val group = parseGroup(b["group"]) ?: return
                val me = publicKeyHex((st["sk"] as String).hexToBytes())
                val g = group.copy(members = group.members.map { if (it.idx == idx) it.copy(role = "device", pk = me, name = android.os.Build.MODEL.ifBlank { "This phone" }) else it })
                val m = Membership(st["sk"] as String, idx, shares.map { Share(it.first, it.second) }, b["signer"] as? String ?: return, g, (b["epochNow"] as? Long)?.toInt() ?: 0, st["mirrored"] as? Boolean)
                secrets.saveMembership(Json.stringify(membershipToMap(m)))
                secrets.save("restoring", null)
                restoreAsk?.cancel(false); restored = null
                ui.update { it.copy(member = m, restoring = null) }
                note("Restored from your paper backup. Make a new paper backup, and report your old phone lost if it is.", "approved")
                connect(g.relays, m.sk)
                start()
                // From a 2-share paper: too few to sign with one server. Grow a device's full 3.
                if (m.shares.size + 1 < m.group.threshold) timer.schedule({ growShares() }, 3, TimeUnit.SECONDS)
            }
        }
    }

    fun cancelRestore() {
        restoreAsk?.cancel(false); restored = null
        secrets.save("restoring", null)
        if (!isMember) { relays?.stop(); relays = null; sk = null }
        ui.update { it.copy(restoring = null) }
    }

    /** Your paper backup is being used, and it isn't you (confirmed with this phone's lock). */
    fun cancelRecovery() {
        for (s in servers()) send(s.pk!!, mapOf("type" to "cancel_recovery", "lock" to true))
        ui.update { it.copy(recovery = null) }
    }

    // --- Adding a server ("Add a server") ---------------------------------------------------
    //
    // A public server joins the key as one more: its host key gives this key a member key
    // of its own, it's enrolled to wait for its share (how: 'repair'), and this phone vouches
    // for it with a server already in the key, which makes its one share by repair as for a
    // device. With a second server the paper backup changes weight (3 → 2): make a new one.

    /** Look for servers this key doesn't use yet. */
    fun chooseServer() {
        val m = ui.value.member ?: return
        ui.update { it.copy(serverChoice = emptyList(), paperStatus = "Looking for servers…") }
        timer.execute {
            val have = m.group.members.filter { it.role == "server" }.map { it.name.lowercase() }.toSet()
            val found = try { cc.aaro.cosign.net.Servers.find() } catch (_: Exception) { emptyList() }
            val choice = found.filter { it.name.lowercase() !in have && it.relays.none { r -> have.any { h -> r.contains(h) } } }
            ui.update { it.copy(serverChoice = choice, paperStatus = null) }
        }
    }
    fun closeServerChoice() = ui.update { it.copy(serverChoice = null) }

    /**
     * A server's own code (`cosign:server?pk=…&r=…&t=…`), shown on its page: a server
     * nobody can look up, like one at home. It goes through the same Add a server as any
     * other, with the code as its way in. The sheet asks for this device's lock first.
     */
    private fun scannedServer(t: String) {
        val m = ui.value.member ?: return ui.update { it.copy(error = "Set up your account on this phone first, then add a server to it.") }
        val u = Uri.parse(t.replace("cosign:server?", "cosign://server?"))
        val pk = u.getQueryParameter("pk")
        val token = u.getQueryParameter("t")
        val relays = u.getQueryParameters("r").filter { it.startsWith("wss://") || it.startsWith("ws://") }
        if (!isHex32(pk) || relays.isEmpty()) return ui.update { it.copy(error = "That server code is damaged. Open the server's page and try again.") }
        val servers = m.group.members.count { it.role == "server" }
        if (servers >= 4) return ui.update { it.copy(error = "This account already has as many servers as it needs.") }
        val name = u.getQueryParameter("name")?.take(40) ?: "Your own server"
        ui.update { it.copy(error = null, serverChoice = listOf(cc.aaro.cosign.net.Servers.Server(pk!!, relays, "open", "", pk, name)), addCode = token) }
    }

    /** After your lock: add [s] to this account; [code] is a one-time code from its own page (COSIGN.md §9.6). */
    fun addServer(s: cc.aaro.cosign.net.Servers.Server, code: String? = null) {
        val m = ui.value.member ?: return
        ui.update { it.copy(serverChoice = null, addCode = null) }
        note("Adding ${s.name}…")
        timer.execute {
            val relaysNow = (m.group.relays + s.relays).distinct()
            connect(relaysNow, m.sk)
            Thread.sleep(2500)
            val ask = { body: Map<String, Any?> ->
                val id = env.random(8).toHex()
                val f = CompletableFuture<Map<*, *>>()
                waiting[id] = f
                val msg = body + ("id" to id)
                var reply: Map<*, *>? = null
                for (i in 0 until 6) { send(s.pk, msg); reply = try { f.get(4, TimeUnit.SECONDS) } catch (_: Exception) { null }; if (reply != null) break }
                waiting.remove(id); reply
            }
            val tok = code?.let { mapOf("token" to it) } ?: emptyMap()
            // Some servers take on accounts only for the people their owner follows or
            // invited (server/join.ts). They say so, and this answers with whose account it
            // is: a kind 27235 signed by the account itself, naming this server and the key
            // being enrolled. Nothing is signed or sent unless a server asks for it.
            val wantsProof = { r: Map<*, *>? -> ((r?.get("reason") as? String) ?: "").startsWith("proof-needed") }
            var proof: Map<String, Any?> = emptyMap()
            var key = ask(mapOf("type" to "enroll_key") + tok)
            if (wantsProof(key)) {
                note("${s.name} asks whose account this is…")
                proof = try {
                    val tags = listOf(listOf("u", "cosign:server?pk=${s.pk}"), listOf("method", "ENROLL"), listOf("p", publicKeyHex(m.sk.hexToBytes())))
                    mapOf("proof" to signOwn(Event(m.group.groupX, env.now(), 27235, tags, "").withId()).toMap())
                } catch (e: Exception) {
                    return@execute note("Couldn't add ${s.name}: it only takes accounts its owner knows, and showing it whose this is didn't work (${e.message ?: "no answer"})", "denied")
                }
                key = ask(mapOf("type" to "enroll_key") + tok + proof)
            }
            if (key?.get("type") != "enroll_key") return@execute note("Couldn't add ${s.name}: ${key?.get("reason") ?: "it didn't answer"}", "denied")
            val k = m.group.members.flatMap { it.idxs }.max() + 1
            val record = mapOf("groupX" to m.group.groupX, "threshold" to m.group.threshold, "relays" to relaysNow,
                "members" to m.group.members.map { mapOf("idx" to it.idx, "name" to it.name, "role" to it.role, "pk" to it.pk, "sharePub" to it.sharePub) +
                    (it.shares?.let { sh -> mapOf("shares" to sh.map { p -> mapOf("idx" to p.idx, "sharePub" to p.sharePub) }) } ?: emptyMap()) })
            val enrolled = ask(mapOf("type" to "enroll", "how" to "repair", "key" to key["key"], "group" to record, "k" to k, "name" to s.name) + tok + proof)
            if (enrolled?.get("type") != "enrolled") return@execute note("Couldn't add ${s.name}: ${enrolled?.get("reason") ?: "it didn't answer"}", "denied")
            val via = servers().sortedBy { if (ui.value.online[it.idx] == true) 0 else 1 }.firstOrNull() ?: return@execute
            send(via.pk!!, mapOf("type" to "add_device", "id" to env.random(8).toHex(), "pk" to key["pk"], "name" to s.name, "relays" to s.relays, "lock" to true, "server" to true, "k" to k))
            val updated = (ui.value.member ?: return@execute).let { it.copy(group = it.group.copy(relays = relaysNow)) }
            secrets.saveMembership(Json.stringify(membershipToMap(updated)))
            ui.update { it.copy(member = updated) }
        }
    }

    // --- An account you already have, dealt on this phone ---------------------------------
    //
    // "I already have an account": you paste its nsec, and this phone deals it as a page
    // would (site/src/import.ts): its own three shares, one for each server it picks (one
    // per operator first), any four sign. Each server gets its share (enroll, how
    // 'dealt'), the key is wiped, and the paper backup is offered at once. The nsec never
    // becomes a String: it's read as characters and decoded to bytes, and both are wiped.

    /** The key in [chars] (nsec1… or 64 hex), as bytes, or null. Wipes [chars]. */
    fun secretFrom(chars: CharArray): ByteArray? = try {
        val t = chars.filter { !it.isWhitespace() }.toCharArray()
        try {
            when {
                t.size == 64 && t.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' } ->
                    ByteArray(32) { ((Character.digit(t[2 * it], 16) shl 4) or Character.digit(t[2 * it + 1], 16)).toByte() }
                else -> cc.aaro.cosign.core.Bech32.decodeNsec(t)
            }
        } finally { t.fill(' ') }
    } finally { chars.fill(' ') }

    /** Deal [secret] here and give each picked server its share. Wipes [secret]. */
    fun importKey(secret: ByteArray) {
        if (isMember) { secret.fill(0); return ui.update { it.copy(error = "This phone already holds an account. Use Add another account first.") } }
        ui.update { it.copy(error = null, moveIn = MoveIn(MoveIn.Stage.WAITING, text = "Finding servers…")) }
        // Its own thread: it waits on servers for a while, and asks them all at once.
        Thread {
            try { importNow(secret) } catch (e: Exception) {
                ui.update { it.copy(moveIn = MoveIn(MoveIn.Stage.FAILED, text = "Not moved: ${e.message ?: "something went wrong"}. Nothing was kept.")) }
            } finally { secret.fill(0) }
        }.start()
    }

    /** One question to a server's host key, asked again every 4 s: its answer, or null. */
    private fun askHost(s: cc.aaro.cosign.net.Servers.Server, body: Map<String, Any?>, tries: Int): Map<*, *>? {
        val id = env.random(8).toHex()
        val f = CompletableFuture<Map<*, *>>()
        waiting[id] = f
        var reply: Map<*, *>? = null
        for (i in 0 until tries) { send(s.pk, body + ("id" to id)); reply = try { f.get(4, TimeUnit.SECONDS) } catch (_: Exception) { null }; if (reply != null) break }
        waiting.remove(id)
        return reply
    }

    /**
     * Connect as a new member key and find servers taking new accounts: up to three that
     * answer, one per operator first (servers.ts pickServers), each with the member key it
     * gives this account. At least two, or it throws.
     */
    private fun pickServers(mySk: String): List<Pair<cc.aaro.cosign.net.Servers.Server, Map<*, *>>> {
        val found = cc.aaro.cosign.net.Servers.find()
        connect(found.flatMap { it.relays }.distinct().take(8), mySk)
        Thread.sleep(2500)
        val pool = Executors.newFixedThreadPool(found.size.coerceIn(1, 8))
        val answering = try {
            found.map { s -> s to CompletableFuture.supplyAsync({ askHost(s, mapOf("type" to "enroll_key"), 3) }, pool) }
                .mapNotNull { (s, f) -> f.get().takeIf { it?.get("type") == "enroll_key" }?.let { s to it } }
        } finally { pool.shutdown() }
        val picked = mutableListOf<Pair<cc.aaro.cosign.net.Servers.Server, Map<*, *>>>()
        for (a in answering) if (picked.size < 3 && picked.none { it.first.operator == a.first.operator }) picked += a
        for (a in answering) if (picked.size < 3 && a !in picked) picked += a
        if (picked.size < 2) throw IllegalStateException(if (picked.isEmpty()) "no Cosign server answered; try again in a minute" else "only one Cosign server answered, and an account needs two; try again in a minute")
        return picked
    }

    private fun importNow(secret: ByteArray) {
        val mySk = generateSecretKey(env).toHex()
        val picked = pickServers(mySk)
        val ask = { s: cc.aaro.cosign.net.Servers.Server, body: Map<String, Any?>, tries: Int -> askHost(s, body, tries) }
        ui.update { it.copy(moveIn = MoveIn(MoveIn.Stage.WAITING, text = "Giving ${if (picked.size == 1) "your server" else "${picked.size} servers"} their part…")) }

        val idxs = IntArray(3 + picked.size) { it + 1 }
        val mirrored = cc.aaro.cosign.core.Secp.oddY(secret)
        val dealt = Json.parse(FrostNative.dealFromSecret(secret, idxs, 4)) as Map<*, *>
        secret.fill(0)
        val shares = (dealt["shares"] as List<*>).map { it as Map<*, *> }.map { Triple((it["idx"] as Long).toInt(), it["secret"] as String, it["sharePub"] as String) }
        val groupX = dealt["groupX"] as String
        val me = publicKeyHex(mySk.hexToBytes())
        val relays = picked.flatMap { it.first.relays }.distinct().take(4)
        val signerSk = generateSecretKey(env).toHex()
        val mine = shares.take(3)
        val record = mapOf("groupX" to groupX, "npub" to Nip19.npub(groupX), "threshold" to 4, "relays" to relays,
            "members" to listOf(mapOf("idx" to 1, "name" to android.os.Build.MODEL.ifBlank { "Phone" }.take(40), "role" to "phone", "pk" to me, "sharePub" to mine[0].third,
                "shares" to mine.map { mapOf("idx" to it.first, "sharePub" to it.third) })) +
                picked.mapIndexed { i, (s, key) -> mapOf("idx" to 4 + i, "name" to s.name, "role" to "server", "pk" to key["pk"], "sharePub" to shares[3 + i].third) })
        for ((i, p) in picked.withIndex()) {
            val r = ask(p.first, mapOf("type" to "enroll", "how" to "dealt", "key" to p.second["key"], "group" to record, "share" to shares[3 + i].second,
                "signer" to mapOf("sk" to signerSk, "pk" to publicKeyHex(signerSk.hexToBytes()))), 6)
            if (r?.get("type") != "enrolled") throw IllegalStateException("${p.first.name} ${r?.get("reason") ?: "didn't answer"}")
        }
        // As it would arrive over the wire (numbers as Long), the way parseGroup reads it.
        val group = parseGroup(Json.parse(Json.stringify(record))) ?: throw IllegalStateException("the account record is damaged")
        val m = Membership(mySk, 1, mine.map { Share(it.first, it.second) }, publicKeyHex(signerSk.hexToBytes()), group, mirrored = mirrored)
        secrets.saveMembership(Json.stringify(membershipToMap(m)))
        connect(relays, mySk)
        ui.update { it.copy(member = m, moveIn = MoveIn(MoveIn.Stage.DONE, text = "Your account is in $appName now.")) }
        note("Moved ${group.npub.take(16)}… in", "approved")
        offerPaper()
        start()
    }

    // --- Taking your account out of Cosign (COSIGN.md §7.6) -----------------------------------
    //
    // After this device's lock, either with the paper (at once: the paper's 2 and this
    // phone's 3 make the key; the servers are told first and must answer `noted` for this
    // request before it's shown) or through a server (it seals its share to this phone
    // after the wait every other device can stop). The key is put back together here
    // (FROST's reconstruct) and shown once; a key brought in with an odd y is flipped back
    // to the nsec you had. Then, if you like, the servers' pieces are removed (forget).

    private var takeOutId: String? = null
    private var takeOutPaper: Pair<String, List<Pair<Int, String>>?>? = null // the paper's key, and its shares once read

    fun askTakeOutPaper(on: Boolean) = ui.update { it.copy(takeOutPaper = on, error = null) }

    /** After the lock: through a server, after the wait. */
    fun takeOutViaServers() {
        val id = env.random(8).toHex().also { takeOutId = it }
        for (s in servers()) send(s.pk!!, mapOf("type" to "take_out", "id" to id, "lock" to true))
        ui.update { it.copy(takeOut = TakeOut(TakeOut.Stage.WAITING, "Asked your servers. Any of your other devices can stop this during the wait.")) }
        note("You asked to take your account out of $appName", "denied")
    }

    /** After the lock, with the paper code: read its shares from the servers' sealed pieces, then announce it. */
    private fun takeOutWithPaper(code: String) {
        val m = ui.value.member ?: return
        val bsk = Uri.parse(code.trim().replace("cosign:backup?", "cosign://backup?")).getQueryParameter("k")
        if (!isHex32(bsk)) return ui.update { it.copy(error = "That paper code is damaged. Try again.") }
        takeOutPaper = bsk!! to null
        ui.update { it.copy(takeOutPaper = false, takeOut = TakeOut(TakeOut.Stage.WAITING, "Reading your paper…")) }
        connect(m.group.relays, m.sk, mapOf(publicKeyHex(bsk.hexToBytes()) to bsk))
        timer.schedule({ for (s in servers()) sendAs(bsk, s.pk!!, mapOf("type" to "backup_get")) }, 2, TimeUnit.SECONDS)
    }

    private fun onTakeOutPaper(msg: Map<*, *>, m: Membership) {
        val (bsk, read) = takeOutPaper ?: return
        if (read != null) return
        val shares = try { Backup.restore(bsk, msg) } catch (e: Exception) {
            takeOutPaper = null
            return ui.update { it.copy(takeOut = TakeOut(TakeOut.Stage.FAILED, "Couldn't read the paper: ${e.message}")) }
        }
        takeOutPaper = bsk to shares
        // Announced before it's shown: every device hears of it, and a server answers for this request.
        val id = env.random(8).toHex().also { takeOutId = it }
        for (s in servers()) send(s.pk!!, mapOf("type" to "take_out", "id" to id, "lock" to true, "paper" to true))
        ui.update { it.copy(takeOut = TakeOut(TakeOut.Stage.WAITING, "Telling your servers and devices…")) }
        timer.schedule({
            if (ui.value.takeOut?.stage == TakeOut.Stage.WAITING && takeOutId == id)
                ui.update { it.copy(takeOut = TakeOut(TakeOut.Stage.FAILED, "None of your servers answered, so it wasn't shown. Try again when you're online.")) }
        }, 40, TimeUnit.SECONDS)
    }

    private fun onNoted(msg: Map<*, *>, m: Membership) {
        if (msg["id"] != takeOutId) return
        val paper = takeOutPaper?.second ?: return
        takeOutPaper = null
        connect(m.group.relays, m.sk)
        reveal(m, m.shares.map { it.idx to it.secret } + paper)
    }

    private fun onReleased(msg: Map<*, *>, m: Membership) {
        if (msg["id"] != takeOutId) return
        val theirs = (msg["shares"] as? List<*>)?.map { val x = it as Map<*, *>; (x["idx"] as Long).toInt() to x["secret"] as String } ?: return
        reveal(m, m.shares.map { it.idx to it.secret } + theirs)
    }

    /** Put the key back together, as the nsec you had (flipped back if it was mirrored), and show it once. */
    private fun reveal(m: Membership, shares: List<Pair<Int, String>>) {
        val key = try { FrostNative.reconstruct(groupJson(m), Json.stringify(shares.map { listOf(it.first, it.second) })) } catch (e: Exception) {
            return ui.update { it.copy(takeOut = TakeOut(TakeOut.Stage.FAILED, "Couldn't put the key together: ${e.message}")) }
        }
        val out = if (m.mirrored == true) cc.aaro.cosign.core.Secp.negate(key).also { key.fill(0) } else key
        val nsec = Nip19.nsec(out)
        out.fill(0)
        takeOutId = null
        ui.update { it.copy(takeOut = TakeOut(TakeOut.Stage.SHOWING, nsec = nsec, npub = m.group.npub, twinUnknown = m.mirrored == null)) }
        note("Your account's key was shown on this phone", "denied")
    }

    fun closeTakeOut() { takeOutId = null; takeOutPaper = null; ui.update { it.copy(takeOut = null, takeOutPaper = false) } }

    /** After the lock: the servers stop at once, and delete their pieces after the wait unless a device cancels. */
    fun forgetServers() {
        val id = env.random(8).toHex()
        for (s in servers()) send(s.pk!!, mapOf("type" to "forget", "id" to id, "lock" to true))
        note("You asked your servers to remove their pieces of your account", "denied")
    }

    /** After the lock: stop a waiting take-out or removal (yours or another device's). */
    fun cancelGuard(id: String) { for (s in servers()) send(s.pk!!, mapOf("type" to "guard_cancel", "id" to id, "lock" to true)) }

    private fun onGuard(msg: Map<*, *>) {
        val g = GuardNote(msg["id"] as? String ?: return, msg["kind"] as? String ?: return, msg["by"] as? String ?: "a device",
            msg["state"] as? String ?: "waiting", (msg["until"] as? Long) ?: 0L, msg["paper"] == true)
        ui.update { u -> u.copy(guards = (listOf(g) + u.guards.filter { it.id != g.id }).take(20)) }
        if (g.id == takeOutId) when (g.state) {
            "waiting" -> ui.update { it.copy(takeOut = TakeOut(TakeOut.Stage.WAITING, "Your servers release their part after the wait. Any of your other devices can stop it.", g.until)) }
            "cancelled" -> { takeOutId = null; ui.update { it.copy(takeOut = TakeOut(TakeOut.Stage.FAILED, "Stopped from one of your devices.")) } }
        }
        val what = when (g.kind) { "take_out" -> "taking your account out of $appName"; "forget" -> "removing your servers' pieces"; else -> "reporting a device lost" }
        if (g.state == "waiting" && g.id != takeOutId) note("${g.by} started $what", "denied")
    }

    // --- Creating an account here -----------------------------------------------------------
    //
    // "Create your account" with no code: this phone picks servers taking new accounts (as
    // for an account you already have), enrolls an account with no key yet on each (enroll,
    // how 'dkg'), and they make the key together (DKG): its 3 shares, each server's 1, any
    // 4 sign, and nobody ever holds the whole key. Then the paper backup.

    fun createAccount() {
        if (isMember) return ui.update { it.copy(error = "This phone already holds an account. Use Add another account first.") }
        ui.update { it.copy(error = null, moveIn = MoveIn(MoveIn.Stage.WAITING, text = "Finding servers…")) }
        Thread {
            try { createNow() } catch (e: Exception) {
                dkg = null; dkgTicker?.cancel(false)
                ui.update { it.copy(moveIn = MoveIn(MoveIn.Stage.FAILED, text = "Not made: ${e.message ?: "something went wrong"}.")) }
            }
        }.start()
    }

    private fun createNow() {
        val mySk = generateSecretKey(env).toHex()
        val me = publicKeyHex(mySk.hexToBytes())
        val picked = pickServers(mySk)
        ui.update { it.copy(moveIn = MoveIn(MoveIn.Stage.WAITING, text = "Making your account with ${picked.size} servers…")) }
        val relays = picked.flatMap { it.first.relays }.distinct().take(4)
        val signerSk = generateSecretKey(env).toHex()
        val name = android.os.Build.MODEL.ifBlank { "Phone" }.take(40)
        val record = mapOf("threshold" to 4, "relays" to relays,
            "members" to listOf(mapOf("idx" to 1, "name" to name, "role" to "phone", "pk" to me, "sharePub" to "", "shares" to (1..3).map { mapOf("idx" to it, "sharePub" to "") })) +
                picked.mapIndexed { i, (s, key) -> mapOf("idx" to 4 + i, "name" to s.name, "role" to "server", "pk" to key["pk"], "sharePub" to "") })
        val plan = mapOf("session" to env.random(16).toHex(), "threshold" to 4,
            "holders" to (1..3).map { mapOf("idx" to it, "pk" to me) } + picked.mapIndexed { i, (_, key) -> mapOf("idx" to 4 + i, "pk" to key["pk"]) })
        for ((s, key) in picked) {
            val r = askHost(s, mapOf("type" to "enroll", "how" to "dkg", "key" to key["key"], "group" to record, "plan" to plan,
                "signer" to mapOf("sk" to signerSk, "pk" to publicKeyHex(signerSk.hexToBytes()))), 6)
            if (r?.get("type") != "enrolled") throw IllegalStateException("${s.name} ${r?.get("reason") ?: "didn't answer"}")
        }
        // The key, made together: as the plan arrives over the wire (numbers as Long), for Dkg.
        val made = CompletableFuture<Dkg.Result>()
        val run = Dkg(Json.parse(Json.stringify(plan)) as Map<*, *>, me, ::send) { made.complete(it) }
        dkg = run
        dkgTicker?.cancel(false)
        dkgTicker = timer.scheduleWithFixedDelay({ if (dkg === run) run.tick() }, 0, 4, TimeUnit.SECONDS)
        val r = try { made.get(90, TimeUnit.SECONDS) } catch (_: Exception) { throw IllegalStateException("the servers didn't finish making the key; try again") }
        // Keep sending a little longer: a server may still be waiting for ours.
        timer.schedule({ if (dkg === run) { dkgTicker?.cancel(false); dkg = null } }, 20, TimeUnit.SECONDS)
        val pub = r.members.toMap()
        val group = parseGroup(Json.parse(Json.stringify(record + mapOf("groupX" to r.groupX, "npub" to Nip19.npub(r.groupX),
            "members" to (record["members"] as List<*>).map { it as Map<*, *> }.map { m ->
                val shares = (m["shares"] as? List<*>)?.map { (it as Map<*, *>)["idx"] as Int }
                m + mapOf("sharePub" to pub[(m["idx"] as Int)]) + (shares?.let { mapOf("shares" to it.map { i -> mapOf("idx" to i, "sharePub" to pub[i]) }) } ?: emptyMap())
            })))) ?: throw IllegalStateException("the account record is damaged")
        val m = Membership(mySk, 1, r.shares.map { Share(it.first, it.second) }, publicKeyHex(signerSk.hexToBytes()), group, mirrored = false)
        secrets.saveMembership(Json.stringify(membershipToMap(m)))
        connect(relays, mySk)
        ui.update { it.copy(member = m, moveIn = MoveIn(MoveIn.Stage.DONE, text = "Your account is made. Nobody, this phone included, ever held all of it.")) }
        note("Made ${group.npub.take(16)}…", "approved")
        offerPaper()
        start()
    }

    // --- A key moving in from a web page ------------------------------------------------
    //
    // The page that held the key dealt it: each server already has its share (and a claim
    // token for this phone), and this phone gets three by QRST. It shows five digits, you
    // type them on the page, it checks the shares and asks before keeping them, then
    // claims its place with each server (pair_ack). Nothing here ever held the whole key.

    private var moving: Transfer<MemberMove>? = null

    private fun moveIn(params: PairingParams) {
        if (params.mode != Mode.REQUEST) return ui.update { it.copy(error = "That code isn't offering a key.") }
        if (isMember) {
            // Say no to the page too, so it stops waiting at once (it hears peer-aborted).
            val t = Transfer.join(TransferDeps(CosignMemberProfile, qrstStore, env, "https://qrst.aaro.cc/", CodeCheck.TYPE), params, true)
            timer.schedule({ t.cancel(); timer.schedule({ t.dispose() }, 10, TimeUnit.SECONDS) }, 3, TimeUnit.SECONDS)
            return ui.update { it.copy(error = "This phone already holds a key. Moving another one in isn't possible yet.") }
        }
        moving?.cancel()
        val t = Transfer.join(TransferDeps(CosignMemberProfile, qrstStore, env, "https://qrst.aaro.cc/", CodeCheck.TYPE), params, true)
        moving = t
        ui.update { it.copy(error = null, moveIn = MoveIn(MoveIn.Stage.WAITING, text = "Reaching the page…")) }
        var kept = false
        t.onChange = {
            val v = t.view()
            when {
                v.value != null && !kept -> { kept = true; keepMoved(v.value) }
                v.session.phase == Phase.ACCEPT -> ui.update { it.copy(moveIn = MoveIn(MoveIn.Stage.ACCEPT, v.session.code, v.session.rendering)) }
                v.session.phase == Phase.CODE && v.session.code != null -> ui.update { it.copy(moveIn = MoveIn(MoveIn.Stage.CODE, v.session.code)) }
                v.stage == TransferView.Stage.ENDED && !kept -> ui.update { it.copy(moveIn = MoveIn(MoveIn.Stage.FAILED, text = when (v.session.outcome) {
                    Outcome.DECLINED, Outcome.PEER_ABORTED -> "Cancelled. Nothing was moved."
                    Outcome.EXPIRED -> "That code expired. Start again on the page."
                    else -> "Not moved (${v.session.outcome?.wire ?: "ended"})."
                })) }
            }
        }
    }

    /** You checked what arrived and said keep it. */
    fun acceptMove() { moving?.accept() }
    fun closeMove() {
        if (ui.value.moveIn?.stage.let { it == MoveIn.Stage.WAITING || it == MoveIn.Stage.CODE || it == MoveIn.Stage.ACCEPT }) moving?.decline()
        moving = null
        ui.update { it.copy(moveIn = null) }
    }

    private fun keepMoved(mv: MemberMove) {
        val group = parseGroup(mv.group) ?: return ui.update { it.copy(moveIn = MoveIn(MoveIn.Stage.FAILED, text = "The page sent a damaged key. Nothing was kept.")) }
        val points = group.members.flatMap { it.points }.associate { it.idx to it.sharePub }
        if (mv.shares.any { (i, sec) -> Frost.sharePub(sec) != points[i] })
            return ui.update { it.copy(moveIn = MoveIn(MoveIn.Stage.FAILED, text = "Those shares don't belong to that key. Nothing was kept.")) }
        val mySk = generateSecretKey(env).toHex()
        val me = publicKeyHex(mySk.hexToBytes())
        val m = Membership(mySk, mv.idx, mv.shares.map { Share(it.first, it.second) }, mv.signer,
            group.copy(npub = Nip19.npub(group.groupX), members = group.members.map { if (it.idx == mv.idx) it.copy(pk = me) else it }))
        secrets.saveMembership(Json.stringify(membershipToMap(m)))
        connect(group.relays, mySk)
        ui.update { it.copy(member = m, moveIn = MoveIn(MoveIn.Stage.DONE, text = "Your account is in $appName now. This phone holds ${m.shares.size} of its shares.")) }
        offerPaper()
        note("Moved ${group.npub.take(16)}… in from a web page", "approved")
        // Claim this member's place with each server, again in case a relay drops it.
        val claim = { for (srv in servers()) send(srv.pk!!, mapOf("type" to "pair_ack", "token" to mv.claim, "name" to android.os.Build.MODEL.ifBlank { "Phone" })) }
        timer.schedule(claim, 2, TimeUnit.SECONDS); timer.schedule(claim, 6, TimeUnit.SECONDS)
        start()
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
        useCode(params.token)
        val ticket = SignerTicket(m.group.groupX, m.signer, m.group.relays, env.random(16).toHex(), env.now() + 900)
        for (s in servers()) send(s.pk!!, mapOf("type" to "ticket", "t" to ticket.t, "origin" to origin, "expires" to ticket.expires))
        ui.update { it.copy(connect = Connect(origin, Connect.Stage.WORKING, "Sending to $origin…")) }
        var released = false
        val deps = TransferDeps(SignerTicketProfile, qrstStore, env, "https://qrst.aaro.cc/", CodeCheck.NONE)
        val t = Transfer.join(deps, params, true, ticket)
        transfer = t
        // A site that has gone (a closed tab, an old code) never answers: don't wait forever.
        timer.schedule({
            if (transfer === t && ui.value.connect?.stage == Connect.Stage.WORKING) {
                t.cancel(); connecting = null
                if (connectInBackground) listener?.onNotice("Not signed in", "$origin didn't answer. Ask it for a new code.")
                connectInBackground = false
                ui.update { it.copy(connect = Connect(origin, Connect.Stage.FAILED, "$origin didn't answer. Ask it for a new code.")) }
            }
        }, 30, TimeUnit.SECONDS)
        t.onChange = {
            val v: TransferView<SignerTicket> = t.view()
            if (v.session.phase == Phase.RELEASE && !released) { released = true; t.release(ticket) }
            if (v.stage == TransferView.Stage.ENDED) finishConnect(origin, v.session.outcome)
        }
    }

    /** As the servers name them: a browser extension's made-up origin, as words (server's siteName). */
    private fun siteLabel(origin: String): String {
        val m = Regex("^https?://([a-z0-9-]+)\\.extension/?$", RegexOption.IGNORE_CASE).find(origin) ?: return origin
        val words = mapOf("iphone" to "iPhone", "ipad" to "iPad", "macbook" to "MacBook", "macos" to "macOS", "ios" to "iOS", "pc" to "PC", "on" to "on", "in" to "in", "for" to "for")
        return m.groupValues[1].lowercase().split('-').filter { it.isNotEmpty() }.joinToString(" ") { w -> words[w] ?: w.replaceFirstChar { it.uppercase() } } + " (browser extension)"
    }

    /** The sign-in is finishing while you're back in the app that asked (MainActivity sent you there). */
    @Volatile var connectInBackground = false

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
        else if (connectInBackground) listener?.onNotice("Not signed in", message)
        connectInBackground = false
        ui.update { it.copy(connect = Connect(origin, stage, message)) }
        // A success needs no tap to dismiss, and mustn't sit over an approval that arrives next.
        if (stage == Connect.Stage.DONE) timer.schedule({ ui.update { u -> if (u.connect?.stage == Connect.Stage.DONE) u.copy(connect = null) else u } }, 2500, TimeUnit.MILLISECONDS)
        connecting = null
        timer.schedule({ requestState() }, 3, TimeUnit.SECONDS)
    }

    /** Sign-in codes already used here (their token, or a nostrconnect site's key): a code is good once. */
    private val usedCodes = context.getSharedPreferences("used-codes", Context.MODE_PRIVATE)
    private fun usedCode(id: String) = usedCodes.contains(id)
    private fun useCode(id: String) {
        val all = usedCodes.all
        val e = usedCodes.edit().putLong(id, System.currentTimeMillis())
        if (all.size > 200) all.entries.sortedBy { it.value as? Long ?: 0 }.take(all.size - 200).forEach { e.remove(it.key) }
        e.apply()
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
            usedCode(client!!) -> ui.update { it.copy(error = "You've already used that code. Ask the site for a new one.") }
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
        useCode(client)
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
        justRemoved[site.pk] = System.currentTimeMillis()
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

    // --- Your devices -------------------------------------------------------------------
    //
    // Adding one: it shows a code, this phone scans it, you unlock this phone (one device
    // vouching is instant only with its own lock), and this phone and a server make its
    // share by repair, each sealing half of it to the new device. Neither ever has it.

    /** You unlocked this phone: ask a server to start. */
    fun confirmAddDevice() {
        val a = ui.value.adding ?: return
        val target = servers().sortedBy { if (ui.value.online[it.idx] == true) 0 else 1 }.firstOrNull() ?: return
        send(target.pk!!, mapOf("type" to "add_device", "id" to env.random(8).toHex(), "pk" to a.pk, "name" to a.name, "relays" to a.relays, "lock" to true))
        ui.update { it.copy(adding = null) }
        note("Adding ${a.name}…")
    }

    fun cancelAddDevice() = ui.update { it.copy(adding = null) }

    /** No screen lock: one device can only vouch instantly with one, so it can't add a device yet. */
    fun lockMissing() = ui.update { it.copy(adding = null, error = "Set a screen lock on this phone first: adding a device needs it.") }

    /**
     * A server's half of the repair. Each of our shares splits its part of each new share
     * into a delta per helper share: the server's go back to it, and ours, with the
     * server's deltas for them, sum to sigmas sealed to the new device.
     */
    private fun onRepair(msg: Map<*, *>, from: Member, m: Membership) {
        val id = msg["id"] as? String ?: return
        val newPk = msg["pk"] as? String ?: return
        val helpers = (msg["helpers"] as? List<*>)?.mapNotNull { (it as? Long)?.toInt() } ?: return
        if (!helpers.containsAll(m.idxs) || !helpers.containsAll(from.idxs)) return
        val ks = (msg["ks"] as? List<*>)?.mapNotNull { (it as? Long)?.toInt() } ?: listOfNotNull((msg["k"] as? Long)?.toInt())
        // [k, from, to, delta]; or the earlier one-share form.
        val fromSrv = (msg["deltas"] as? List<*>)?.map { it as List<*> }
            ?: listOf(listOf(ks.first().toLong(), from.idx.toLong(), m.idx.toLong(), msg["delta"] as? String ?: return))
        val group = groupJson(m)
        val local = HashMap<Pair<Int, Int>, MutableList<String>>()
        val toSrv = mutableListOf<List<Any>>()
        for (k in ks) for (sh in m.shares) {
            for (d in Json.parse(FrostNative.repairStep1(group, sh.idx, sh.secret, Json.stringify(helpers), k)) as List<*>) {
                val j = ((d as List<*>)[0] as Long).toInt(); val delta = d[1] as String
                if (j in m.idxs) local.getOrPut(k to j) { mutableListOf() }.add(delta) else toSrv.add(listOf(k, sh.idx, j, delta))
            }
        }
        val sigmas = ks.flatMap { k -> m.idxs.map { j ->
            val theirs = fromSrv.filter { (it[0] as Long).toInt() == k && (it[2] as Long).toInt() == j }.map { it[3] as String }
            listOf(k, j, FrostNative.repairStep2(Json.stringify(local[k to j].orEmpty() + theirs)))
        } }
        val one = sigmas.size == 1
        send(from.pk!!, mapOf("type" to "repair_delta", "id" to id, "deltas" to toSrv) + (if (one) mapOf("delta" to toSrv[0][3]) else emptyMap()))
        if (making?.second == newPk) {
            // A paper: our pieces, sealed to it, kept by the servers.
            val content = Nip44.encrypt(Json.stringify(mapOf("sigmas" to sigmas)), Nip44.conversationKey(m.sk.hexToBytes(), newPk), env.random(32))
            return send(from.pk!!, mapOf("type" to "backup_piece", "id" to id, "content" to content))
        }
        send(newPk, mapOf("type" to "sigma", "id" to id, "sigmas" to sigmas) + (if (one) mapOf("k" to ks[0], "sigma" to sigmas[0][2]) else emptyMap()))
    }

    /** Who's in your key now: a server added or removed someone. */
    private fun onMembers(msg: Map<*, *>, m: Membership) {
        val list = (msg["members"] as? List<*>)?.mapNotNull { parseMember(it) } ?: return
        if (list.none { it.idx == m.idx }) return // a list without this phone isn't one to take
        // One from before a refresh this phone has done (a relay sending it late) has the old points.
        if (((msg["epoch"] as? Long)?.toInt() ?: m.epoch) < m.epoch) return
        val members = list.map { if (it.idx == m.idx) it.copy(pk = publicKeyHex(m.sk.hexToBytes())) else it }
        val updated = m.copy(group = m.group.copy(members = members))
        secrets.saveMembership(Json.stringify(membershipToMap(updated)))
        val added = members.filter { n -> m.group.members.none { it.idx == n.idx } }
        ui.update { it.copy(member = updated) }
        for (n in added) note(if (n.role == "server") "${n.name} is one of your servers now" else "${n.name} joined your key", "approved")
        // A second server changes the paper's weight (3 → 2): the old one should be replaced.
        if (added.any { it.role == "server" } && members.any { it.role == "backup" } && members.count { it.role == "server" } == 2) {
            ui.update { it.copy(askPaper = true) }; note("Make a new paper backup: with a second server, your paper changes", "denied")
        }
    }

    // Joining, on the new device: show a code, wait for a server's welcome and a device's sigma.
    private var joinWith: String? = null
    private val joinPieces = ConcurrentHashMap<String, Any>()

    fun startJoin(relays: List<String> = listOf("wss://syb.lol", "wss://nos.lol", "wss://relay.primal.net")) {
        val sk = generateSecretKey(env).toHex()
        joinWith = sk; joinPieces.clear()
        connect(relays, sk)
        val name = android.os.Build.MODEL.ifBlank { "A device" }
        val code = "cosign:join?pk=${publicKeyHex(sk.hexToBytes())}&name=${Uri.encode(name)}&" + relays.joinToString("&") { "r=" + Uri.encode(it) }
        ui.update { it.copy(joinCode = code, error = null) }
        // Debug builds only: the code names this device and its relays, which is nobody's business but the user's.
        if (context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0)
            android.util.Log.d("Cosign", "join code: $code") // for testing on an emulator, where nothing can scan the screen
    }

    /**
     * An invite from a device already in a key (`cosign:invite?pk=<its member key>&r=…`): the
     * same as showing our own join code, except we send it to that device (`join_request`),
     * again until a server's welcome arrives. It asks you, with its lock, then adds us.
     */
    private fun joinByInvite(code: String) {
        val u = Uri.parse(code.trim().replace("cosign:invite?", "cosign://invite?"))
        val inviter = u.getQueryParameter("pk")
        val urls = u.getQueryParameters("r").filter { it.startsWith("wss://") || it.startsWith("ws://") }
        if (!isHex32(inviter) || urls.isEmpty()) return ui.update { it.copy(error = "That invite is damaged. Ask for a new one.") }
        startJoin(urls)
        val sk = joinWith ?: return
        val name = android.os.Build.MODEL.ifBlank { "A phone" }
        val ask = mapOf("type" to "join_request", "pk" to publicKeyHex(sk.hexToBytes()), "name" to name, "relays" to urls)
        val started = System.currentTimeMillis()
        timer.scheduleWithFixedDelay(object : Runnable {
            override fun run() {
                if (joinWith != sk || System.currentTimeMillis() - started > 180_000) throw RuntimeException("done") // stops the schedule
                if (joinPieces["welcome"] == null) send(inviter!!, ask)
            }
        }, 1, 5, TimeUnit.SECONDS)
        note("Asked your other device to add this phone")
    }

    fun cancelJoin() { joinWith = null; relays?.stop(); relays = null; sk = null; ui.update { it.copy(joinCode = null) } }

    private fun onJoinPiece(msg: Map<*, *>, fromPk: String) {
        // A sigma per helper share for each new share, from the server's welcome and the vouching device: [k, helper, sigma].
        @Suppress("UNCHECKED_CAST")
        val pieces = (joinPieces.getOrPut("sigmas") { java.util.Collections.synchronizedList(mutableListOf<List<Any?>>()) } as MutableList<List<Any?>>)
        if (msg["type"] == "welcome") {
            joinPieces["welcome"] = msg; joinPieces["server"] = fromPk
            pieces.addAll((msg["sigmas"] as? List<*>)?.map { it as List<*> } ?: listOf(listOf(msg["k"], 0L, msg["sigma"])))
        } else pieces.addAll((msg["sigmas"] as? List<*>)?.map { it as List<*> } ?: listOf(listOf(msg["k"], -1L, msg["sigma"] as? String ?: return)))
        val w = joinPieces["welcome"] as? Map<*, *> ?: return
        val mySk = joinWith ?: return
        val group = parseGroup(w["group"]) ?: return
        val ks = (w["ks"] as? List<*>)?.mapNotNull { (it as? Long)?.toInt() } ?: listOfNotNull((w["k"] as? Long)?.toInt())
        val need = (w["helpers"] as? List<*>)?.size ?: 2
        val forK = { k: Int -> pieces.toList().filter { (it[0] as? Long)?.toInt() == k }.map { it[2] as String } }
        if (ks.isEmpty() || ks.any { forK(it).size < need }) return
        val g = groupJson(group)
        val shares = try { ks.map { k -> Share(k, FrostNative.repairStep3(g, Json.stringify(forK(k)), k)) } } catch (e: Exception) {
            return ui.update { it.copy(error = "The pieces didn't add up to a share of that key. Nothing was kept.") }
        }
        val points = shares.map { Point(it.idx, Frost.sharePub(it.secret)) }
        val me = Member(ks[0], w["name"] as? String ?: "This device", "device", publicKeyHex(mySk.hexToBytes()), points[0].sharePub, if (points.size > 1) points else null)
        val m = Membership(mySk, ks[0], shares, w["signer"] as? String ?: return, group.copy(members = group.members + me), (w["epoch"] as? Long)?.toInt() ?: 0)
        secrets.saveMembership(Json.stringify(membershipToMap(m)))
        send(joinPieces["server"] as String, mapOf("type" to "joined", "id" to w["id"], "sharePub" to me.sharePub, "sharePubs" to points.map { listOf(it.idx, it.sharePub) }))
        joinWith = null
        ui.update { it.copy(member = m, joinCode = null) }
        note("Joined. This device holds ${shares.size} of ${group.members.sumOf { it.points.size } + shares.size} shares of ${group.npub.take(16)}…")
        start() // same relays and key: it keeps the connection the joined message just went out on
    }

    // --- Deletions, and undoing a site -------------------------------------------------

    private val signedLog = java.io.File(context.filesDir, named("signed") + ".jsonl")
    private val approvedBatches = ConcurrentHashMap.newKeySet<String>()
    private val decidedBatches = ConcurrentHashMap.newKeySet<String>()

    /** Undo, during a deletion's few seconds. */
    fun cancelDeletion(batch: String) {
        for (s in servers()) send(s.pk!!, mapOf("type" to "cancel_batch", "batch" to batch))
        ui.update { u -> u.copy(deleting = u.deleting.filter { it.batch != batch }) }
        listener?.onDeletingGone(batch)
        note("Stopped a deletion", "denied")
    }

    fun decideBatch(batch: String, approve: Boolean) {
        val b = ui.value.batchAsks.firstOrNull { it.batch == batch } ?: return
        decidedBatches.add(batch)
        if (approve) approvedBatches.add(batch)
        for (s in servers()) send(s.pk!!, mapOf("type" to "batch_decision", "batch" to batch, "approve" to approve))
        ui.update { u -> u.copy(batchAsks = u.batchAsks.filter { it.batch != batch }) }
        listener?.onBatchGone(batch)
        note(if (approve) "You approved: ${b.text}" else "You declined: ${b.text}", if (approve) "approved" else "denied")
    }

    /** Ask a server what undoing this site would do; the answer opens the confirm sheet. */
    fun askUndoSite(site: Site) {
        val target = servers().sortedBy { if (ui.value.online[it.idx] == true) 0 else 1 }.firstOrNull() ?: return
        send(target.pk!!, mapOf("type" to "site_summary", "pk" to site.pk))
    }

    fun confirmUndoSite() {
        val sum = ui.value.summary ?: return
        val target = servers().sortedBy { if (ui.value.online[it.idx] == true) 0 else 1 }.firstOrNull() ?: return
        myUndos["site:${sum.pk}"] = System.currentTimeMillis()
        send(target.pk!!, mapOf("type" to "undo_site", "pk" to sum.pk))
        appByPk(sum.pk)?.let { apps.edit().remove(it.pkg).apply() }
        justRemoved[sum.pk] = System.currentTimeMillis()
        ui.update { u -> u.copy(summary = null, sites = u.sites.filter { it.pk != sum.pk && it.parent != sum.pk }) }
        note("Undoing everything ${sum.origin} did…")
    }

    fun closeSummary() = ui.update { it.copy(summary = null) }

    fun repost(d: Deleted) {
        val target = servers().sortedBy { if (ui.value.online[it.idx] == true) 0 else 1 }.firstOrNull() ?: return
        myUndos["repost:${d.id}"] = System.currentTimeMillis()
        justRemoved[d.id] = System.currentTimeMillis()
        send(target.pk!!, mapOf("type" to "repost", "id" to d.id))
        ui.update { u -> u.copy(deleted = u.deleted.filter { it.id != d.id }) }
        note("Posting a deleted ${d.kind} again")
    }

    /** Delete a version dated in the future, by its id. You asked, so this phone co-signs it without asking again. */
    fun removeFuture(f: Future) {
        val target = servers().sortedBy { if (ui.value.online[it.idx] == true) 0 else 1 }.firstOrNull() ?: return
        myUndos[f.id] = System.currentTimeMillis()
        justRemoved[f.id] = System.currentTimeMillis()
        send(target.pk!!, mapOf("type" to "remove_future", "id" to f.id))
        ui.update { it.copy(future = it.future.filter { x -> x.id != f.id }) }
        note("Removing a version dated in the future")
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

    private val apps = context.getSharedPreferences(named("apps"), Context.MODE_PRIVATE)
    private val waiting = ConcurrentHashMap<String, CompletableFuture<Map<*, *>>>()
    private val sharedXs = ConcurrentHashMap<String, Pair<Long, ByteArray>>()

    fun appGrant(pkg: String): AppGrant? = apps.getString(pkg, null)?.let { j ->
        (Json.parse(j) as? Map<*, *>)?.let { AppGrant(pkg, it["pk"] as String, it["label"] as String, it["dm"] == true) }
    }
    private fun appByPk(pk: String) = apps.all.keys.mapNotNull { appGrant(it) }.firstOrNull { it.pk == pk }
    private fun store(g: AppGrant) = apps.edit().putString(g.pkg, Json.stringify(mapOf("pk" to g.pk, "label" to g.label, "dm" to g.dm))).apply()

    fun connectApp(pkg: String, label: String): AppGrant {
        val had = appGrant(pkg)
        // This app's own grant follows its name: one made when it was called Cosign still
        // said so after it became Marble. Another app's label stays as it was when you
        // allowed it, so nothing can take on a name you already trusted.
        val renamed = had != null && pkg == context.packageName && had.label != label
        val g = when {
            had == null -> AppGrant(pkg, env.random(32).toHex(), label, false).also(::store)
            renamed -> had.copy(label = label).also(::store)
            else -> had
        }
        for (s in servers()) send(s.pk!!, mapOf("type" to "app_grant", "pk" to g.pk, "origin" to g.label))
        if (had == null) note("Connected ${g.label}", "approved")
        timer.schedule({ requestState() }, 2, TimeUnit.SECONDS)
        return g
    }

    fun allowDms(g: AppGrant): AppGrant = g.copy(dm = true).also { store(it); note("${g.label} may read and send your messages", "approved") }

    /** What would be destroyed, if this needs you to approve it; else null. */
    fun holdFor(ev: Event): String? = Policy.hold(ev, lists.latest(Policy.keyOf(ev)))

    /** The event an app sent, as it will be signed: under your key, with its id. */
    fun appEvent(json: String): Event {
        val m = ui.value.member ?: error("$appName isn't set up yet")
        val raw = Json.parse(json) as? Map<*, *> ?: throw IllegalArgumentException("not an event")
        val tags = (raw["tags"] as? List<*>)?.map { t -> (t as List<*>).map { it.toString() } } ?: emptyList()
        return Event(m.group.groupX, raw["created_at"] as? Long ?: env.now(), (raw["kind"] as Long).toInt(), tags, raw["content"] as? String ?: "").withId()
    }

    /** Sign for an app, with one of your servers. Blocks for up to a few seconds; never call on the main thread. */
    fun signForApp(g: AppGrant, ev: Event, approved: Boolean): Event {
        val m = ui.value.member ?: error("$appName isn't set up yet")
        Policy.refuse(ev)?.let { throw IllegalStateException(it) }
        if (!approved) holdFor(ev)?.let { throw NeedsApproval(it) }
        awake()
        val group = groupJson(m)
        val tried = mutableListOf<String>()
        for (srv in partners(m)) {
            val cs = m.shares.map { it to (Json.parse(FrostNative.commit(group, it.idx, it.secret)) as Map<*, *>) }
            val mine = cs.map { it.second["commit"] as Map<*, *> }
            val res = askServer(srv, mapOf("type" to "cosign_req", "id" to env.random(8).toHex(), "event" to ev.toMap(), "msg" to ev.id,
                "participants" to (m.idxs + srv.idxs).sorted(), "commits" to mine, "commit" to mine[0], "frost" to 2, "grant" to g.pk, "approved" to approved))
                ?: run { tried += "${srv.name}: no answer"; null } ?: continue
            if (res["ok"] != true) {
                val why = res["reason"] as? String ?: "refused"
                if (why.startsWith("revoked")) { apps.edit().remove(g.pkg).apply(); throw Revoked() }
                if (why.startsWith("needs-approval:")) throw NeedsApproval(why.removePrefix("needs-approval:").trim())
                tried += "${srv.name}: $why"; continue
            }
            // A server holds one share; it may answer the earlier way, one commit and one z.
            val theirs = (res["commits"] as? List<*>)?.map { it as Map<*, *> } ?: listOf(res["commit"] as Map<*, *>)
            val theirZs = (res["zs"] as? List<*>)?.map { val l = it as List<*>; (l[0] as Long).toInt() to l[1] as String } ?: listOf(srv.idx to res["z"] as String)
            if (theirs.map { (it["idx"] as Long).toInt() }.sorted() != srv.idxs.sorted() || theirZs.map { it.first }.sorted() != srv.idxs.sorted()) { tried += "${srv.name}: bad partial"; continue }
            val commits = Json.stringify(mine + theirs)
            if (!theirZs.all { (i, z) -> FrostNative.verifyPartial(group, ev.id, commits, i, z) }) { tried += "${srv.name}: bad partial"; continue }
            val zs = cs.map { (s, c) -> listOf(s.idx, FrostNative.sign(group, s.idx, s.secret, c["nonces"] as String, ev.id, commits)) }
            val signed = ev.copy(sig = FrostNative.aggregate(group, ev.id, commits, Json.stringify(zs + theirZs.map { listOf(it.first, it.second) })))
            send(srv.pk!!, mapOf("type" to "phone_signed", "event" to signed.toMap(), "grant" to g.pk, "approved" to approved))
            // Relay logins happen once per relay an app connects to: not worth a line each.
            if (ev.kind != 22242 || approved) note("Signed ${Describe.kind(ev.kind)} for ${g.label}", if (approved) "approved" else "auto")
            return signed
        }
        throw IllegalStateException("Couldn't reach your servers (${tried.joinToString("; ")})")
    }

    // --- Cosign's own actions (a like, a follow) -----------------------------------------
    //
    // Signed the way an app on this phone signs, under a grant of Cosign's own: your servers
    // judge the event, log it and keep the list version it replaced, so Undo works as for any app.

    /** The latest version of one of your lists this phone has seen signed ("3": your follows). */
    fun latest(key: String): Event? = lists.latest(key)

    /** Sign something you did in Cosign itself. Blocks for a few seconds; never call on the main thread. */
    fun signOwn(ev: Event, approved: Boolean = false): Event {
        val m = ui.value.member ?: error("$appName isn't set up yet")
        val own = context.packageName
        // A new grant has to reach your servers before the first request that uses it.
        val g = appGrant(own) ?: connectApp(own, appName).also { Thread.sleep(2500) }
        val signed = try { signForApp(g, ev, approved) } catch (_: Revoked) {
            val again = connectApp(own, appName); Thread.sleep(2500); signForApp(again, ev, approved)
        }
        lists.record(signed, m.group.groupX)
        return signed
    }

    /**
     * The app's own data, encrypted to this account itself (NIP-44 to self): what Marble keeps
     * in app data (NIP-78) and nobody else should read. The other side is this account's own
     * key, always — there is no peer to pass in, so this is no way to read anyone else's
     * messages, and the servers still hand out decryption partials to live devices only
     * (COSIGN.md §5.6).
     */
    fun nip44Self(text: String, encrypt: Boolean): String {
        val m = ui.value.member ?: error("$appName isn't set up yet")
        val own = context.packageName
        val g = appGrant(own) ?: connectApp(own, appName).also { Thread.sleep(2500) }
        return try { nip44(g, m.group.groupX, text, encrypt) } catch (_: Revoked) {
            val again = connectApp(own, appName); Thread.sleep(2500); nip44(again, m.group.groupX, text, encrypt)
        }
    }

    /** The shared x with [peerX], from this phone's half and a server's. Kept ten minutes, in memory. */
    private fun sharedX(g: AppGrant, peerX: String): ByteArray {
        sharedXs[peerX]?.let { (at, x) -> if (System.currentTimeMillis() - at < 600_000) return x }
        val m = ui.value.member ?: error("$appName isn't set up yet")
        awake()
        for (srv in partners(m)) {
            val participants = (m.idxs + srv.idxs).sorted()
            val res = askServer(srv, mapOf("type" to "ecdh_req", "id" to env.random(8).toHex(), "peerX" to peerX, "participants" to participants, "grant" to g.pk)) ?: continue
            if (res["ok"] != true) { if ((res["reason"] as? String)?.startsWith("revoked") == true) throw Revoked(); continue }
            val mine = m.shares.map { Frost.ecdhPartial(it.idx, it.secret, participants, peerX).hexToBytes() }
            val theirs = ((res["points"] as? List<*>) ?: listOf(res["point"])).map { (it as String).hexToBytes() }
            val x = Secp256k1.pubKeyCombine((mine + theirs).toTypedArray()).copyOfRange(1, 33)
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

    private fun groupJson(m: Membership) = groupJson(m.group)
    /** The group as the library takes it: every share point, whoever holds it. */
    private fun groupJson(g: Group) = Json.stringify(mapOf("groupX" to g.groupX, "threshold" to g.threshold,
        "members" to g.members.flatMap { it.points }.map { mapOf("idx" to it.idx, "sharePub" to it.sharePub) }))

    /** Your servers that make the threshold with this device, the ones online first. */
    private fun partners(m: Membership) = servers().filter { (m.idxs + it.idxs).toSet().size >= m.group.threshold }
        .sortedBy { if (ui.value.online[it.idx] == true) 0 else 1 }

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

    /** Other keys this phone reads member messages for (a paper being restored): public key → secret. */
    private var alsoFor = mapOf<String, String>()

    private fun connect(urls: List<String>, secret: String, also: Map<String, String> = emptyMap()) {
        relays?.stop()
        sk = secret
        alsoFor = also
        relays = Relays(urls, ::onEvent, ::status).also {
            it.start(mapOf("kinds" to listOf(KIND_MEMBER), "#p" to listOf(publicKeyHex(secret.hexToBytes())) + also.keys))
        }
    }

    private fun onEvent(e: Event) {
        if (e.kind != KIND_MEMBER) { ui.value.member?.let { lists.record(e, it.group.groupX) }; return }
        val msg = whole(e.pubkey, open(e) ?: return) ?: return
        val type = msg["type"] as? String ?: return
        // Relays replay recent ephemeral events to a new subscription; the sender has given up on those.
        if ((type == "sign_req" || type == "ecdh_req") && System.currentTimeMillis() / 1000 - e.createdAt > 30) return
        if (type == "pair_offer") return onOffer(msg, e.pubkey)
        if (type == "dkg1" || type == "dkg2") { dkg?.take(msg, e.pubkey); return }
        // A server's host key answering (adding a server): not a member, so before that check.
        if (type.startsWith("enroll") || type == "pong") { (msg["id"] as? String)?.let { waiting.remove(it)?.complete(msg) }; return }
        if (ui.value.restoring != null && !isMember) return onRestoreMsg(msg, e)
        ui.value.member?.let { m -> if (m.group.members.any { it.pk == e.pubkey } && onRefreshMsg(msg, e.pubkey, m)) return }
        if (joinWith != null && (type == "welcome" || type == "sigma")) return onJoinPiece(msg, e.pubkey)
        if (growing != null && (type == "welcome" || type == "sigma") && msg["id"] == growing?.first) return onGrowPiece(msg, e.pubkey)
        val m = ui.value.member ?: return
        val from = m.group.members.firstOrNull { it.pk == e.pubkey && it.role == "server" } ?: return
        lastSeen[from.idx] = System.currentTimeMillis()
        when (type) {
            "sign_req" -> onSignReq(msg, from, m)
            "ecdh_req" -> onEcdhReq(msg, from, m)
            "state" -> onState(msg, from.pk!!)
            "repair" -> onRepair(msg, from, m)
            "members" -> onMembers(msg, m)
            "backup_made" -> onBackupMade()
            "guard" -> onGuard(msg)
            "released" -> onReleased(msg, m)
            "noted" -> onNoted(msg, m)
            "backup" -> onTakeOutPaper(msg, m)
            "take_out_failed", "forget_failed" -> { ui.update { it.copy(takeOut = TakeOut(TakeOut.Stage.FAILED, "Not done: ${msg["reason"]}")) } }
            "add_failed" -> { note("Couldn't add the device: ${msg["reason"]}", "denied"); ui.update { it.copy(error = "Couldn't add the device: ${msg["reason"]}") } }
            "connected" -> onConnected(msg)
            // Whoever runs that server stopped serving this account, and is deleting its piece.
            "server_left" -> {
                note("${from.name} stopped serving this account. Add another server, so you always have one to sign with.", "denied")
                ui.update { it.copy(error = "${from.name} stopped serving this account. Open Servers and add another one.") }
            }
            "cosign_res", "ecdh_res" -> (msg["id"] as? String)?.let { waiting.remove(it)?.complete(msg) }
            "logged" -> (msg["entry"] as? Map<*, *>)?.let { signedLog.appendText(Json.stringify(it) + "\n") }
            "deleting" -> {
                val d = Deleting(msg["batch"] as? String ?: return, msg["by"] as? String ?: "a site", (msg["count"] as? Long)?.toInt() ?: 1, msg["until"] as? Long ?: 0)
                ui.update { u -> u.copy(deleting = u.deleting.filter { it.batch != d.batch } + d) }
                listener?.onDeleting(d)
            }
            "deleting_done" -> (msg["batch"] as? String)?.let { b -> ui.update { u -> u.copy(deleting = u.deleting.filter { it.batch != b }) }; listener?.onDeletingGone(b) }
            "approve_batch" -> {
                val b = BatchAsk(msg["batch"] as? String ?: return, msg["text"] as? String ?: "Delete several events", msg["by"] as? String ?: "a site", msg["expires"] as? Long ?: (System.currentTimeMillis() + 55_000))
                if (ui.value.batchAsks.none { it.batch == b.batch } && b.batch !in decidedBatches) { ui.update { it.copy(batchAsks = it.batchAsks + b) }; listener?.onBatch(b) }
            }
            "site_summary" -> {
                val counts = (msg["counts"] as? Map<*, *>)?.entries?.associate { (k, v) -> k.toString() to ((v as? Long)?.toInt() ?: 0) } ?: emptyMap()
                ui.update { it.copy(summary = SiteSummary(msg["pk"] as? String ?: return, msg["origin"] as? String ?: "that site", (msg["total"] as? Long)?.toInt() ?: 0,
                    counts, (msg["lists"] as? List<*>)?.map { it.toString() } ?: emptyList(), (msg["deletable"] as? Long)?.toInt() ?: 0)) }
            }
            "undone_site" -> note("Undid ${msg["origin"]}: ${msg["restored"]} list(s) put back, ${msg["deleted"]} event(s) deleted (copies kept)", "approved")
            "signed" -> Event.fromMap(msg["event"])?.let { lists.record(it, m.group.groupX) }
            "undo_failed" -> note("Couldn't undo: ${msg["reason"]}", "denied")
        }
        status()
    }

    private class ServerState(val sites: List<Site>, val changes: List<Change>, val deleted: List<Deleted>, val future: List<Future>)
    /** The newest state from each server. One that hasn't heard of something yet mustn't hide
     *  what the other has, so the phone shows them together. */
    private val states = ConcurrentHashMap<String, ServerState>()

    private fun onState(msg: Map<*, *>, fromPk: String) {
        val sites = (msg["sites"] as? List<*>)?.mapNotNull { x -> (x as? Map<*, *>)?.let {
            Site(it["pk"] as? String ?: return@let null, it["origin"] as? String ?: "a site", it["added"] as? Long ?: 0, it["lastUsed"] as? Long ?: 0,
                it["parent"] as? String, it["via"] as? String) } } ?: return
        val changes = (msg["changes"] as? List<*>)?.mapNotNull { x -> (x as? Map<*, *>)?.let {
            Change(it["id"] as? String ?: return@let null, it["text"] as? String ?: "", it["by"] as? String ?: "", it["at"] as? Long ?: 0, it["held"] == true, it["undone"] == true) } } ?: emptyList()
        val deleted = (msg["deleted"] as? List<*>)?.mapNotNull { x -> (x as? Map<*, *>)?.let {
            Deleted(it["id"] as? String ?: return@let null, it["kind"] as? String ?: "event", it["at"] as? Long ?: 0, it["text"] as? String ?: "") } } ?: emptyList()
        val future = (msg["future"] as? List<*>)?.mapNotNull { x -> (x as? Map<*, *>)?.let { Future(it["id"] as? String ?: return@let null, it["text"] as? String ?: "") } } ?: emptyList()
        states[fromPk] = ServerState(sites, changes, deleted, future)
        val all = states.values
        val mergedSites = all.flatMap { it.sites }.groupBy { it.pk }.values.map { same -> same.maxBy { it.lastUsed } }
        val mergedChanges = all.flatMap { it.changes }.groupBy { it.id }.values.map { same -> same.first().copy(undone = same.any { it.undone }) }
        ui.update { it.copy(
            sites = mergedSites.filter { s -> !removedHere(s.pk) && !(s.parent != null && removedHere(s.parent)) }.sortedByDescending { s -> s.lastUsed },
            changes = mergedChanges.sortedByDescending { c -> c.at },
            deleted = all.flatMap { s -> s.deleted }.distinctBy { d -> d.id }.filter { d -> !removedHere(d.id) }.sortedByDescending { d -> d.at }.take(20),
            future = all.flatMap { s -> s.future }.distinctBy { f -> f.id }.filter { f -> !removedHere(f.id) },
        ) }
    }

    private fun onSignReq(msg: Map<*, *>, from: Member, m: Membership) {
        val id = msg["id"] as? String ?: return
        answered[id]?.let { send(from.pk!!, it); return }
        if (id in asking) return
        val reply = { body: Map<String, Any?> -> val full = mapOf("type" to "sign_res", "id" to id) + body; answered[id] = full; send(from.pk!!, full) }
        val ev = Event.fromMap(msg["event"]) ?: return reply(mapOf("ok" to false, "reason" to "malformed event"))
        val participants = (msg["participants"] as? List<*>)?.mapNotNull { (it as? Long)?.toInt() } ?: emptyList()
        val cs = (msg["commits"] as? List<*>) ?: listOfNotNull(msg["commit"])
        val commits = cs.mapNotNull { c -> (c as? Map<*, *>)?.let { Frost.Commit((it["idx"] as Long).toInt(), it["D"] as String, it["E"] as String) } }
        val digest = msg["msg"] as? String
        if (commits.isEmpty() || digest == null || commits.map { it.idx }.sorted() != from.idxs.sorted() || participants.sorted() != (from.idxs + m.idxs).sorted())
            return reply(mapOf("ok" to false, "reason" to "bad participants"))
        val commit = commits[0]
        // Sign only what we were shown: the digest must be this event's id under your key.
        if (ev.pubkey != m.group.groupX || ev.computeId() != digest) return reply(mapOf("ok" to false, "reason" to "event does not match the message"))
        Policy.refuse(ev)?.let { note("Refused: $it", "denied"); return reply(mapOf("ok" to false, "reason" to "refused: $it")) }
        val app = msg["app"] as? String ?: "a site"
        // Your server's judgement, or this phone's own: either one is enough to ask you.
        val hold = msg["hold"] as? String ?: Policy.hold(ev, lists.latest(Policy.keyOf(ev)))
        val undo = msg["undo"] as? String
        val ask = Ask(id, from.pk!!, from.name, app, ev, digest, commit, hold ?: "", System.currentTimeMillis() + 55_000, if (msg["frost"] == 2L) 2 else 1, commits)
        // Something you asked for on this phone (Undo, Post again, undoing a site), or a
        // batch of deletions you already approved: signed without asking again.
        val myUndo = undo != null && System.currentTimeMillis() - (myUndos[undo] ?: 0) < 600_000 ||
            (msg["batch"] as? String)?.let { it in approvedBatches } == true
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

    /** FROST (RFC 9591) only: the earlier hand-rolled math is no longer taken. */
    private fun sign(ask: Ask, m: Membership, reply: (Map<String, Any?>) -> Unit) {
        if (ask.frost != 2) return reply(mapOf("ok" to false, "reason" to "only FROST (RFC 9591) rounds are taken"))
        val group = groupJson(m)
        val cs = m.shares.map { it to (Json.parse(FrostNative.commit(group, it.idx, it.secret)) as Map<*, *>) }
        val mine = cs.map { it.second["commit"] as Map<*, *> }
        val theirs = ask.commits.map { mapOf("idx" to it.idx, "D" to it.D, "E" to it.E) }
        val all = Json.stringify(theirs + mine)
        val zs = cs.map { (s, c) -> listOf(s.idx, FrostNative.sign(group, s.idx, s.secret, c["nonces"] as String, ask.msg, all)) }
        reply(mapOf("ok" to true, "commits" to mine, "zs" to zs, "commit" to mine[0], "z" to zs[0][1]))
    }

    private fun expire(id: String) {
        val ask = ui.value.asks.firstOrNull { it.id == id } ?: return
        pendingReplies.remove(id)
        asking.remove(id)
        ui.update { it.copy(asks = it.asks.filter { a -> a.id != id }) }
        listener?.onAskGone(id)
        note("Not answered in time: ${ask.hold} (${ask.app})", "denied")
    }

    /**
     * Who may ask this phone for a piece of a decryption (COSIGN.md §5.6). Your own devices
     * may: they hold as much of your key as this one does, and one of them coordinating a
     * decryption is you reading your own messages. A server may not. A server never
     * coordinates a decryption — it asks because something else wants to read your messages,
     * and nothing on this phone asked for it. Until now any server that asked was helped,
     * which left that rule a promise rather than a fact.
     */
    internal object Helping {
        fun helps(role: String?) = role == "phone" || role == "device"
    }

    private fun onEcdhReq(msg: Map<*, *>, from: Member, m: Membership) {
        val id = msg["id"] as? String ?: return
        answered[id]?.let { send(from.pk!!, it); return }
        if (!Helping.helps(from.role)) {
            val no = mapOf("type" to "ecdh_res", "id" to id, "ok" to false,
                "reason" to "not-allowed: your devices read your messages, your servers don't")
            answered[id] = no
            send(from.pk!!, no)
            if (System.currentTimeMillis() - lastEcdhNote > 60_000) {
                lastEcdhNote = System.currentTimeMillis()
                note("${from.name} asked for a piece of reading your messages. Refused: only your own devices do that.", "denied")
            }
            return
        }
        val participants = (msg["participants"] as? List<*>)?.mapNotNull { (it as? Long)?.toInt() } ?: return
        val peerX = msg["peerX"] as? String ?: return
        if (!isHex32(peerX) || participants.sorted() != (from.idxs + m.idxs).sorted()) return
        val points = m.shares.map { Frost.ecdhPartial(it.idx, it.secret, participants, peerX) }
        val body = mapOf("type" to "ecdh_res", "id" to id, "ok" to true, "points" to points, "point" to points[0])
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
        val to = e.tags.firstOrNull { it.firstOrNull() == "p" }?.getOrNull(1)
        val secret = (alsoFor[to] ?: sk)?.hexToBytes() ?: throw IllegalStateException()
        Json.parse(Nip44.decrypt(e.content, Nip44.conversationKey(secret, e.pubkey))) as? Map<*, *>
    } catch (_: Exception) { null }

    // --- Serialisation -------------------------------------------------------

    private fun parseGroup(v: Any?): Group? {
        val g = v as? Map<*, *> ?: return null
        val members = (g["members"] as? List<*>)?.mapNotNull { parseMember(it) } ?: return null
        // A weighted offer has no key yet: it's made after you say yes.
        return Group(g["groupX"] as? String ?: "", g["npub"] as? String ?: "", (g["threshold"] as? Long)?.toInt() ?: 2,
            (g["relays"] as? List<*>)?.filterIsInstance<String>() ?: return null, members)
    }

    private fun parseMember(x: Any?): Member? {
        val mm = x as? Map<*, *> ?: return null
        val shares = (mm["shares"] as? List<*>)?.mapNotNull { s -> (s as? Map<*, *>)?.let { Point((it["idx"] as Long).toInt(), it["sharePub"] as? String ?: "") } }
        return Member((mm["idx"] as Long).toInt(), mm["name"] as? String ?: "?", mm["role"] as? String ?: "device", mm["pk"] as? String, mm["sharePub"] as? String ?: return null, shares)
    }

    private fun parseMembership(v: Any?): Membership? {
        val m = v as? Map<*, *> ?: return null
        val idx = (m["idx"] as Long).toInt()
        // Saved before weighted keys: one share, under "share".
        val shares = (m["shares"] as? List<*>)?.map { val s = it as Map<*, *>; Share((s["idx"] as Long).toInt(), s["secret"] as String) }
            ?: listOf(Share(idx, m["share"] as? String ?: return null))
        return Membership(m["sk"] as String, idx, shares, m["signer"] as? String ?: return null, parseGroup(m["group"])?.takeIf { it.groupX.isNotEmpty() } ?: return null,
            (m["epoch"] as? Long)?.toInt() ?: 0, m["mirrored"] as? Boolean)
    }

    private fun membershipToMap(m: Membership) = mapOf(
        "sk" to m.sk, "idx" to m.idx, "shares" to m.shares.map { mapOf("idx" to it.idx, "secret" to it.secret) }, "signer" to m.signer, "epoch" to m.epoch, "mirrored" to m.mirrored,
        "group" to mapOf(
            "groupX" to m.group.groupX, "npub" to m.group.npub, "threshold" to m.group.threshold, "relays" to m.group.relays,
            "members" to m.group.members.map { mapOf("idx" to it.idx, "name" to it.name, "role" to it.role, "pk" to it.pk, "sharePub" to it.sharePub) +
                (it.shares?.let { s -> mapOf("shares" to s.map { p -> mapOf("idx" to p.idx, "sharePub" to p.sharePub) }) } ?: emptyMap()) },
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
