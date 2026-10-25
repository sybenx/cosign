package cc.aaro.cosign

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.util.Log
import cc.aaro.cosign.core.Event
import cc.aaro.cosign.core.Json
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

// The main process's side of the signer. The UI works with [Accounts] and [Phone] as it
// always did; underneath, each call goes to SignerService in the signer process, and each
// account's state comes back with its secrets taken out. Nothing here can sign or decrypt
// by itself, or read a share.

/** The accounts on this phone, as the UI sees them. Main process only. */
class Accounts(private val context: Context) {
    private val phones = java.util.concurrent.ConcurrentHashMap<String, Phone>()
    private val order = MutableStateFlow<List<String>>(emptyList())
    private val shown = MutableStateFlow("0")
    /** Which account is on screen, by slot. */
    val activeSlot: StateFlow<String> = shown
    private val known = MutableStateFlow(false)
    /** The signer has said which accounts there are (and how each one is): until then, draw nothing. */
    val ready: StateFlow<Boolean> = known
    @Volatile private var signer: ISigner? = null

    private val client = object : ISignerClient.Stub() {
        override fun accounts(slots: Array<String>, active: String) {
            for (s in slots) at(s)
            order.value = slots.toList()
            shown.value = active
            known.value = true
        }

        override fun state(slot: String, ui: ByteArray, label: String, needsPaper: Boolean) {
            val p = at(slot)
            p.label = label
            p.needsPaper = needsPaper
            p.ui.value = try { Wire.read(ui) } catch (e: Exception) { Log.w(TAG, "state: $e"); return }
        }
    }

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            Startup.mark("signer")
            val s = ISigner.Stub.asInterface(binder)
            signer = s
            try { s.listen(client) } catch (e: Exception) { Log.w(TAG, "listen: $e") }
        }
        // The signer process stopped: Android starts it again and calls onServiceConnected.
        override fun onServiceDisconnected(name: ComponentName) { signer = null }
        override fun onBindingDied(name: ComponentName) { signer = null; context.unbindService(this); bind() }
    }

    fun bind() { context.bindService(Intent(context, SignerService::class.java), connection, Context.BIND_AUTO_CREATE or Context.BIND_IMPORTANT) }

    private fun at(slot: String) = phones.getOrPut(slot) { Phone(slot) { signer } }

    val all: List<Phone> get() = order.value.map(::at)
    val active: Phone get() = at(shown.value)
    fun phone(slot: String): Phone? = phones[slot]

    fun show(slot: String) {
        if (slot !in order.value) return
        shown.value = slot
        call("show") { it.show(slot) }
    }

    /** A place for another account: a new, empty one, shown, ready to be joined, made, imported or restored. */
    fun add(): Phone {
        val slot = call("add") { it.add() } ?: return active
        if (slot !in order.value) order.value = order.value + slot
        shown.value = slot
        return at(slot)
    }

    /** An empty place given up: forget it, and show another. */
    fun forget(slot: String) {
        if (order.value.size <= 1) return
        order.value = order.value - slot
        if (shown.value == slot) shown.value = order.value.first()
        call("forget") { it.forget(slot) }
    }

    private fun <T> call(what: String, f: (ISigner) -> T): T? = try {
        signer?.let(f) ?: run { Log.w(TAG, "$what: the signer isn't connected"); null }
    } catch (e: Exception) { Log.w(TAG, "$what: $e"); null }

    private companion object { const val TAG = "CosignClient" }
}

/**
 * One account, as the UI sees it: its state ([ui], with no secrets in it) and what you can
 * do with it. Every action goes to the account's [Signer] in the signer process and comes
 * back as a change of state; the UI never waits on one. Main process only.
 */
class Phone internal constructor(val slot: String, private val signer: () -> ISigner?) {
    val ui = MutableStateFlow(Ui())
    /** Which key this is, for a list: its npub, shortened (from the signer, with each state). */
    @Volatile var label = "New key"; internal set
    /** One device and no paper backup: lose this phone and the key is gone. */
    @Volatile var needsPaper = false; internal set
    val isMember get() = ui.value.member != null

    /** A sign-in you said yes to finishes in the background; a failure is a notification. */
    var connectInBackground = false
        set(v) { field = v; act("connectInBackground", flag = v) }

    private fun act(action: String, text: String? = null, flag: Boolean = false) {
        try { signer()?.act(slot, action, text, flag) ?: Log.w("CosignClient", "$action: the signer isn't connected") } catch (e: Exception) { Log.w("CosignClient", "$action: $e") }
    }

    // Joining, making, importing or restoring a key.
    fun accept() = act("accept")
    fun decline() = act("decline")
    fun createAccount() = act("createAccount")
    fun startJoin() = act("startJoin")
    fun cancelJoin() = act("cancelJoin")
    fun scanned(text: String) = act("scanned", text)
    fun pastedBackup(text: String) = act("pastedBackup", text)
    fun cancelRestore() = act("cancelRestore")
    fun cancelRecovery() = act("cancelRecovery")
    /** The nsec typed in: straight to the signer, which reads it and wipes it. Wipes [chars] here. */
    fun importKey(chars: CharArray) {
        try { signer()?.importKey(slot, chars) ?: Log.w("CosignClient", "importKey: the signer isn't connected") } catch (e: Exception) { Log.w("CosignClient", "importKey: $e") }
        finally { chars.fill(' ') }
    }
    fun clearError() = act("clearError")
    fun showError(text: String) = act("showError", text)
    fun lockMissing() = act("lockMissing")
    fun leave() = act("leave")

    // Approvals, deletions, sign-ins.
    fun decide(id: String, approve: Boolean) = act("decide", id, approve)
    fun decideBatch(batch: String, approve: Boolean) = act("decideBatch", batch, approve)
    fun cancelDeletion(batch: String) = act("cancelDeletion", batch)
    fun cancelGuard(id: String) = act("cancelGuard", id)
    fun confirmConnect() = act("confirmConnect")
    fun closeConnect() = act("closeConnect")
    fun acceptMove() = act("acceptMove")
    fun closeMove() = act("closeMove")

    // Devices, sites, history.
    fun confirmAddDevice() = act("confirmAddDevice")
    fun cancelAddDevice() = act("cancelAddDevice")
    fun askReportLost(d: Member) = act("askReportLost", d.idx.toString())
    fun confirmReportLost() = act("confirmReportLost")
    fun cancelReportLost() = act("cancelReportLost")
    fun removeSite(site: Site) = act("removeSite", site.pk)
    fun askUndoSite(site: Site) = act("askUndoSite", site.pk)
    fun confirmUndoSite() = act("confirmUndoSite")
    fun closeSummary() = act("closeSummary")
    fun undo(change: Change) = act("undo", change.id)
    fun repost(d: Deleted) = act("repost", d.id)
    fun removeFuture(f: Future) = act("removeFuture", f.id)

    // Backups, servers, taking the account out.
    fun makePaper() = act("makePaper")
    fun laterPaper() = act("laterPaper")
    fun closePaper() = act("closePaper")
    fun chooseServer() = act("chooseServer")
    fun addServer(s: cc.aaro.cosign.net.Servers.Server, code: String? = null) = act("addServer", s.pk, code != null)
    fun closeServerChoice() = act("closeServerChoice")
    fun askTakeOutPaper(on: Boolean) = act("askTakeOutPaper", flag = on)
    fun takeOutViaServers() = act("takeOutViaServers")
    fun closeTakeOut() = act("closeTakeOut")
    fun forgetServers() = act("forgetServers")
    /** The paper's code or the key taken out is ready ([ui] says so, without it): the signer shows it, over this app. */
    fun reveal() = act("reveal")

    // Cosign's own actions (a like, a follow).

    /** Sign something you did in Cosign itself. Blocks for a few seconds; never call on the main thread. */
    fun signOwn(ev: Event, approved: Boolean = false): Event {
        val s = signer() ?: throw IllegalStateException("$appName's signer isn't running")
        val r = s.signOwn(slot, ev.toJson(), approved)
        r.getString("approval")?.let { throw NeedsApproval(it) }
        r.getString("event")?.let { j -> return Event.fromMap(Json.parse(j)) ?: throw IllegalStateException("bad event from the signer") }
        throw IllegalStateException(r.getString("error") ?: "no answer")
    }

    /**
     * Encrypt or decrypt your own app data with your own account (NIP-44 to self). The other
     * side is always your account, so this reads nothing but what it wrote. Blocks for a few
     * seconds, as a server takes part: never call it on the main thread. Null if it failed.
     */
    fun nip44Self(text: String, encrypt: Boolean): String? = try { signer()?.nip44Own(slot, text, encrypt) } catch (e: Exception) { null }

    /** The latest version of one of your lists this phone has seen signed ("3": your follows). */
    fun latest(key: String): Event? = try { signer()?.latest(slot, key)?.let { Event.fromMap(Json.parse(it)) } } catch (e: Exception) { null }
}
