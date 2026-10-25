package cc.aaro.cosign

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * The keys on this phone, each a [Signer] of its own: its own shares, servers, sites,
 * history and relay connection, so adding a key never touches another. One is on
 * screen at a time; all of them answer their servers all the time.
 *
 * Signer process only. The UI's view of the same list is [Accounts].
 */
class Signers(private val context: Context) {
    private val prefs = context.getSharedPreferences("accounts", Context.MODE_PRIVATE)
    private val signers = LinkedHashMap<String, Signer>()
    private val shown = MutableStateFlow("0")
    /** Which key is on screen, by slot. */
    val activeSlot: StateFlow<String> = shown
    private val order = MutableStateFlow<List<String>>(emptyList())
    /** Every key's slot, in order: changes when one is added or forgotten. */
    val slots: StateFlow<List<String>> = order

    init {
        Proc.signerOnly("Signers")
        // "0" is the key this phone always had (or none yet), with its storage as it was.
        val slots = (prefs.getString("slots", null)?.split(',')?.filter { it.isNotBlank() } ?: listOf("0")).ifEmpty { listOf("0") }
        for (s in slots) open(s)
        shown.value = prefs.getString("active", null)?.takeIf { it in signers } ?: slots.first()
    }

    private fun open(slot: String) = Signer(context, slot).also { p -> signers[slot] = p; order.value = signers.keys.toList(); p.onLeft = { forget(it.slot) } }
    private fun persist() = prefs.edit().putString("slots", signers.keys.joinToString(",")).putString("active", shown.value).apply()

    val all: List<Signer> get() = signers.values.toList()
    val active: Signer get() = signers[shown.value] ?: signers.values.first()
    fun signer(slot: String) = signers[slot]

    fun show(slot: String) { if (slot in signers) { shown.value = slot; persist() } }

    /** A place for another key: a new, empty one, shown, ready to be joined, made, imported or restored. */
    fun add(): Signer {
        signers.values.firstOrNull { !it.isMember && it.ui.value.restoring == null }?.let { show(it.slot); return it }
        val slot = java.lang.Long.toHexString(System.nanoTime()).takeLast(8)
        val p = open(slot)
        p.listener = all.firstOrNull { it.listener != null }?.listener
        show(slot)
        return p
    }

    /** A key left (or an empty place given up): forget it, and show another. */
    fun forget(slot: String) {
        if (signers.size <= 1) return // the last place stays, empty
        signers.remove(slot)
        order.value = signers.keys.toList()
        if (shown.value == slot) shown.value = signers.keys.first()
        persist()
    }

    /** The key an app on this phone connected to. */
    fun forApp(pkg: String): Signer? = all.firstOrNull { it.appGrant(pkg) != null }
}
