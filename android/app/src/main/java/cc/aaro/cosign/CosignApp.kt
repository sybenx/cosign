package cc.aaro.cosign

import android.app.Application
import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

class CosignApp : Application() {
    lateinit var accounts: Accounts
        private set
    /** The key on screen. Code that serves every key (notifications, apps, push) uses [accounts]. */
    val phone get() = accounts.active

    override fun onCreate() {
        super.onCreate()
        instance = this
        accounts = Accounts(this)
        if (accounts.all.any { it.isMember }) CosignService.start(this)
    }

    companion object {
        lateinit var instance: CosignApp
            private set
    }
}

/**
 * The keys on this phone, each a [Phone] of its own: its own shares, servers, sites,
 * history and relay connection, so adding a key never touches another. One is on
 * screen at a time; all of them answer their servers all the time.
 */
class Accounts(private val context: Context) {
    private val prefs = context.getSharedPreferences("accounts", Context.MODE_PRIVATE)
    private val phones = LinkedHashMap<String, Phone>()
    private val shown = MutableStateFlow("0")
    /** Which key is on screen, by slot. */
    val activeSlot: StateFlow<String> = shown

    init {
        // "0" is the key this phone always had (or none yet), with its storage as it was.
        val slots = (prefs.getString("slots", null)?.split(',')?.filter { it.isNotBlank() } ?: listOf("0")).ifEmpty { listOf("0") }
        for (s in slots) open(s)
        shown.value = prefs.getString("active", null)?.takeIf { it in phones } ?: slots.first()
    }

    private fun open(slot: String) = Phone(context, slot).also { p -> phones[slot] = p; p.onLeft = { forget(it.slot) } }
    private fun persist() = prefs.edit().putString("slots", phones.keys.joinToString(",")).putString("active", shown.value).apply()

    val all: List<Phone> get() = phones.values.toList()
    val active: Phone get() = phones[shown.value] ?: phones.values.first()
    fun phone(slot: String) = phones[slot]

    fun show(slot: String) { if (slot in phones) { shown.value = slot; persist() } }

    /** A place for another key: a new, empty one, shown, ready to be joined, made, imported or restored. */
    fun add(): Phone {
        phones.values.firstOrNull { !it.isMember && it.ui.value.restoring == null }?.let { show(it.slot); return it }
        val slot = java.lang.Long.toHexString(System.nanoTime()).takeLast(8)
        val p = open(slot)
        p.listener = all.firstOrNull { it.listener != null }?.listener
        show(slot)
        return p
    }

    /** A key left (or an empty place given up): forget it, and show another. */
    fun forget(slot: String) {
        if (phones.size <= 1) return // the last place stays, empty
        phones.remove(slot)
        if (shown.value == slot) shown.value = phones.keys.first()
        persist()
    }

    /** The key an app on this phone connected to. */
    fun forApp(pkg: String): Phone? = all.firstOrNull { it.appGrant(pkg) != null }
}
