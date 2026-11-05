// The keykin-android demo: one screen in the app's main process, which holds no key material; every action
// goes to the signer process through KeykinClient. Driven by intents (`adb shell am start ... --es cmd join
// --es code ... --es relays ws://10.0.2.2:...`) or by its buttons; every result a JSON line on screen and in
// logcat (tag KeykinDemo).
package cc.aaro.keykin.demo

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import keykin.android.KeykinClient
import org.json.JSONObject

class Main : Activity() {
    private lateinit var out: TextView
    private lateinit var input: EditText
    private val work = HandlerThread("keykin-demo").apply { start() }
    private val bg = Handler(work.looper)
    private val client get() = shared(applicationContext)
    private val prefs by lazy { getSharedPreferences("demo", MODE_PRIVATE) }
    private val told get() = toldOnce

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        out = TextView(this).apply { setTextIsSelectable(true); textSize = 12f }
        input = EditText(this).apply { hint = "invite code (keykin:join?…)" }
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 48, 32, 32) }
        col.addView(input)
        for ((label, cmd) in listOf("Join" to "join", "Post a note" to "sign", "State" to "state", "Fetch" to "fetch", "Forget" to "forget"))
            col.addView(Button(this).apply { text = label; setOnClickListener { run(JSONObject().put("cmd", cmd).put("code", input.text.toString()).put("relays", RELAYS)
                .put("content", if (cmd == "sign" && input.text.isNotBlank() && !input.text.startsWith("keykin")) input.text.toString() else "gm from the keykin-android demo")) } })
        // Report a device lost, and check the paper: on a screen in the signer process (the lock, the paper's words).
        col.addView(Button(this).apply { text = "Devices and paper"; setOnClickListener {
            prefs.getString("slot", null)?.let { s -> startActivity(Intent(this@Main, Tools::class.java).putExtra("slot", s)) } } })
        col.addView(out)
        setContentView(ScrollView(this).apply { addView(col) })
        // What the signer tells: the check digits once, the join once, errors as they come. One client and one
        // listener per process: an activity recreated between intents must not hear (and say) things twice.
        if (!listening) { listening = true; client.listen(object : KeykinClient.Listener {
            override fun state(slot: String, state: JSONObject) {
                if (slot != prefs.getString("slot", null)) return
                state.optString("check").takeIf { it.isNotEmpty() && told.add("check:$it") }?.let { say(JSONObject().put("check", it)) }
                if (state.optBoolean("joined") && told.add("joined:$slot")) say(JSONObject().put("device", state.getString("device")).put("state", state.getString("state")))
                state.optString("error").takeIf { it.isNotEmpty() && told.add("error:$it") }?.let { say(JSONObject().put("error", it)) }
                if (state.optBoolean("joined")) told.add("joined:$slot")
                // Device policy's cards and held events, each said once (the person's answer is a command).
                state.optJSONArray("cards")?.let { a -> for (i in 0 until a.length()) a.getJSONObject(i).let { c -> if (told.add("card:${c.getInt("id")}")) say(JSONObject().put("card", c)) } }
                state.optJSONArray("held")?.let { a -> for (i in 0 until a.length()) a.getJSONObject(i).let { h -> if (told.add("held:${h.getString("id")}")) say(JSONObject().put("held", h)) } }
            }
        }) }
        lastSay = ::sayHere
        handle(intent)
    }
    override fun onNewIntent(i: Intent) { super.onNewIntent(i); handle(i) }
    private fun handle(i: Intent?) {
        // Commands come only through the `.Drive` alias, which needs DUMP (the shell has it; other apps don't):
        // the launcher entry is exported, and must not let any app join, sign or forget (review 15 M3).
        val driven = i?.component?.className?.endsWith(".Drive") == true
        val cmd = i?.getStringExtra("cmd")?.takeIf { driven } ?: run { run(JSONObject().put("cmd", "open")); return }
        run(JSONObject().put("cmd", cmd).put("code", i.getStringExtra("code") ?: "").put("relays", i.getStringExtra("relays") ?: RELAYS)
            .put("content", i.getStringExtra("content") ?: "gm from the keykin-android demo").put("scopes", i.getStringExtra("scopes") ?: "sign-in,post")
            .put("id", i.getStringExtra("id") ?: "").put("allow", i.getStringExtra("allow") == "true").put("signer", i.getStringExtra("signer") ?: "").put("scope", i.getStringExtra("scope") ?: ""))
    }
    private fun say(x: JSONObject) { (lastSay ?: ::sayHere)(x) }
    private fun sayHere(x: JSONObject) { val line = x.toString(); Log.i("KeykinDemo", line); runOnUiThread { out.append(line + "\n\n") } }

    private fun run(c: JSONObject) = bg.post {
        try {
            val k = client.signer()
            when (c.getString("cmd")) {
                "open" -> say(JSONObject().put("ready", true).put("slot", prefs.getString("slot", null) ?: JSONObject.NULL))
                "join" -> {
                    val slot = prefs.getString("slot", null) ?: k.add().also { prefs.edit().putString("slot", it).apply() }
                    told.clear(); k.join(slot, c.getString("code"), c.getString("relays"))
                }
                "sign" -> say(JSONObject(k.signOwn(slot(), JSONObject().put("kind", 1).put("content", c.optString("content")).put("tags", org.json.JSONArray()).toString())).let { it.optJSONObject("event") ?: it })
                "state" -> say(client.states[slot()] ?: JSONObject().put("error", "no_state"))
                "fetch" -> k.fetch(slot())
                "grants" -> say(JSONObject().put("grants", org.json.JSONArray(k.grants(slot()))))
                // The NIP-46 home on the phone: a bunker:// link for a site; the person's answer to a card or a scope ask.
                // A test harness: in a debug build the link (its secret included) goes to logcat for the e2e test to read;
                // a release build never logs it (LinkLog).
                "bunker" -> say(JSONObject().put("bunker", k.bunker(slot(), c.getString("relays"), c.getString("scopes"))?.let(LinkLog::shown) ?: JSONObject.NULL))
                "answer" -> { k.answerCard(slot(), c.getString("id").toInt(), c.getBoolean("allow")); say(JSONObject().put("answered", c.getString("id"))) }
                "allow" -> { k.allowScope(slot(), c.getString("signer"), c.getString("scope")); say(JSONObject().put("allowed", c.getString("scope"))) }
                "forget" -> { k.forget(slot()); prefs.edit().remove("slot").apply(); say(JSONObject().put("forgotten", true)) }
                else -> say(JSONObject().put("error", "unknown command"))
            }
        } catch (e: Exception) { say(JSONObject().put("error", "internal").put("detail", e.toString())) }
    }
    private fun slot() = prefs.getString("slot", null) ?: error("join first")
    companion object {
        /** The relays a join uses: the emulator's local stack in a debug build, the test stack's in the dry-run build. */
        val RELAYS: String = BuildConfig.RELAYS
        private var client: KeykinClient? = null
        @Synchronized fun shared(c: android.content.Context) = client ?: KeykinClient(c).bind().also { client = it }
        @Volatile private var listening = false
        private val toldOnce: MutableSet<String> = java.util.Collections.synchronizedSet(HashSet())
        private var lastSay: ((JSONObject) -> Unit)? = null
    }
}

/** What the demo may log of a bunker link: the whole link in a debug build (the e2e test reads it), never its secret
 *  in a release build. */
object LinkLog {
    fun shown(link: String, debug: Boolean = BuildConfig.DEBUG): String = if (debug) link else link.substringBefore('?') + "?(relays and secret not logged)"
}
