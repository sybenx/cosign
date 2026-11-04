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
    private val client by lazy { KeykinClient(applicationContext).bind() }
    private val prefs by lazy { getSharedPreferences("demo", MODE_PRIVATE) }
    private var told = HashSet<String>()

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        out = TextView(this).apply { setTextIsSelectable(true); textSize = 12f }
        input = EditText(this).apply { hint = "invite code (keykin:join?…)" }
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 48, 32, 32) }
        col.addView(input)
        for ((label, cmd) in listOf("Join" to "join", "Sign a note" to "sign", "State" to "state", "Fetch" to "fetch", "Forget" to "forget"))
            col.addView(Button(this).apply { text = label; setOnClickListener { run(JSONObject().put("cmd", cmd).put("code", input.text.toString()).put("relays", RELAYS)) } })
        col.addView(out)
        setContentView(ScrollView(this).apply { addView(col) })
        // What the signer tells: the check digits once, the join once, errors as they come.
        client.listen(object : KeykinClient.Listener {
            override fun state(slot: String, state: JSONObject) {
                if (slot != prefs.getString("slot", null)) return
                state.optString("check").takeIf { it.isNotEmpty() && told.add("check:$it") }?.let { say(JSONObject().put("check", it)) }
                if (state.optBoolean("joined") && told.add("joined:$slot")) say(JSONObject().put("device", state.getString("device")).put("state", state.getString("state")))
                state.optString("error").takeIf { it.isNotEmpty() && told.add("error:$it") }?.let { say(JSONObject().put("error", it)) }
                if (state.optBoolean("joined")) told.add("joined:$slot")
            }
        })
        handle(intent)
    }
    override fun onNewIntent(i: Intent) { super.onNewIntent(i); handle(i) }
    private fun handle(i: Intent?) {
        val cmd = i?.getStringExtra("cmd") ?: run { run(JSONObject().put("cmd", "open")); return }
        run(JSONObject().put("cmd", cmd).put("code", i.getStringExtra("code") ?: "").put("relays", i.getStringExtra("relays") ?: RELAYS)
            .put("content", i.getStringExtra("content") ?: "gm from the keykin-android demo"))
    }
    private fun say(x: JSONObject) { val line = x.toString(); Log.i("KeykinDemo", line); runOnUiThread { out.append(line + "\n\n") } }

    private fun run(c: JSONObject) = bg.post {
        try {
            val k = client.signer()
            when (c.getString("cmd")) {
                "open" -> say(JSONObject().put("ready", true).put("slot", prefs.getString("slot", null) ?: JSONObject.NULL))
                "echo" -> say(JSONObject().put("code", c.optString("code")).put("relays", c.optString("relays")))
                "join" -> {
                    val slot = prefs.getString("slot", null) ?: k.add().also { prefs.edit().putString("slot", it).apply() }
                    told.clear(); k.join(slot, c.getString("code"), c.getString("relays"))
                }
                "sign" -> say(JSONObject(k.signOwn(slot(), JSONObject().put("kind", 1).put("content", c.optString("content")).put("tags", org.json.JSONArray()).toString())).let { it.optJSONObject("event") ?: it })
                "state" -> say(client.states[slot()] ?: JSONObject().put("error", "no_state"))
                "fetch" -> k.fetch(slot())
                "forget" -> { k.forget(slot()); prefs.edit().remove("slot").apply(); say(JSONObject().put("forgotten", true)) }
                else -> say(JSONObject().put("error", "unknown command"))
            }
        } catch (e: Exception) { say(JSONObject().put("error", "internal").put("detail", e.toString())) }
    }
    private fun slot() = prefs.getString("slot", null) ?: error("join first")
    companion object { const val RELAYS = "ws://10.0.2.2:17311,ws://10.0.2.2:17312" }
}
