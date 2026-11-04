// The keykin-android demo: one screen, driven by intents (`adb shell am start ... --es cmd join --es code
// ... --es relays ws://10.0.2.2:...`) or by its buttons, every result a JSON line on screen and in logcat
// (tag KeykinDemo), the device's state sealed by keykin-android's SealedStore.
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
import keykin.Device
import keykin.KeykinException
import keykin.RelayNet
import keykin.android.KeykinAndroid
import keykin.android.SealedStore
import keykin.hex
import org.json.JSONArray
import org.json.JSONObject

class Main : Activity() {
    private lateinit var out: TextView
    private lateinit var input: EditText
    private val work = HandlerThread("keykin-demo").apply { start() }
    private val bg = Handler(work.looper)
    private var device: Device? = null
    private var net: RelayNet? = null
    private val store by lazy { SealedStore(this, "demo") }

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        KeykinAndroid.init()
        out = TextView(this).apply { setTextIsSelectable(true); textSize = 12f }
        input = EditText(this).apply { hint = "invite code (keykin:join?…)" }
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 48, 32, 32) }
        col.addView(input)
        for ((label, cmd) in listOf("Join" to "join", "Sign a note" to "sign", "Data key" to "datakey", "Members" to "members", "Fetch" to "fetch"))
            col.addView(Button(this).apply { text = label; setOnClickListener { run(JSONObject().put("cmd", cmd).put("code", input.text.toString()).put("relays", RELAYS)) } })
        col.addView(out)
        setContentView(ScrollView(this).apply { addView(col) })
        handle(intent)
    }
    override fun onNewIntent(i: Intent) { super.onNewIntent(i); handle(i) }
    private fun handle(i: Intent?) {
        val cmd = i?.getStringExtra("cmd") ?: run { run(JSONObject().put("cmd", "open")); return }
        run(JSONObject().put("cmd", cmd).put("code", i.getStringExtra("code") ?: "").put("relays", i.getStringExtra("relays") ?: RELAYS)
            .put("content", i.getStringExtra("content") ?: "gm from the keykin-android demo"))
    }
    private fun say(x: JSONObject) {
        val line = x.toString()
        Log.i("KeykinDemo", line)
        runOnUiThread { out.append(line + "\n\n") }
    }
    private fun relaysOf(c: JSONObject) = c.optString("relays").split(",").filter { it.isNotBlank() }
    private fun netFor(c: JSONObject) = net ?: RelayNet(relaysOf(c), wire = KeykinAndroid.wire).connect().also { net = it }
    private fun loaded(c: JSONObject): Device = device ?: store.load()?.let { s -> Device.fromSnapshot(s, netFor(c)).also { d -> d.persist = { store.save(it) }; device = d } } ?: throw KeykinException("no_device", "join first")

    private fun run(c: JSONObject) = bg.post {
        try {
            say(when (c.getString("cmd")) {
                "open" -> JSONObject().put("ready", true).put("stored", store.load() != null)
                "echo" -> JSONObject().put("code", c.optString("code")).put("relays", c.optString("relays"))
                "join" -> {
                    val d = Device.join(c.getString("code"), netFor(c), { check -> say(JSONObject().put("check", check)) })
                    d.persist = { store.save(it) }; store.save(d.snapshot()); device = d
                    JSONObject().put("device", d.pub).put("state", d.ctx.state)
                }
                "sign" -> loaded(c).sign(1, c.optString("content", "gm from the keykin-android demo"))
                "datakey" -> loaded(c).dataKey().let { (st, k) -> JSONObject().put("state", st).put("key", hex(k)) }
                "fetch" -> loaded(c).let { d -> d.fetch(); JSONObject().put("state", d.ctx.state).put("ids", JSONArray(d.ids.sorted())) }
                "members" -> loaded(c).members.devices().let { (self, asOf, keys) -> JSONObject().put("self", self).put("asOf", asOf).put("keys", JSONArray(keys.map { it.key })) }
                "forget" -> { store.destroy(); device = null; JSONObject().put("forgotten", true) }
                else -> JSONObject().put("error", "unknown command")
            })
        } catch (e: KeykinException) { say(JSONObject().put("error", e.code).put("detail", e.message)) }
        catch (e: Exception) { say(JSONObject().put("error", "internal").put("detail", e.toString())) }
    }
    companion object { const val RELAYS = "ws://10.0.2.2:17311,ws://10.0.2.2:17312" }
}
