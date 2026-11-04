// A headless Kotlin device, for cross-language tests (test/kotlin.e2e.test.ts): load a TS device's
// snapshot, run each command of a JSON list over the given relays, print one JSON line per result.
//   keykin.HeadlessKt <snapshot.json> <relay,relay> <commands.json>
//   commands: [{"cmd":"sign","content":"…"}, {"cmd":"nip44"|"nip04","peer":"<hex>","text":"…","encrypt":true}, {"cmd":"fetch"}, {"cmd":"members"}, {"cmd":"datakey"}]
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.io.File

fun main(args: Array<String>) {
    val net = RelayNet(args[1].split(",")).connect()
    try {
        // The first argument is a TS device's snapshot, or `join:<invite code>` to join as a new device.
        val d = if (args[0].startsWith("join:")) Device.join(args[0].removePrefix("join:"), net, { println(JSONObject().put("check", it).toString()); System.out.flush() })
            else Device.fromSnapshot(File(args[0]).readText(), net)
        println(JSONObject().put("device", d.pub).toString()); System.out.flush()
        val cmds = JSONArray(File(args[2]).readText())
        for (k in 0 until cmds.length()) {
            val c = cmds.getJSONObject(k)
            val out = try {
                when (c.getString("cmd")) {
                    "sign" -> d.sign(1, c.getString("content"))
                    // Catch up from every server (changes, then the inbox) and say where this device now is.
                    "fetch" -> { d.fetch(); JSONObject().put("state", d.ctx.state).put("ids", JSONArray(d.ids.sorted())) }
                    "members" -> d.members.devices().let { (self, asOf, keys) -> JSONObject().put("self", self).put("asOf", asOf)
                        .put("keys", JSONArray(keys.map { JSONObject().put("key", it.key).put("added_by", it.addedBy ?: JSONObject.NULL).put("flagged", it.flagged) }))
                        .put("removed", JSONArray(d.members.removed(0).map { it.json() })) }
                    "datakey" -> d.dataKey().let { (st, k) -> JSONObject().put("state", st).put("key", hex(k)) }
                    // Be a NIP-46 home (Doors §3.3): print a bunker:// link, then answer sites for `seconds`.
                    "bunker" -> { val home = Nip46Home(d, net); println(JSONObject().put("bunker", home.mintBunker(args[1].split(","))).toString()); System.out.flush()
                        Thread.sleep(c.optLong("seconds", 30) * 1000); JSONObject().put("served", true) }
                    "nip44" -> JSONObject().put("result", d.nip44(c.getString("peer"), c.getString("text"), c.optBoolean("encrypt", true)))
                    "nip04" -> JSONObject().put("result", d.nip04(c.getString("peer"), c.getString("text"), c.optBoolean("encrypt", true)))
                    else -> JSONObject().put("error", "unknown command")
                }
            } catch (e: KeykinException) { JSONObject().put("error", e.code) }
            println(out.toString()); System.out.flush()
        }
    } catch (e: KeykinException) { println("""{"error":"${e.code}"}""") } finally { net.close() }
    System.exit(0)
}
