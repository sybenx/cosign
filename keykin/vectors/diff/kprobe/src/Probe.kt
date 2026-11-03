// Runs each probe of probes.json through the Kotlin port and writes kt-results.json (same order).
package keykin

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.io.File

private fun res(f: () -> Any?): Any = try { f() ?: JSONObject.NULL } catch (e: KeykinException) { "refuse:${e.code}" } catch (e: Throwable) { "CRASH:${e::class.simpleName}: ${e.message?.take(80)}" }
private fun strsOf(a: JSONArray) = (0 until a.length()).map { a.getString(it) }

fun main(args: Array<String>) {
    val probes = JSONArray(File(args[0]).readText())
    val out = JSONArray()
    for (k in 0 until probes.length()) {
        val p = probes.getJSONObject(k); val i = p.get("input")
        val r: Any = when (p.getString("area")) {
            "event_id" -> res { eventId(Event.of(JSONObject(i as String))) }
            "jcs" -> res { Jcs.of(JSONTokener(i as String).nextValue()) }
            "schnorr" -> { val o = i as JSONObject; res { schnorrVerify(o.getString("sig"), unhex(o.getString("msg")), o.getString("pub")) } }
            "lock" -> { val o = i as JSONObject; res { checkAssertion(o.getString("g"), o.getString("pub"), o.getString("rp"), unhex(o.getString("what")), o.getJSONObject("assertion")) } }
            "destructive" -> { val o = i as JSONObject; val t = o.getJSONArray("tags"); res { Rules.destructive(o.getInt("kind"), o.getString("content"), (0 until t.length()).map { strsOf(t.getJSONArray(it)) }, o.getInt("recent")) } }
            "lifetime" -> { val o = i as JSONObject; res { Rules.lifetime(o.getString("type"), o.getString("cls"), o.getLong("age")) } }
            "record" -> { val o = i as JSONObject; res { Record.check(Event.of(o.getJSONObject("event")), o.getString("g")); "ok" } }
            "membership" -> { val o = i as JSONObject; res {
                val rec = JSONObject(Event.of(o.getJSONObject("record")).content); val ch = o.getJSONArray("changes")
                val m = Membership.compute(rec, (0 until ch.length()).map { Event.of(ch.getJSONObject(it)) })
                JSONObject().put("devices", JSONArray(m.devices)).put("removed", JSONArray(m.removed))
                    .put("seats", JSONObject().also { s -> m.seats.forEach { (a, b) -> s.put(a, b ?: JSONObject.NULL) } })
                    .put("backup", m.backup ?: JSONObject.NULL).put("refused", JSONArray(m.refused)).put("invariant", m.invariant)
                    .put("locks", JSONObject().also { s -> m.locks.forEach { (a, b) -> s.put(a, b ?: JSONObject.NULL) } })
            } }
            "slip39" -> { val o = i as JSONObject; val ms = o.getJSONArray("mnemonics"); val l = (0 until ms.length()).map { ms.getString(it) }; res { hex(if (o.optBoolean("backup")) Slip39.recoverBackup(l) else Slip39.combine(l, o.getString("passphrase"))) } }
            else -> "unknown area"
        }
        out.put(r)
    }
    File(args[1]).writeText(out.toString(1))
}
