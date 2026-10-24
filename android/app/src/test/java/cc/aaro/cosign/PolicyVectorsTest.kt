package cc.aaro.cosign

import cc.aaro.cosign.core.Event
import cc.aaro.cosign.core.Policy
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

/** The phone's policy against cases judged by the servers' (server/test/policy-vectors.ts). */
class PolicyVectorsTest {
    private fun event(o: JSONObject): Event {
        val tags = o.getJSONArray("tags").let { a -> (0 until a.length()).map { i -> a.getJSONArray(i).let { t -> (0 until t.length()).map(t::getString) } } }
        return Event("0".repeat(64), o.getLong("created_at"), o.getInt("kind"), tags, o.getString("content"))
    }

    @Test fun sameJudgementAsTheServers() {
        val cases = JSONArray(javaClass.classLoader!!.getResource("policy.json")!!.readText())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val prev = if (c.isNull("prev")) null else event(c.getJSONObject("prev"))
            val want = if (c.isNull("hold")) null else c.getString("hold")
            assertEquals(c.getString("label"), want, Policy.hold(event(c.getJSONObject("event")), prev))
        }
    }
}
