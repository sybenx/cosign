// A repair round (core §4.2 step 3, §6.7.4) coordinated by one helper holding shares: as a device, or as the paper's
// holder at a recovery (its backup seat's shares, core §4.4). `repair_start` to every other helper, the deltas
// exchanged, `repair_finish`; one sigma wrap per helper, every one sealed to `sealTo`. `sk` is the coordinator's key
// (a member key, or the paper's), and `st` its shares at the state the repair runs at.
package keykin

import org.json.JSONArray
import org.json.JSONObject

object Repair {
    fun run(net: RelayNet, env: Envelope, sk: ByteArray, st: ShareState, helpers: List<Signer>, participant: Long, sealTo: String, why: String, extra: JSONObject? = null): List<JSONObject> {
        val pub = Keykin.secp.pub(sk)
        val sh = Codes.stateHash(st.ids.toList())
        val rid = hex(ByteArray(16).also { java.security.SecureRandom().nextBytes(it) })
        val hj = JSONArray(helpers.map { JSONObject().put("key", it.key).put("indices", JSONArray(it.indices)) })
        val all = helpers.flatMap { it.indices }
        // Our own step 1: for each of our indices, the deltas to every helper index.
        val keptMine = ArrayList<String>(); val toOthers = HashMap<String, MutableList<String>>()
        for ((i, s) in st.shares) {
            val byIndex = Frost.repairDeltas(st.C, all, i, s, participant)
            for (h in helpers) for (j in h.indices) { val d = byIndex[j] ?: refuse("repair_failed"); if (h.key == pub) keptMine += d else toOthers.getOrPut(h.key) { ArrayList() } += d }
        }
        val start = JSONObject().put("type", "repair_start").put("participant", participant).put("helpers", hj).put("state", sh).put("rid", rid).put("why", why).put("seal_to", sealTo)
        extra?.let { x -> for (k in x.keys()) start.put(k, x.get(k)) }
        val outs = HashMap<String, JSONObject>()
        for (h in helpers.filter { it.key != pub }) {
            val a = net.send(sk, h.key, JSONObject(start.toString()))
            if (a.optString("type") != "repair_delta") refuse(a.optString("code").ifEmpty { "repair_refused" }, a.optString("detail"))
            outs[h.key] = a.optJSONObject("out") ?: refuse("repair_refused")
        }
        val wraps = ArrayList<JSONObject>()
        for (h in helpers.filter { it.key != pub }) {
            val mine = env.wrap(sk, h.key, JSONObject().put("type", "repair_delta").put("participant", participant).put("rid", rid).put("deltas", JSONArray(toOthers[h.key] ?: emptyList<String>())), net.now)
            val deltas = JSONArray().put(mine)
            for (o in helpers.filter { it.key != pub && it.key != h.key }) outs[o.key]?.optJSONObject(h.key)?.let { deltas.put(it) }
            val a = net.send(sk, h.key, JSONObject().put("type", "repair_finish").put("participant", participant).put("rid", rid).put("seal_to", sealTo).put("deltas", deltas))
            if (a.optString("type") != "repair_sigma") refuse(a.optString("code").ifEmpty { "repair_refused" })
            wraps += a.getJSONObject("wrap")
        }
        // Our own sigma, from what we kept and what every other helper sent us.
        val received = helpers.filter { it.key != pub }.flatMap { h -> outs[h.key]?.optJSONObject(pub)?.let { w -> env.unwrap(sk, w).body.getJSONArray("deltas").let { d -> (0 until d.length()).map { d.getString(it) } } } ?: refuse("repair_refused", "no deltas for us") }
        val sigma = Frost.repairSigma(keptMine + received)
        wraps += env.wrap(sk, sealTo, JSONObject().put("type", "repair_sigma").put("index", participant).put("sigma", sigma).put("state", sh), net.now)
        return wraps
    }
}
