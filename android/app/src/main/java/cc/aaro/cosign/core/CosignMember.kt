package cc.aaro.cosign.core

import java.util.Base64

/**
 * QRST profile `cosign-member` (site/src/member.ts is the other half): this phone's place
 * in a key, handed over by the web page that dealt it, when you move a key out of a web
 * app into Cosign (site/src/import.ts). The page shows the code; this phone shows five
 * digits and you type them there.
 *
 * Payload: base64 of JSON { v, group, idx, shares, signer, claim }.
 * Lowest check: `type`: these shares and a server are your key, like an nsec.
 */
data class MemberMove(val group: Map<*, *>, val idx: Int, val shares: List<Pair<Int, String>>, val signer: String, val claim: String)

object CosignMemberProfile : Profile<MemberMove> {
    override val id = "cosign-member"
    override val maxPayloadBytes = 8192
    override val revocable = false
    override val minCheck = CodeCheck.TYPE
    private val HEX32 = Regex("^[0-9a-f]{64}$")

    override fun encode(value: MemberMove): String =
        Base64.getEncoder().encodeToString(Json.stringify(mapOf("v" to 1, "group" to value.group, "idx" to value.idx,
            "shares" to value.shares.map { mapOf("idx" to it.first, "secret" to it.second) }, "signer" to value.signer, "claim" to value.claim)).toByteArray())

    override fun check(content: String): Checked<MemberMove> {
        val m = try { Json.parse(String(Base64.getDecoder().decode(content), Charsets.UTF_8)) as? Map<*, *> } catch (_: Exception) { null }
            ?: return Checked.Bad("not a key move")
        val g = m["group"] as? Map<*, *>; val idx = (m["idx"] as? Long)?.toInt(); val signer = m["signer"] as? String; val claim = m["claim"] as? String
        val shares = (m["shares"] as? List<*>)?.mapNotNull { s -> (s as? Map<*, *>)?.let { ((it["idx"] as? Long)?.toInt() ?: return@let null) to (it["secret"] as? String ?: return@let null) } }
        if (m["v"] != 1L || g == null || idx == null || signer == null || !HEX32.matches(signer) || claim == null || !Regex("^[0-9a-f]{32}$").matches(claim)
            || shares.isNullOrEmpty() || shares.any { !HEX32.matches(it.second) } || (g["groupX"] as? String)?.let(HEX32::matches) != true)
            return Checked.Bad("malformed")
        val me = (g["members"] as? List<*>)?.mapNotNull { it as? Map<*, *> }?.firstOrNull { (it["idx"] as? Long)?.toInt() == idx }
            ?: return Checked.Bad("no such member")
        val idxs = (me["shares"] as? List<*>)?.mapNotNull { ((it as? Map<*, *>)?.get("idx") as? Long)?.toInt() } ?: listOf(idx)
        if (me["role"] == "server" || idxs.sorted() != shares.map { it.first }.sorted()) return Checked.Bad("the shares aren't that member's")
        return Checked.Ok(MemberMove(g, idx, shares, signer, claim))
    }

    override fun render(value: MemberMove): String {
        val servers = (value.group["members"] as? List<*>)?.mapNotNull { it as? Map<*, *> }?.filter { it["role"] == "server" }?.map { it["name"] } ?: emptyList()
        return "Keep ${Nip19.npub(value.group["groupX"] as String).take(14)}… in Cosign: this phone holds ${value.shares.size} of its shares, with ${servers.joinToString(", ").ifEmpty { "no server" }}"
    }
}
