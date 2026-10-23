package cc.aaro.cosign.core

import java.util.Base64

// One transfer session: the state machine of spec §7 (Flow A) and §8 (Flow B), the
// commit-then-reveal exchange of §6, the consent rules of §9 that can be enforced in
// code, and the multiple-responder handling of §13. A line-for-line port of
// src/core/session.ts in sybenx/qr-secret-transfer.
//
// This file performs no I/O. It is handed gift wraps and user decisions, and it
// returns effects for a host to carry out.
//
//                 shows the QR        contacts
//   Flow A        Receiver            Sender         QR says mode=offer
//   Flow B        Sender              Receiver       QR says mode=request

enum class Phase { WAITING, RELEASE, CODE, ACCEPT, SENT, ENDED }

enum class Outcome(val wire: String) {
    DELIVERED("delivered"),
    SENT_UNCONFIRMED("sent-unconfirmed"),
    RECEIVED("received"),
    DECLINED("declined"),
    CANCELLED("cancelled"),
    PEER_ABORTED("peer-aborted"),
    ATTEMPTS_EXHAUSTED("attempts-exhausted"),
    EXPIRED("expired"),
    BAD_PAYLOAD("bad-payload"),
    BLOCKED_PEER("blocked-peer"),
    SECOND_RESPONDER("second-responder"),
}

data class TransferRecord(
    val ts: Long,
    val profile: String,
    val role: Role,
    val outcome: Outcome,
    val sas: String,
    val peer: String,
    val multi: Boolean,
    val check: CodeCheck,
)

sealed class Effect<out T> {
    /** Publish this wrap to every relay, and keep sending `giftWrap(seal, to)` until settled (§11.5). */
    data class Publish(val event: Event, val seal: Event, val to: String, val kind: Int, val unanswered: Boolean, val label: String) : Effect<Nothing>()
    data class Settled(val peer: String, val kinds: List<Int>) : Effect<Nothing>()
    data class Commit<T>(val value: T) : Effect<T>()
    data class Record(val record: TransferRecord) : Effect<Nothing>()
    data class FailedPeers(val pubs: List<String>) : Effect<Nothing>()
    data class Trace(val text: String) : Effect<Nothing>()
    data class Ended(val outcome: Outcome) : Effect<Nothing>()
}

data class SessionView(
    val role: Role,
    val showing: Boolean,
    val phase: Phase,
    val outcome: Outcome?,
    val check: CodeCheck,
    /** Receiver, phase CODE or ACCEPT, unless the check is none: the five digits to show. */
    val code: String?,
    /** Sender, phase RELEASE, check compare: the code of the device being compared. */
    val compare: String?,
    /** Receiver, phase ACCEPT: the P5 rendering. */
    val rendering: String?,
    val attemptsLeft: Int,
    val ready: Int,
    val multipleResponders: Boolean,
    val dropped: Int,
    val canAdvance: Boolean,
    val expiresAt: Long,
    val ackDeadline: Long?,
    val released: Boolean,
)

class Session<T>(
    val role: Role,
    val showing: Boolean,
    val profile: Profile<T>,
    /** This session's burner. The session owns it from here and wipes it when it ends. */
    private val secretKey: ByteArray,
    private val env: Env,
    /** Contacting party only: the burner public key read from the QR. */
    private val peerPub: String? = null,
    /**
     * Sender only: what to send. May instead be handed to the release call, so that a
     * platform credential check can unlock it at the moment of release (nostr-nsec).
     */
    payload: T? = null,
    private val isBlocked: (String) -> Boolean = { false },
    /** This device's setting. Defaults to the strictest. */
    check: CodeCheck = CodeCheck.TYPE,
    /** Contacting party only: the token read from the QR. */
    token: String? = null,
    /** Contacting party only: the `check` read from the QR. */
    peerCheck: CodeCheck? = null,
) {
    private class Peer<T>(
        val pub: String,
        val order: Int,
        val commit: String?,
        val ownNonce: String,
        var check: CodeCheck,
    ) {
        var peerNonce: String? = null
        var sas: String? = null
        var displayed = false
        var held: T? = null
        var failed = false
    }

    val pub: String = publicKeyHex(secretKey)
    val startedAt: Long = env.now()
    private val own: CodeCheck = stricter(check, profile.minCheck)
    val token: String
    private var peak: CodeCheck
    private val rejected = HashSet<String>()
    private var noneAgreed = false
    private var payloadContent: String? = null

    private var phase = Phase.WAITING
    private var outcome: Outcome? = null
    private val peers = LinkedHashMap<String, Peer<T>>()
    private val seen = HashSet<String>()
    private val contacted = HashSet<String>()
    private val failedPeers = LinkedHashSet<String>()
    private var order = 0
    private var attempts = 0
    private var multipleResponders = false
    private var dropped = 0
    private var active: String? = null
    private var releasedTo: String? = null
    private var releasedSas: String? = null
    private var ackDeadline: Long? = null
    private var released = false
    private var started = false

    init {
        require(PROFILE_ID.matches(profile.id)) { "profile: bad identifier" }
        if (showing) {
            require(peerPub == null) { "session: the showing device has no peer yet" }
            this.token = env.random(TOKEN_BYTES).toHex()
            peak = own
        } else {
            require(PairingUri.isToken(token)) { "session: the contacting device needs the token from the QR" }
            this.token = token!!
            peak = stricter(own, peerCheck ?: CodeCheck.TYPE)
            require(isHex32(peerPub)) { "session: the contacting device needs the key from the QR" }
            require(peerPub != pub) { "session: a device cannot pair with itself" }
            require(isValidPublicKey(peerPub)) { "session: the key from the QR is not a valid key" }
        }
        if (role == Role.SENDER) {
            // Encoded now so that a payload that does not fit fails before anything is on the wire.
            if (payload != null) payloadContent = profile.encode(payload)
        } else {
            require(payload == null) { "session: a Receiver sends no payload" }
        }
    }

    /** The relay subscription filter (§11.5). */
    fun filter(): Map<String, Any> = mapOf("kinds" to listOf(Kinds.WRAP), "#p" to listOf(pub), "since" to startedAt - SLACK_SECONDS)

    fun view(): SessionView {
        val ready = peers.values.filter { it.sas != null }
        val activePeer = active?.let { peers[it] }
        val check = if (role == Role.RECEIVER && showing) activePeer?.check ?: own else peak
        val code = if (role == Role.RECEIVER && activePeer?.sas != null && check != CodeCheck.NONE && (phase == Phase.CODE || phase == Phase.ACCEPT)) activePeer.sas else null
        val compare = if (phase == Phase.RELEASE && check == CodeCheck.COMPARE) comparing()?.sas else null
        val rendering = if (phase == Phase.ACCEPT) activePeer?.held?.let { profile.render(it) } else null
        return SessionView(
            role, showing, phase, outcome, check, code, compare, rendering,
            attemptsLeft = MAX_ATTEMPTS - attempts,
            ready = ready.size,
            multipleResponders = multipleResponders,
            dropped = dropped,
            canAdvance = role == Role.RECEIVER && showing && ready.any { it.pub != active },
            expiresAt = startedAt + SESSION_SECONDS,
            ackDeadline = if (phase == Phase.SENT) ackDeadline else null,
            released = released,
        )
    }

    // ---- messages out -------------------------------------------------------------------

    private fun send(to: String, kind: Int, tags: List<List<String>> = emptyList(), content: String = "", label: String): Effect<T> {
        val r = Wrap.rumor(kind, tags, content, pub, env.now())
        val sealed = Wrap.seal(r, secretKey, to, env)
        return Effect.Publish(Wrap.giftWrap(sealed, to, env), sealed, to, kind, kind == Kinds.ACK || kind == Kinds.ABORT, "$label → ${short(to)}")
    }

    private fun abort(to: String, reason: Outcome? = null): Effect<T> =
        send(to, Kinds.ABORT, if (reason != null) listOf(listOf("reason", reason.wire)) else emptyList(), label = "ABORT")

    /** The loopback probe of §11.3a: a PAYLOAD-shaped rumor at the profile's maximum, to ourselves. */
    fun probe(): Event {
        assertLive()
        val content = Base64.getEncoder().encodeToString(env.random(profile.maxPayloadBytes))
        return Wrap.wrap(Wrap.rumor(Kinds.PAYLOAD, emptyList(), content, pub, env.now()), secretKey, pub, env)
    }

    /** NIP-42 authentication with the burner, the only identity a session ever shows a relay (§11.5). */
    fun signAuth(relayUrl: String, challenge: String): Event {
        assertLive()
        return Event.sign(pub, env.now(), Kinds.AUTH, listOf(listOf("relay", relayUrl), listOf("challenge", challenge)), "", secretKey, env)
    }

    // ---- inputs -------------------------------------------------------------------------

    /** Contacting party: speak first. */
    fun start(): List<Effect<T>> {
        if (phase == Phase.ENDED || started) return emptyList()
        started = true
        val peerPub = this.peerPub
        if (showing || peerPub == null) return emptyList()
        if (role == Role.SENDER && isBlocked(peerPub)) return finish(Outcome.BLOCKED_PEER, mutableListOf())
        val ownNonce = env.random(32).toHex()
        peers[peerPub] = Peer(peerPub, order++, null, ownNonce, peak)
        val commitment = Sas.commit(VERSION, pub, ownNonce).toHex()
        val kind = if (role == Role.SENDER) Kinds.HELLO else Kinds.REQUEST
        val tags = listOf(listOf("commit", commitment), listOf("token", token), listOf("check", peak.wire))
        return listOf(send(peerPub, kind, tags, label = if (role == Role.SENDER) "HELLO" else "REQUEST"))
    }

    /** A gift wrap arrived from a relay. Anything that is not a valid message of this session is ignored. */
    fun receive(event: Event): List<Effect<T>> {
        if (phase == Phase.ENDED) return emptyList()
        return when (val opened = Wrap.unwrap(event, secretKey)) {
            is Wrap.Unwrapped.Failed -> listOf(Effect.Trace("ignored a wrap: ${opened.reason}"))
            is Wrap.Unwrapped.Ok -> receiveRumor(opened.rumor)
        }
    }

    private fun expired(): Boolean = phase != Phase.SENT && phase != Phase.ENDED && env.now() >= startedAt + SESSION_SECONDS

    fun receiveRumor(r: Event): List<Effect<T>> {
        if (phase == Phase.ENDED) return emptyList()
        if (expired()) return tick()
        if (r.pubkey == pub) return emptyList()
        if (r.createdAt < startedAt - SLACK_SECONDS || r.createdAt > startedAt + SESSION_SECONDS + SLACK_SECONDS) {
            return listOf(Effect.Trace("ignored a message outside the session window"))
        }
        if (r.id in seen) return emptyList()
        if (seen.size < MAX_SEEN) seen += r.id
        val effects = dispatch(r)
        val answered = if (effects.isNotEmpty()) answeredBy(r.kind) else emptyList()
        return if (answered.isNotEmpty()) listOf(Effect.Settled(r.pubkey, answered)) + effects else effects
    }

    private fun dispatch(r: Event): List<Effect<T>> = when (r.kind) {
        Kinds.HELLO -> if (showing && role == Role.RECEIVER) onContact(r) else emptyList()
        Kinds.REQUEST -> if (showing && role == Role.SENDER) onContact(r) else emptyList()
        Kinds.NONCE -> if (!showing) onNonce(r) else emptyList()
        Kinds.REVEAL -> if (showing) onReveal(r) else emptyList()
        Kinds.PAYLOAD -> if (role == Role.RECEIVER) onPayload(r) else emptyList()
        Kinds.ACK -> if (role == Role.SENDER) onAck(r) else emptyList()
        Kinds.ABORT -> onAbort(r)
        else -> emptyList()
    }

    private fun onContact(r: Event): List<Effect<T>> {
        val commitment = r.firstTag("commit")
        if (!isHex32(commitment)) return emptyList()
        val token = r.firstTag("token")
        if (token == null || !equalAscii(token, this.token)) {
            return listOf(Effect.Trace("ignored ${short(r.pubkey)}: it did not echo this code's token"))
        }
        if (r.pubkey in contacted) return emptyList()
        if (role == Role.SENDER && isBlocked(r.pubkey)) {
            return listOf(Effect.Trace("ignored ${short(r.pubkey)}: a code already failed against it"))
        }
        val check = stricter(own, CodeCheck.parseOrType(r.firstTag("check")))
        if (contacted.size >= 1 && (check == CodeCheck.NONE || noneAgreed)) return secondResponder(r.pubkey)
        if (phase != Phase.WAITING && phase != Phase.RELEASE && phase != Phase.CODE) {
            multipleResponders = true
            return listOf(Effect.Trace("another device, ${short(r.pubkey)}, answered after this one was chosen"))
        }
        if (contacted.size >= 1) multipleResponders = true
        val cap = if (role == Role.RECEIVER) MAX_HELD else MAX_PENDING
        if (contacted.size >= cap) {
            dropped++
            return listOf(Effect.Trace("turned away ${short(r.pubkey)}: this code has already been answered $cap times"))
        }
        contacted += r.pubkey
        if (check == CodeCheck.NONE) noneAgreed = true
        peak = stricter(peak, check)
        val ownNonce = env.random(32).toHex()
        peers[r.pubkey] = Peer(r.pubkey, order++, commitment, ownNonce, check)
        return listOf(
            Effect.Trace("${if (r.kind == Kinds.HELLO) "HELLO" else "REQUEST"} ← ${short(r.pubkey)}"),
            send(r.pubkey, Kinds.NONCE, listOf(listOf("nonce", ownNonce)), label = "NONCE"),
        )
    }

    private fun secondResponder(pub: String): List<Effect<T>> {
        multipleResponders = true
        if (phase == Phase.SENT) return listOf(Effect.Trace("another device, ${short(pub)}, answered after the payload was sent"))
        if (phase == Phase.ENDED) return emptyList()
        val effects = mutableListOf<Effect<T>>(Effect.Trace("a second device, ${short(pub)}, answered; with no code there is no telling which is yours"))
        for (p in peers.values) effects += abort(p.pub, Outcome.SECOND_RESPONDER)
        effects += abort(pub, Outcome.SECOND_RESPONDER)
        return finish(Outcome.SECOND_RESPONDER, effects)
    }

    private fun onNonce(r: Event): List<Effect<T>> {
        if (r.pubkey != peerPub) return emptyList()
        val peer = peers[r.pubkey]
        val nonce = r.firstTag("nonce")
        if (peer == null || peer.peerNonce != null || !isHex32(nonce)) return emptyList()
        peer.peerNonce = nonce
        peer.sas = codeFor(peer)
        val effects = listOf(
            Effect.Trace("NONCE ← ${short(r.pubkey)}"),
            send(peer.pub, Kinds.REVEAL, listOf(listOf("nonce", peer.ownNonce)), label = "REVEAL"),
        )
        if (role == Role.SENDER) {
            phase = Phase.RELEASE
        } else {
            active = peer.pub
            peer.displayed = true
            phase = Phase.CODE
        }
        return effects
    }

    private fun onReveal(r: Event): List<Effect<T>> {
        val peer = peers[r.pubkey]
        val nonce = r.firstTag("nonce")
        if (peer == null || peer.commit == null || peer.peerNonce != null || !isHex32(nonce)) return emptyList()
        if (!equalAscii(Sas.commit(VERSION, peer.pub, nonce!!).toHex(), peer.commit)) {
            peers.remove(peer.pub)
            return listOf(Effect.Trace("dropped ${short(peer.pub)}: reveal does not match its commitment"))
        }
        peer.peerNonce = nonce
        peer.sas = codeFor(peer)
        if (role == Role.SENDER) {
            if (phase == Phase.WAITING) phase = Phase.RELEASE
        } else if (active == null) {
            activateNext()
        }
        return listOf(Effect.Trace("REVEAL ← ${short(peer.pub)}, commitment verified"))
    }

    /** The code for a peer, with the two burners in ROLE order whoever made contact (§6). */
    private fun codeFor(peer: Peer<T>): String {
        val iAmSender = role == Role.SENDER
        return Sas.sas(
            VERSION, profile.id,
            senderPub = if (iAmSender) pub else peer.pub,
            receiverPub = if (iAmSender) peer.pub else pub,
            senderNonce = if (iAmSender) peer.ownNonce else peer.peerNonce!!,
            receiverNonce = if (iAmSender) peer.peerNonce!! else peer.ownNonce,
        )
    }

    private fun activateNext(): Boolean {
        val next = peers.values.filter { it.sas != null }.minByOrNull { it.order }
        if (next == null) {
            active = null
            phase = Phase.WAITING
            return false
        }
        active = next.pub
        next.displayed = true
        phase = Phase.CODE
        return true
    }

    private fun onPayload(r: Event): List<Effect<T>> {
        val peer = peers[r.pubkey]
        if (peer == null || peer.held != null) return emptyList()
        if (peer.sas == null) {
            // Ahead of its REVEAL: not seen yet, so that the next re-send is taken once the REVEAL is in.
            seen -= r.id
            return listOf(Effect.Trace("PAYLOAD ← ${short(peer.pub)} arrived before its REVEAL; waiting for it again"))
        }
        if (phase != Phase.CODE) return emptyList()
        if (peer.pub != active || !peer.displayed) {
            peers.remove(peer.pub)
            return listOf(Effect.Trace("dropped ${short(peer.pub)}: payload arrived before its code was shown"))
        }
        when (val checked = profile.check(r.content)) {
            is Checked.Bad -> {
                peers.remove(peer.pub)
                val effects = mutableListOf(
                    Effect.Trace("dropped ${short(peer.pub)}: payload is not a ${profile.id} (${checked.reason})"),
                    abort(peer.pub),
                )
                if (activateNext()) return effects
                return finish(Outcome.BAD_PAYLOAD, effects)
            }
            is Checked.Ok -> {
                peer.held = checked.value
                phase = Phase.ACCEPT
                return listOf(Effect.Trace("PAYLOAD ← ${short(peer.pub)}, held for confirmation"))
            }
        }
    }

    private fun onAck(r: Event): List<Effect<T>> {
        if (phase != Phase.SENT || r.pubkey != releasedTo) return emptyList()
        return finish(Outcome.DELIVERED, mutableListOf(Effect.Trace("ACK ← ${short(r.pubkey)}")))
    }

    private fun onAbort(r: Event): List<Effect<T>> {
        val peer = peers[r.pubkey] ?: return emptyList()
        val effects = mutableListOf<Effect<T>>(Effect.Trace("ABORT ← ${short(r.pubkey)}"))
        if (!showing || r.pubkey == releasedTo) {
            return finish(if (r.firstTag("reason") == Outcome.SECOND_RESPONDER.wire) Outcome.SECOND_RESPONDER else Outcome.PEER_ABORTED, effects)
        }
        peers.remove(peer.pub)
        if (role == Role.SENDER) {
            if (phase == Phase.RELEASE && !hasCandidate()) phase = Phase.WAITING
            return effects
        }
        if (peer.pub != active) return effects
        activateNext()
        return effects
    }

    /** Sender, check `type`: the user typed the five digits shown on the Receiver. Compared here and only here (§9.2). */
    fun enterCode(digits: String, payload: T? = null): List<Effect<T>> {
        if (!canRelease(CodeCheck.TYPE)) return emptyList()
        if (expired()) return tick()
        require(Regex("^[0-9]{5}$").matches(digits)) { "session: a pairing code is exactly five digits" }
        provide(payload)
        val ready = peers.values.filter { it.sas != null }
        val matches = ready.filter { equalAscii(it.sas!!, digits) }
        if (matches.size == 1) return releaseTo(matches[0])
        return miss(ready)
    }

    /** Sender, check `compare`: the user says the code on screen is the one on the other device. */
    fun confirmMatch(payload: T? = null): List<Effect<T>> {
        if (!canRelease(CodeCheck.COMPARE)) return emptyList()
        if (expired()) return tick()
        provide(payload)
        return comparing()?.let { releaseTo(it) } ?: emptyList()
    }

    /** Sender, check `compare`: the codes differ. Spends an attempt. */
    fun rejectMatch(): List<Effect<T>> {
        if (!canRelease(CodeCheck.COMPARE)) return emptyList()
        if (expired()) return tick()
        val target = comparing() ?: return emptyList()
        if (showing) rejected += target.pub
        val effects = miss(listOf(target))
        if (phase == Phase.RELEASE && !hasCandidate()) phase = Phase.WAITING
        return effects
    }

    /** Sender, check `none`: the user confirmed the release prompt. Only ever to a lone responder. */
    fun release(payload: T? = null): List<Effect<T>> {
        if (!canRelease(CodeCheck.NONE)) return emptyList()
        if (expired()) return tick()
        provide(payload)
        val ready = peers.values.filter { it.sas != null }
        if (ready.size != 1 || (showing && contacted.size != 1)) return emptyList()
        return releaseTo(ready[0])
    }

    private fun provide(payload: T?) {
        if (payload != null && payloadContent == null) payloadContent = profile.encode(payload)
        checkNotNull(payloadContent) { "session: the Sender has nothing to send" }
    }

    private fun canRelease(check: CodeCheck) = phase == Phase.RELEASE && role == Role.SENDER && peak == check

    private fun comparing(): Peer<T>? = peers.values.filter { it.sas != null && it.pub !in rejected }.minByOrNull { it.order }

    private fun hasCandidate() = peers.values.any { it.sas != null && it.pub !in rejected }

    private fun releaseTo(target: Peer<T>): List<Effect<T>> {
        val effects = mutableListOf(send(target.pub, Kinds.PAYLOAD, content = payloadContent!!, label = "PAYLOAD"))
        for (other in peers.values) if (other.pub != target.pub) effects += abort(other.pub)
        releasedTo = target.pub
        releasedSas = target.sas
        released = true
        payloadContent = null
        ackDeadline = env.now() + ACK_WAIT_SECONDS
        phase = Phase.SENT
        effects += record(Outcome.SENT_UNCONFIRMED, target.pub, target.sas!!)
        return effects
    }

    private fun miss(missed: List<Peer<T>>): List<Effect<T>> {
        attempts++
        for (p in missed) {
            p.failed = true
            failedPeers += p.pub
        }
        val effects = mutableListOf<Effect<T>>(Effect.Trace("code did not match (attempt $attempts of $MAX_ATTEMPTS)"))
        if (attempts < MAX_ATTEMPTS) return effects
        for (p in peers.values) effects += abort(p.pub)
        return finish(Outcome.ATTEMPTS_EXHAUSTED, effects)
    }

    /** Receiver: the user confirmed the rendering. Keep the payload and acknowledge. */
    fun accept(): List<Effect<T>> {
        val peer = active?.let { peers[it] }
        if (phase != Phase.ACCEPT || peer == null || peer.held == null) return emptyList()
        if (expired()) return tick()
        val value = peer.held!!
        // Handed to the host, so not wiped with the rest of what the session held.
        peer.held = null
        return finish(
            Outcome.RECEIVED,
            mutableListOf(Effect.Commit(value), send(peer.pub, Kinds.ACK, label = "ACK")),
            peer.pub to peer.sas!!,
        )
    }

    /** The user refused: a Sender declining to release, or a Receiver discarding what arrived. */
    fun decline(): List<Effect<T>> {
        val gone = active
        if (role == Role.RECEIVER && showing && phase == Phase.ACCEPT && gone != null) {
            peers.remove(gone)
            activateNext()
            return listOf(Effect.Trace("discarded what ${short(gone)} sent; ${if (active != null) "showing the next code" else "waiting"}"), abort(gone))
        }
        return leave(Outcome.DECLINED)
    }

    fun cancel(): List<Effect<T>> = leave(Outcome.CANCELLED)

    private fun leave(outcome: Outcome): List<Effect<T>> {
        if (phase == Phase.ENDED) return emptyList()
        if (phase == Phase.SENT) return finish(Outcome.SENT_UNCONFIRMED, mutableListOf())
        val effects = mutableListOf<Effect<T>>()
        for (p in peers.values) effects += abort(p.pub)
        return finish(outcome, effects)
    }

    /** Receiver that showed the QR: the other device rejected the code on screen; show the next (§13). */
    fun advance(): List<Effect<T>> {
        val gone = active
        if (role != Role.RECEIVER || !showing || phase != Phase.CODE || gone == null) return emptyList()
        peers.remove(gone)
        activateNext()
        return listOf(Effect.Trace("set ${short(gone)} aside; ${if (active != null) "showing the next code" else "waiting"}"))
    }

    /** Call about once a second. Enforces the ten-minute lifetime and the acknowledgement wait. */
    fun tick(): List<Effect<T>> {
        if (phase == Phase.ENDED) return emptyList()
        val now = env.now()
        if (phase == Phase.SENT) {
            val deadline = ackDeadline
            return if (deadline != null && now >= deadline) finish(Outcome.SENT_UNCONFIRMED, mutableListOf()) else emptyList()
        }
        if (now < startedAt + SESSION_SECONDS) return emptyList()
        val effects = mutableListOf<Effect<T>>()
        for (p in peers.values) effects += abort(p.pub)
        return finish(Outcome.EXPIRED, effects)
    }

    // ---- ending -------------------------------------------------------------------------

    private fun finish(outcome: Outcome, effects: MutableList<Effect<T>>, done: Pair<String, String>? = null): List<Effect<T>> {
        val completed = done ?: if (releasedTo != null && releasedSas != null) releasedTo!! to releasedSas!! else null
        if (completed != null) {
            effects += record(outcome, completed.first, completed.second)
        } else if (role == Role.SENDER && failedPeers.isNotEmpty()) {
            effects += Effect.FailedPeers(failedPeers.toList())
        }
        phase = Phase.ENDED
        this.outcome = outcome
        active = null
        payloadContent = null
        for (p in peers.values) (p.held as? ByteArray)?.let { wipe(it) }
        peers.clear()
        seen.clear()
        contacted.clear()
        failedPeers.clear()
        rejected.clear()
        wipe(secretKey)
        effects += Effect.Ended(outcome)
        return effects
    }

    private fun record(outcome: Outcome, peer: String, sas: String): Effect<T> = Effect.Record(
        TransferRecord(env.now(), profile.id, role, outcome, sas, peer, multipleResponders, recordedCheck(peer)),
    )

    private fun recordedCheck(pub: String): CodeCheck =
        if (role == Role.RECEIVER && showing) peers[pub]?.check ?: peak else peak

    private fun assertLive() = check(phase != Phase.ENDED) { "session: ended" }

    companion object {
        private const val MAX_SEEN = 512
        private fun short(pub: String) = "${pub.take(8)}…"

        private val STEPS = listOf(listOf(Kinds.HELLO, Kinds.REQUEST), listOf(Kinds.NONCE), listOf(Kinds.REVEAL), listOf(Kinds.PAYLOAD), listOf(Kinds.ACK))
        val ALL_KINDS = STEPS.flatten() + Kinds.ABORT

        /** Receiving a message at one step settles everything this side sent at the steps before (§11.5). */
        fun answeredBy(kind: Int): List<Int> {
            if (kind == Kinds.ABORT) return ALL_KINDS
            val step = STEPS.indexOfFirst { kind in it }
            return if (step > 0) STEPS.subList(0, step).flatten() else emptyList()
        }
    }
}
