package cc.aaro.cosign.net

import cc.aaro.cosign.core.CodeCheck
import cc.aaro.cosign.core.Effect
import cc.aaro.cosign.core.Env
import cc.aaro.cosign.core.Kinds
import cc.aaro.cosign.core.Mode
import cc.aaro.cosign.core.Outcome
import cc.aaro.cosign.core.PairingParams
import cc.aaro.cosign.core.PairingUri
import cc.aaro.cosign.core.Phase
import cc.aaro.cosign.core.Profile
import cc.aaro.cosign.core.Role
import cc.aaro.cosign.core.Session
import cc.aaro.cosign.core.SessionView
import cc.aaro.cosign.core.Wrap
import cc.aaro.cosign.core.generateSecretKey
import cc.aaro.cosign.core.scannerRole
import cc.aaro.cosign.core.showingMode
import okhttp3.OkHttpClient
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

// One transfer, end to end: a core Session, the relays that carry it, and the local
// store. Headless: a UI drives it through a handful of methods and re-reads view()
// whenever onChange fires. A port of src/web/transfer.ts.

data class RelayStatus(val url: String, val state: String, val inUse: Boolean, val why: String?)

data class TransferView<T>(
    val role: Role,
    val showing: Boolean,
    val mode: Mode,
    /** RELAYS: the showing device is still finding a relay that passes. */
    val stage: Stage,
    val session: SessionView,
    val uri: String?,
    val relays: List<RelayStatus>,
    val connected: Boolean,
    val peerOrigin: String?,
    /** False when the pairing did not come from this app's own camera (§9.1, §12.1). */
    val viaCamera: Boolean,
    /** Receiver: the value, once the user has confirmed it. */
    val value: T?,
    val log: List<String>,
) {
    enum class Stage { RELAYS, SESSION, ENDED }
}

enum class Refusal { UNKNOWN_PROFILE, BLOCKED_PEER, ROLE_COLLISION }

class TransferDeps<T>(
    val profile: Profile<T>,
    val store: Store,
    val env: Env,
    /** The https address the QRs this device shows point at (§11.2a). */
    val baseUrl: String,
    val check: CodeCheck = CodeCheck.TYPE,
    val http: OkHttpClient = OkHttpClient.Builder().pingInterval(20, TimeUnit.SECONDS).build(),
)

class Transfer<T> private constructor(
    private val deps: TransferDeps<T>,
    private val session: Session<T>,
    private val params: PairingParams?,
    private val viaCamera: Boolean,
) {
    @Volatile var onChange: () -> Unit = {}

    private val loop: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { Thread(it, "qrst-transfer").apply { isDaemon = true } }
    private val pool: Pool
    private val log = ArrayList<String>()
    private val startedMs = System.currentTimeMillis()
    private var progress: List<RelayProgress> = emptyList()
    private var relays: List<String> = emptyList()
    private var uri: String? = null
    private var value: T? = null
    private var disposed = false
    @Volatile private var snapshot: TransferView<T>

    init {
        pool = Pool(
            PoolOptions(
                filter = session.filter(),
                signAuth = { url, challenge -> session.signAuth(url, challenge) },
                onEvent = { event, _ -> apply(session.receive(event)) },
                onChange = { emit() },
            ),
            loop, deps.http,
        )
        snapshot = build()
        loop.scheduleWithFixedDelay({ run { apply(session.tick()) } }, 1, 1, TimeUnit.SECONDS)
    }

    private fun run(block: () -> Unit) {
        try { loop.execute { try { block() } catch (e: Exception) { trace("error: ${e.message}"); emit() } } } catch (_: Exception) {}
    }

    companion object {
        /**
         * Why this device must not act on a scanned code, checked before a burner is
         * generated: unknown profile (§11.2), role collision, or a burner it recently
         * failed a code against (§9.3).
         */
        fun refusal(store: Store, profileId: String, params: PairingParams, committedRole: Role? = null): Refusal? {
            if (params.profile != profileId) return Refusal.UNKNOWN_PROFILE
            val role = scannerRole(params.mode)
            if (committedRole != null && committedRole != role) return Refusal.ROLE_COLLISION
            if (role == Role.SENDER && store.isBlocked(params.pub)) return Refusal.BLOCKED_PEER
            return null
        }

        /** This device shows the code. A Receiver shows mode=offer (Flow A), a Sender mode=request (Flow B). */
        fun <T> show(deps: TransferDeps<T>, role: Role, payload: T? = null): Transfer<T> {
            val session = Session(
                role, true, deps.profile, generateSecretKey(deps.env), deps.env,
                payload = payload, isBlocked = { deps.store.isBlocked(it) }, check = deps.check,
            )
            val t = Transfer(deps, session, null, true)
            Thread({ t.findRelays() }, "qrst-relays").apply { isDaemon = true }.start()
            return t
        }

        /** This device scanned, opened or pasted a code. Its role is the complement of the code's mode. */
        fun <T> join(deps: TransferDeps<T>, params: PairingParams, viaCamera: Boolean, payload: T? = null): Transfer<T> {
            val session = Session(
                scannerRole(params.mode), false, deps.profile, generateSecretKey(deps.env), deps.env,
                peerPub = params.pub, payload = payload, isBlocked = { deps.store.isBlocked(it) },
                check = deps.check, token = params.token, peerCheck = params.check,
            )
            val t = Transfer(deps, session, params, viaCamera)
            t.run {
                t.relays = params.relays
                // The showing device listens on these and nowhere else.
                for (url in params.relays) t.pool.add(url, true)
                t.apply(session.start())
            }
            return t
        }
    }

    private fun findRelays() {
        val listed = try {
            selectRelays(
                pool, deps.store,
                probe = { pool.onLoop { session.probe() } ?: throw IllegalStateException("session ended") },
                alive = { !disposed && session.view().phase != Phase.ENDED },
                onProgress = { p -> run { progress = p; emit() } },
            )
        } catch (e: Exception) {
            run { trace("stopped: ${e.message}"); apply(session.cancel()) }
            return
        }
        run {
            if (disposed || listed.isEmpty() || session.view().phase == Phase.ENDED) return@run
            relays = listed
            uri = PairingUri.build(
                deps.baseUrl,
                PairingParams(showingMode(session.role), deps.profile.id, session.pub, session.view().check, session.token, listed),
            )
            trace("listening on ${listed.size} relay${if (listed.size == 1) "" else "s"} that passed the loopback test")
            emit()
        }
    }

    fun view(): TransferView<T> = snapshot

    private fun build(): TransferView<T> {
        val s = session.view()
        val links = pool.all()
        val inUse = relays.ifEmpty { progress.filter { it.state == ProgressState.LISTED }.map { it.url } }
        val statuses = ArrayList<RelayStatus>()
        for (url in inUse) {
            val link = links.firstOrNull { it.url == url }
            statuses += RelayStatus(url, link?.state?.name?.lowercase() ?: "closed", true, link?.lastReason)
        }
        for (p in progress) if (p.url !in inUse) statuses += RelayStatus(p.url, if (p.state == ProgressState.LISTED) "spare" else p.state.name.lowercase(), false, p.why)
        return TransferView(
            role = session.role,
            showing = session.showing,
            mode = params?.mode ?: showingMode(session.role),
            stage = when {
                s.phase == Phase.ENDED -> TransferView.Stage.ENDED
                session.showing && uri == null -> TransferView.Stage.RELAYS
                else -> TransferView.Stage.SESSION
            },
            session = s,
            uri = if (s.phase != Phase.ENDED) uri else null,
            relays = statuses,
            connected = inUse.any { url -> links.firstOrNull { it.url == url }?.state == LinkState.OPEN },
            peerOrigin = params?.origin,
            viaCamera = viaCamera,
            value = value,
            log = log.toList(),
        )
    }

    /** Sender: `payload` may be handed over here instead of at the start (Session). */
    fun enterCode(digits: String, payload: T? = null) = run { try { apply(session.enterCode(digits, payload)) } finally { wipePayload(payload) } }
    fun confirmMatch(payload: T? = null) = run { try { apply(session.confirmMatch(payload)) } finally { wipePayload(payload) } }
    fun rejectMatch() = run { apply(session.rejectMatch()) }
    fun release(payload: T? = null) = run { try { apply(session.release(payload)) } finally { wipePayload(payload) } }

    /** A key handed over at release has been encoded into the session by now; this copy can go. */
    private fun wipePayload(payload: T?) { (payload as? ByteArray)?.fill(0) }
    fun decline() = run { apply(session.decline()) }
    fun accept() = run { apply(session.accept()) }
    fun advance() = run { apply(session.advance()) }
    fun cancel() = run { apply(session.cancel()) }
    /** The app came back to the foreground: reconnect and re-send now (§11.5). */
    fun wake() = run { pool.wake() }

    /** Takes the received value out, so the transfer no longer holds it. */
    fun takeValue(): T? = pool.onLoop { value.also { value = null; emit() } }

    fun dispose() {
        run {
            if (disposed) return@run
            apply(session.cancel())
            disposed = true
            value = null
        }
        loop.schedule({ loop.shutdown() }, 30, TimeUnit.SECONDS)
    }

    private fun trace(text: String) {
        val seconds = (System.currentTimeMillis() - startedMs) / 1000
        log += "%02d:%02d  %s".format(seconds / 60, seconds % 60, text)
        if (log.size > 200) log.removeAt(0)
    }

    private fun apply(effects: List<Effect<T>>) {
        if (effects.isEmpty()) return
        for (e in effects) {
            when (e) {
                is Effect.Publish -> {
                    // An ABORT ends the exchange with that peer: only the ABORT itself goes out again.
                    if (e.kind == Kinds.ABORT) pool.settle(e.to, Session.ALL_KINDS - Kinds.ABORT)
                    val seal = e.seal
                    val to = e.to
                    pool.publish(Outgoing(e.event, { Wrap.giftWrap(seal, to, deps.env) }, to, e.kind, e.unanswered))
                    trace(e.label)
                }
                is Effect.Settled -> pool.settle(e.peer, e.kinds)
                is Effect.Commit -> value = e.value
                is Effect.Record -> deps.store.addRecord(LoggedTransfer(e.record, "relay", relays))
                is Effect.FailedPeers -> deps.store.noteFailedSession(e.pubs)
                is Effect.Trace -> trace(e.text)
                is Effect.Ended -> ended(e.outcome)
            }
        }
        emit()
    }

    private fun ended(outcome: Outcome) {
        trace("session ended: ${outcome.wire}")
        if (!session.showing && params != null && outcome in setOf(Outcome.DELIVERED, Outcome.SENT_UNCONFIRMED, Outcome.RECEIVED)) {
            deps.store.noteLearned(params.relays)
        }
        pool.windDown()
    }

    private fun emit() {
        snapshot = build()
        if (!disposed) onChange()
    }
}
