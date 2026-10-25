package cc.aaro.cosign.core

// Every number the specification fixes, in one place. The message kinds are
// PROVISIONAL (spec §11.4): chosen from the ephemeral range, not reserved by a NIP.

object Kinds {
    const val SEAL = 13
    const val WRAP = 21059
    const val AUTH = 22242
    const val HELLO = 24401
    const val REQUEST = 24402
    const val NONCE = 24403
    const val REVEAL = 24404
    const val PAYLOAD = 24405
    const val ACK = 24406
    const val ABORT = 24407
}

/** Protocol version carried in the QR as `v=1` and hashed as a single byte (§6). */
const val VERSION = 1
const val SESSION_SECONDS = 600L
/** Tolerance at each end of the session window. Normative (§11.4). */
const val SLACK_SECONDS = 120L
const val ACK_WAIT_SECONDS = 60L
const val MAX_ATTEMPTS = 5
/** Responders a Receiver that showed the QR answers over the whole session (§13). */
const val MAX_HELD = 3
/** Responders a Sender that showed the QR answers over the whole session (§8, §13). */
const val MAX_PENDING = 5
const val DEFAULT_MAX_PAYLOAD = 2048
const val THROTTLE_SECONDS = 3600L
const val FAILED_SESSIONS_BEFORE_WARNING = 3
const val MAX_RELAYS = 4
const val TOKEN_BYTES = 16

val PROFILE_ID = Regex("^[a-z0-9-]{1,24}$")

/** How the Sender makes sure it is releasing to the device in front of the user, weakest first (§9.2). */
enum class CodeCheck(val wire: String) {
    NONE("none"), COMPARE("compare"), TYPE("type");

    companion object {
        /** A missing or unrecognised value reads as `type`, the strictest (§9.2). */
        fun parse(value: String?): CodeCheck? = entries.firstOrNull { it.wire == value }
        fun parseOrType(value: String?): CodeCheck = parse(value) ?: TYPE
    }
}

fun stricter(a: CodeCheck, b: CodeCheck): CodeCheck = if (a.ordinal >= b.ordinal) a else b
