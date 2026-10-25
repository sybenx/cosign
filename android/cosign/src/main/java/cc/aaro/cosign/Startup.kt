package cc.aaro.cosign

/**
 * How long opening the app takes, step by step, in logcat (tag CosignStartup): time since the
 * process started, and the clock (uptime) for measuring a warm start from "activity".
 * A few lines per launch, in every build, so a release build can be measured too.
 */
object Startup {
    private val seen = HashSet<String>()

    fun mark(what: String, once: Boolean = true) {
        if (once && !synchronized(seen) { seen.add(what) }) return
        val now = android.os.SystemClock.uptimeMillis()
        android.util.Log.i("CosignStartup", "$what +${now - android.os.Process.getStartUptimeMillis()}ms @$now")
    }
}
