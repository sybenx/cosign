package cc.aaro.cosign

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

/**
 * Keeps the phone reachable: one relay connection, kept open, so a server can ask
 * for a signature while the app isn't on screen. Shows an ongoing notification
 * (Android requires one) and a heads-up notification for each request.
 */
class CosignService : Service() {
    private val accounts get() = CosignApp.instance.signers
    private var lastStatus = ""

    /** One key's side: its notifications say which key they're for when there's more than one, and act on that key. */
    private inner class For(val p: Signer) : Signer.Listener {
        override fun onAsk(ask: Ask) = ask(p, ask)
        override fun onAskGone(id: String) = NotificationManagerCompat.from(this@CosignService).cancel(id.hashCode())
        override fun onStatus() = status()
        override fun onDeleting(d: Deleting) = deleting(p, d)
        override fun onDeletingGone(batch: String) = NotificationManagerCompat.from(this@CosignService).cancel(("del" + batch).hashCode())
        override fun onBatch(b: BatchAsk) = batch(p, b)
        override fun onBatchGone(batch: String) = NotificationManagerCompat.from(this@CosignService).cancel(("batch" + batch).hashCode())
        override fun onNotice(title: String, text: String) = notice(p, title, text)
    }

    /** "for npub1…" when there's more than one key here; nothing when there's one. */
    private fun forKey(p: Signer) = if (accounts.all.count { it.isMember } > 1) " · ${p.label}" else ""

    private fun listenAll() { for (p in accounts.all) if (p.listener !is For) p.listener = For(p) }

    override fun onCreate() {
        super.onCreate()
        Startup.mark("service")
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(STATUS, "Connection", NotificationManager.IMPORTANCE_MIN).apply { setShowBadge(false) })
        nm.createNotificationChannel(NotificationChannel(ASKS, "Signing requests", NotificationManager.IMPORTANCE_HIGH))
        if (Build.VERSION.SDK_INT >= 34) startForeground(STATUS_ID, statusNote(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(STATUS_ID, statusNote())
        listenAll()
        for (p in accounts.all) if (p.isMember) p.start()
        Startup.mark("service done")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (accounts.all.none { it.isMember }) { stopSelf(); return START_NOT_STICKY }
        listenAll()
        for (p in accounts.all) if (p.isMember) p.start()
        return START_STICKY
    }

    override fun onDestroy() {
        for (p in accounts.all) { if (p.listener is For) p.listener = null; if (!p.isMember) p.stop() }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun openApp() = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), PendingIntent.FLAG_IMMUTABLE)

    private fun statusText(): String {
        val keys = accounts.all.filter { it.isMember }
        if (keys.isEmpty()) return "Not in a group"
        if (keys.size > 1) return "${keys.size} keys · " + keys.joinToString(" · ") { p -> "${p.label} ${if (p.ui.value.relaysUp == 0) "offline" else "connected"}" }
        val u = keys[0].ui.value
        val m = u.member!!
        val servers = m.group.members.filter { it.role == "server" }.joinToString(" · ") { "${it.name} ${if (u.online[it.idx] == true) "online" else "offline"}" }
        return if (u.relaysUp == 0) "No relay connection · retrying" else servers
    }

    private fun statusNote() = NotificationCompat.Builder(this, STATUS)
        .setSmallIcon(R.drawable.ic_stat)
        .setContentTitle(appName)
        .setContentText(statusText())
        .setOngoing(true).setSilent(true).setShowWhen(false)
        .setContentIntent(openApp())
        .build()

    private fun status() {
        val text = statusText()
        if (text == lastStatus) return
        lastStatus = text
        if (canNotify()) NotificationManagerCompat.from(this).notify(STATUS_ID, statusNote())
    }

    private fun ask(p: Signer, ask: Ask) {
        if (!canNotify()) return
        fun decision(approve: Boolean) = PendingIntent.getBroadcast(
            this, (ask.id + approve).hashCode(),
            Intent(this, DecisionReceiver::class.java).putExtra("id", ask.id).putExtra("approve", approve).putExtra("slot", p.slot),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = NotificationCompat.Builder(this, ASKS)
            .setSmallIcon(R.drawable.ic_stat)
            .setContentTitle(cc.aaro.cosign.ui.question(ask.hold) + forKey(p))
            .setContentText("${ask.app} asked")
            .setStyle(NotificationCompat.BigTextStyle().bigText("${ask.app} asked. It doesn't happen unless you say yes."))
            .setSubText(ask.app)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setTimeoutAfter(ask.expiresAt - System.currentTimeMillis())
            .setAutoCancel(true)
            .setContentIntent(openApp())
            .addAction(NotificationCompat.Action.Builder(0, "Deny", decision(false)).build())
            // Approving from a locked phone needs the phone unlocked first.
            .addAction(NotificationCompat.Action.Builder(0, "Approve", decision(true)).setAuthenticationRequired(true).build())
            .build()
        NotificationManagerCompat.from(this).notify(ask.id.hashCode(), n)
    }


    private fun action(p: Signer, key: String, value: String, approve: Boolean = false) = PendingIntent.getBroadcast(
        this, (key + value + approve).hashCode(),
        Intent(this, DecisionReceiver::class.java).putExtra(key, value).putExtra("approve", approve).putExtra("slot", p.slot),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    /** A deletion in its few seconds: Undo stops it. */
    private fun deleting(p: Signer, d: Deleting) {
        if (!canNotify()) return
        val what = "Deleting ${d.count} post${if (d.count == 1) "" else "s"} for ${d.by}" + forKey(p)
        val n = NotificationCompat.Builder(this, ASKS)
            .setSmallIcon(R.drawable.ic_stat)
            .setContentTitle(what)
            .setContentText("A deletion can't be fully taken back. $appName keeps a copy.")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setOnlyAlertOnce(true)
            .setTimeoutAfter((d.until - System.currentTimeMillis()).coerceAtLeast(1000))
            .setContentIntent(openApp())
            .addAction(NotificationCompat.Action.Builder(0, "Undo", action(p, "cancel", d.batch)).build())
            .build()
        NotificationManagerCompat.from(this).notify(("del" + d.batch).hashCode(), n)
    }

    /** One approval for a batch of deletions. */
    private fun batch(p: Signer, b: BatchAsk) {
        if (!canNotify()) return
        val n = NotificationCompat.Builder(this, ASKS)
            .setSmallIcon(R.drawable.ic_stat)
            .setContentTitle(cc.aaro.cosign.ui.question(b.text) + forKey(p))
            .setContentText("${b.by} asked")
            .setStyle(NotificationCompat.BigTextStyle().bigText("${b.by} asked. A deletion can't be fully taken back; $appName keeps copies."))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setTimeoutAfter((b.expiresAt - System.currentTimeMillis()).coerceAtLeast(1000))
            .setAutoCancel(true)
            .setContentIntent(openApp())
            .addAction(NotificationCompat.Action.Builder(0, "Deny", action(p, "batch", b.batch, false)).build())
            .addAction(NotificationCompat.Action.Builder(0, "Approve", action(p, "batch", b.batch, true)).setAuthenticationRequired(true).build())
            .build()
        NotificationManagerCompat.from(this).notify(("batch" + b.batch).hashCode(), n)
    }

    private fun notice(p: Signer, title: String, text: String) {
        if (!canNotify()) return
        NotificationManagerCompat.from(this).notify((title + text).hashCode(), NotificationCompat.Builder(this, ASKS)
            .setSmallIcon(R.drawable.ic_stat).setContentTitle(title + forKey(p)).setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text)).setAutoCancel(true).setContentIntent(openApp()).build())
    }

    private fun canNotify() = Build.VERSION.SDK_INT < 33 ||
        ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS) == android.content.pm.PackageManager.PERMISSION_GRANTED

    companion object {
        private const val STATUS = "status"
        private const val ASKS = "asks"
        private const val STATUS_ID = 1
        fun start(context: Context) = ContextCompat.startForegroundService(context, Intent(context, CosignService::class.java))
    }
}
