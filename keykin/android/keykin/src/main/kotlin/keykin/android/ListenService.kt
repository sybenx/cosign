// The signer, listening (Doors §3.3, core §8): a foreground service in the signer process that keeps each
// membership's relay connections and its inbox fetches alive while the app is in the background, with the
// notification Android requires. Its fetches run on a timer without a wakelock, so a phone in Doze defers
// them: push (KeykinSigner.onMessage) is what wakes a sleeping phone. (A NIP-46 home per membership runs here
// once the app turns one on.) The app starts it when the person turns listening on,
// and stops it when they turn it off; push wakes the signer without it (KeykinSigner.onMessage).
package keykin.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class ListenService : Service() {
    private val tick = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "keykin-listen").also { it.isDaemon = true } }
    override fun onCreate() {
        super.onCreate()
        Proc.signerOnly("ListenService")
        Memberships.init(this)
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Signing in the background", NotificationManager.IMPORTANCE_LOW))
        val n = Notification.Builder(this, CHANNEL).setContentTitle(TITLE).setSmallIcon(android.R.drawable.ic_lock_idle_lock).setOngoing(true).build()
        startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        // Every few minutes, each membership catches up: changes, inbox, re-issues (the relays stay open meanwhile).
        tick.scheduleWithFixedDelay({ for (s in Memberships.slots()) try { Memberships.signer(s).device?.fetch() } catch (_: Exception) {} }, 5, 300, TimeUnit.SECONDS)
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // The line comes with the start (the app's words reach this process only through the intent: review 15 L6).
        intent?.getStringExtra("title")?.let { t -> getSystemService(NotificationManager::class.java).notify(1, Notification.Builder(this, CHANNEL).setContentTitle(t).setSmallIcon(android.R.drawable.ic_lock_idle_lock).setOngoing(true).build()) }
        return START_STICKY
    }
    override fun onDestroy() { tick.shutdownNow(); super.onDestroy() }
    override fun onBind(intent: Intent?): IBinder? = null
    companion object {
        private const val CHANNEL = "keykin-listen"
        private const val TITLE = "Ready to sign"
        /** Start listening; `title` is the notification's line, in the app's words. */
        fun start(c: Context, title: String = TITLE) = c.startForegroundService(Intent(c, ListenService::class.java).putExtra("title", title))
        fun stop(c: Context) = c.stopService(Intent(c, ListenService::class.java))
    }
}
