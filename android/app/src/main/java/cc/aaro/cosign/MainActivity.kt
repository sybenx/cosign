package cc.aaro.cosign

import android.Manifest
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import cc.aaro.cosign.ui.App
import cc.aaro.cosign.ui.CosignTheme
import org.unifiedpush.android.connector.UnifiedPush

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The app is always dark; keep the system bar icons light whatever the phone's theme.
        enableEdgeToEdge(SystemBarStyle.dark(android.graphics.Color.TRANSPARENT), SystemBarStyle.dark(android.graphics.Color.TRANSPARENT))
        val phone = CosignApp.instance.phone
        if (savedInstanceState == null) opened(intent)
        setContent {
            CosignTheme {
                val ui by phone.ui.collectAsState()
                val notify = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
                // Once in a group: stay reachable, and be allowed to say so.
                LaunchedEffect(ui.member != null) {
                    if (ui.member != null) {
                        if (Build.VERSION.SDK_INT >= 33) notify.launch(Manifest.permission.POST_NOTIFICATIONS)
                        CosignService.start(this@MainActivity)
                        // ntfy, if it's installed. Without it, approvals reach you while Cosign is running.
                        UnifiedPush.tryUseCurrentOrDefaultDistributor(this@MainActivity) { ok -> if (ok) UnifiedPush.register(this@MainActivity) }
                    }
                }
                App(phone, ui)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        opened(intent)
    }

    /** A code handed over by the camera app or a link; the app asks before doing anything with it. */
    private fun opened(intent: Intent?) {
        // Reopened from Recents, Android hands back the link that first opened Cosign, maybe
        // hours old: that's not something you just scanned.
        if (intent == null || intent.flags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY != 0) return
        if (intent.action == Intent.ACTION_VIEW) intent.dataString?.let { CosignApp.instance.phone.scanned(it) }
        testHook(intent)
    }

    // Debug builds only: hand the app a pairing code without a camera, for the
    // emulator (adb shell am start -n cc.aaro.cosign/.MainActivity --es pair '<code>').
    private fun testHook(intent: Intent?) {
        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) return
        intent?.getStringExtra("pair")?.let { CosignApp.instance.phone.scanned(it) }
    }
}
