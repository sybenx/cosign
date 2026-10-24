package cc.aaro.cosign

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED && CosignApp.instance.accounts.all.any { it.isMember }) CosignService.start(context)
    }
}
