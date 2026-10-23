package cc.aaro.cosign

import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.PushService
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage

/**
 * ntfy, by way of UnifiedPush: how your servers wake this phone when something needs
 * your approval and Android has put Cosign to sleep. The message itself says nothing;
 * the request comes over relays, sealed, once the phone is listening again.
 */
class Push : PushService() {
    private val phone get() = CosignApp.instance.phone

    override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) = phone.setPushEndpoint(endpoint.url)

    override fun onMessage(message: PushMessage, instance: String) {
        try { CosignService.start(this) } catch (_: Exception) { }
        phone.start()
    }

    override fun onRegistrationFailed(reason: FailedReason, instance: String) = phone.setPushEndpoint(null)
    override fun onUnregistered(instance: String) = phone.setPushEndpoint(null)
}
