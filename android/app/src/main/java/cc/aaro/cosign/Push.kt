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
    /** Every key's servers wake the phone through the same endpoint. */
    private val phones get() = CosignApp.instance.signers.all

    override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) { for (p in phones) p.setPushEndpoint(endpoint.url) }

    override fun onMessage(message: PushMessage, instance: String) {
        try { CosignService.start(this) } catch (_: Exception) { }
        for (p in phones) if (p.isMember) p.start()
    }

    override fun onRegistrationFailed(reason: FailedReason, instance: String) { for (p in phones) p.setPushEndpoint(null) }
    override fun onUnregistered(instance: String) { for (p in phones) p.setPushEndpoint(null) }
}
