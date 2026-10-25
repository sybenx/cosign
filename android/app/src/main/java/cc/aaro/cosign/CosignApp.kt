package cc.aaro.cosign

import android.app.Application

/** Runs in both processes (Proc): the signer holds the keys ([signers]), the main process draws ([accounts]). */
class CosignApp : Application() {
    /** The accounts as the UI sees them, through the signer process. Main process only. */
    lateinit var accounts: Accounts
        private set
    /** The keys themselves. Signer process only. */
    lateinit var signers: Signers
        private set
    /** The account on screen. Code that serves every account uses [accounts]. */
    val phone get() = accounts.active

    override fun onCreate() {
        super.onCreate()
        instance = this
        Startup.mark("app")
        if (Proc.isSigner) {
            signers = Signers(this)
            Startup.mark("signers")
            // After the app's first screen is drawn. Signing never waits on this (it connects by itself); boot and push start it directly.
            if (signers.all.any { it.isMember }) android.os.Handler(mainLooper).postDelayed({ CosignService.start(this) }, 1500)
        } else {
            accounts = Accounts(this).also { it.bind() }
            Startup.mark("accounts")
        }
        Startup.mark("app done")
    }

    companion object {
        lateinit var instance: CosignApp
            private set
    }
}
