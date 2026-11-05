// The one question for a vault app (Doors 20 §3.7), in the app list's own wording for the three open domains: "Let
// Notes use all your vaults, in every app, on this device?" Started only from VaultService.askGrant's PendingIntent,
// fresh and single-use, which the signer process made with the calling app's id in it; not exported, so no other app
// can name an app here. The dialog shows the app's icon, label and package (a label alone is the app's to choose) and
// the one account it is for. Allow grants the set on that account's device; Don't allow is remembered until the
// person changes it; closing grants nothing.
package keykin.android

import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle

class VaultGrantActivity : Activity() {
    companion object { const val APP = "keykin.vault.app"; const val ACCOUNT = "keykin.vault.account" }

    override fun onCreate(saved: Bundle?) {
        super.onCreate(saved)
        Proc.signerOnly("VaultGrantActivity")
        Memberships.init(this)
        val app = intent.getStringExtra(APP) ?: return finish()
        val account = intent.getStringExtra(ACCOUNT).orEmpty().ifEmpty { return finish() }
        val pkg = app.substringBefore('@')
        val info = try { packageManager.getApplicationInfo(pkg, 0) } catch (_: Exception) { return finish() }
        val label = packageManager.getApplicationLabel(info).toString()
        // The package installed now must still be the app that asked (same signing certificate).
        val uid = try { packageManager.getPackageUid(pkg, 0) } catch (_: Exception) { return finish() }
        if (VaultService.appOf(this, uid) != app) return finish()
        val d = Memberships.slots().firstNotNullOfOrNull { s -> Memberships.signer(s).device?.takeIf { !it.wiped && it.g == account } } ?: return finish()
        AlertDialog.Builder(this)
            .setIcon(packageManager.getApplicationIcon(info))
            .setTitle("Let $label use all your vaults?")
            .setMessage("Let $label ($pkg) use all your vaults, in every app, on this device?\n\nFor your account ${account.take(12)}…. " +
                "It can read and write your vaults and invite people to them. It can't read your messages or anything else of your account's.")
            .setPositiveButton("Allow") { _, _ -> Thread { try { d.vault.allow(app) } catch (_: Exception) {} }.start(); finish() }
            .setNegativeButton("Don't allow") { _, _ -> Thread { try { d.vault.decline(app) } catch (_: Exception) {} }.start(); finish() }
            .setOnCancelListener { finish() }
            .show()
    }
}
