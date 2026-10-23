package cc.aaro.cosign

import android.app.Application

class CosignApp : Application() {
    lateinit var phone: Phone
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this
        phone = Phone(this)
        if (phone.isMember) CosignService.start(this)
    }

    companion object {
        lateinit var instance: CosignApp
            private set
    }
}
