// keykin-android's start: libsecp256k1 for every secret-key operation, the FROST library from the APK, and
// OkHttp for the relays. Call `init()` once, before any Device.
package keykin.android

import keykin.FrostNative
import keykin.Keykin

object KeykinAndroid {
    val wire = OkWire()
    @Volatile private var done = false
    @Synchronized fun init() {
        if (done) return
        Keykin.secp = AndroidSecp
        FrostNative.loadLibrary("keykin_frost")
        done = true
    }
}
