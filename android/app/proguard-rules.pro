# secp256k1 JNI bindings are looked up by name.
-keep class fr.acinq.secp256k1.** { *; }
# Cosign's FROST JNI bindings (frost/src/android.rs) are looked up by name.
-keep class cc.aaro.cosign.core.FrostNative { *; }
