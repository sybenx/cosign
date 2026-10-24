// A stand-in for an Android Nostr app (Amethyst and the like) that signs through an
// external signer, for testing Cosign's NIP-55 side on an emulator. Not shipped.
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "cc.aaro.nip55tester"
    compileSdk = 35
    defaultConfig {
        applicationId = "cc.aaro.nip55tester"
        minSdk = 30
        targetSdk = 35
        versionCode = 1
        versionName = "1"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("androidx.activity:activity-ktx:1.9.3")
}
