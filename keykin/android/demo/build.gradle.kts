// A small demo app that drives keykin-android on one emulator against the local stack (B3): join by an
// invite code, show the check, sign a note, show the data key and the members. Driven by intents and read
// from logcat by test/android.e2e.test.ts, so the same steps run by hand and in the test.
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
android {
    namespace = "cc.aaro.keykin.demo"
    compileSdk = 35
    defaultConfig {
        applicationId = "cc.aaro.keykin.demo"
        minSdk = 30; targetSdk = 35
        versionCode = 1; versionName = "0.1"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }
    buildTypes { debug { isMinifyEnabled = false } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}
dependencies {
    implementation(project(":keykin"))
}
