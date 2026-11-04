// The Keykin device library for Android: the shared Kotlin device (../../kotlin, the same sources the JVM
// tests run) with Android's parts: libsecp256k1 for every secret-key operation, the FROST library built for
// Android (jniLibs, `cargo ndk ... --features jni` in ../../frost), a Keystore lock, Keystore-sealed state,
// and OkHttp for the relays. It draws nothing.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

group = "cc.aaro.keykin"

android {
    namespace = "cc.aaro.keykin"
    compileSdk = 35
    defaultConfig {
        minSdk = 30
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    sourceSets["main"].kotlin.srcDir("../../kotlin/src/main/kotlin")
    testOptions { unitTests.isReturnDefaultValues = true }
}
// The headless test device and the JDK relay socket are desktop-only.
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    exclude("**/Headless.kt", "**/JdkWire.kt")
}

dependencies {
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-android:0.19.0")
    implementation("androidx.biometric:biometric:1.1.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    testImplementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.19.0")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
