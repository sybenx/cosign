plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "cc.aaro.cosign"
    compileSdk = 35

    defaultConfig {
        applicationId = "cc.aaro.cosign"
        minSdk = 30
        targetSdk = 35
        versionCode = 16
        versionName = "0.11.1"
        // Cosign's FROST library (libcosign_frost.so) is built for these two only, so the
        // APK carries no others: an app store then offers it only where it runs.
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    buildTypes {
        // Release builds are signed with the debug key here, then re-signed by release.sh
        // with Cosign's release key (rotated from the debug key, so each installs over the last).
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
    testOptions { unitTests.isReturnDefaultValues = true }
    // Unit tests run the native FROST too, from a desktop build of the same library:
    // (cd ../frost && cargo build --release --features android)
    tasks.withType<Test> { systemProperty("java.library.path", rootProject.file("../frost/target/release").absolutePath) }
    packaging { resources.excludes += "/META-INF/{AL2.0,LGPL2.1}" }
}

dependencies {
    val bom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(bom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.camera:camera-camera2:1.4.1")
    implementation("androidx.camera:camera-lifecycle:1.4.1")
    implementation("androidx.camera:camera-view:1.4.1")
    implementation("com.google.zxing:core:3.5.3")
    implementation("androidx.print:print:1.0.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("org.unifiedpush.android:connector:3.0.10")
    implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-android:0.19.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    testImplementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.19.0")
}
