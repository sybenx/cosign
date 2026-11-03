plugins {
    kotlin("jvm") version "2.0.21"
}

repositories { mavenCentral() }

dependencies {
    implementation("org.json:json:20240303")
    testImplementation(kotlin("test"))
}

kotlin { jvmToolchain(21) }

tasks.test {
    useJUnitPlatform()
    // The vectors live with the spec, two levels up.
    systemProperty("keykin.vectors", file("../../docs/keykin/vectors/vectors.json").absolutePath)
    systemProperty("keykin.behaviour", file("../vectors/behaviour.json").absolutePath)
    systemProperty("keykin.cosigner", file("../vectors/cosigner.json").absolutePath)
    // Built by `cargo build --release --features jni` in ../frost.
    systemProperty("keykin.frostlib", file("../frost/target/release/libkeykin_frost.dylib").absolutePath)
    testLogging { events("passed", "failed"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
}
