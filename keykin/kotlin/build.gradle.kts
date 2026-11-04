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
    systemProperty("keykin.slip39words", file("../vectors/slip39/wordlist.txt").absolutePath)
    systemProperty("keykin.slip39vectors", file("../vectors/slip39/vectors.json").absolutePath)
    // Built by `cargo build --release --features jni` in ../frost. A plain `cargo build` leaves out the JNI
    // bindings, and the tests would die with UnsatisfiedLinkError; say what to run instead.
    val lib = file("../frost/target/release/" + if (System.getProperty("os.name").startsWith("Mac")) "libkeykin_frost.dylib" else "libkeykin_frost.so")
    systemProperty("keykin.frostlib", lib.absolutePath)
    inputs.files(lib).withPropertyName("frostlib").optional()
    doFirst {
        val hint = "Build it with: (cd keykin/frost && cargo build --release --features jni)"
        if (!lib.exists()) throw GradleException("The FROST library ${lib.path} is missing. $hint")
        if (!String(lib.readBytes(), Charsets.ISO_8859_1).contains("Java_keykin_FrostNative_call"))
            throw GradleException("${lib.path} has no JNI bindings (built without --features jni). $hint")
    }
    testLogging { events("passed", "failed"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
}
