// Runs the Kotlin port's sources, unchanged, on probes.json (written by ../gen.ts) into kt-results.json.
plugins { kotlin("jvm") version "2.0.21"; application }
repositories { mavenCentral() }
dependencies { implementation("org.json:json:20240303") }
kotlin { jvmToolchain(21) }
sourceSets { main { kotlin.srcDirs(file("../../../kotlin/src/main/kotlin"), "src"); kotlin.exclude("**/CoSigner.kt", "**/Frost.kt") } }
application { mainClass.set("keykin.ProbeKt") }
tasks.named<JavaExec>("run") { systemProperty("keykin.slip39words", file("../../slip39/wordlist.txt").absolutePath); args(file("../probes.json").absolutePath, file("../kt-results.json").absolutePath) }
