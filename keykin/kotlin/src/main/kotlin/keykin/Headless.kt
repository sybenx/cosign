// A headless Kotlin device, for cross-language tests (test/kotlin.e2e.test.ts): load a TS device's
// snapshot, sign one note over the given relays, print the signed event as one JSON line.
//   keykin.HeadlessKt <snapshot.json> <relay,relay> <content>
package keykin

import java.io.File

fun main(args: Array<String>) {
    val net = RelayNet(args[1].split(",")).connect()
    try {
        val d = Device(File(args[0]).readText(), net)
        println(d.sign(1, args[2]).toString())
    } catch (e: KeykinException) { println("""{"error":"${e.code}"}""") } finally { net.close() }
    System.exit(0)
}
