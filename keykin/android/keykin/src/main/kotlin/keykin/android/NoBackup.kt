// Small state the signer keeps beside the sealed membership (slots, relays, NIP-55 grants, push endpoints) in
// one JSON file in `noBackupFilesDir`: never in SharedPreferences, which Android backs up and, from Android 12,
// moves to a new phone even with allowBackup="false" (review 15 L1). Nothing here is secret, but a grant moved to
// another phone would be a grant the person never gave there.
package keykin.android

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream

class NoBackup(context: Context, name: String) {
    private val file = File(context.noBackupFilesDir, "keykin-$name.json")
    private var data: JSONObject = try { if (file.exists()) JSONObject(file.readText()) else JSONObject() } catch (_: Exception) { JSONObject() }
    @Synchronized fun get(): JSONObject = JSONObject(data.toString())
    @Synchronized fun update(f: (JSONObject) -> Unit) {
        val d = JSONObject(data.toString()); f(d); data = d
        val tmp = File(file.path + ".tmp")
        FileOutputStream(tmp).use { it.write(d.toString().toByteArray()); it.fd.sync() }
        if (!tmp.renameTo(file)) { file.delete(); tmp.renameTo(file) }
    }
}
