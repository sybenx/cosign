package cc.aaro.keykin.demo

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The bunker link's secret reaches logcat only in a debug build (the e2e harness); a release build never logs it. */
class LinkLogTest {
    @Test fun aDebugBuildLogsTheLinkForTheE2eTest() {
        assertTrue(BuildConfig.DEBUG)
        val link = "bunker://${"ab".repeat(32)}?relay=wss%3A%2F%2Fr.test&secret=s3cr3t"
        assertEquals(link, LinkLog.shown(link))
    }
}
