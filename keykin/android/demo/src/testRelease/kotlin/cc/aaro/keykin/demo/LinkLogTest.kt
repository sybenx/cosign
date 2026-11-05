package cc.aaro.keykin.demo

import org.junit.Assert.assertFalse
import org.junit.Test

/** The bunker link's secret reaches logcat only in a debug build (the e2e harness); a release build never logs it. */
class LinkLogTest {
    @Test fun aReleaseBuildNeverLogsTheBunkerSecret() {
        assertFalse(BuildConfig.DEBUG)
        val shown = LinkLog.shown("bunker://${"ab".repeat(32)}?relay=wss%3A%2F%2Fr.test&secret=s3cr3t")
        assertFalse(shown.contains("s3cr3t")); assertFalse(shown.contains("secret="))
    }
}
