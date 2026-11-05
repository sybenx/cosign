package keykin.android

import keykin.Doors
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The app's own process reads to-self data only of the kinds it declares; a wallet's only when declared. */
class DoorsOwnTest {
    @Test fun defaultsAreListsAndAppDataNeverAWallet() {
        assertTrue(Doors.ownMay(10000, null)); assertTrue(Doors.ownMay(30000, null)); assertTrue(Doors.ownMay(30078, null))
        for (k in Doors.WALLET_KINDS) assertFalse("$k", Doors.ownMay(k, null))
        assertFalse(Doors.ownMay(4, null))
    }
    @Test fun aDeclarationIsTheListExactly() {
        assertTrue(Doors.ownMay(17375, setOf(17375, 30078)))
        assertFalse(Doors.ownMay(10000, setOf(30078)))
    }
}
