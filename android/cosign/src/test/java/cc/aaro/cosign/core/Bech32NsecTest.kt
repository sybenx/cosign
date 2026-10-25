package cc.aaro.cosign.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

class Bech32NsecTest {
    // The key 01 02 … 20 (a test value, nobody's).
    private val nsec = "nsec1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqpqcc2y"

    @Test fun decodesAnNsecFromCharacters() {
        val (_, want) = Bech32.decode(nsec)
        assertArrayEquals(want, Bech32.decodeNsec(nsec.toCharArray()))
        assertArrayEquals(want, Bech32.decodeNsec(nsec.uppercase().toCharArray()))
    }

    @Test fun refusesDamagedOnes() {
        assertNull(Bech32.decodeNsec(nsec.dropLast(1).toCharArray()))
        assertNull(Bech32.decodeNsec((nsec.dropLast(1) + if (nsec.last() == 'q') 'p' else 'q').toCharArray()))
        assertNull(Bech32.decodeNsec(nsec.replaceFirst("nsec", "npub").toCharArray()))
    }
}
