package app.pwhs.blockads.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Parsing of the Root WireGuard helper's status file (tools/wghelper writeStatus). */
class RootWireGuardStatusTest {

    private val t0 = RootWireGuardStatus.parseRfc3339("2026-11-17T10:27:56Z")!!

    private val sample = """
        time=2026-11-17T10:27:56Z
        peer=0/x2PdBG endpoint=62.182.99.141:51820 handshake=2026-11-17T10:27:46Z rx=1432332 tx=455460
    """.trimIndent() + "\n"

    @Test
    fun parsesRfc3339WithZoneAndOffset() {
        assertEquals(1794911276000L, t0)
        assertEquals(t0, RootWireGuardStatus.parseRfc3339("2026-11-17T11:27:56+01:00"))
        assertEquals(t0, RootWireGuardStatus.parseRfc3339("2026-11-17T05:27:56.123-05:00"))
        assertNull(RootWireGuardStatus.parseRfc3339("Tue 2026-11-17 11:27 AM"))
        assertNull(RootWireGuardStatus.parseRfc3339(""))
    }

    @Test
    fun parsesHelperOutput() {
        val s = RootWireGuardStatus.parse(sample)
        assertNotNull(s)
        s!!
        assertEquals(t0, s.updatedAtMs)
        assertEquals(1, s.peers.size)
        val p = s.peers[0]
        assertEquals("0/x2PdBG", p.key)
        assertEquals("62.182.99.141:51820", p.endpoint)
        assertEquals(t0 - 10_000L, p.lastHandshakeMs)
        assertEquals(1432332L, s.rxBytes)
        assertEquals(455460L, s.txBytes)
        assertEquals("62.182.99.141:51820", s.endpoint)
    }

    @Test
    fun connectedWhileFreshAndRecentHandshake() {
        val s = RootWireGuardStatus.parse(sample)!!
        assertTrue(s.isFresh(t0 + 5_000))
        assertTrue(s.isConnected(t0 + 5_000))
        assertEquals(15L, s.handshakeAgeSec(t0 + 5_000))
    }

    @Test
    fun staleFileMeansDown() {
        // The helper exited; the file stays behind with its last values.
        val s = RootWireGuardStatus.parse(sample)!!
        val later = t0 + 6 * 60_000L
        assertFalse(s.isFresh(later))
        assertFalse(s.isConnected(later))
    }

    @Test
    fun oldHandshakeMeansNotConnectedEvenIfFresh() {
        val s = RootWireGuardStatus.parse(
            "time=2026-11-17T10:40:00Z\n" +
                "peer=abc endpoint=1.2.3.4:51820 handshake=2026-11-17T10:30:00Z rx=1 tx=2\n"
        )!!
        val now = RootWireGuardStatus.parseRfc3339("2026-11-17T10:40:05Z")!!
        assertTrue(s.isFresh(now))
        assertFalse(s.isConnected(now))
    }

    @Test
    fun neverHandshakeAndNilEndpoint() {
        val s = RootWireGuardStatus.parse(
            "time=2026-11-17T10:27:56Z\npeer=abc endpoint=<nil> handshake=never rx=0 tx=0\n"
        )!!
        assertNull(s.peers[0].lastHandshakeMs)
        assertNull(s.peers[0].endpoint)
        assertNull(s.handshakeAgeSec(t0))
        assertFalse(s.isConnected(t0))
    }

    @Test
    fun emptyOrGarbageIsNull() {
        assertNull(RootWireGuardStatus.parse(""))
        assertNull(RootWireGuardStatus.parse("hello\nworld"))
    }

    @Test
    fun formatsBytes() {
        assertEquals("512 B", RootWireGuardStatus.formatBytes(512))
        assertEquals("1.5 KB", RootWireGuardStatus.formatBytes(1536))
        assertEquals("1.4 MB", RootWireGuardStatus.formatBytes(1432332))
        assertEquals("444 KB", RootWireGuardStatus.formatBytes(455460))
    }
}
