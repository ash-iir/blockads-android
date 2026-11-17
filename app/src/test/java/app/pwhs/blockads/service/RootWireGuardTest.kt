package app.pwhs.blockads.service

import app.pwhs.blockads.data.entities.WireGuardConfig
import app.pwhs.blockads.data.entities.WireGuardInterface
import app.pwhs.blockads.data.entities.WireGuardPeer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Root-mode WireGuard (kernel WireGuard + uid policy routing, no VpnService). */
class RootWireGuardTest {

    private val plain = WireGuardConfig(
        interfaceConfig = WireGuardInterface(
            privateKey = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
            address = listOf("10.66.66.2/32", "fd42::2/128"),
        ),
        peers = listOf(
            WireGuardPeer(
                publicKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                presharedKey = " ",
                endpoint = "2001:db8::5:51820",
                allowedIPs = listOf("0.0.0.0/0", "::/0"),
                persistentKeepalive = 25,
            )
        ),
    )

    @Test
    fun `all app uids of a user minus exclusions`() {
        assertEquals(
            listOf(RootWireGuard.UidRange(10000, 19999)),
            RootWireGuard.uidRanges(listOf(0), emptyList()),
        )
        assertEquals(
            listOf(RootWireGuard.UidRange(10000, 10684), RootWireGuard.UidRange(10686, 19999)),
            RootWireGuard.uidRanges(listOf(0), listOf(10685)),
        )
        // Boundaries and ids outside the app range are handled.
        assertEquals(
            listOf(RootWireGuard.UidRange(10001, 19998)),
            RootWireGuard.uidRanges(listOf(0), listOf(10000, 19999, 1000, 99999)),
        )
    }

    @Test
    fun `every user and work profile gets its own ranges`() {
        assertEquals(
            listOf(
                RootWireGuard.UidRange(10000, 10099), RootWireGuard.UidRange(10101, 19999),
                RootWireGuard.UidRange(1010000, 1010099), RootWireGuard.UidRange(1010101, 1019999),
            ),
            RootWireGuard.uidRanges(listOf(10, 0, 0), listOf(10100)),
        )
    }

    @Test
    fun `never routes system uids`() {
        for (r in RootWireGuard.uidRanges(listOf(0, 10), listOf(10500))) {
            assertTrue("$r", r.start % 100_000 >= 10000 && r.end % 100_000 <= 19999)
        }
    }

    @Test
    fun `helper config carries profile, routing and safety settings`() {
        val ranges = RootWireGuard.uidRanges(listOf(0), listOf(10685))
        val js = Json.parseToJsonElement(
            RootWireGuard.buildConfigJson(plain, appUid = 10682, ranges = ranges, excludeLan = true, killSwitch = false)
        ).jsonObject
        assertEquals("bawg0", js["interface"]!!.jsonPrimitive.content)
        assertEquals(980, js["table"]!!.jsonPrimitive.int)
        assertEquals(0x20000000L, js["fwmark"]!!.jsonPrimitive.long)
        assertEquals(1280, js["mtu"]!!.jsonPrimitive.int)
        assertEquals(10682, js["appUid"]!!.jsonPrimitive.int)
        assertTrue(js["excludeLan"]!!.jsonPrimitive.boolean)
        assertFalse(js["killSwitch"]!!.jsonPrimitive.boolean)
        assertEquals(RootWireGuard.HANDSHAKE_TIMEOUT_SEC, js["handshakeTimeoutSec"]!!.jsonPrimitive.int)
        assertEquals(2, js["uidRanges"]!!.jsonArray.size)
        assertEquals(10686, js["uidRanges"]!!.jsonArray[1].jsonObject["start"]!!.jsonPrimitive.int)
        assertEquals(listOf("10.66.66.2/32", "fd42::2/128"), js["addresses"]!!.jsonArray.map { it.jsonPrimitive.content })
        val peer = js["peers"]!!.jsonArray[0].jsonObject
        assertEquals("[2001:db8::5]:51820", peer["endpoint"]!!.jsonPrimitive.content)
        assertNull("blank preshared key must be omitted", peer["presharedKey"])
        assertEquals(25, peer["persistentKeepalive"]!!.jsonPrimitive.int)
        assertNull(js["jc"])
    }

    @Test
    fun `endpoints are normalized for the helper`() {
        assertEquals("203.0.113.5:51820", RootWireGuard.normalizeEndpoint(" 203.0.113.5:51820 "))
        assertEquals("[2001:db8::5]:51820", RootWireGuard.normalizeEndpoint("[2001:db8::5]:51820"))
        assertEquals("[2001:db8::5]:51820", RootWireGuard.normalizeEndpoint("2001:db8::5:51820"))
        assertNull(RootWireGuard.normalizeEndpoint(null))
        assertNull(RootWireGuard.normalizeEndpoint(""))
    }

    @Test
    fun `AmneziaWG profiles are refused, plain WireGuard is accepted`() {
        assertNull(RootWireGuard.unsupportedReason(plain))
        val zeroAwg = plain.copy(interfaceConfig = plain.interfaceConfig.copy(jc = 0, h1 = 0L))
        assertNull(RootWireGuard.unsupportedReason(zeroAwg))
        val awg = plain.copy(interfaceConfig = plain.interfaceConfig.copy(jc = 4, jmin = 40, jmax = 70, h1 = 12345L))
        assertNotNull(RootWireGuard.unsupportedReason(awg))
        val awg2 = plain.copy(interfaceConfig = plain.interfaceConfig.copy(i1 = "<b 0xf6ab>"))
        assertNotNull(RootWireGuard.unsupportedReason(awg2))
        assertNotNull(RootWireGuard.unsupportedReason(plain.copy(peers = emptyList())))
    }

    @Test
    fun `table and prefs stay clear of netd and the IPv6 DNS redirect`() {
        assertFalse(RootWireGuard.ROUTE_TABLE in 97..99)
        assertTrue(RootWireGuard.PREF_FIRST > Ipv6DnsRedirect.RULE_PREF)
        assertTrue(RootWireGuard.PREF_LAST < 11000)
        assertTrue(RootWireGuard.MAX_UID_RANGES > 0)
    }

    @Test
    fun `cleanup only touches our rules, table and interface`() {
        val cleanup = RootWireGuard.cleanupCommands().joinToString("\n")
        assertTrue(cleanup.contains("ip -4 rule del pref \$p lookup 980"))
        assertTrue(cleanup.contains("ip -6 rule del pref \$p lookup 980"))
        assertTrue(cleanup.contains("ip -4 rule del pref \$p goto 10099"))
        assertTrue(cleanup.contains("ip -6 rule del pref \$p nop"))
        assertTrue(cleanup.contains("grep -E '^100[0-9][0-9]:'"))
        assertTrue(cleanup.contains("ip -4 route flush table 980"))
        assertTrue(cleanup.contains("ip -6 route flush table 980"))
        assertTrue(cleanup.contains("ip link del dev bawg0"))
        // Never the IPv6 DNS redirect (pref 9999 / table 97) or netd's tables.
        assertFalse(cleanup.contains("9999"))
        assertFalse(Regex("table 9[789]\\b").containsMatchIn(cleanup))
        // A bare "rule del pref N" would delete whatever rule sits there.
        assertFalse(Regex("rule del pref \\\$p( 2>|;|$)").containsMatchIn(cleanup))
    }

    @Test
    fun `teardown stops the helper first and is part of the iptables teardown`() {
        val teardown = RootWireGuard.teardownCommands()
        assertEquals("pkill -f libblockadswg.so 2>/dev/null", teardown.first())
        assertTrue(IptablesManager.teardownCommands().containsAll(teardown))
    }

    @Test
    fun `helper start command passes config, ready file and parent watch`() {
        val cmd = RootWireGuard.startCommand(
            "/x/libblockadswg.so", "/f/rootwg.json", "/c/r", "/c/s", "/c/l", 1234, "app.pwhs.blockads"
        )
        assertTrue(cmd.contains("setsid '/x/libblockadswg.so' up -config '/f/rootwg.json'"))
        assertTrue(cmd.contains("-ready '/c/r'"))
        assertTrue(cmd.contains("-ppid 1234"))
        assertTrue(cmd.contains("-pname 'app.pwhs.blockads'"))
        assertTrue(cmd.startsWith("rm -f '/c/r'; "))
        assertTrue(cmd.trimEnd().endsWith("&)"))
    }

    @Test
    fun `health check needs helper, interface and app rules together`() {
        val h = RootWireGuard.healthCommand()
        assertTrue(h.contains("pgrep -f libblockadswg.so"))
        assertTrue(h.contains("ip link show dev bawg0"))
        assertTrue(h.contains("uidrange.*lookup 980"))
        assertTrue(h.endsWith("echo yes"))
    }
}
