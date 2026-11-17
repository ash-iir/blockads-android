package app.pwhs.blockads.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * IPv6 DNS on kernels without ip6tables nat is redirected (TPROXY helper),
 * never rejected: rejecting it took every app offline on 2026-11-17 once netd
 * had marked the carrier's IPv4 DNS servers broken.
 */
class Ipv6DnsRedirectTest {

    private val rules = Ipv6DnsRedirect.ruleCommands(appUid = 10682, whitelistUids = listOf(10100))

    @Test
    fun `never rejects DNS`() {
        assertFalse(rules.any { it.contains("REJECT") || it.contains("DROP") })
    }

    @Test
    fun `marks v6 port 53 except loopback, BlockAds and whitelist`() {
        val firstMark = rules.indexOfFirst { it.contains("-j MARK") }
        val exemptions = listOf("-d ::1 -j RETURN", "--uid-owner 10682 -j RETURN", "--uid-owner 10100 -j RETURN")
        for (e in exemptions) {
            val i = rules.indexOfFirst { it.contains(e) }
            assertTrue("missing $e", i >= 0)
            assertTrue("$e must precede the MARK rules", i < firstMark)
        }
        assertTrue(rules.any { it.contains("-p udp --dport 53 -j MARK --set-xmark 0x10000000/0x10000000") })
        assertTrue(rules.any { it.contains("-p tcp --dport 53 -j MARK --set-xmark 0x10000000/0x10000000") })
    }

    @Test
    fun `tproxies marked lo traffic to the helper`() {
        for (p in listOf("udp", "tcp")) {
            assertTrue(rules.any {
                it.contains("-i lo -p $p --dport 53") && it.contains("-j TPROXY --on-ip ::1 --on-port 15355")
            })
        }
        assertTrue(rules.any { it == "ip -6 route replace local ::/0 dev lo table 97" })
        assertTrue(rules.any { it == "ip -6 rule add pref 9999 fwmark 0x10000000/0x10000000 lookup 97" })
    }

    @Test
    fun `hooks are added last so traffic is only diverted once the chains are complete`() {
        val hooks = rules.takeLast(2)
        assertEquals("ip6tables -t mangle -I OUTPUT -j BLOCKADS_DNS6M", hooks[0])
        assertEquals("ip6tables -t mangle -I PREROUTING -j BLOCKADS_DNS6T", hooks[1])
    }

    @Test
    fun `cleanup undoes every rule and is part of the iptables teardown`() {
        val cleanup = Ipv6DnsRedirect.cleanupCommands()
        assertTrue(cleanup.any { it.startsWith("ip6tables -t mangle -D OUTPUT -j BLOCKADS_DNS6M") })
        assertTrue(cleanup.any { it.startsWith("ip6tables -t mangle -D PREROUTING -j BLOCKADS_DNS6T") })
        assertTrue(cleanup.any { it.startsWith("ip -6 rule del pref 9999") })
        assertTrue(cleanup.any { it.startsWith("ip -6 route flush table 97") })
        val teardown = IptablesManager.teardownCommands()
        assertTrue(teardown.any { it.startsWith("pkill -f libblockadsdns6.so") })
        assertTrue(teardown.containsAll(cleanup))
    }

    @Test
    fun `helper start command passes cleanup and parent watch`() {
        val cmd = Ipv6DnsRedirect.startCommand("/x/libblockadsdns6.so", "/c/r", "/c/l", 1234, "app.pwhs.blockads")
        assertTrue(cmd.contains("-ppid 1234"))
        assertTrue(cmd.contains("-pname 'app.pwhs.blockads'"))
        assertTrue(cmd.contains("-cleanup '" + Ipv6DnsRedirect.cleanupScript() + "'"))
        assertFalse(Ipv6DnsRedirect.cleanupScript().contains("'"))
        assertTrue(cmd.contains("setsid '/x/libblockadsdns6.so'"))
    }
}
