package app.pwhs.blockads.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

/**
 * IPv6 DNS leak guard for kernels without ip6tables nat (OnePlus/ColorOS etc.).
 * Root cause of "Chrome blocks ads sometimes, works again after force-stop".
 */
class Ipv6DnsGuardTest {

    @Test
    fun `enabled guard rejects v6 port 53 but exempts app and whitelist`() {
        val cmds = IptablesManager.ipv6DnsGuardCommands(uid = 10682, whitelistUids = listOf(10100), enable = true)
        assertTrue(cmds.any { it.contains("--uid-owner 10682 -j RETURN") })
        assertTrue(cmds.any { it.contains("--uid-owner 10100 -j RETURN") })
        assertTrue(cmds.any { it.contains("-p udp --dport 53 -j REJECT") })
        assertTrue(cmds.any { it.contains("-p tcp --dport 53 -j REJECT") })
        // Exemptions must come before the rejects.
        val lastReturn = cmds.indexOfLast { it.endsWith("-j RETURN") }
        val firstReject = cmds.indexOfFirst { it.contains("-j REJECT") }
        assertTrue(lastReturn < firstReject)
        assertTrue(cmds.all { it.startsWith("ip6tables") })
    }

    @Test
    fun `disabled guard only flushes and keeps the hook idempotent`() {
        val cmds = IptablesManager.ipv6DnsGuardCommands(uid = 10682, whitelistUids = emptyList(), enable = false)
        assertFalse(cmds.any { it.contains("REJECT") })
        assertTrue(cmds.any { it.contains("-F BLOCKADS_DNS6") })
        // Hook is added with -C || -I so repeated syncs never stack duplicates.
        assertTrue(cmds.any { it.contains("-C OUTPUT -j BLOCKADS_DNS6") && it.contains("-I OUTPUT -j BLOCKADS_DNS6") })
    }

    @Test
    fun `teardown removes the guard chain`() {
        val cmds = IptablesManager.teardownCommands()
        assertTrue(cmds.contains("ip6tables -t filter -D OUTPUT -j BLOCKADS_DNS6 2>/dev/null"))
        assertTrue(cmds.contains("ip6tables -t filter -X BLOCKADS_DNS6 2>/dev/null"))
    }

    @Test
    fun `ipv4 dns detection`() {
        val v4 = InetAddress.getByName("80.251.201.178")
        val v6 = InetAddress.getByName("2a02:aa0::56")
        assertTrue(DnsNetworkInspector.hasIpv4Dns(listOf(v6, v4)))
        assertFalse(DnsNetworkInspector.hasIpv4Dns(listOf(v6)))
        assertFalse(DnsNetworkInspector.hasIpv4Dns(emptyList()))
    }

    @Test
    fun `local dns probe builds a valid query and matches its response`() {
        val q = LocalDnsProbe.buildQuery(0x1234, "dns-probe.blockads.invalid")
        assertEquals(0x12, q[0].toInt() and 0xFF)
        assertEquals(0x34, q[1].toInt() and 0xFF)
        val resp = q.copyOf()
        resp[2] = (resp[2].toInt() or 0x80).toByte() // QR=1
        assertTrue(LocalDnsProbe.isResponseFor(0x1234, resp, resp.size))
        assertFalse(LocalDnsProbe.isResponseFor(0x1235, resp, resp.size))
        assertFalse(LocalDnsProbe.isResponseFor(0x1234, q, q.size)) // a query is not a response
    }
}
