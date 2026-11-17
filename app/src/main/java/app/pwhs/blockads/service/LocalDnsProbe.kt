package app.pwhs.blockads.service

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import kotlin.random.Random

/**
 * Sends one real DNS query to the local Root Proxy engine and reports whether
 * ANY well-formed answer (NOERROR, NXDOMAIN, SERVFAIL, a block response…) with
 * the matching transaction id came back.
 *
 * BlockAds' own UID is excluded from the iptables redirect, so this socket
 * talks to 127.0.0.1:[port] directly. It detects the case the old watchdog
 * missed: rules still in place but the Go standalone server dead or wedged,
 * which silently breaks IPv4 DNS and pushes the system resolver onto other
 * paths.
 */
object LocalDnsProbe {

    fun isAlive(port: Int, timeoutMs: Int = 5000, host: String = "dns-probe.blockads.invalid"): Boolean {
        val id = Random.nextInt(0, 0xFFFF)
        val query = buildQuery(id, host)
        return try {
            DatagramSocket().use { sock ->
                sock.soTimeout = timeoutMs
                val addr = InetAddress.getByName("127.0.0.1")
                sock.send(DatagramPacket(query, query.size, addr, port))
                val buf = ByteArray(1500)
                val resp = DatagramPacket(buf, buf.size)
                sock.receive(resp)
                isResponseFor(id, buf, resp.length)
            }
        } catch (_: SocketTimeoutException) {
            false
        } catch (_: Exception) {
            false
        }
    }

    internal fun buildQuery(id: Int, host: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(id shr 8 and 0xFF); out.write(id and 0xFF)
        out.write(0x01); out.write(0x00)          // RD
        out.write(0x00); out.write(0x01)          // QDCOUNT=1
        repeat(6) { out.write(0x00) }             // AN/NS/AR = 0
        for (label in host.trimEnd('.').split('.')) {
            val b = label.toByteArray(Charsets.US_ASCII)
            out.write(b.size); out.write(b)
        }
        out.write(0x00)
        out.write(0x00); out.write(0x01)          // QTYPE A
        out.write(0x00); out.write(0x01)          // QCLASS IN
        return out.toByteArray()
    }

    internal fun isResponseFor(id: Int, buf: ByteArray, len: Int): Boolean {
        if (len < 12) return false
        val rid = (buf[0].toInt() and 0xFF shl 8) or (buf[1].toInt() and 0xFF)
        val isResponse = buf[2].toInt() and 0x80 != 0
        return rid == id && isResponse
    }
}
