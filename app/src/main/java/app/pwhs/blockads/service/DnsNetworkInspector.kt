package app.pwhs.blockads.service

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import java.net.Inet4Address
import java.net.InetAddress
import timber.log.Timber

/**
 * Reads the DNS servers Android hands to apps on the active network.
 * Used by Root Proxy mode to decide whether IPv6 DNS can safely be rejected
 * (forcing the resolver onto the redirected IPv4 path) on kernels without
 * ip6tables nat.
 */
object DnsNetworkInspector {

    /**
     * @return true if the active network has at least one IPv4 DNS server,
     *         false if it only has IPv6 DNS servers (or none),
     *         null if the active network/link properties are unknown right now.
     */
    fun activeNetworkHasIpv4Dns(context: Context): Boolean? {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return null
            val network = cm.activeNetwork ?: return null
            val lp = cm.getLinkProperties(network) ?: return null
            hasIpv4Dns(lp.dnsServers)
        } catch (e: Exception) {
            Timber.w(e, "Failed to inspect active network DNS servers")
            null
        }
    }

    internal fun hasIpv4Dns(servers: List<InetAddress>): Boolean =
        servers.any { it is Inet4Address && !it.isAnyLocalAddress }

    @Suppress("unused")
    internal fun hasIpv4Dns(lp: LinkProperties): Boolean = hasIpv4Dns(lp.dnsServers)
}
