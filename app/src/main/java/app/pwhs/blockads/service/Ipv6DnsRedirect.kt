package app.pwhs.blockads.service

import android.content.Context
import app.pwhs.blockads.utils.RootShell
import java.io.File
import timber.log.Timber

/**
 * IPv6 DNS for Root Proxy mode on kernels without ip6tables nat
 * (CONFIG_IP6_NF_NAT unset: many GKI builds, OnePlus/ColorOS among them).
 *
 * The IPv4 path uses nat REDIRECT. There is no IPv6 nat table here, so IPv6
 * port-53 traffic is diverted with TPROXY instead:
 *
 *   mangle OUTPUT      mark IPv6 udp/tcp dport 53 (not ::1, not BlockAds)
 *   ip -6 rule/route   marked packets loop back through lo
 *   mangle PREROUTING  TPROXY them to the root helper on [::1]:15355
 *
 * The helper (lib/<abi>/libblockadsdns6.so, tools/dns6helper) forwards each
 * query to the engine on [::1]:15353 and answers from the original server
 * address. It needs CAP_NET_ADMIN, so it is started through su.
 *
 * Never REJECT IPv6 DNS instead: once netd has marked the carrier's IPv4
 * servers broken it sends DNS only over IPv6, and rejecting that leaves no
 * resolver at all (every app offline; seen 2026-11-17).
 *
 * Fail-open: rules are only installed after the helper is listening, the
 * helper removes them when it exits or BlockAds dies, and [ensure] removes
 * them whenever the helper is gone.
 */
object Ipv6DnsRedirect {

    internal const val BINARY_NAME = "libblockadsdns6.so"
    internal const val CHAIN_MARK = "BLOCKADS_DNS6M"
    internal const val CHAIN_TPROXY = "BLOCKADS_DNS6T"
    internal const val MARK = "0x10000000"
    internal const val ROUTE_TABLE = 97
    internal const val RULE_PREF = 9999
    internal const val HELPER_PORT = 15355
    private const val READY_WAIT_MS = 3000L

    // Same root shell as IptablesManager, so tests inject one fake for both.
    private val shell: RootShell get() = IptablesManager.shell

    fun helperBinary(context: Context): File =
        File(context.applicationInfo.nativeLibraryDir, BINARY_NAME)

    /** Commands that remove the redirect. Safe to run any number of times. */
    internal fun cleanupCommands(): List<String> = listOf(
        "ip6tables -t mangle -D OUTPUT -j $CHAIN_MARK 2>/dev/null",
        "ip6tables -t mangle -F $CHAIN_MARK 2>/dev/null",
        "ip6tables -t mangle -X $CHAIN_MARK 2>/dev/null",
        "ip6tables -t mangle -D PREROUTING -j $CHAIN_TPROXY 2>/dev/null",
        "ip6tables -t mangle -F $CHAIN_TPROXY 2>/dev/null",
        "ip6tables -t mangle -X $CHAIN_TPROXY 2>/dev/null",
        "ip -6 rule del pref $RULE_PREF 2>/dev/null",
        "ip -6 route flush table $ROUTE_TABLE 2>/dev/null",
    )

    /** The same cleanup as one shell line, handed to the helper for its exit path. */
    internal fun cleanupScript(): String = cleanupCommands().joinToString("; ")

    internal fun ruleCommands(appUid: Int, whitelistUids: Collection<Int>): List<String> = buildList {
        add("ip -6 route replace local ::/0 dev lo table $ROUTE_TABLE")
        add("ip -6 rule add pref $RULE_PREF fwmark $MARK/$MARK lookup $ROUTE_TABLE")
        add("ip6tables -t mangle -N $CHAIN_MARK")
        add("ip6tables -t mangle -A $CHAIN_MARK -d ::1 -j RETURN")
        add("ip6tables -t mangle -A $CHAIN_MARK -m owner --uid-owner $appUid -j RETURN")
        for (w in whitelistUids) {
            add("ip6tables -t mangle -A $CHAIN_MARK -m owner --uid-owner $w -j RETURN")
        }
        for (proto in listOf("udp", "tcp")) {
            add("ip6tables -t mangle -A $CHAIN_MARK -p $proto --dport 53 -j MARK --set-xmark $MARK/$MARK")
        }
        add("ip6tables -t mangle -N $CHAIN_TPROXY")
        for (proto in listOf("udp", "tcp")) {
            add(
                "ip6tables -t mangle -A $CHAIN_TPROXY -i lo -p $proto --dport 53 -m mark --mark $MARK/$MARK " +
                    "-j TPROXY --on-ip ::1 --on-port $HELPER_PORT --tproxy-mark $MARK/$MARK"
            )
        }
        add("ip6tables -t mangle -I OUTPUT -j $CHAIN_MARK")
        add("ip6tables -t mangle -I PREROUTING -j $CHAIN_TPROXY")
    }

    internal fun startCommand(binary: String, readyFile: String, logFile: String, pid: Int, processName: String): String =
        "rm -f '$readyFile'; " +
            "(setsid '$binary' -l '[::1]:$HELPER_PORT' -u '[::1]:15353' " +
            "-ppid $pid -pname '$processName' -ready '$readyFile' " +
            "-cleanup '${cleanupScript()}' > '$logFile' 2>&1 < /dev/null &)"

    fun isHelperRunning(): Boolean =
        shell.exec("pgrep -f $BINARY_NAME >/dev/null && echo yes").out.any { it.trim() == "yes" }

    fun rulesPresent(): Boolean =
        shell.exec("ip6tables -t mangle -C OUTPUT -j $CHAIN_MARK 2>/dev/null && ip6tables -t mangle -C PREROUTING -j $CHAIN_TPROXY 2>/dev/null && echo yes")
            .out.any { it.trim() == "yes" }

    /**
     * Starts the helper and installs the redirect. Returns false (with no
     * redirect installed) when the helper is missing or does not come up.
     */
    fun start(context: Context, appUid: Int, whitelistUids: Collection<Int>): Boolean {
        stop()
        // An old helper runs its own cleanup when it exits; wait for it, or that
        // cleanup could remove the rules installed below.
        val gone = System.currentTimeMillis() + 2000L
        while (isHelperRunning() && System.currentTimeMillis() < gone) Thread.sleep(100)
        val bin = helperBinary(context)
        if (!bin.exists()) {
            Timber.w("IPv6 DNS helper not packaged ($bin) — IPv6 DNS stays unfiltered")
            return false
        }
        val ready = File(context.cacheDir, "dns6helper.ready").absolutePath
        val log = File(context.cacheDir, "dns6helper.log").absolutePath
        shell.exec(startCommand(bin.absolutePath, ready, log, android.os.Process.myPid(), context.packageName))

        val deadline = System.currentTimeMillis() + READY_WAIT_MS
        var up = false
        while (System.currentTimeMillis() < deadline) {
            if (shell.exec("test -f '$ready' && echo yes").out.any { it.trim() == "yes" }) {
                up = true
                break
            }
            Thread.sleep(100)
        }
        if (!up) {
            Timber.e("IPv6 DNS helper did not start: ${shell.exec("tail -5 '$log'").out.joinToString(" | ")}")
            stop()
            return false
        }
        for (cmd in ruleCommands(appUid, whitelistUids)) {
            val r = shell.exec(cmd)
            if (!r.isSuccess) {
                Timber.e("IPv6 DNS redirect rule failed [$cmd]: ${r.err} — removing redirect")
                stop()
                return false
            }
        }
        Timber.d("IPv6 DNS redirected to BlockAds via TPROXY helper")
        return true
    }

    /** Stops the helper, then removes the redirect (also part of IptablesManager teardown). */
    internal fun teardownCommands(): List<String> =
        listOf("pkill -f $BINARY_NAME 2>/dev/null") + cleanupCommands()

    /** Stops the helper and removes the redirect. */
    fun stop() {
        shell.exec(*teardownCommands().toTypedArray())
    }

    /**
     * Watchdog step: keeps helper and redirect together. If either half is
     * missing the redirect is removed first (fail-open), then restarted.
     * @return true when the redirect is active after this call.
     */
    fun ensure(context: Context, appUid: Int, whitelistUids: Collection<Int>): Boolean {
        if (isHelperRunning() && rulesPresent()) return true
        Timber.w("IPv6 DNS helper or rules missing — restarting redirect")
        return start(context, appUid, whitelistUids)
    }
}
