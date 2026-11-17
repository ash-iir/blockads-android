package app.pwhs.blockads.service

import android.content.Context
import android.os.UserManager
import app.pwhs.blockads.data.entities.WireGuardConfig
import app.pwhs.blockads.utils.RootShell
import java.io.File
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import timber.log.Timber

/**
 * WireGuard in Root mode without Android's VpnService (the VPN slot stays free).
 *
 * The root helper (lib/<abi>/libblockadswg.so, tools/wghelper) creates a
 * kernel WireGuard interface [IFACE] and routes app uids into it:
 *
 *   table 980          <allowed IPs> dev bawg0; `unreachable default` for a
 *                      family the tunnel has no address for; LAN `throw`s
 *   pref 10001         fwmark 0x40000000 (helper's handshake probe only)
 *   pref 10002         BlockAds' uid → engine upstream DNS + HTTPS MITM outbound
 *   pref 10003/10004   udp/tcp dport 53 → goto 10099 (app DNS never uses the tunnel;
 *                      it is redirected into BlockAds by iptables / the IPv6 TPROXY)
 *   pref 10010..10098  uidrange A-B → table 980
 *   pref 10099         nop
 *
 * Table 980, not 98: 97/98/99 are netd's local_network/legacy_network/legacy_system.
 * Kernel WireGuard's socket is uid 0 with fwmark 0x20000000 → never matched, no loop.
 *
 * Fail-open: apps are routed only after the first handshake; the helper
 * removes everything on exit, on BlockAds' death and (kill switch off) when
 * the tunnel is dead; [ensure] never keeps rules without helper + interface.
 */
object RootWireGuard {

    internal const val BINARY_NAME = "libblockadswg.so"
    internal const val IFACE = "bawg0"
    internal const val ROUTE_TABLE = 980
    internal const val FWMARK = 0x20000000L
    internal const val PREF_FIRST = 10000
    internal const val PREF_RANGES_FIRST = 10010
    internal const val PREF_LAST = 10099
    internal const val MAX_UID_RANGES = PREF_LAST - PREF_RANGES_FIRST
    internal const val DEFAULT_MTU = 1280
    internal const val HANDSHAKE_TIMEOUT_SEC = 15
    private const val READY_WAIT_MS = (HANDSHAKE_TIMEOUT_SEC + 8) * 1000L
    /** After a failed start, the watchdog waits this long before trying again. */
    internal const val RETRY_BACKOFF_MS = 60_000L

    internal const val CONFIG_FILE = "rootwg.json"

    private const val PER_USER_RANGE = 100_000
    private const val FIRST_APP_ID = 10_000
    private const val LAST_APP_ID = 19_999

    private val shell: RootShell get() = IptablesManager.shell

    data class UidRange(val start: Int, val end: Int)

    /** A prepared session: the helper config, built once per proxy start (endpoints resolved). */
    data class Session(val configJson: String, val profileName: String)

    fun helperBinary(context: Context): File =
        File(context.applicationInfo.nativeLibraryDir, BINARY_NAME)

    // ── pure parts (unit tested) ─────────────────────────────────────

    /**
     * App uids to route: every app uid (10000–19999) of each Android user,
     * minus the excluded app ids (BlockAds' whitelisted apps, like VPN mode's
     * disallowed apps). BlockAds itself always gets its own rule.
     */
    internal fun uidRanges(userIds: Collection<Int>, excludedAppIds: Collection<Int>): List<UidRange> {
        val excluded = excludedAppIds.filter { it in FIRST_APP_ID..LAST_APP_ID }.toSortedSet()
        val out = mutableListOf<UidRange>()
        for (u in userIds.distinct().sorted()) {
            val base = u * PER_USER_RANGE
            var start = FIRST_APP_ID
            for (x in excluded) {
                if (x > start) out += UidRange(base + start, base + x - 1)
                start = x + 1
            }
            if (start <= LAST_APP_ID) out += UidRange(base + start, base + LAST_APP_ID)
        }
        return out
    }

    /**
     * Why this profile cannot run on kernel WireGuard, or null. AmneziaWG
     * obfuscation needs the userspace engine (phase 2).
     */
    internal fun unsupportedReason(config: WireGuardConfig): String? {
        val i = config.interfaceConfig
        val nums = listOf(i.jc, i.jmin, i.jmax, i.s1, i.s2, i.s3, i.s4).map { (it ?: 0).toLong() } +
            listOf(i.h1, i.h2, i.h3, i.h4).map { it ?: 0L }
        val strs = listOf(i.i1, i.i2, i.i3, i.i4, i.i5, i.headerProtectionKey)
        if (nums.any { it != 0L } || strs.any { !it.isNullOrBlank() }) {
            return "AmneziaWG profiles are not supported in Root mode yet"
        }
        if (config.peers.isEmpty()) return "profile has no peer"
        if (i.address.isEmpty()) return "profile has no address"
        return null
    }

    /** "host:port" / "[v6]:port" / "v6:port" (as resolveEndpoints writes it) → "ip:port" or "[ip6]:port". */
    internal fun normalizeEndpoint(endpoint: String?): String? {
        val e = endpoint?.trim().orEmpty()
        if (e.isEmpty()) return null
        val colon = e.lastIndexOf(':')
        if (colon <= 0) return e
        val host = e.substring(0, colon).removeSurrounding("[", "]")
        val port = e.substring(colon + 1)
        return if (host.contains(':')) "[$host]:$port" else "$host:$port"
    }

    internal fun buildConfigJson(
        config: WireGuardConfig,
        appUid: Int,
        ranges: List<UidRange>,
        excludeLan: Boolean,
        killSwitch: Boolean,
        mtu: Int = DEFAULT_MTU,
    ): String {
        val i = config.interfaceConfig
        val obj: JsonObject = buildJsonObject {
            put("interface", IFACE)
            put("privateKey", i.privateKey.trim())
            putJsonArray("addresses") { i.address.forEach { add(it.trim()) } }
            put("mtu", mtu)
            i.listenPort?.let { put("listenPort", it) }
            put("fwmark", FWMARK)
            put("table", ROUTE_TABLE)
            putJsonArray("peers") {
                for (p in config.peers) {
                    add(buildJsonObject {
                        put("publicKey", p.publicKey.trim())
                        p.presharedKey?.takeIf { it.isNotBlank() }?.let { put("presharedKey", it.trim()) }
                        normalizeEndpoint(p.endpoint)?.let { put("endpoint", it) }
                        putJsonArray("allowedIPs") { p.allowedIPs.forEach { add(it.trim()) } }
                        p.persistentKeepalive?.let { put("persistentKeepalive", it) }
                    })
                }
            }
            putJsonArray("uidRanges") {
                for (r in ranges) add(buildJsonObject { put("start", r.start); put("end", r.end) })
            }
            put("appUid", appUid)
            put("excludeLan", excludeLan)
            put("killSwitch", killSwitch)
            put("handshakeTimeoutSec", HANDSHAKE_TIMEOUT_SEC)
            // Passed through so the helper refuses AmneziaWG on its own too.
            i.jc?.let { put("jc", it) }
            i.jmin?.let { put("jmin", it) }
            i.jmax?.let { put("jmax", it) }
            i.s1?.let { put("s1", it) }
            i.s2?.let { put("s2", it) }
            i.h1?.let { put("h1", it) }
            i.h2?.let { put("h2", it) }
            i.h3?.let { put("h3", it) }
            i.h4?.let { put("h4", it) }
        }
        return obj.toString()
    }

    /**
     * Removes rules (only ours: prefs 10000–10099 with table 980 / goto 10099 /
     * nop), the table and the interface. Needs no config and is safe to run
     * any number of times, also when the feature was never on.
     */
    internal fun cleanupCommands(): List<String> = buildList {
        for (f in listOf("-4", "-6")) {
            add(
                "for p in \$(ip $f rule show 2>/dev/null | grep -E '^100[0-9][0-9]:' | cut -d: -f1 | sort -un); do " +
                    "while ip $f rule del pref \$p lookup $ROUTE_TABLE 2>/dev/null; do :; done; " +
                    "while ip $f rule del pref \$p goto $PREF_LAST 2>/dev/null; do :; done; " +
                    "if [ \$p = $PREF_LAST ]; then while ip $f rule del pref \$p nop 2>/dev/null; do :; done; fi; " +
                    "done"
            )
        }
        add("ip -4 route flush table $ROUTE_TABLE 2>/dev/null")
        add("ip -6 route flush table $ROUTE_TABLE 2>/dev/null")
        add("ip link del dev $IFACE 2>/dev/null")
    }

    /** Stops the helper (it cleans up itself), then removes whatever is left. Part of IptablesManager teardown. */
    internal fun teardownCommands(): List<String> =
        listOf("pkill -f $BINARY_NAME 2>/dev/null") + cleanupCommands()

    internal fun startCommand(
        binary: String,
        configFile: String,
        readyFile: String,
        statusFile: String,
        logFile: String,
        pid: Int,
        processName: String,
    ): String =
        "rm -f '$readyFile'; " +
            "(setsid '$binary' up -config '$configFile' -ready '$readyFile' -status '$statusFile' " +
            "-ppid $pid -pname '$processName' > '$logFile' 2>&1 < /dev/null &)"

    internal fun healthCommand(): String =
        "pgrep -f $BINARY_NAME >/dev/null && ip link show dev $IFACE >/dev/null 2>&1 && " +
            "ip rule show 2>/dev/null | grep -q 'uidrange.*lookup $ROUTE_TABLE' && echo yes"

    // ── system side ──────────────────────────────────────────────────

    /** Users whose apps are routed: this user and its profiles (work profile). */
    fun userIds(context: Context): List<Int> {
        val own = android.os.Process.myUid() / PER_USER_RANGE
        val profiles = runCatching {
            context.getSystemService(UserManager::class.java)?.userProfiles?.map { it.hashCode() }
        }.getOrNull().orEmpty()
        return (listOf(own) + profiles).distinct()
    }

    /**
     * Builds the session from the active profile. Resolves the endpoint host
     * now, before any rule exists, so it never loops through our own routing.
     * Returns null (feature stays off, nothing installed) when not usable.
     */
    suspend fun prepare(
        context: Context,
        profileName: String,
        config: WireGuardConfig,
        excludedAppIds: Collection<Int>,
        excludeLan: Boolean,
        killSwitch: Boolean,
    ): Session? {
        unsupportedReason(config)?.let {
            Timber.w("Root WireGuard: profile '$profileName' not usable: $it")
            return null
        }
        val resolved = runCatching { config.resolveEndpoints() }.getOrElse {
            Timber.w(it, "Root WireGuard: endpoint resolution failed")
            return null
        }
        val ranges = uidRanges(userIds(context), excludedAppIds)
        if (ranges.size > MAX_UID_RANGES) {
            Timber.w("Root WireGuard: too many excluded apps (${ranges.size} ranges > $MAX_UID_RANGES)")
            return null
        }
        val json = buildConfigJson(resolved, context.applicationInfo.uid, ranges, excludeLan, killSwitch)
        return Session(json, profileName)
    }

    fun isUp(): Boolean = shell.exec(healthCommand()).out.any { it.trim() == "yes" }

    private fun isHelperRunning(): Boolean =
        shell.exec("pgrep -f $BINARY_NAME >/dev/null && echo yes").out.any { it.trim() == "yes" }

    private fun writeConfig(context: Context, json: String): File {
        val f = File(context.filesDir, CONFIG_FILE)
        f.delete()
        f.createNewFile()
        // 0600 before the key goes in.
        f.setReadable(false, false); f.setWritable(false, false)
        f.setReadable(true, true); f.setWritable(true, true)
        f.writeText(json)
        return f
    }

    /**
     * Starts the helper. Blocks until apps are routed (first handshake) or it
     * gives up. Returns false with nothing installed when it does not come up.
     */
    fun start(context: Context, session: Session): Boolean {
        stop()
        // An old helper cleans up on exit; wait so that cleanup cannot remove
        // the rules the new one installs.
        val gone = System.currentTimeMillis() + 3000L
        while (isHelperRunning() && System.currentTimeMillis() < gone) Thread.sleep(100)
        val bin = helperBinary(context)
        if (!bin.exists()) {
            Timber.w("Root WireGuard helper not packaged ($bin)")
            return false
        }
        val cfg = writeConfig(context, session.configJson)
        val ready = File(context.cacheDir, "wghelper.ready").absolutePath
        val status = File(context.cacheDir, "wghelper.status").absolutePath
        val log = File(context.cacheDir, "wghelper.log").absolutePath
        shell.exec(
            startCommand(bin.absolutePath, cfg.absolutePath, ready, status, log, android.os.Process.myPid(), context.packageName)
        )
        val deadline = System.currentTimeMillis() + READY_WAIT_MS
        while (System.currentTimeMillis() < deadline) {
            if (shell.exec("test -f '$ready' && echo yes").out.any { it.trim() == "yes" }) {
                Timber.d("Root WireGuard up ('${session.profileName}', $IFACE, table $ROUTE_TABLE)")
                return true
            }
            if (!isHelperRunning()) break
            Thread.sleep(200)
        }
        Timber.e("Root WireGuard did not come up: ${shell.exec("tail -5 '$log'").out.joinToString(" | ")}")
        stop()
        return false
    }

    /** Stops the helper and removes interface, table and rules. */
    fun stop() {
        shell.exec(*teardownCommands().toTypedArray())
    }

    /**
     * Watchdog step: helper, interface and rules must exist together. If any
     * part is missing everything is removed first (fail-open), then restarted.
     * @return true when the tunnel is up after this call.
     */
    fun ensure(context: Context, session: Session): Boolean {
        if (isUp()) return true
        Timber.w("Root WireGuard helper, $IFACE or rules missing — restarting")
        return start(context, session)
    }
}
