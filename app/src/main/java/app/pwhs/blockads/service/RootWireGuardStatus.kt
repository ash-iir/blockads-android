package app.pwhs.blockads.service

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import java.io.File
import java.util.Calendar
import java.util.TimeZone

/**
 * Live state of the Root WireGuard tunnel, read from the status file the helper
 * (`libblockadswg.so up -status …`) rewrites every 10 s:
 *
 * ```
 * time=2026-11-17T10:27:56Z
 * peer=0/x2PdBG endpoint=62.182.99.141:51820 handshake=2026-11-17T10:27:46Z rx=1432332 tx=455460
 * ```
 *
 * The file outlives the helper, so a status is only "live" while `time=` is
 * recent; an old file means the helper is gone and the tunnel is down.
 */
data class RootWireGuardStatus(
    /** When the helper last wrote the file (epoch ms), null if missing/unparseable. */
    val updatedAtMs: Long?,
    val peers: List<Peer>,
) {
    data class Peer(
        val key: String,
        val endpoint: String?,
        /** Last handshake (epoch ms), null for "never". */
        val lastHandshakeMs: Long?,
        val rxBytes: Long,
        val txBytes: Long,
    )

    /** The helper wrote the file recently (it rewrites every 10 s). */
    fun isFresh(nowMs: Long): Boolean =
        updatedAtMs != null && nowMs - updatedAtMs in -FUTURE_SKEW_MS..STALE_AFTER_MS

    /** Most recent handshake over all peers. */
    val lastHandshakeMs: Long? get() = peers.mapNotNull { it.lastHandshakeMs }.maxOrNull()

    /** Seconds since the last handshake, or null when there was none. */
    fun handshakeAgeSec(nowMs: Long): Long? = lastHandshakeMs?.let { ((nowMs - it) / 1000L).coerceAtLeast(0L) }

    /**
     * Connected = helper alive and a handshake within the WireGuard reject
     * window (keys are renewed every 2 min while traffic flows; after 180 s
     * without one the session is dead).
     */
    fun isConnected(nowMs: Long): Boolean {
        if (!isFresh(nowMs)) return false
        val age = handshakeAgeSec(nowMs) ?: return false
        return age <= HANDSHAKE_DEAD_AFTER_SEC
    }

    val endpoint: String? get() = peers.firstOrNull { !it.endpoint.isNullOrBlank() }?.endpoint
    val rxBytes: Long get() = peers.sumOf { it.rxBytes }
    val txBytes: Long get() = peers.sumOf { it.txBytes }

    /** One poll of the status file: [status] is null when the file is missing. */
    data class Reading(val status: RootWireGuardStatus?, val readAtMs: Long)

    companion object {
        const val FILE_NAME = "wghelper.status"
        const val STALE_AFTER_MS = 35_000L
        private const val FUTURE_SKEW_MS = 60_000L
        const val HANDSHAKE_DEAD_AFTER_SEC = 180L
        const val POLL_INTERVAL_MS = 5_000L

        /** Parses the helper's status text; null when it has neither a time nor a peer. */
        fun parse(text: String): RootWireGuardStatus? {
            var updated: Long? = null
            val peers = mutableListOf<Peer>()
            for (raw in text.lineSequence()) {
                val line = raw.trim()
                if (line.isEmpty()) continue
                if (line.startsWith("time=")) {
                    updated = parseRfc3339(line.removePrefix("time="))
                    continue
                }
                if (!line.startsWith("peer=")) continue
                val fields = line.split(' ', '\t').filter { it.isNotEmpty() }.mapNotNull { f ->
                    val i = f.indexOf('=')
                    if (i <= 0) null else f.substring(0, i) to f.substring(i + 1)
                }.toMap()
                peers += Peer(
                    key = fields["peer"].orEmpty(),
                    endpoint = fields["endpoint"]?.takeUnless { it.isBlank() || it == "<nil>" },
                    lastHandshakeMs = fields["handshake"]?.takeUnless { it == "never" }?.let(::parseRfc3339),
                    rxBytes = fields["rx"]?.toLongOrNull() ?: 0L,
                    txBytes = fields["tx"]?.toLongOrNull() ?: 0L,
                )
            }
            if (updated == null && peers.isEmpty()) return null
            return RootWireGuardStatus(updated, peers)
        }

        private val RFC3339 = Regex(
            """^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|z|[+-]\d{2}:?\d{2})$"""
        )

        /** RFC 3339 (Go's time.RFC3339) to epoch ms; no java.time (minSdk 24). */
        internal fun parseRfc3339(value: String): Long? {
            val m = RFC3339.matchEntire(value.trim()) ?: return null
            val (y, mo, d, h, mi, s, zone) = m.destructured
            val cal = Calendar.getInstance(TimeZone.getTimeZone("UTC")).apply {
                clear()
                set(y.toInt(), mo.toInt() - 1, d.toInt(), h.toInt(), mi.toInt(), s.toInt())
            }
            var ms = cal.timeInMillis
            if (zone != "Z" && zone != "z") {
                val digits = zone.substring(1).replace(":", "")
                val offMin = digits.substring(0, 2).toInt() * 60 + digits.substring(2, 4).toInt()
                val sign = if (zone[0] == '-') -1 else 1
                ms -= sign * offMin * 60_000L
            }
            return ms
        }

        fun statusFile(context: Context): File = File(context.cacheDir, FILE_NAME)

        /** Reads the status file (world-readable, written by the root helper). */
        fun read(context: Context): RootWireGuardStatus? = runCatching {
            val f = statusFile(context)
            if (!f.canRead()) null else parse(f.readText())
        }.getOrNull()

        /**
         * Polls the status file while collected. Each emission carries its read
         * time, so an unchanged (stale) file still re-emits and ages out.
         */
        fun poll(context: Context, intervalMs: Long = POLL_INTERVAL_MS): Flow<Reading> = flow {
            while (true) {
                emit(Reading(read(context), System.currentTimeMillis()))
                delay(intervalMs)
            }
        }.flowOn(Dispatchers.IO)

        /** 1536 -> "1.5 KB". */
        fun formatBytes(bytes: Long): String {
            if (bytes < 1024) return "$bytes B"
            val units = arrayOf("KB", "MB", "GB", "TB")
            var v = bytes / 1024.0
            var i = 0
            while (v >= 1024 && i < units.size - 1) { v /= 1024; i++ }
            return if (v >= 100) "${v.toLong()} ${units[i]}" else String.format(java.util.Locale.US, "%.1f %s", v, units[i])
        }
    }
}
