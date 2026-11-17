package app.pwhs.blockads.ui.component

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.pwhs.blockads.R
import app.pwhs.blockads.data.entities.WireGuardProfile
import app.pwhs.blockads.service.RootWireGuard
import app.pwhs.blockads.service.RootWireGuardStatus
import app.pwhs.blockads.ui.theme.DangerRed
import app.pwhs.blockads.ui.theme.TextSecondary

/**
 * Root mode only: WireGuard through kernel WireGuard + uid routing (no VpnService).
 * Shared by the Home routing sheet and Settings → Proxy & VPN so both drive the
 * same prefs (see RootWireGuardSettings).
 *
 * @param rootModeActive false shows a "switch to Root Proxy mode" note; the
 *   switch can then only be turned off.
 * @param status live helper status; null hides the status block.
 * @param nowMs clock for status ages (recomposed by the caller's poll).
 */
@Composable
fun RootWireGuardOptions(
    activeWgProfile: WireGuardProfile?,
    enabled: Boolean,
    killSwitch: Boolean,
    onEnabledChange: (Boolean) -> Unit,
    onKillSwitchChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
    title: String = stringResource(R.string.root_wg_title),
    rootModeActive: Boolean = true,
    status: RootWireGuardStatus? = null,
    showStatus: Boolean = false,
    nowMs: Long = System.currentTimeMillis(),
) {
    val unsupported = activeWgProfile?.let { RootWireGuard.unsupportedReason(it.config) }
    val profileText = when {
        activeWgProfile == null -> stringResource(R.string.root_wg_no_profile)
        unsupported != null -> stringResource(R.string.root_wg_amnezia)
        else -> stringResource(R.string.root_wg_profile, activeWgProfile.name)
    }
    val usable = activeWgProfile != null && unsupported == null
    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.25f))
            .padding(horizontal = 14.dp, vertical = 8.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = stringResource(R.string.root_wg_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                )
                Text(
                    text = profileText,
                    style = MaterialTheme.typography.labelSmall,
                    color = if (usable) MaterialTheme.colorScheme.primary else DangerRed,
                )
            }
            Switch(
                checked = enabled,
                onCheckedChange = onEnabledChange,
                enabled = (usable && rootModeActive) || enabled,
            )
        }
        if (!rootModeActive) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.root_wg_needs_root_mode),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.tertiary,
            )
        }
        if (enabled) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.root_wg_kill_switch),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        text = stringResource(R.string.root_wg_kill_switch_desc),
                        style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary,
                    )
                }
                Switch(checked = killSwitch, onCheckedChange = onKillSwitchChange)
            }
            if (showStatus && rootModeActive) {
                Spacer(modifier = Modifier.height(4.dp))
                RootWireGuardStatusBlock(status = status, nowMs = nowMs)
            }
        }
    }
}

@Composable
private fun RootWireGuardStatusBlock(status: RootWireGuardStatus?, nowMs: Long) {
    val connected = status?.isConnected(nowMs) == true
    val fresh = status?.isFresh(nowMs) == true
    val dotColor = when {
        connected -> Color(0xFF16A34A)
        fresh -> Color(0xFFF59E0B)
        else -> DangerRed
    }
    val headline = when {
        connected -> stringResource(R.string.root_wg_status_connected)
        fresh -> stringResource(R.string.root_wg_status_no_handshake)
        else -> stringResource(R.string.root_wg_status_down)
    }
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(dotColor)
            )
            Text(
                text = headline,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
        if (status != null && fresh) {
            val age = status.handshakeAgeSec(nowMs)
            Text(
                text = if (age != null) {
                    stringResource(R.string.root_wg_status_handshake, formatAge(age))
                } else {
                    stringResource(R.string.root_wg_status_handshake_never)
                },
                style = MaterialTheme.typography.bodySmall,
                color = TextSecondary,
            )
            status.endpoint?.let {
                Text(
                    text = stringResource(R.string.root_wg_status_endpoint, it),
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                )
            }
            Text(
                text = stringResource(
                    R.string.root_wg_status_traffic,
                    RootWireGuardStatus.formatBytes(status.rxBytes),
                    RootWireGuardStatus.formatBytes(status.txBytes),
                ),
                style = MaterialTheme.typography.bodySmall,
                color = TextSecondary,
            )
        }
    }
}

private fun formatAge(sec: Long): String = when {
    sec < 60 -> "${sec}s"
    sec < 3600 -> "${sec / 60}m ${sec % 60}s"
    else -> "${sec / 3600}h ${(sec % 3600) / 60}m"
}
