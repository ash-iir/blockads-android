package main

import (
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// rejectAfter is WireGuard's REJECT_AFTER_TIME: a session older than this
// cannot carry data any more.
const rejectAfter = 180 * time.Second

// monitor decides when a tunnel is dead, so that (kill switch off) the
// helper fails open instead of blackholing every routed app.
//
// Dead = we keep transmitting (data or handshake initiations) but have
// received nothing for DeadAfterSec, and the last handshake is older than
// REJECT_AFTER_TIME (or never happened). An idle healthy tunnel sends
// nothing, and one with keepalive re-handshakes every 2 min, so neither trips it.
type monitor struct {
	disabled  bool
	deadAfter time.Duration
	lastRx    uint64
	rxAt      time.Time
	txAtRx    uint64
	started   bool
}

func newMonitor(c *Config) *monitor {
	return &monitor{
		disabled:  c.KillSwitch || c.DeadAfterSec < 0,
		deadAfter: time.Duration(c.DeadAfterSec) * time.Second,
	}
}

func totals(d *wgtypes.Device) (rx, tx uint64, hs time.Time) {
	for _, p := range d.Peers {
		rx += uint64(p.ReceiveBytes)
		tx += uint64(p.TransmitBytes)
		if p.LastHandshakeTime.After(hs) {
			hs = p.LastHandshakeTime
		}
	}
	return
}

// observe returns a non-empty reason when the tunnel is considered dead.
func (m *monitor) observe(d *wgtypes.Device, now time.Time) string {
	if m.disabled {
		return ""
	}
	rx, tx, hs := totals(d)
	if !m.started || rx != m.lastRx {
		m.started = true
		m.lastRx, m.rxAt, m.txAtRx = rx, now, tx
		return ""
	}
	if tx <= m.txAtRx || now.Sub(m.rxAt) < m.deadAfter {
		return ""
	}
	if !hs.IsZero() && now.Sub(hs) < rejectAfter {
		return ""
	}
	return "sending but nothing received for " + now.Sub(m.rxAt).Round(time.Second).String() +
		", last handshake " + hsAge(hs, now)
}

func hsAge(hs, now time.Time) string {
	if hs.IsZero() {
		return "never"
	}
	return now.Sub(hs).Round(time.Second).String() + " ago"
}
