package main

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Cmd is one `ip` invocation (arguments only, without the binary).
type Cmd []string

func (c Cmd) String() string { return "ip " + strings.Join(c, " ") }

func ipcmd(s string) Cmd { return Cmd(strings.Fields(s)) }

// Plan is everything the helper does to the routing state, in order.
// It is pure (no system access) so it can be unit tested.
type Plan struct {
	// After `ip link add <if> type wireguard` and the wgctrl configuration.
	Link []Cmd
	// Routes in the private table.
	Routes []Cmd
	// Rule that routes the helper's handshake probe (mark ProbeMark) into the table.
	Probe []Cmd
	// Rules that route apps into the table. Installed last, after the handshake.
	Rules []Cmd
}

var lanV4 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
var lanV6 = []string{"fe80::/10", "fc00::/7"}

func fam(v6 bool) string {
	if v6 {
		return "-6"
	}
	return "-4"
}

func prefixArg(p netip.Prefix) string {
	if p.Bits() == 0 {
		return "default"
	}
	return p.String()
}

// BuildPlan turns a validated config into ip commands.
func BuildPlan(c *Config) Plan {
	var p Plan
	ifn := c.Interface
	tbl := strconv.Itoa(c.Table)

	for _, a := range c.addrs {
		p.Link = append(p.Link, ipcmd(fmt.Sprintf("%s addr add %s dev %s", fam(a.Addr().Is6()), a.String(), ifn)))
	}
	p.Link = append(p.Link, ipcmd(fmt.Sprintf("link set dev %s mtu %d up", ifn, c.MTU)))

	full := fullTunnel(c.allowed(false)) || fullTunnel(c.allowed(true))
	for _, v6 := range []bool{false, true} {
		f := fam(v6)
		allowed := c.allowed(v6)
		if !c.hasFamily(v6) {
			// No tunnel address for this family. With a full tunnel, block it
			// instead of letting it leak around the tunnel; apps fall back to
			// the other family (Happy Eyeballs).
			if full {
				p.Routes = append(p.Routes, ipcmd(fmt.Sprintf("%s route replace unreachable default table %s", f, tbl)))
			}
			continue
		}
		for _, a := range allowed {
			p.Routes = append(p.Routes, ipcmd(fmt.Sprintf("%s route replace %s dev %s table %s", f, prefixArg(a), ifn, tbl)))
		}
		// The tunnel's own subnet stays in the tunnel even when it is inside a
		// LAN range that exclude-LAN throws out (e.g. 10.66.66.0/24).
		for _, a := range c.addrs {
			if a.Addr().Is6() == v6 && a.Bits() < a.Addr().BitLen() {
				p.Routes = append(p.Routes, ipcmd(fmt.Sprintf("%s route replace %s dev %s table %s", f, a.Masked().String(), ifn, tbl)))
			}
		}
		if c.KillSwitch {
			// Stays in the table while the feature is on: if bawg0 disappears
			// (its routes go with it), routed apps hit this instead of leaking.
			for _, a := range allowed {
				p.Routes = append(p.Routes, ipcmd(fmt.Sprintf("%s route replace unreachable %s metric 4294967295 table %s", f, prefixArg(a), tbl)))
			}
		}
	}
	if c.ExcludeLAN {
		for _, s := range lanV4 {
			p.Routes = append(p.Routes, ipcmd(fmt.Sprintf("-4 route replace throw %s table %s", s, tbl)))
		}
		for _, s := range lanV6 {
			p.Routes = append(p.Routes, ipcmd(fmt.Sprintf("-6 route replace throw %s table %s", s, tbl)))
		}
	}

	for _, v6 := range []bool{false, true} {
		f := fam(v6)
		p.Probe = append(p.Probe, ipcmd(fmt.Sprintf("%s rule add pref %d fwmark 0x%x/0x%x lookup %s", f, PrefProbe, ProbeMark, ProbeMark, tbl)))

		// Order matters: the nop target first, then the DNS exemption, then
		// BlockAds, then the app ranges last so routing only flips once
		// everything else is in place.
		p.Rules = append(p.Rules, ipcmd(fmt.Sprintf("%s rule add pref %d nop", f, PrefLast)))
		if c.AppUID != 0 {
			p.Rules = append(p.Rules, ipcmd(fmt.Sprintf("%s rule add pref %d uidrange %d-%d lookup %s", f, PrefApp, c.AppUID, c.AppUID, tbl)))
		}
		// App DNS never depends on the tunnel. netd chowns its DNS sockets to
		// the asking app's uid, so without this the uid rules would catch it:
		// IPv4 DNS is REDIRECTed to the engine anyway and IPv6 DNS is TPROXYed
		// (pref 9999), but a tunnel without IPv6 would make IPv6 DNS
		// unreachable — and once netd has marked the IPv4 servers broken that
		// is a full DNS outage (FINDINGS 2026-11-17 03:28).
		p.Rules = append(p.Rules, ipcmd(fmt.Sprintf("%s rule add pref %d ipproto udp dport 53 goto %d", f, PrefDNSUDP, PrefLast)))
		p.Rules = append(p.Rules, ipcmd(fmt.Sprintf("%s rule add pref %d ipproto tcp dport 53 goto %d", f, PrefDNSTCP, PrefLast)))
		for i, r := range c.UIDRanges {
			p.Rules = append(p.Rules, ipcmd(fmt.Sprintf("%s rule add pref %d uidrange %d-%d lookup %s", f, PrefRangesFirst+i, r.Start, r.End, tbl)))
		}
	}
	return p
}

// UndoRule turns "rule add ..." into "rule del ..." (exact match).
func UndoRule(c Cmd) Cmd {
	out := append(Cmd(nil), c...)
	for i, a := range out {
		if a == "add" {
			out[i] = "del"
			break
		}
	}
	return out
}

// Teardown is the exact reverse of a plan: app rules first (traffic goes
// back to normal routing at once), then the probe rule, then the table and
// the interface.
func (p Plan) Teardown(c *Config) []Cmd {
	var out []Cmd
	for i := len(p.Rules) - 1; i >= 0; i-- {
		out = append(out, UndoRule(p.Rules[i]))
	}
	for i := len(p.Probe) - 1; i >= 0; i-- {
		out = append(out, UndoRule(p.Probe[i]))
	}
	return append(out, CleanupTail(c.Table, c.Interface)...)
}

func CleanupTail(table int, ifn string) []Cmd {
	t := strconv.Itoa(table)
	return []Cmd{
		ipcmd("-4 route flush table " + t),
		ipcmd("-6 route flush table " + t),
		ipcmd("link del dev " + ifn),
	}
}

// RuleLine is one parsed line of `ip rule show`.
type RuleLine struct {
	Pref int
	Rest string
}

func ParseRules(out string) []RuleLine {
	var rs []RuleLine
	for _, l := range strings.Split(out, "\n") {
		i := strings.IndexByte(l, ':')
		if i <= 0 {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(l[:i]))
		if err != nil {
			continue
		}
		rs = append(rs, RuleLine{Pref: n, Rest: strings.TrimSpace(l[i+1:])})
	}
	return rs
}

// OwnedRuleDeletes finds rules that belong to us in `ip rule show` output
// (pref 10000-10099 AND our table / our goto / our nop) and returns exact
// delete commands. Rules of anyone else at the same prefs are left alone.
func OwnedRuleDeletes(f string, out string, table int) []Cmd {
	var del []Cmd
	lookup := "lookup " + strconv.Itoa(table)
	gotoLast := "goto " + strconv.Itoa(PrefLast)
	for _, r := range ParseRules(out) {
		if r.Pref < PrefFirst || r.Pref > PrefLast {
			continue
		}
		rest := strings.TrimSpace(strings.ReplaceAll(r.Rest, "[unresolved]", ""))
		fields := strings.Fields(rest)
		own := strings.HasSuffix(rest, lookup) || strings.HasSuffix(rest, gotoLast) ||
			(r.Pref == PrefLast && len(fields) > 0 && fields[len(fields)-1] == "nop")
		if !own {
			continue
		}
		cmd := Cmd{f, "rule", "del", "pref", strconv.Itoa(r.Pref)}
		del = append(del, append(cmd, fields...))
	}
	// App ranges first (highest pref), the nop goto target last.
	sort.SliceStable(del, func(i, j int) bool {
		pi, pj := atoiSafe(del[i][4]), atoiSafe(del[j][4])
		if (pi == PrefLast) != (pj == PrefLast) {
			return pj == PrefLast
		}
		return pi > pj
	})
	return del
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
