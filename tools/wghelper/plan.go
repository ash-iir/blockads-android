package main

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Cmd is one `ip` invocation (arguments only, without the binary). The
// helper changes routing state over netlink; Cmd is the human-readable
// equivalent (`plan`, logs) and the fallback when a netlink call fails.
type Cmd []string

func (c Cmd) String() string { return "ip " + strings.Join(c, " ") }

func ipcmd(s string) Cmd { return Cmd(strings.Fields(s)) }

// Rule actions (FR_ACT_* in linux/fib_rules.h).
const (
	ActTable uint8 = 1
	ActGoto  uint8 = 2
	ActNop   uint8 = 3
)

// RuleSpec is one policy routing rule, exactly as the helper installs it.
type RuleSpec struct {
	V6       bool
	Pref     int
	Action   uint8
	Table    int // ActTable
	Goto     int // ActGoto
	Mark     uint32
	Mask     uint32 // Mark/Mask apply when Mask != 0
	HasUID   bool
	UIDStart uint32
	UIDEnd   uint32
	IPProto  uint8  // 0 = any
	Dport    uint16 // 0 = any (single port, start = end)
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	}
	return strconv.Itoa(int(p))
}

func (r RuleSpec) selectors() string {
	var b strings.Builder
	if r.Mask != 0 {
		fmt.Fprintf(&b, " fwmark 0x%x/0x%x", r.Mark, r.Mask)
	}
	if r.HasUID {
		fmt.Fprintf(&b, " uidrange %d-%d", r.UIDStart, r.UIDEnd)
	}
	if r.IPProto != 0 {
		b.WriteString(" ipproto " + protoName(r.IPProto))
	}
	if r.Dport != 0 {
		fmt.Fprintf(&b, " dport %d", r.Dport)
	}
	return b.String()
}

func (r RuleSpec) action() string {
	switch r.Action {
	case ActTable:
		return "lookup " + strconv.Itoa(r.Table)
	case ActGoto:
		return "goto " + strconv.Itoa(r.Goto)
	case ActNop:
		return "nop"
	}
	return fmt.Sprintf("action(%d)", r.Action)
}

func (r RuleSpec) cmd(verb string) Cmd {
	return ipcmd(fmt.Sprintf("%s rule %s pref %d%s %s", fam(r.V6), verb, r.Pref, r.selectors(), r.action()))
}

// AddCmd / DelCmd are the `ip` equivalents (exact match on every attribute).
func (r RuleSpec) AddCmd() Cmd { return r.cmd("add") }
func (r RuleSpec) DelCmd() Cmd { return r.cmd("del") }

// Route kinds.
const (
	RouteDev = iota
	RouteUnreachable
	RouteThrow
)

// RouteSpec is one route in the private table.
type RouteSpec struct {
	V6     bool
	Kind   int
	Dst    netip.Prefix
	Dev    string // RouteDev
	Metric uint32
	Table  int
}

func (r RouteSpec) Cmd() Cmd {
	s := fam(r.V6) + " route replace "
	switch r.Kind {
	case RouteUnreachable:
		s += "unreachable "
	case RouteThrow:
		s += "throw "
	}
	s += prefixArg(r.Dst)
	if r.Kind == RouteDev {
		s += " dev " + r.Dev
	}
	if r.Metric != 0 {
		s += " metric " + strconv.FormatUint(uint64(r.Metric), 10)
	}
	return ipcmd(s + " table " + strconv.Itoa(r.Table))
}

// KillSwitchMetric: the kill switch's unreachable routes sit behind the
// tunnel routes (metric 0). Fits a signed 32-bit int (netlink.Route.Priority
// on armeabi-v7a/x86).
const KillSwitchMetric = 0x7fffffff

// Plan is everything the helper does to the routing state, in order.
// It is pure (no system access) so it can be unit tested.
type Plan struct {
	Interface string
	MTU       int
	// Addresses on the interface (after `link add` and the wgctrl configuration).
	Addrs []netip.Prefix
	// Routes in the private table.
	Routes []RouteSpec
	// Rule that routes the helper's handshake probe (mark ProbeMark) into the table.
	Probe []RuleSpec
	// Rules that route apps into the table. Installed last, after the handshake.
	Rules []RuleSpec
}

// LinkCmds: addresses, then mtu + up.
func (p Plan) LinkCmds() []Cmd {
	var out []Cmd
	for _, a := range p.Addrs {
		out = append(out, ipcmd(fmt.Sprintf("%s addr add %s dev %s", fam(a.Addr().Is6()), a.String(), p.Interface)))
	}
	return append(out, ipcmd(fmt.Sprintf("link set dev %s mtu %d up", p.Interface, p.MTU)))
}

func RouteCmds(rs []RouteSpec) []Cmd {
	out := make([]Cmd, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Cmd())
	}
	return out
}

func RuleAddCmds(rs []RuleSpec) []Cmd {
	out := make([]Cmd, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.AddCmd())
	}
	return out
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

func defaultRoute(v6 bool) netip.Prefix {
	if v6 {
		return netip.MustParsePrefix("::/0")
	}
	return netip.MustParsePrefix("0.0.0.0/0")
}

// BuildPlan turns a validated config into routing state.
func BuildPlan(c *Config) Plan {
	p := Plan{Interface: c.Interface, MTU: c.MTU, Addrs: append([]netip.Prefix(nil), c.addrs...)}
	ifn := c.Interface
	tbl := c.Table

	full := fullTunnel(c.allowed(false)) || fullTunnel(c.allowed(true))
	for _, v6 := range []bool{false, true} {
		allowed := c.allowed(v6)
		if !c.hasFamily(v6) {
			// No tunnel address for this family. With a full tunnel, block it
			// instead of letting it leak around the tunnel; apps fall back to
			// the other family (Happy Eyeballs).
			if full {
				p.Routes = append(p.Routes, RouteSpec{V6: v6, Kind: RouteUnreachable, Dst: defaultRoute(v6), Table: tbl})
			}
			continue
		}
		for _, a := range allowed {
			p.Routes = append(p.Routes, RouteSpec{V6: v6, Kind: RouteDev, Dst: a, Dev: ifn, Table: tbl})
		}
		// The tunnel's own subnet stays in the tunnel even when it is inside a
		// LAN range that exclude-LAN throws out (e.g. 10.66.66.0/24).
		for _, a := range c.addrs {
			if a.Addr().Is6() == v6 && a.Bits() < a.Addr().BitLen() {
				p.Routes = append(p.Routes, RouteSpec{V6: v6, Kind: RouteDev, Dst: a.Masked(), Dev: ifn, Table: tbl})
			}
		}
		if c.KillSwitch {
			// Stays in the table while the feature is on: if bawg0 disappears
			// (its routes go with it), routed apps hit this instead of leaking.
			for _, a := range allowed {
				p.Routes = append(p.Routes, RouteSpec{V6: v6, Kind: RouteUnreachable, Dst: a, Metric: KillSwitchMetric, Table: tbl})
			}
		}
	}
	if c.ExcludeLAN {
		for _, s := range lanV4 {
			p.Routes = append(p.Routes, RouteSpec{Kind: RouteThrow, Dst: netip.MustParsePrefix(s), Table: tbl})
		}
		for _, s := range lanV6 {
			p.Routes = append(p.Routes, RouteSpec{V6: true, Kind: RouteThrow, Dst: netip.MustParsePrefix(s), Table: tbl})
		}
	}

	for _, v6 := range []bool{false, true} {
		p.Probe = append(p.Probe, RuleSpec{V6: v6, Pref: PrefProbe, Action: ActTable, Table: tbl, Mark: ProbeMark, Mask: ProbeMark})

		// Order matters: the nop target first, then the DNS exemption, then
		// BlockAds, then the app ranges last so routing only flips once
		// everything else is in place.
		p.Rules = append(p.Rules, RuleSpec{V6: v6, Pref: PrefLast, Action: ActNop})
		if c.AppUID != 0 {
			p.Rules = append(p.Rules, RuleSpec{V6: v6, Pref: PrefApp, Action: ActTable, Table: tbl,
				HasUID: true, UIDStart: uint32(c.AppUID), UIDEnd: uint32(c.AppUID)})
		}
		// App DNS never depends on the tunnel. netd chowns its DNS sockets to
		// the asking app's uid, so without this the uid rules would catch it:
		// IPv4 DNS is REDIRECTed to the engine anyway and IPv6 DNS is TPROXYed
		// (pref 9999), but a tunnel without IPv6 would make IPv6 DNS
		// unreachable — and once netd has marked the IPv4 servers broken that
		// is a full DNS outage (FINDINGS 2026-11-17 03:28).
		// Installed over netlink: old iproute2 (ss171113, Android) has no
		// `ipproto`/`dport` keywords although the kernel supports them.
		p.Rules = append(p.Rules, RuleSpec{V6: v6, Pref: PrefDNSUDP, Action: ActGoto, Goto: PrefLast, IPProto: 17, Dport: 53})
		p.Rules = append(p.Rules, RuleSpec{V6: v6, Pref: PrefDNSTCP, Action: ActGoto, Goto: PrefLast, IPProto: 6, Dport: 53})
		for i, r := range c.UIDRanges {
			p.Rules = append(p.Rules, RuleSpec{V6: v6, Pref: PrefRangesFirst + i, Action: ActTable, Table: tbl,
				HasUID: true, UIDStart: uint32(r.Start), UIDEnd: uint32(r.End)})
		}
	}
	return p
}

// TeardownRules is the exact reverse of the plan's rules: app rules first
// (traffic goes back to normal routing at once), then the probe rule. The
// table and the interface go after that (cleanupAll).
func (p Plan) TeardownRules() []RuleSpec {
	var out []RuleSpec
	for i := len(p.Rules) - 1; i >= 0; i-- {
		out = append(out, p.Rules[i])
	}
	for i := len(p.Probe) - 1; i >= 0; i-- {
		out = append(out, p.Probe[i])
	}
	return out
}

func CleanupTail(table int, ifn string) []Cmd {
	t := strconv.Itoa(table)
	return []Cmd{
		ipcmd("-4 route flush table " + t),
		ipcmd("-6 route flush table " + t),
		ipcmd("link del dev " + ifn),
	}
}

// Selftest prefs: a udp dport 53 goto rule and its nop target, inside our
// range but outside the prefs a running tunnel uses.
const (
	PrefSelftestGoto = 10097
	PrefSelftestNop  = 10098
)

// Owned reports whether a kernel rule belongs to us: pref 10000–10099 AND
// one of our shapes (lookup <table> / goto 10099 / nop at 10099, or the
// selftest pair), with no attribute we never set. Never by pref alone.
func Owned(r KRule, table int) bool {
	if r.Foreign || r.Pref < PrefFirst || r.Pref > PrefLast {
		return false
	}
	noSel := r.Mask == 0 && r.Mark == 0 && !r.HasUID && r.IPProto == 0 && r.Dport == nil
	switch r.Action {
	case ActTable:
		return r.Table == table
	case ActGoto:
		if r.Goto == PrefLast {
			return true
		}
		return r.Pref == PrefSelftestGoto && r.Goto == PrefSelftestNop &&
			(r.IPProto == 17 || r.IPProto == 6) && r.Dport != nil && r.Dport[0] == 53 && r.Dport[1] == 53
	case ActNop:
		return noSel && (r.Pref == PrefLast || r.Pref == PrefSelftestNop)
	}
	return false
}

// OwnedOrdered returns the owned rules in delete order: app ranges first
// (highest pref), nop targets last.
func OwnedOrdered(rs []KRule, table int) []KRule {
	var out []KRule
	for _, r := range rs {
		if Owned(r, table) {
			out = append(out, r)
		}
	}
	isNop := func(r KRule) bool { return r.Action == ActNop }
	for i := 1; i < len(out); i++ { // insertion sort, stable
		for j := i; j > 0; j-- {
			a, b := out[j-1], out[j]
			swap := false
			if isNop(a) != isNop(b) {
				swap = isNop(a)
			} else {
				swap = a.Pref < b.Pref
			}
			if !swap {
				break
			}
			out[j-1], out[j] = b, a
		}
	}
	return out
}
