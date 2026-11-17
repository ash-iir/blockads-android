package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Policy rules are written, listed and deleted over rtnetlink directly:
// Android's /system/bin/ip (iproute2 ss171113) cannot express ipproto/dport
// and does not print them, although the kernel (FRA_IP_PROTO,
// FRA_DPORT_RANGE, 4.17+) supports them.

// FRA_* attribute types (linux/fib_rules.h).
const (
	fraDst               = 1
	fraSrc               = 2
	fraIifname           = 3
	fraGoto              = 4
	fraPriority          = 6
	fraFwmark            = 10
	fraFlow              = 11
	fraTunID             = 12
	fraSuppressIfgroup   = 13
	fraSuppressPrefixlen = 14
	fraTable             = 15
	fraFwmask            = 16
	fraOifname           = 17
	fraPad               = 18
	fraL3mdev            = 19
	fraUIDRange          = 20
	fraProtocol          = 21
	fraIPProto           = 22
	fraSportRange        = 23
	fraDportRange        = 24

	fibRuleUnresolved = 0x4
	fibRuleHdrLen     = 12
)

var ne = binary.NativeEndian

// KRule is a rule as the kernel dumps it.
type KRule struct {
	Family  uint8
	Pref    int
	Action  uint8
	Table   int
	Goto    int
	Mark    uint32
	Mask    uint32
	HasUID  bool
	UID     [2]uint32
	IPProto uint8
	Dport   *[2]uint16
	// Foreign: carries something the helper never sets (src/dst, tos,
	// invert, iif/oif, sport, tun id, l3mdev, suppress_*, unknown attrs).
	Foreign bool
	// Raw fib_rule_hdr + attributes, echoed back for an exact delete.
	Raw []byte
}

func (r KRule) String() string {
	s := RuleSpec{V6: r.Family == unix.AF_INET6, Pref: r.Pref, Action: r.Action, Table: r.Table, Goto: r.Goto,
		Mark: r.Mark, Mask: r.Mask, HasUID: r.HasUID, UIDStart: r.UID[0], UIDEnd: r.UID[1], IPProto: r.IPProto}
	if r.Dport != nil {
		s.Dport = r.Dport[0]
	}
	out := s.AddCmd().String()
	if r.Dport != nil && r.Dport[0] != r.Dport[1] {
		out += fmt.Sprintf(" (dport %d-%d)", r.Dport[0], r.Dport[1])
	}
	if r.Foreign {
		out += " (+foreign attrs)"
	}
	return out
}

func family(v6 bool) uint8 {
	if v6 {
		return unix.AF_INET6
	}
	return unix.AF_INET
}

func appendAttr(b []byte, typ uint16, data []byte) []byte {
	l := 4 + len(data)
	var h [4]byte
	ne.PutUint16(h[0:2], uint16(l))
	ne.PutUint16(h[2:4], typ)
	b = append(b, h[:]...)
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func u32(v uint32) []byte { b := make([]byte, 4); ne.PutUint32(b, v); return b }

// EncodeRule builds the RTM_NEWRULE/RTM_DELRULE body (fib_rule_hdr + attrs)
// for a spec, with every attribute set so a delete matches exactly.
func EncodeRule(r RuleSpec) []byte {
	b := make([]byte, fibRuleHdrLen)
	b[0] = family(r.V6)
	if r.Action == ActTable && r.Table < 256 {
		b[4] = uint8(r.Table)
	}
	b[7] = r.Action
	b = appendAttr(b, fraPriority, u32(uint32(r.Pref)))
	if r.Action == ActTable {
		b = appendAttr(b, fraTable, u32(uint32(r.Table)))
	}
	if r.Action == ActGoto {
		b = appendAttr(b, fraGoto, u32(uint32(r.Goto)))
	}
	if r.Mask != 0 {
		b = appendAttr(b, fraFwmark, u32(r.Mark))
		b = appendAttr(b, fraFwmask, u32(r.Mask))
	}
	if r.HasUID {
		d := make([]byte, 8)
		ne.PutUint32(d[0:4], r.UIDStart)
		ne.PutUint32(d[4:8], r.UIDEnd)
		b = appendAttr(b, fraUIDRange, d)
	}
	if r.IPProto != 0 {
		b = appendAttr(b, fraIPProto, []byte{r.IPProto})
	}
	if r.Dport != 0 {
		d := make([]byte, 4)
		ne.PutUint16(d[0:2], r.Dport)
		ne.PutUint16(d[2:4], r.Dport)
		b = appendAttr(b, fraDportRange, d)
	}
	return b
}

// ParseRule decodes one RTM_NEWRULE body from a dump.
func ParseRule(m []byte) (KRule, error) {
	if len(m) < fibRuleHdrLen {
		return KRule{}, errors.New("short fib_rule_hdr")
	}
	r := KRule{Family: m[0], Action: m[7], Table: int(m[4]), Goto: -1, Raw: append([]byte(nil), m...)}
	dstLen, srcLen, tos, flags := m[1], m[2], m[3], ne.Uint32(m[8:12])
	if dstLen != 0 || srcLen != 0 || tos != 0 || flags&^fibRuleUnresolved != 0 {
		r.Foreign = true
	}
	for a := m[fibRuleHdrLen:]; len(a) >= 4; {
		l := int(ne.Uint16(a[0:2]))
		typ := ne.Uint16(a[2:4]) & 0x3fff // strip NLA_F_NESTED / NLA_F_NET_BYTEORDER
		if l < 4 || l > len(a) {
			return r, errors.New("bad attribute length")
		}
		d := a[4:l]
		need := func(n int) bool {
			if len(d) < n {
				r.Foreign = true
				return false
			}
			return true
		}
		switch typ {
		case fraPriority:
			if need(4) {
				r.Pref = int(ne.Uint32(d))
			}
		case fraTable:
			if need(4) {
				r.Table = int(ne.Uint32(d))
			}
		case fraGoto:
			if need(4) {
				r.Goto = int(ne.Uint32(d))
			}
		case fraFwmark:
			if need(4) {
				r.Mark = ne.Uint32(d)
			}
		case fraFwmask:
			if need(4) {
				r.Mask = ne.Uint32(d)
			}
		case fraUIDRange:
			if need(8) {
				r.HasUID = true
				r.UID = [2]uint32{ne.Uint32(d[0:4]), ne.Uint32(d[4:8])}
			}
		case fraIPProto:
			if need(1) {
				r.IPProto = d[0]
			}
		case fraDportRange:
			if need(4) {
				r.Dport = &[2]uint16{ne.Uint16(d[0:2]), ne.Uint16(d[2:4])}
			}
		case fraSuppressPrefixlen, fraSuppressIfgroup:
			// Dumped always; -1 means unset.
			if need(4) && ne.Uint32(d) != 0xffffffff {
				r.Foreign = true
			}
		case fraProtocol, fraPad:
			// Who installed it (boot/kernel/...): not a selector.
		case fraL3mdev:
			if need(1) && d[0] != 0 {
				r.Foreign = true
			}
		default: // dst, src, iif/oif, flow, tun id, sport, anything newer
			r.Foreign = true
		}
		if nlaAlign(l) >= len(a) {
			break
		}
		a = a[nlaAlign(l):]
	}
	return r, nil
}

func nlaAlign(l int) int { return (l + 3) &^ 3 }

func ruleRequest(msgType uint16, body []byte, flags int) error {
	req := nl.NewNetlinkRequest(int(msgType), flags|unix.NLM_F_ACK)
	req.AddRawData(body)
	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// nlRuleAdd installs a rule (fails with EEXIST when an identical one exists).
func nlRuleAdd(r RuleSpec) error {
	return ruleRequest(unix.RTM_NEWRULE, EncodeRule(r), unix.NLM_F_CREATE|unix.NLM_F_EXCL)
}

// nlRuleDel deletes the first rule matching every attribute of r.
func nlRuleDel(r RuleSpec) error {
	return ruleRequest(unix.RTM_DELRULE, EncodeRule(r), 0)
}

// nlRuleDelRaw echoes a dumped rule back as a delete (what `ip rule flush` does).
func nlRuleDelRaw(k KRule) error {
	return ruleRequest(unix.RTM_DELRULE, k.Raw, 0)
}

// nlRuleList dumps the rules of one family.
func nlRuleList(v6 bool) ([]KRule, error) {
	req := nl.NewNetlinkRequest(unix.RTM_GETRULE, unix.NLM_F_DUMP)
	hdr := make([]byte, fibRuleHdrLen)
	hdr[0] = family(v6)
	req.AddRawData(hdr)
	msgs, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWRULE)
	if err != nil && !errors.Is(err, nl.ErrDumpInterrupted) {
		return nil, err
	}
	var out []KRule
	for _, m := range msgs {
		k, perr := ParseRule(m)
		if perr != nil {
			k.Foreign = true
		}
		if k.Family != family(v6) {
			continue
		}
		out = append(out, k)
	}
	if err != nil { // interrupted dump: caller may retry
		return out, err
	}
	return out, nil
}

// FindRule reports whether a rule matching the spec (all attributes) exists.
func FindRule(rs []KRule, s RuleSpec) bool {
	for _, k := range rs {
		if k.Foreign || k.Family != family(s.V6) || k.Pref != s.Pref || k.Action != s.Action {
			continue
		}
		if s.Action == ActTable && k.Table != s.Table || s.Action == ActGoto && k.Goto != s.Goto {
			continue
		}
		if k.Mark != s.Mark || k.Mask != s.Mask || k.HasUID != s.HasUID || k.IPProto != s.IPProto {
			continue
		}
		if s.HasUID && (k.UID[0] != s.UIDStart || k.UID[1] != s.UIDEnd) {
			continue
		}
		if (s.Dport == 0) != (k.Dport == nil) || s.Dport != 0 && (k.Dport[0] != s.Dport || k.Dport[1] != s.Dport) {
			continue
		}
		return true
	}
	return false
}

// ── links, addresses, routes (vishvananda/netlink) ─────────────────

func nlLinkAddWireguard(ifn string) error {
	return netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: ifn}})
}

func nlLinkSetup(p Plan) error {
	l, err := netlink.LinkByName(p.Interface)
	if err != nil {
		return err
	}
	for _, a := range p.Addrs {
		ipn := &net.IPNet{IP: net.IP(a.Addr().AsSlice()), Mask: net.CIDRMask(a.Bits(), a.Addr().BitLen())}
		if err := netlink.AddrReplace(l, &netlink.Addr{IPNet: ipn}); err != nil {
			return fmt.Errorf("addr %s: %w", a, err)
		}
	}
	if err := netlink.LinkSetMTU(l, p.MTU); err != nil {
		return fmt.Errorf("mtu: %w", err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return fmt.Errorf("up: %w", err)
	}
	return nil
}

func prefixNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(p.Masked().Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func nlRouteReplace(r RouteSpec) error {
	rt := &netlink.Route{Dst: prefixNet(r.Dst), Table: r.Table, Family: int(family(r.V6)), Priority: int(r.Metric)}
	switch r.Kind {
	case RouteDev:
		l, err := netlink.LinkByName(r.Dev)
		if err != nil {
			return err
		}
		rt.LinkIndex = l.Attrs().Index
		rt.Scope = netlink.SCOPE_LINK
	case RouteUnreachable:
		rt.Type = unix.RTN_UNREACHABLE
	case RouteThrow:
		rt.Type = unix.RTN_THROW
	}
	return netlink.RouteReplace(rt)
}

// nlRouteFlushTable deletes every route of one family in table (dump + echo,
// like `ip route flush table N`).
func nlRouteFlushTable(v6 bool, table int) error {
	req := nl.NewNetlinkRequest(unix.RTM_GETROUTE, unix.NLM_F_DUMP)
	hdr := make([]byte, unix.SizeofRtMsg)
	hdr[0] = family(v6)
	req.AddRawData(hdr)
	msgs, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWROUTE)
	if err != nil && !errors.Is(err, nl.ErrDumpInterrupted) {
		return err
	}
	var firstErr error
	for _, m := range msgs {
		if len(m) < unix.SizeofRtMsg || m[0] != family(v6) {
			continue
		}
		t := int(m[4])
		for a := m[unix.SizeofRtMsg:]; len(a) >= 4; {
			l := int(ne.Uint16(a[0:2]))
			if l < 4 || l > len(a) {
				break
			}
			if ne.Uint16(a[2:4]) == unix.RTA_TABLE && l >= 8 {
				t = int(ne.Uint32(a[4:8]))
			}
			if nlaAlign(l) >= len(a) {
				break
			}
			a = a[nlaAlign(l):]
		}
		if t != table {
			continue
		}
		if e := ruleRequest(unix.RTM_DELROUTE, m, 0); e != nil && firstErr == nil && !errors.Is(e, unix.ESRCH) {
			firstErr = e
		}
	}
	if firstErr == nil && err != nil {
		firstErr = err
	}
	return firstErr
}

func nlLinkDel(ifn string) error {
	l, err := netlink.LinkByName(ifn)
	if err != nil {
		return err
	}
	return netlink.LinkDel(l)
}
