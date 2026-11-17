package main

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	privKey = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	pubKey  = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
)

func baseJSON(extra string) string {
	return `{"privateKey":"` + privKey + `","addresses":["10.66.66.2/32"],
	"peers":[{"publicKey":"` + pubKey + `","endpoint":"203.0.113.5:51820","allowedIPs":["0.0.0.0/0","::/0"],"persistentKeepalive":25}],
	"uidRanges":[{"start":10000,"end":10684},{"start":10686,"end":19999}],"appUid":10682` + extra + `}`
}

func mustParse(t *testing.T, s string) *Config {
	t.Helper()
	c, err := ParseConfig([]byte(s))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

func joined(cs []Cmd) string {
	var b strings.Builder
	for _, c := range cs {
		b.WriteString(c.String())
		b.WriteByte('\n')
	}
	return b.String()
}

func TestDefaults(t *testing.T) {
	c := mustParse(t, baseJSON(""))
	if c.Interface != "bawg0" || c.MTU != 1280 || c.FwMark != 0x20000000 || c.Table != 980 {
		t.Fatalf("defaults: %+v", c)
	}
	if c.HandshakeTimeoutSec != DefaultHandshakeTO || c.DeadAfterSec != DefaultDeadAfter {
		t.Fatalf("timeouts: %d %d", c.HandshakeTimeoutSec, c.DeadAfterSec)
	}
}

func TestRejectsAmnezia(t *testing.T) {
	for _, extra := range []string{`,"jc":4`, `,"s1":15`, `,"h3":12345`, `,"i1":"<b 0xf6>"`} {
		_, err := ParseConfig([]byte(baseJSON(extra)))
		if !errors.Is(err, ErrAmnezia) {
			t.Errorf("%s: want ErrAmnezia, got %v", extra, err)
		}
	}
	// Zero values are plain WireGuard.
	mustParse(t, baseJSON(`,"jc":0,"h1":0,"i1":""`))
}

func TestRejectsBadInput(t *testing.T) {
	bad := map[string]string{
		"hostname endpoint": strings.Replace(baseJSON(""), "203.0.113.5:51820", "vpn.example.com:51820", 1),
		"short key":         strings.Replace(baseJSON(""), privKey, "abcd", 1),
		"system uid":        strings.Replace(baseJSON(""), `"start":10000`, `"start":0`, 1),
		"netd table":        baseJSON(`,"table":98`),
		"no address":        strings.Replace(baseJSON(""), `["10.66.66.2/32"]`, `[]`, 1),
		"bad allowed":       strings.Replace(baseJSON(""), `"::/0"`, `"nope"`, 1),
	}
	for name, js := range bad {
		if _, err := ParseConfig([]byte(js)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPlanV4OnlyFullTunnelBlocksV6(t *testing.T) {
	c := mustParse(t, baseJSON(""))
	p := BuildPlan(c)
	r := joined(RouteCmds(p.Routes))
	for _, want := range []string{
		"ip -4 route replace default dev bawg0 table 980",
		"ip -6 route replace unreachable default table 980",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("missing %q in\n%s", want, r)
		}
	}
	if strings.Contains(r, "-6 route replace default dev") {
		t.Errorf("v6 routed without a v6 address:\n%s", r)
	}
	l := joined(p.LinkCmds())
	if !strings.Contains(l, "ip -4 addr add 10.66.66.2/32 dev bawg0") || !strings.Contains(l, "ip link set dev bawg0 mtu 1280 up") {
		t.Errorf("link:\n%s", l)
	}
}

func TestPlanDualStackKillSwitchAndLAN(t *testing.T) {
	js := strings.Replace(baseJSON(`,"killSwitch":true,"excludeLan":true,"mtu":1420`),
		`["10.66.66.2/32"]`, `["10.66.66.2/24","fd42::2/64"]`, 1)
	c := mustParse(t, js)
	p := BuildPlan(c)
	r := joined(RouteCmds(p.Routes))
	for _, want := range []string{
		"ip -4 route replace default dev bawg0 table 980",
		"ip -6 route replace default dev bawg0 table 980",
		"ip -4 route replace 10.66.66.0/24 dev bawg0 table 980",
		"ip -6 route replace fd42::/64 dev bawg0 table 980",
		"ip -4 route replace unreachable default metric 2147483647 table 980",
		"ip -6 route replace unreachable default metric 2147483647 table 980",
		"ip -4 route replace throw 192.168.0.0/16 table 980",
		"ip -4 route replace throw 10.0.0.0/8 table 980",
		"ip -6 route replace throw fe80::/10 table 980",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("missing %q in\n%s", want, r)
		}
	}
	if strings.Contains(r, "-6 route replace unreachable default table") {
		t.Errorf("v6 blocked although the tunnel has v6:\n%s", r)
	}
	if !strings.Contains(joined(p.LinkCmds()), "mtu 1420") {
		t.Error("mtu not applied")
	}
}

func TestPlanSplitTunnelDoesNotBlockOtherFamily(t *testing.T) {
	js := strings.Replace(baseJSON(""), `["0.0.0.0/0","::/0"]`, `["10.8.0.0/16"]`, 1)
	c := mustParse(t, js)
	r := joined(RouteCmds(BuildPlan(c).Routes))
	if !strings.Contains(r, "ip -4 route replace 10.8.0.0/16 dev bawg0 table 980") {
		t.Errorf("split route missing:\n%s", r)
	}
	if strings.Contains(r, "unreachable") || strings.Contains(r, "default") {
		t.Errorf("split tunnel must not catch everything:\n%s", r)
	}
}

func TestRulesOrderAndPrefs(t *testing.T) {
	c := mustParse(t, baseJSON(""))
	p := BuildPlan(c)
	rules := joined(RuleAddCmds(p.Rules))
	for _, f := range []string{"-4", "-6"} {
		idx := func(s string) int { return strings.Index(rules, "ip "+f+" rule add pref "+s) }
		nop, app, dnsU, dnsT, r0, r1 := idx("10099 nop"), idx("10002 uidrange 10682-10682 lookup 980"),
			idx("10003 ipproto udp dport 53 goto 10099"), idx("10004 ipproto tcp dport 53 goto 10099"),
			idx("10010 uidrange 10000-10684 lookup 980"), idx("10011 uidrange 10686-19999 lookup 980")
		for name, i := range map[string]int{"nop": nop, "app": app, "dnsU": dnsU, "dnsT": dnsT, "r0": r0, "r1": r1} {
			if i < 0 {
				t.Fatalf("%s %s missing in\n%s", f, name, rules)
			}
		}
		if !(nop < app && app < dnsU && dnsU < dnsT && dnsT < r0 && r0 < r1) {
			t.Errorf("%s order wrong:\n%s", f, rules)
		}
	}
	for _, r := range p.Rules {
		if r.Pref < PrefFirst || r.Pref > PrefLast || r.Pref == PrefSelftestGoto || r.Pref == PrefSelftestNop {
			t.Errorf("pref out of range: %s", r.AddCmd())
		}
		if r.Action == ActGoto && r.Goto <= r.Pref {
			t.Errorf("goto must jump forward: %s", r.AddCmd())
		}
	}
	if probe := joined(RuleAddCmds(p.Probe)); !strings.Contains(probe, "ip -4 rule add pref 10001 fwmark 0x40000000/0x40000000 lookup 980") {
		t.Errorf("probe rule: %s", probe)
	}
}

func TestTeardownReversesRules(t *testing.T) {
	c := mustParse(t, baseJSON(""))
	p := BuildPlan(c)
	td := p.TeardownRules()
	if len(td) != len(p.Rules)+len(p.Probe) {
		t.Fatalf("teardown length %d", len(td))
	}
	// App ranges go first, the probe rule last.
	if got := td[0].DelCmd().String(); got != "ip -6 rule del pref 10011 uidrange 10686-19999 lookup 980" {
		t.Errorf("first teardown step: %s", got)
	}
	if td[len(td)-1].Pref != PrefProbe {
		t.Errorf("last teardown step: %s", td[len(td)-1].DelCmd())
	}
	tail := joined(CleanupTail(980, "bawg0"))
	if !strings.HasSuffix(tail, "ip link del dev bawg0\n") {
		t.Errorf("tail: %s", tail)
	}
}

// kernelDump builds what the kernel dumps for a rule: our encoding plus the
// attributes fib_nl_fill_rule always adds (table, suppress_*, protocol).
func kernelDump(r RuleSpec, extra ...func([]byte) []byte) KRule {
	b := EncodeRule(r)
	if r.Action == ActTable && r.Table >= 256 {
		b[4] = 252 // RT_TABLE_COMPAT
	}
	if r.Action != ActTable {
		b = appendAttr(b, fraTable, u32(0))
	}
	b = appendAttr(b, fraSuppressPrefixlen, u32(0xffffffff))
	b = appendAttr(b, fraProtocol, []byte{3})
	for _, e := range extra {
		b = e(b)
	}
	k, err := ParseRule(b)
	if err != nil {
		panic(err)
	}
	return k
}

func TestEncodeParseRoundTrip(t *testing.T) {
	c := mustParse(t, baseJSON(""))
	p := BuildPlan(c)
	for _, r := range append(p.Probe, p.Rules...) {
		k := kernelDump(r)
		if k.Foreign {
			t.Errorf("own rule parsed as foreign: %s", r.AddCmd())
		}
		if !FindRule([]KRule{k}, r) {
			t.Errorf("round trip lost attributes: %s -> %s", r.AddCmd(), k)
		}
		if !Owned(k, 980) {
			t.Errorf("own rule not owned: %s", k)
		}
	}
	dns := RuleSpec{Pref: PrefDNSUDP, Action: ActGoto, Goto: PrefLast, IPProto: 17, Dport: 53}
	b := EncodeRule(dns)
	// fib_rule_hdr: family AF_INET, action FR_ACT_GOTO at byte 7.
	if b[0] != 2 || b[7] != 2 {
		t.Fatalf("header % x", b[:12])
	}
	k := kernelDump(dns)
	if k.IPProto != 17 || k.Dport == nil || k.Dport[0] != 53 || k.Dport[1] != 53 || k.Goto != PrefLast || k.Pref != PrefDNSUDP {
		t.Errorf("dns rule parsed as %+v", k)
	}
	if got := dns.AddCmd().String(); got != "ip -4 rule add pref 10003 ipproto udp dport 53 goto 10099" {
		t.Errorf("ip equivalent: %s", got)
	}
}

func TestOwnedOnlyOurs(t *testing.T) {
	ours := []RuleSpec{
		{Pref: 10001, Action: ActTable, Table: 980, Mark: ProbeMark, Mask: ProbeMark},
		{Pref: 10002, Action: ActTable, Table: 980, HasUID: true, UIDStart: 10682, UIDEnd: 10682},
		{Pref: 10003, Action: ActGoto, Goto: 10099, IPProto: 17, Dport: 53},
		{Pref: 10004, Action: ActGoto, Goto: 10099, IPProto: 6, Dport: 53},
		{Pref: 10010, Action: ActTable, Table: 980, HasUID: true, UIDStart: 10000, UIDEnd: 10684},
		{Pref: 10099, Action: ActNop},
		{Pref: PrefSelftestGoto, Action: ActGoto, Goto: PrefSelftestNop, IPProto: 17, Dport: 53},
		{Pref: PrefSelftestNop, Action: ActNop},
	}
	iif := func(b []byte) []byte { return appendAttr(b, fraIifname, []byte("lo\x00")) }
	foreign := []KRule{
		kernelDump(RuleSpec{Pref: 10000, Action: ActTable, Table: 99, Mark: 0xc0000, Mask: 0xd0000}),
		kernelDump(RuleSpec{Pref: 10050, Action: ActTable, Table: 1050, HasUID: true, UIDStart: 10000, UIDEnd: 19999}),
		kernelDump(RuleSpec{Pref: 10010, Action: ActTable, Table: 980, HasUID: true, UIDStart: 0, UIDEnd: 0}, iif),
		kernelDump(RuleSpec{Pref: 10050, Action: ActNop}),               // nop elsewhere
		kernelDump(RuleSpec{Pref: 10099, Action: ActNop, IPProto: 17}),  // nop with a selector
		kernelDump(RuleSpec{Pref: 10020, Action: ActGoto, Goto: 10098}), // goto elsewhere
		kernelDump(RuleSpec{Pref: 9999, Action: ActTable, Table: 980}),  // below our range
		kernelDump(RuleSpec{Pref: 11000, Action: ActGoto, Goto: 10099}), // above our range
		{Pref: 10099, Action: 6 /* unreachable */},
	}
	var all []KRule
	for _, r := range ours {
		all = append(all, kernelDump(r))
	}
	all = append(all, foreign...)
	got := OwnedOrdered(all, 980)
	if len(got) != len(ours) {
		for _, k := range got {
			t.Logf("owned: %s", k)
		}
		t.Fatalf("owned %d rules, want %d", len(got), len(ours))
	}
	for _, k := range foreign {
		if Owned(k, 980) {
			t.Errorf("would delete foreign rule %s", k)
		}
	}
	// Highest pref first, nop targets last.
	for i := 1; i < len(got); i++ {
		a, b := got[i-1], got[i]
		if a.Action == ActNop && b.Action != ActNop || (a.Action == ActNop) == (b.Action == ActNop) && a.Pref < b.Pref {
			t.Errorf("order: %s before %s", a, b)
		}
	}
	if got[len(got)-1].Action != ActNop || got[len(got)-2].Action != ActNop {
		t.Errorf("nop targets must go last")
	}
}

func TestParseRejectsShortAndFlagsForeign(t *testing.T) {
	if _, err := ParseRule([]byte{2, 0, 0}); err == nil {
		t.Error("short header accepted")
	}
	b := EncodeRule(RuleSpec{Pref: 10002, Action: ActTable, Table: 980, HasUID: true, UIDStart: 1, UIDEnd: 2})
	b[2] = 24 // src_len: "from 10.0.0.0/24"
	if k, _ := ParseRule(b); !k.Foreign || Owned(k, 980) {
		t.Error("rule with a source prefix must be foreign")
	}
	// Linux 6.16+ dumps FRA_DPORT_MASK 0xffff for a plain port: still ours.
	dns := RuleSpec{Pref: 10003, Action: ActGoto, Goto: 10099, IPProto: 17, Dport: 53}
	full := func(b []byte) []byte { return appendAttr(b, fraDportMask, []byte{0xff, 0xff}) }
	if k := kernelDump(dns, full); k.Foreign || !Owned(k, 980) || !FindRule([]KRule{k}, dns) {
		t.Errorf("dport mask 0xffff must not make the rule foreign: %s", k)
	}
	part := func(b []byte) []byte { return appendAttr(b, fraDportMask, []byte{0xf0, 0xff}) }
	if k := kernelDump(dns, part); !k.Foreign || Owned(k, 980) {
		t.Error("a partial dport mask is not ours")
	}
	b = EncodeRule(RuleSpec{Pref: 10099, Action: ActNop})
	ne.PutUint32(b[8:12], 0x2) // FIB_RULE_INVERT
	if k, _ := ParseRule(b); !k.Foreign {
		t.Error("inverted rule must be foreign")
	}
	b = EncodeRule(RuleSpec{Pref: 10003, Action: ActGoto, Goto: 10099, IPProto: 17, Dport: 53})
	ne.PutUint32(b[8:12], fibRuleUnresolved)
	if k, _ := ParseRule(b); k.Foreign || !Owned(k, 980) {
		t.Error("unresolved goto is still ours")
	}
}

func TestProbeTargetsAvoidDNSPort(t *testing.T) {
	c := mustParse(t, baseJSON(""))
	ts := ProbeTargets(c)
	if len(ts) != 1 || ts[0] != netip.MustParseAddrPort("1.1.1.1:9") {
		t.Fatalf("targets: %v", ts)
	}
	js := strings.Replace(baseJSON(""), `["0.0.0.0/0","::/0"]`, `["10.8.0.0/16"]`, 1)
	ts = ProbeTargets(mustParse(t, js))
	if len(ts) != 1 || ts[0] != netip.MustParseAddrPort("10.8.0.1:9") {
		t.Fatalf("split targets: %v", ts)
	}
}

func dev(rx, tx int64, hs time.Time) *wgtypes.Device {
	return &wgtypes.Device{Peers: []wgtypes.Peer{{ReceiveBytes: rx, TransmitBytes: tx, LastHandshakeTime: hs}}}
}

func TestMonitorDeadTunnel(t *testing.T) {
	c := mustParse(t, baseJSON(""))
	m := newMonitor(c)
	t0 := time.Unix(1_000_000, 0)
	hs := t0.Add(-10 * time.Second)
	if r := m.observe(dev(100, 100, hs), t0); r != "" {
		t.Fatal(r)
	}
	// Healthy: rx keeps moving.
	if r := m.observe(dev(200, 300, hs), t0.Add(30*time.Second)); r != "" {
		t.Fatal(r)
	}
	// Sending, nothing back, but session still young: not dead yet.
	if r := m.observe(dev(200, 900, hs), t0.Add(100*time.Second)); r != "" {
		t.Fatal(r)
	}
	// Session expired, still nothing received: dead.
	if r := m.observe(dev(200, 1500, hs), t0.Add(200*time.Second)); r == "" {
		t.Fatal("expected dead")
	}
}

func TestMonitorIdleIsNotDead(t *testing.T) {
	m := newMonitor(mustParse(t, baseJSON("")))
	t0 := time.Unix(1_000_000, 0)
	m.observe(dev(100, 100, t0), t0)
	if r := m.observe(dev(100, 100, t0), t0.Add(time.Hour)); r != "" {
		t.Fatalf("idle tunnel flagged: %s", r)
	}
}

func TestMonitorDisabledWithKillSwitch(t *testing.T) {
	m := newMonitor(mustParse(t, baseJSON(`,"killSwitch":true`)))
	t0 := time.Unix(1_000_000, 0)
	m.observe(dev(0, 0, time.Time{}), t0)
	if r := m.observe(dev(0, 5000, time.Time{}), t0.Add(time.Hour)); r != "" {
		t.Fatalf("kill switch must never fail open: %s", r)
	}
}
