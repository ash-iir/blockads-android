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
	r := joined(p.Routes)
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
	l := joined(p.Link)
	if !strings.Contains(l, "ip -4 addr add 10.66.66.2/32 dev bawg0") || !strings.Contains(l, "ip link set dev bawg0 mtu 1280 up") {
		t.Errorf("link:\n%s", l)
	}
}

func TestPlanDualStackKillSwitchAndLAN(t *testing.T) {
	js := strings.Replace(baseJSON(`,"killSwitch":true,"excludeLan":true,"mtu":1420`),
		`["10.66.66.2/32"]`, `["10.66.66.2/24","fd42::2/64"]`, 1)
	c := mustParse(t, js)
	p := BuildPlan(c)
	r := joined(p.Routes)
	for _, want := range []string{
		"ip -4 route replace default dev bawg0 table 980",
		"ip -6 route replace default dev bawg0 table 980",
		"ip -4 route replace 10.66.66.0/24 dev bawg0 table 980",
		"ip -6 route replace fd42::/64 dev bawg0 table 980",
		"ip -4 route replace unreachable default metric 4294967295 table 980",
		"ip -6 route replace unreachable default metric 4294967295 table 980",
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
	if !strings.Contains(joined(p.Link), "mtu 1420") {
		t.Error("mtu not applied")
	}
}

func TestPlanSplitTunnelDoesNotBlockOtherFamily(t *testing.T) {
	js := strings.Replace(baseJSON(""), `["0.0.0.0/0","::/0"]`, `["10.8.0.0/16"]`, 1)
	c := mustParse(t, js)
	r := joined(BuildPlan(c).Routes)
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
	rules := joined(p.Rules)
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
	for _, c := range p.Rules {
		s := c.String()
		var pref int
		for i, a := range c {
			if a == "pref" {
				pref = atoi(c[i+1])
			}
		}
		if pref < PrefFirst || pref > PrefLast {
			t.Errorf("pref out of range: %s", s)
		}
	}
	if probe := joined(p.Probe); !strings.Contains(probe, "ip -4 rule add pref 10001 fwmark 0x40000000/0x40000000 lookup 980") {
		t.Errorf("probe rule: %s", probe)
	}
}

func atoi(s string) int {
	n := 0
	for _, ch := range s {
		n = n*10 + int(ch-'0')
	}
	return n
}

func TestTeardownReversesRules(t *testing.T) {
	c := mustParse(t, baseJSON(""))
	p := BuildPlan(c)
	td := p.Teardown(c)
	if len(td) != len(p.Rules)+len(p.Probe)+3 {
		t.Fatalf("teardown length %d", len(td))
	}
	// App ranges go first, nop target last among rules.
	if !strings.Contains(td[0].String(), "rule del pref 10011") {
		t.Errorf("first teardown step: %s", td[0])
	}
	last := td[len(td)-1].String()
	if last != "ip link del dev bawg0" {
		t.Errorf("last teardown step: %s", last)
	}
	for _, x := range td {
		if strings.Contains(x.String(), " add ") {
			t.Errorf("teardown adds: %s", x)
		}
	}
}

const ruleShow = `0:	from all lookup local
9999:	from all fwmark 0x10000000/0x10000000 lookup local_network
10000:	from all fwmark 0xc0000/0xd0000 lookup legacy_system
10001:	from all fwmark 0x40000000/0x40000000 lookup 980
10002:	from all uidrange 10682-10682 lookup 980
10003:	from all ipproto udp dport 53 goto 10099
10004:	from all ipproto tcp dport 53 goto 10099 [unresolved]
10010:	from all uidrange 10000-10684 lookup 980
10050:	from all uidrange 10000-19999 lookup 1050
10099:	from all nop
11000:	from all iif lo oif dummy0 uidrange 0-0 lookup dummy0
32000:	from all unreachable
`

func TestOwnedRuleDeletesOnlyOurs(t *testing.T) {
	del := OwnedRuleDeletes("-4", ruleShow, 980)
	got := joined(del)
	for _, want := range []string{
		"ip -4 rule del pref 10001 from all fwmark 0x40000000/0x40000000 lookup 980",
		"ip -4 rule del pref 10002 from all uidrange 10682-10682 lookup 980",
		"ip -4 rule del pref 10003 from all ipproto udp dport 53 goto 10099",
		"ip -4 rule del pref 10004 from all ipproto tcp dport 53 goto 10099",
		"ip -4 rule del pref 10010 from all uidrange 10000-10684 lookup 980",
		"ip -4 rule del pref 10099 from all nop",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	for _, not := range []string{"legacy_system", "lookup 1050", "local_network", "dummy0", "32000"} {
		if strings.Contains(got, not) {
			t.Errorf("would delete foreign rule %q:\n%s", not, got)
		}
	}
	if !strings.Contains(del[len(del)-1].String(), "nop") {
		t.Errorf("nop target must go last:\n%s", got)
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
