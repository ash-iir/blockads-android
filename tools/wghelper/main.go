// Command wghelper is BlockAds' root helper for "WireGuard in Root mode"
// (no Android VpnService, the VPN slot stays free).
//
// It brings up a kernel WireGuard interface (CONFIG_WIREGUARD) and routes
// chosen app uids into it with uid policy routing:
//
//	ip link add bawg0 type wireguard        + key/peers/fwmark via wgctrl
//	table 980:  <allowed IPs> dev bawg0      (unreachable default for a
//	            family the tunnel has no address for; throw LAN ranges)
//	pref 10001  fwmark 0x40000000 lookup 980 (helper's handshake probe)
//	pref 10002  uidrange <BlockAds> lookup 980
//	pref 10003/4 udp|tcp dport 53 goto 10099 (app DNS never uses the tunnel)
//	pref 10010+ uidrange A-B lookup 980
//	pref 10099  nop
//
// The kernel WireGuard socket is uid 0 with fwmark 0x20000000, so it never
// matches the uid rules: no routing loop. IPv6 DNS TPROXY (pref 9999) and
// netd (prefs 11000+) are untouched.
//
// Fail-open: apps are only routed after the first handshake; on SIGTERM,
// parent death, error, or (kill switch off) a dead tunnel, everything is
// removed again. `down` removes leftovers idempotently.
//
// Shipped in the APK as lib/<abi>/libblockadswg.so and started via su.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var ipBin = "/system/bin/ip"

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  %[1]s up -config FILE [-ready FILE] [-status FILE] [-ppid PID -pname NAME]
  %[1]s down [-interface bawg0] [-table 980]     remove everything (idempotent)
  %[1]s plan -config FILE                         print the commands, change nothing
`, os.Args[0])
	os.Exit(2)
}

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "up":
		cmdUp(os.Args[2:])
	case "down":
		cmdDown(os.Args[2:])
	case "plan":
		cmdPlan(os.Args[2:])
	default:
		usage()
	}
}

func runIP(c Cmd) error {
	out, err := exec.Command(ipBin, c...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", c, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ipOut(args ...string) string {
	out, _ := exec.Command(ipBin, args...).Output()
	return string(out)
}

// cleanupAll removes every rule we own (found by scanning, so it also
// catches leftovers of an older run), the table and the interface.
func cleanupAll(table int, ifn string) {
	for _, f := range []string{"-4", "-6"} {
		for _, c := range OwnedRuleDeletes(f, ipOut(f, "rule", "show"), table) {
			if err := runIP(c); err != nil {
				log.Printf("cleanup: %v", err)
			}
		}
	}
	for _, c := range CleanupTail(table, ifn) {
		_ = runIP(c) // missing table/interface is fine
	}
}

func cmdDown(args []string) {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	ifn := fs.String("interface", DefaultInterface, "interface")
	table := fs.Int("table", DefaultTable, "routing table")
	fs.StringVar(&ipBin, "ip", ipBin, "ip binary")
	_ = fs.Parse(args)
	cleanupAll(*table, *ifn)
}

func cmdPlan(args []string) {
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	cfgPath := fs.String("config", "", "config json")
	_ = fs.Parse(args)
	c, err := LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	p := BuildPlan(c)
	fmt.Printf("ip link add dev %s type wireguard\n# wgctrl: key, listen port %d, fwmark 0x%x, %d peer(s)\n", c.Interface, c.ListenPort, c.FwMark, len(c.Peers))
	for _, group := range [][]Cmd{p.Link, p.Routes, p.Probe} {
		for _, x := range group {
			fmt.Println(x)
		}
	}
	fmt.Println("# wait for handshake, then:")
	for _, x := range p.Rules {
		fmt.Println(x)
	}
	fmt.Println("# teardown:")
	for _, x := range p.Teardown(c) {
		fmt.Println(x)
	}
}

type upState struct {
	cfg   *Config
	plan  Plan
	ready string
	once  sync.Once
}

func (s *upState) cleanup() {
	s.once.Do(func() {
		if s.ready != "" {
			_ = os.Remove(s.ready)
		}
		for _, c := range s.plan.Teardown(s.cfg) {
			_ = runIP(c)
		}
		// Catch anything a partial setup left behind.
		cleanupAll(s.cfg.Table, s.cfg.Interface)
		log.Printf("cleaned up")
	})
}

func (s *upState) fatal(format string, a ...any) {
	log.Printf("fatal: "+format, a...)
	s.cleanup()
	os.Exit(1)
}

func cmdUp(args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	cfgPath := fs.String("config", "", "config json (0600)")
	ready := fs.String("ready", "", "file created once apps are routed through the tunnel")
	status := fs.String("status", "", "file updated with tunnel stats every 10 s")
	ppid := fs.Int("ppid", 0, "exit when this pid (the BlockAds process) is gone")
	pname := fs.String("pname", "app.pwhs.blockads", "expected cmdline prefix of -ppid")
	fs.StringVar(&ipBin, "ip", ipBin, "ip binary")
	_ = fs.Parse(args)

	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		log.Printf("fatal: config: %v", err)
		os.Exit(1)
	}
	s := &upState{cfg: cfg, plan: BuildPlan(cfg), ready: *ready}
	if s.ready != "" {
		_ = os.Remove(s.ready)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	// Leftovers of a crashed run (rules without an interface) go first.
	cleanupAll(cfg.Table, cfg.Interface)

	if err := runIP(ipcmd(fmt.Sprintf("link add dev %s type wireguard", cfg.Interface))); err != nil {
		s.fatal("%v", err)
	}
	wg, err := wgctrl.New()
	if err != nil {
		s.fatal("wgctrl: %v", err)
	}
	defer wg.Close()
	if err := configureDevice(wg, cfg); err != nil {
		s.fatal("configure %s: %v", cfg.Interface, err)
	}
	for _, group := range [][]Cmd{s.plan.Link, s.plan.Routes, s.plan.Probe} {
		for _, c := range group {
			if err := runIP(c); err != nil {
				s.fatal("%v", err)
			}
		}
	}
	// Loose reverse-path filter on the tunnel: replies from the internet arrive
	// on bawg0 although netd's tables would route their source elsewhere.
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/"+cfg.Interface+"/rp_filter", []byte("2\n"), 0o644)

	if cfg.HandshakeTimeoutSec > 0 {
		if err := waitHandshake(wg, cfg, time.Duration(cfg.HandshakeTimeoutSec)*time.Second, sigs); err != nil {
			s.fatal("%v", err)
		}
	}
	for _, c := range s.plan.Rules {
		if err := runIP(c); err != nil {
			s.fatal("%v", err)
		}
	}
	if s.ready != "" {
		_ = os.WriteFile(s.ready, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644)
	}
	log.Printf("up: %s, table %d, %d uid range(s) + app uid %d, killSwitch=%v excludeLan=%v",
		cfg.Interface, cfg.Table, len(cfg.UIDRanges), cfg.AppUID, cfg.KillSwitch, cfg.ExcludeLAN)

	mon := newMonitor(cfg)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	n := 0
	for {
		select {
		case sig := <-sigs:
			log.Printf("signal %v, exiting", sig)
			s.cleanup()
			return
		case <-tick.C:
			n++
			if *ppid > 0 && !parentAlive(*ppid, *pname) {
				log.Printf("BlockAds process %d gone, exiting", *ppid)
				s.cleanup()
				return
			}
			if n%5 != 0 {
				continue
			}
			if _, err := net.InterfaceByName(cfg.Interface); err != nil {
				// Interface deleted under us. Never leave rules without it.
				s.fatal("%s disappeared: %v", cfg.Interface, err)
			}
			dev, err := wg.Device(cfg.Interface)
			if err != nil {
				s.fatal("read %s: %v", cfg.Interface, err)
			}
			if *status != "" {
				writeStatus(*status, dev)
			}
			if reason := mon.observe(dev, time.Now()); reason != "" {
				s.fatal("tunnel dead (%s) — failing open", reason)
			}
		}
	}
}

func configureDevice(wg *wgctrl.Client, c *Config) error {
	key, err := wgtypes.ParseKey(strings.TrimSpace(c.PrivateKey))
	if err != nil {
		return err
	}
	mark := int(c.FwMark)
	wc := wgtypes.Config{PrivateKey: &key, FirewallMark: &mark, ReplacePeers: true}
	if c.ListenPort > 0 {
		lp := c.ListenPort
		wc.ListenPort = &lp
	}
	for _, p := range c.Peers {
		pk, err := wgtypes.ParseKey(strings.TrimSpace(p.PublicKey))
		if err != nil {
			return err
		}
		pc := wgtypes.PeerConfig{PublicKey: pk, ReplaceAllowedIPs: true}
		if strings.TrimSpace(p.PresharedKey) != "" {
			psk, err := wgtypes.ParseKey(strings.TrimSpace(p.PresharedKey))
			if err != nil {
				return err
			}
			pc.PresharedKey = &psk
		}
		if p.endpoint.IsValid() {
			pc.Endpoint = net.UDPAddrFromAddrPort(p.endpoint)
		}
		if p.PersistentKeepalive > 0 {
			d := time.Duration(p.PersistentKeepalive) * time.Second
			pc.PersistentKeepaliveInterval = &d
		}
		for _, a := range p.allowed {
			pc.AllowedIPs = append(pc.AllowedIPs, net.IPNet{
				IP:   net.IP(a.Addr().AsSlice()),
				Mask: net.CIDRMask(a.Bits(), a.Addr().BitLen()),
			})
		}
		wc.Peers = append(wc.Peers, pc)
	}
	return wg.ConfigureDevice(c.Interface, wc)
}

func handshaked(d *wgtypes.Device) bool {
	for _, p := range d.Peers {
		if !p.LastHandshakeTime.IsZero() {
			return true
		}
	}
	return false
}

// waitHandshake sends a few probe datagrams into the tunnel (routed by the
// probe mark) so WireGuard initiates a handshake, and waits for it. Apps are
// only routed into a tunnel that has shaken hands: a wrong key or a dead
// endpoint must never blackhole the phone.
func waitHandshake(wg *wgctrl.Client, c *Config, timeout time.Duration, sigs chan os.Signal) error {
	targets := ProbeTargets(c)
	deadline := time.Now().Add(timeout)
	for i := 0; time.Now().Before(deadline); i++ {
		if i%10 == 0 { // every second
			for _, t := range targets {
				if err := sendProbe(t); err != nil && i == 0 {
					log.Printf("probe %s: %v", t, err)
				}
			}
		}
		d, err := wg.Device(c.Interface)
		if err != nil {
			return err
		}
		if handshaked(d) {
			log.Printf("handshake ok after %v", timeout-time.Until(deadline))
			return nil
		}
		select {
		case sig := <-sigs:
			return fmt.Errorf("signal %v during handshake", sig)
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("no WireGuard handshake within " + timeout.String() + " (wrong key, blocked endpoint or no network) — nothing routed")
}

// ProbeTargets picks addresses that the peers' allowed IPs cover (port 9,
// discard: never port 53, which BlockAds' nat rules redirect to the engine).
func ProbeTargets(c *Config) []netip.AddrPort {
	var out []netip.AddrPort
	for _, v6 := range []bool{false, true} {
		if !c.hasFamily(v6) {
			continue
		}
		allowed := c.allowed(v6)
		if len(allowed) == 0 {
			continue
		}
		var a netip.Addr
		if fullTunnel(allowed) {
			if v6 {
				a = netip.MustParseAddr("2606:4700:4700::1111")
			} else {
				a = netip.MustParseAddr("1.1.1.1")
			}
		} else {
			a = allowed[0].Addr()
			if allowed[0].Bits() < a.BitLen() {
				a = a.Next()
			}
		}
		out = append(out, netip.AddrPortFrom(a, 9))
	}
	return out
}

func sendProbe(t netip.AddrPort) error {
	network := "udp4"
	if t.Addr().Is6() {
		network = "udp6"
	}
	d := net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, ProbeMark)
		}); err != nil {
			return err
		}
		return serr
	}}
	conn, err := d.Dial(network, t.String())
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte("blockads-wg-probe"))
	return err
}

func parentAlive(pid int, name string) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return name == "" || strings.HasPrefix(string(b), name)
}

func writeStatus(path string, d *wgtypes.Device) {
	var b strings.Builder
	fmt.Fprintf(&b, "time=%s\n", time.Now().Format(time.RFC3339))
	for _, p := range d.Peers {
		hs := "never"
		if !p.LastHandshakeTime.IsZero() {
			hs = p.LastHandshakeTime.Format(time.RFC3339)
		}
		fmt.Fprintf(&b, "peer=%s endpoint=%v handshake=%s rx=%d tx=%d\n",
			p.PublicKey.String()[:8], p.Endpoint, hs, p.ReceiveBytes, p.TransmitBytes)
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, []byte(b.String()), 0o644) == nil {
		_ = os.Rename(tmp, path)
	}
}
