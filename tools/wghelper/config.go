package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// Defaults shared with the app (RootWireGuard.kt). Keep them in sync.
const (
	DefaultInterface   = "bawg0"
	DefaultMTU         = 1280
	DefaultFwMark      = 0x20000000 // bit 29: kernel WireGuard's own UDP socket
	ProbeMark          = 0x40000000 // bit 30: helper's handshake probe only
	DefaultTable       = 980        // NOT 97/98/99: netd's local_network/legacy_network/legacy_system
	PrefFirst          = 10000
	PrefProbe          = 10001
	PrefApp            = 10002
	PrefDNSUDP         = 10003
	PrefDNSTCP         = 10004
	PrefRangesFirst    = 10010
	PrefLast           = 10099 // nop rule, target of the DNS goto rules
	MaxUIDRanges       = PrefLast - PrefRangesFirst
	DefaultHandshakeTO = 15
	DefaultDeadAfter   = 60
)

// Config is the JSON file the app writes (0600) and passes by path.
type Config struct {
	Interface  string   `json:"interface"`
	PrivateKey string   `json:"privateKey"`
	Addresses  []string `json:"addresses"`
	MTU        int      `json:"mtu"`
	ListenPort int      `json:"listenPort"`
	FwMark     uint32   `json:"fwmark"`
	Table      int      `json:"table"`
	Peers      []Peer   `json:"peers"`
	// UID ranges routed into the tunnel (inclusive).
	UIDRanges []UIDRange `json:"uidRanges"`
	// BlockAds' own uid. Routed through the tunnel before the DNS exemption,
	// so the engine's upstream DNS and the HTTPS MITM's outbound use it.
	AppUID     int  `json:"appUid"`
	ExcludeLAN bool `json:"excludeLan"`
	KillSwitch bool `json:"killSwitch"`
	// Seconds to wait for the first handshake before any app is routed.
	// 0 = default, negative = do not wait.
	HandshakeTimeoutSec int `json:"handshakeTimeoutSec"`
	// Fail open when the tunnel looks dead for this many seconds (only when
	// the kill switch is off). 0 = default, negative = never.
	DeadAfterSec int `json:"deadAfterSec"`

	// AmneziaWG obfuscation (phase 2). Any non-zero value is rejected:
	// the kernel module speaks plain WireGuard only.
	Jc   int64  `json:"jc"`
	Jmin int64  `json:"jmin"`
	Jmax int64  `json:"jmax"`
	S1   int64  `json:"s1"`
	S2   int64  `json:"s2"`
	S3   int64  `json:"s3"`
	S4   int64  `json:"s4"`
	H1   int64  `json:"h1"`
	H2   int64  `json:"h2"`
	H3   int64  `json:"h3"`
	H4   int64  `json:"h4"`
	I1   string `json:"i1"`
	I2   string `json:"i2"`
	I3   string `json:"i3"`
	I4   string `json:"i4"`
	I5   string `json:"i5"`

	// Parsed forms, filled by Validate.
	addrs []netip.Prefix
}

type Peer struct {
	PublicKey           string   `json:"publicKey"`
	PresharedKey        string   `json:"presharedKey"`
	Endpoint            string   `json:"endpoint"`
	AllowedIPs          []string `json:"allowedIPs"`
	PersistentKeepalive int      `json:"persistentKeepalive"`

	endpoint netip.AddrPort
	allowed  []netip.Prefix
}

type UIDRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// ErrAmnezia is returned for AmneziaWG configs.
var ErrAmnezia = errors.New("AmneziaWG obfuscation parameters are set (Jc/Jmin/Jmax/S1-S4/H1-H4/I1-I5); " +
	"kernel WireGuard cannot speak AmneziaWG — not supported in root mode yet (phase 2)")

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(b)
}

func ParseConfig(b []byte) (*Config, error) {
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config json: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) IsAmnezia() bool {
	for _, v := range []int64{c.Jc, c.Jmin, c.Jmax, c.S1, c.S2, c.S3, c.S4, c.H1, c.H2, c.H3, c.H4} {
		if v != 0 {
			return true
		}
	}
	for _, s := range []string{c.I1, c.I2, c.I3, c.I4, c.I5} {
		if strings.TrimSpace(s) != "" {
			return true
		}
	}
	return false
}

func checkKey(name, k string) error {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k))
	if err != nil || len(b) != 32 {
		return fmt.Errorf("%s: not a base64 32-byte key", name)
	}
	return nil
}

// Validate applies defaults and checks everything that can be checked
// without touching the system.
func (c *Config) Validate() error {
	if c.IsAmnezia() {
		return ErrAmnezia
	}
	if c.Interface == "" {
		c.Interface = DefaultInterface
	}
	if len(c.Interface) > 15 || strings.ContainsAny(c.Interface, " /'\"") {
		return fmt.Errorf("bad interface name %q", c.Interface)
	}
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	if c.MTU < 576 || c.MTU > 9000 {
		return fmt.Errorf("bad mtu %d", c.MTU)
	}
	if c.FwMark == 0 {
		c.FwMark = DefaultFwMark
	}
	if c.Table == 0 {
		c.Table = DefaultTable
	}
	if c.Table >= 97 && c.Table <= 99 || c.Table >= 253 && c.Table <= 255 || c.Table < 1 {
		return fmt.Errorf("table %d is reserved (netd 97-99, kernel 253-255)", c.Table)
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return fmt.Errorf("bad listenPort %d", c.ListenPort)
	}
	if c.HandshakeTimeoutSec == 0 {
		c.HandshakeTimeoutSec = DefaultHandshakeTO
	}
	if c.DeadAfterSec == 0 {
		c.DeadAfterSec = DefaultDeadAfter
	}
	if err := checkKey("privateKey", c.PrivateKey); err != nil {
		return err
	}
	if len(c.Addresses) == 0 {
		return errors.New("no interface address")
	}
	c.addrs = c.addrs[:0]
	for _, a := range c.Addresses {
		p, err := parsePrefixOrAddr(a)
		if err != nil {
			return fmt.Errorf("address %q: %w", a, err)
		}
		c.addrs = append(c.addrs, p)
	}
	if len(c.Peers) == 0 {
		return errors.New("no peer")
	}
	for i := range c.Peers {
		p := &c.Peers[i]
		if err := checkKey(fmt.Sprintf("peer %d publicKey", i), p.PublicKey); err != nil {
			return err
		}
		if strings.TrimSpace(p.PresharedKey) != "" {
			if err := checkKey(fmt.Sprintf("peer %d presharedKey", i), p.PresharedKey); err != nil {
				return err
			}
		}
		if p.Endpoint != "" {
			ap, err := netip.ParseAddrPort(strings.TrimSpace(p.Endpoint))
			if err != nil {
				return fmt.Errorf("peer %d endpoint %q must be a resolved IP:port (resolve the host name in the app): %v", i, p.Endpoint, err)
			}
			p.endpoint = ap
		}
		if p.PersistentKeepalive < 0 || p.PersistentKeepalive > 65535 {
			return fmt.Errorf("peer %d bad persistentKeepalive", i)
		}
		p.allowed = p.allowed[:0]
		for _, a := range p.AllowedIPs {
			pr, err := parsePrefixOrAddr(a)
			if err != nil {
				return fmt.Errorf("peer %d allowedIP %q: %w", i, a, err)
			}
			p.allowed = append(p.allowed, pr.Masked())
		}
	}
	if len(c.UIDRanges) == 0 && c.AppUID == 0 {
		return errors.New("nothing to route: no uidRanges and no appUid")
	}
	if len(c.UIDRanges) > MaxUIDRanges {
		return fmt.Errorf("too many uid ranges (%d > %d)", len(c.UIDRanges), MaxUIDRanges)
	}
	for _, r := range c.UIDRanges {
		// uid 0-9999 are system/root: never route them (the kernel WireGuard
		// socket and netd run there; routing them would loop or cut the phone off).
		if r.Start < 10000 || r.End < r.Start {
			return fmt.Errorf("bad uid range %d-%d (must be >= 10000)", r.Start, r.End)
		}
	}
	if c.AppUID != 0 && c.AppUID < 10000 {
		return fmt.Errorf("bad appUid %d", c.AppUID)
	}
	return nil
}

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func (c *Config) hasFamily(v6 bool) bool {
	for _, a := range c.addrs {
		if a.Addr().Is6() == v6 && !a.Addr().Is4In6() {
			return true
		}
	}
	return false
}

func (c *Config) allowed(v6 bool) []netip.Prefix {
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, p := range c.Peers {
		for _, a := range p.allowed {
			if a.Addr().Is6() == v6 && !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

func fullTunnel(ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Bits() == 0 {
			return true
		}
	}
	return false
}
