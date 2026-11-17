package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	mdns "github.com/miekg/dns"
)

// Upstream host names (an ODoH relay, a DoH/DoT/DoQ server given by name) must
// never be resolved through the system resolver. In Root Proxy mode the system
// resolver's queries are sent by netd, not by this app's uid, so the iptables
// exclusion for BlockAds does not apply: the lookup is redirected back into
// this engine, which needs the very same host name to answer it. That loop
// times out, the system resolver marks the carrier's DNS servers broken, and
// apps lose DNS (seen 2026-11-17 on OnePlus CPH2653: thousands of queries per
// minute for odoh-relay.edgecompute.app).
//
// bootstrapLookup resolves such names with plain DNS sent straight to public
// resolvers on protected sockets, and caches the answer.

var bootstrapServers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

const (
	bootstrapTimeout = 2 * time.Second
	bootstrapMinTTL  = 5 * time.Minute
	bootstrapMaxTTL  = 6 * time.Hour
	bootstrapFailTTL = 30 * time.Second
)

type bootstrapEntry struct {
	ip      string
	err     error
	expires time.Time
}

var (
	bootstrapMu    sync.Mutex
	bootstrapCache = map[string]bootstrapEntry{}
	// Overridden in tests.
	bootstrapExchange = exchangeBootstrap
	// Last resort only (no answer from any bootstrap server).
	systemLookupHost = net.LookupHost
)

// bootstrapLookup returns an IPv4 address for an upstream host name.
func (r *Resolver) bootstrapLookup(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	if ip := resolveBootstrapIP(host, r); ip != "" {
		return ip, nil
	}
	key := strings.ToLower(strings.TrimSuffix(host, "."))
	now := time.Now()

	bootstrapMu.Lock()
	if e, ok := bootstrapCache[key]; ok && now.Before(e.expires) {
		bootstrapMu.Unlock()
		return e.ip, e.err
	}
	bootstrapMu.Unlock()

	var protect func(fd int) bool
	if r != nil {
		protect = r.protectSocketFn
	}
	ip, ttl, err := lookupViaBootstrapServers(key, protect)
	if err != nil {
		if ips, serr := systemLookupHost(key); serr == nil && len(ips) > 0 {
			ip, ttl, err = ips[0], bootstrapMinTTL, nil
		}
	}

	e := bootstrapEntry{ip: ip, err: err, expires: now.Add(ttl)}
	if err != nil {
		e.expires = now.Add(bootstrapFailTTL)
	}
	bootstrapMu.Lock()
	bootstrapCache[key] = e
	bootstrapMu.Unlock()
	return ip, err
}

func lookupViaBootstrapServers(host string, protect func(fd int) bool) (string, time.Duration, error) {
	q := new(mdns.Msg)
	q.SetQuestion(mdns.Fqdn(host), mdns.TypeA)
	q.RecursionDesired = true
	var lastErr error
	for _, server := range bootstrapServers {
		resp, err := bootstrapExchange(q, server, protect)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Rcode != mdns.RcodeSuccess {
			lastErr = fmt.Errorf("%s: rcode %s", server, mdns.RcodeToString[resp.Rcode])
			continue
		}
		for _, rr := range resp.Answer {
			if a, ok := rr.(*mdns.A); ok {
				ttl := time.Duration(a.Hdr.Ttl) * time.Second
				if ttl < bootstrapMinTTL {
					ttl = bootstrapMinTTL
				}
				if ttl > bootstrapMaxTTL {
					ttl = bootstrapMaxTTL
				}
				return a.A.String(), ttl, nil
			}
		}
		lastErr = fmt.Errorf("%s: no A record for %s", server, host)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no bootstrap servers")
	}
	return "", 0, fmt.Errorf("bootstrap resolve %s: %w", host, lastErr)
}

func exchangeBootstrap(q *mdns.Msg, server string, protect func(fd int) bool) (*mdns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), bootstrapTimeout)
	defer cancel()
	d := &net.Dialer{
		Timeout: bootstrapTimeout,
		Control: func(_, _ string, c syscall.RawConn) error {
			if protect == nil {
				return nil
			}
			return c.Control(func(fd uintptr) { protect(int(fd)) })
		},
	}
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	co := &mdns.Conn{Conn: conn}
	_ = conn.SetDeadline(time.Now().Add(bootstrapTimeout))
	if err := co.WriteMsg(q); err != nil {
		return nil, err
	}
	resp, err := co.ReadMsg()
	if err != nil {
		return nil, err
	}
	if resp.Id != q.Id {
		return nil, fmt.Errorf("%s: id mismatch", server)
	}
	return resp, nil
}
