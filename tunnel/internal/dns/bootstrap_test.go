package dns

import (
	"errors"
	"net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func resetBootstrap(t *testing.T) {
	t.Helper()
	bootstrapMu.Lock()
	bootstrapCache = map[string]bootstrapEntry{}
	bootstrapMu.Unlock()
	oldEx, oldSys := bootstrapExchange, systemLookupHost
	t.Cleanup(func() { bootstrapExchange, systemLookupHost = oldEx, oldSys })
}

func TestBootstrapLookupNeverUsesSystemResolverWhenServersAnswer(t *testing.T) {
	resetBootstrap(t)
	calls := 0
	bootstrapExchange = func(q *mdns.Msg, server string, _ func(int) bool) (*mdns.Msg, error) {
		calls++
		m := new(mdns.Msg)
		m.SetReply(q)
		rr, _ := mdns.NewRR(q.Question[0].Name + " 60 IN A 151.101.1.1")
		m.Answer = append(m.Answer, rr)
		return m, nil
	}
	systemLookupHost = func(string) ([]string, error) {
		t.Fatal("system resolver must not be used (it loops back into the engine in Root Proxy mode)")
		return nil, nil
	}
	var r *Resolver
	ip, err := r.bootstrapLookup("odoh-relay.edgecompute.app")
	if err != nil || ip != "151.101.1.1" {
		t.Fatalf("got %q, %v", ip, err)
	}
	// cached
	if ip, _ = r.bootstrapLookup("ODOH-relay.edgecompute.app."); ip != "151.101.1.1" || calls != 1 {
		t.Fatalf("cache miss: ip=%q calls=%d", ip, calls)
	}
}

func TestBootstrapLookupFallsThroughServersThenSystem(t *testing.T) {
	resetBootstrap(t)
	tried := []string{}
	bootstrapExchange = func(q *mdns.Msg, server string, _ func(int) bool) (*mdns.Msg, error) {
		tried = append(tried, server)
		return nil, errors.New("timeout")
	}
	systemLookupHost = func(string) ([]string, error) { return []string{"10.0.0.9"}, nil }
	var r *Resolver
	ip, err := r.bootstrapLookup("relay.example")
	if err != nil || ip != "10.0.0.9" {
		t.Fatalf("got %q, %v", ip, err)
	}
	if len(tried) != len(bootstrapServers) {
		t.Fatalf("tried %v", tried)
	}
}

func TestBootstrapLookupKnownAndLiteral(t *testing.T) {
	resetBootstrap(t)
	bootstrapExchange = func(*mdns.Msg, string, func(int) bool) (*mdns.Msg, error) {
		t.Fatal("no network for known hosts")
		return nil, nil
	}
	var r *Resolver
	if ip, _ := r.bootstrapLookup("dns.google"); ip != "8.8.8.8" {
		t.Fatalf("dns.google -> %q", ip)
	}
	if ip, _ := r.bootstrapLookup("9.9.9.9"); ip != "9.9.9.9" {
		t.Fatalf("literal -> %q", ip)
	}
	_ = net.ParseIP
	_ = time.Second
}
