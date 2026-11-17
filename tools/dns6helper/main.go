// Command dns6helper is BlockAds' root helper for IPv6 DNS in Root Proxy mode.
//
// Many Android kernels (GKI builds on OnePlus/ColorOS and others) ship without
// CONFIG_IP6_NF_NAT, so the ip6tables REDIRECT BlockAds uses for IPv4 does not
// exist for IPv6. Queries the system resolver sends to the carrier's IPv6 DNS
// servers then bypass filtering, and rejecting them is not safe either: once
// netd has marked the IPv4 servers broken, rejecting IPv6 leaves no resolver
// at all and every app goes offline.
//
// Instead, ip6tables mangle marks outgoing IPv6 port-53 traffic, a policy route
// loops it back to lo, and TPROXY hands it to this helper. The helper forwards
// each query to the BlockAds engine on [::1]:15353 and answers from the
// original destination address, so the client accepts the reply.
//
// Fail-open rule (a helper bug must never take the phone offline): on exit
// (signal, fatal error, or the BlockAds process dying) the helper runs the
// cleanup command it was given, which removes the redirect.
//
// The helper needs CAP_NET_ADMIN (IPV6_TRANSPARENT), so BlockAds
// starts it through su. It is shipped in the APK as lib/<abi>/libblockadsdns6.so.
package main

import (
	"context"
	"encoding/binary"
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

	"github.com/miekg/dns"
)

const (
	ipv6Transparent    = 75 // IPV6_TRANSPARENT
	ipv6RecvOrigDstAdr = 74 // IPV6_RECVORIGDSTADDR
	maxInflight        = 256
)

var (
	listenAddr    = flag.String("l", "[::1]:15355", "TPROXY listen address")
	upstreamAddr  = flag.String("u", "[::1]:15353", "BlockAds engine address")
	engineTimeout = flag.Duration("engine-timeout", 2500*time.Millisecond, "time to wait for the engine")
	parentPID     = flag.Int("ppid", 0, "exit when this pid (the BlockAds process) is gone")
	parentName    = flag.String("pname", "app.pwhs.blockads", "expected cmdline prefix of -ppid")
	cleanupCmd    = flag.String("cleanup", "", "shell command run on exit (removes the redirect)")
	readyFile     = flag.String("ready", "", "file created once both sockets listen")
	verbose       = flag.Bool("v", false, "log every query")
)

var cleanupOnce sync.Once

func cleanup() {
	cleanupOnce.Do(func() {
		if *readyFile != "" {
			_ = os.Remove(*readyFile)
		}
		if *cleanupCmd == "" {
			return
		}
		out, err := exec.Command("/system/bin/sh", "-c", *cleanupCmd).CombinedOutput()
		if err != nil {
			log.Printf("cleanup: %v: %s", err, strings.TrimSpace(string(out)))
		}
	})
}

func fatal(format string, a ...any) {
	log.Printf("fatal: "+format, a...)
	cleanup()
	os.Exit(1)
}

// sockopts returns a Control func setting IPV6_TRANSPARENT and, optionally,
// IPV6_RECVORIGDSTADDR.
func sockopts(transparent, recvOrigDst bool) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			f := int(fd)
			if transparent {
				if serr = syscall.SetsockoptInt(f, syscall.SOL_IPV6, ipv6Transparent, 1); serr != nil {
					return
				}
				if serr = syscall.SetsockoptInt(f, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); serr != nil {
					return
				}
			}
			if recvOrigDst {
				serr = syscall.SetsockoptInt(f, syscall.SOL_IPV6, ipv6RecvOrigDstAdr, 1)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}

func origDst(oob []byte) (netip.AddrPort, bool) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, false
	}
	for _, m := range msgs {
		if m.Header.Level == syscall.SOL_IPV6 && m.Header.Type == ipv6RecvOrigDstAdr && len(m.Data) >= 24 {
			// struct sockaddr_in6: family(2) port(2) flowinfo(4) addr(16)
			port := binary.BigEndian.Uint16(m.Data[2:4])
			var a [16]byte
			copy(a[:], m.Data[8:24])
			return netip.AddrPortFrom(netip.AddrFrom16(a), port), true
		}
	}
	return netip.AddrPort{}, false
}

// exchange forwards a query to the engine. When the engine does not answer,
// the client gets SERVFAIL at once and its resolver moves on to the next
// server; the app watchdog restarts the engine, and the helper removes the
// redirect when BlockAds is gone.
func exchange(r *dns.Msg, network string, orig netip.AddrPort) *dns.Msg {
	engine := &dns.Client{Net: network, Timeout: *engineTimeout}
	resp, _, err := engine.Exchange(r, *upstreamAddr)
	if err == nil && resp != nil {
		return resp
	}
	if *verbose {
		log.Printf("engine %s for %s (orig %s): %v", network, qname(r), orig, err)
	}
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	return m
}

func qname(r *dns.Msg) string {
	if len(r.Question) == 0 {
		return "?"
	}
	return r.Question[0].Name
}

func serveTCP(ln net.Listener) {
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		// With TPROXY the accepted socket's local address is the original destination.
		var orig netip.AddrPort
		if la, ok := w.LocalAddr().(*net.TCPAddr); ok {
			orig = la.AddrPort()
		}
		resp := exchange(r, "tcp", orig)
		if *verbose {
			log.Printf("tcp %s from %s to %s", qname(r), w.RemoteAddr(), orig)
		}
		_ = w.WriteMsg(resp)
	})
	srv := &dns.Server{Listener: ln, Handler: h}
	if err := srv.ActivateAndServe(); err != nil {
		fatal("tcp server: %v", err)
	}
}

func serveUDP(uc *net.UDPConn) {
	sem := make(chan struct{}, maxInflight)
	buf := make([]byte, 65535)
	oob := make([]byte, 512)
	for {
		n, oobn, _, src, err := uc.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			fatal("udp read: %v", err)
		}
		dst, ok := origDst(oob[:oobn])
		pkt := append([]byte(nil), buf[:n]...)
		select {
		case sem <- struct{}{}:
		default:
			continue // overloaded: drop, the client retries
		}
		go func() {
			defer func() { <-sem }()
			r := new(dns.Msg)
			if r.Unpack(pkt) != nil || len(r.Question) == 0 {
				return
			}
			resp := exchange(r, "udp", dst)
			// Keep within the client's UDP size; it retries over TCP if truncated.
			size := dns.MinMsgSize
			if opt := r.IsEdns0(); opt != nil && int(opt.UDPSize()) > size {
				size = int(opt.UDPSize())
			}
			resp.Truncate(size)
			out, err := resp.Pack()
			if err != nil {
				return
			}
			if !ok {
				_, _ = uc.WriteToUDPAddrPort(out, src)
				return
			}
			// Reply from the original destination so the client accepts it.
			rc, err := (&net.ListenConfig{Control: sockopts(true, false)}).
				ListenPacket(context.Background(), "udp6", net.UDPAddrFromAddrPort(dst).String())
			if err != nil {
				log.Printf("bind %s: %v", dst, err)
				return
			}
			defer rc.Close()
			_, err = rc.(*net.UDPConn).WriteToUDPAddrPort(out, src)
			if *verbose {
				log.Printf("udp %s from %s to %s err=%v", qname(r), src, dst, err)
			}
		}()
	}
}

func parentAlive(pid int, name string) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return name == "" || strings.HasPrefix(string(b), name)
}

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	ln, err := (&net.ListenConfig{Control: sockopts(true, false)}).
		Listen(context.Background(), "tcp6", *listenAddr)
	if err != nil {
		fatal("listen tcp %s: %v", *listenAddr, err)
	}
	pc, err := (&net.ListenConfig{Control: sockopts(true, true)}).
		ListenPacket(context.Background(), "udp6", *listenAddr)
	if err != nil {
		fatal("listen udp %s: %v", *listenAddr, err)
	}
	go serveTCP(ln)
	go serveUDP(pc.(*net.UDPConn))

	if *readyFile != "" {
		_ = os.WriteFile(*readyFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644)
	}
	log.Printf("listening on %s, engine %s", *listenAddr, *upstreamAddr)

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case s := <-sigs:
			log.Printf("signal %v, exiting", s)
			cleanup()
			return
		case <-tick.C:
			if *parentPID > 0 && !parentAlive(*parentPID, *parentName) {
				log.Printf("BlockAds process %d gone, exiting", *parentPID)
				cleanup()
				return
			}
		}
	}
}
