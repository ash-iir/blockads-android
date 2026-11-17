package main

import (
	"context"
	"flag"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

func transparent(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, 75 /*IPV6_TRANSPARENT*/, 1)
	})
	if err != nil {
		return err
	}
	return serr
}

func main() {
	listen := flag.String("l", "[::1]:15354", "listen")
	up := flag.String("u", "[::1]:15353", "upstream")
	flag.Parse()
	lc := net.ListenConfig{Control: transparent}
	pc, err := lc.ListenPacket(context.Background(), "udp6", *listen)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := lc.Listen(context.Background(), "tcp6", *listen)
	if err != nil {
		log.Fatal(err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		cl := &dns.Client{Net: "udp", Timeout: 4 * time.Second}
		resp, _, err := cl.Exchange(r, *up)
		q := ""
		if len(r.Question) > 0 {
			q = r.Question[0].Name
		}
		log.Printf("q=%s from=%s local=%s err=%v", q, w.RemoteAddr(), w.LocalAddr(), err)
		if err != nil {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
			return
		}
		w.WriteMsg(resp)
	})
	go func() { log.Fatal((&dns.Server{Listener: ln, Handler: h}).ActivateAndServe()) }()
	log.Printf("listening %s", *listen)
	log.Fatal((&dns.Server{PacketConn: pc, Handler: h}).ActivateAndServe())
}
