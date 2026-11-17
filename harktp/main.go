package main

// harktp: transparent IPv6 DNS forwarder (TPROXY test helper).
// UDP: reads IPV6_ORIGDSTADDR and replies from the original destination
// via a transparent socket, so the client accepts the answer.
import (
	"context"
	"encoding/binary"
	"flag"
	"log"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const (
	ipv6Transparent    = 75
	ipv6RecvOrigDstAdr = 74
)

func ctl(recv bool) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, ipv6Transparent, 1); serr != nil {
				return
			}
			if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); serr != nil {
				return
			}
			if recv {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, ipv6RecvOrigDstAdr, 1)
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
			port := binary.BigEndian.Uint16(m.Data[2:4])
			var a [16]byte
			copy(a[:], m.Data[8:24])
			return netip.AddrPortFrom(netip.AddrFrom16(a), port), true
		}
	}
	return netip.AddrPort{}, false
}

func forward(up string, r *dns.Msg, netw string) *dns.Msg {
	cl := &dns.Client{Net: netw, Timeout: 4 * time.Second}
	resp, _, err := cl.Exchange(r, up)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		return m
	}
	return resp
}

func main() {
	listen := flag.String("l", "[::1]:15354", "listen")
	up := flag.String("u", "[::1]:15353", "upstream")
	flag.Parse()
	ln, err := (&net.ListenConfig{Control: ctl(false)}).Listen(context.Background(), "tcp6", *listen)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			resp := forward(*up, r, "tcp")
			log.Printf("tcp q=%s from=%s orig=%s", r.Question[0].Name, w.RemoteAddr(), w.LocalAddr())
			w.WriteMsg(resp)
		})
		log.Fatal((&dns.Server{Listener: ln, Handler: h}).ActivateAndServe())
	}()
	pc, err := (&net.ListenConfig{Control: ctl(true)}).ListenPacket(context.Background(), "udp6", *listen)
	if err != nil {
		log.Fatal(err)
	}
	uc := pc.(*net.UDPConn)
	log.Printf("listening %s", *listen)
	buf := make([]byte, 65535)
	oob := make([]byte, 512)
	for {
		n, oobn, _, src, err := uc.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			log.Fatal(err)
		}
		dst, ok := origDst(oob[:oobn])
		pkt := append([]byte(nil), buf[:n]...)
		go func() {
			r := new(dns.Msg)
			if r.Unpack(pkt) != nil || len(r.Question) == 0 {
				return
			}
			resp := forward(*up, r, "udp")
			out, _ := resp.Pack()
			if !ok {
				log.Printf("udp q=%s from=%s NO ORIGDST", r.Question[0].Name, src)
				uc.WriteToUDPAddrPort(out, src)
				return
			}
			rc, err := (&net.ListenConfig{Control: ctl(false)}).ListenPacket(context.Background(), "udp6", net.UDPAddrFromAddrPort(dst).String())
			if err != nil {
				log.Printf("udp bind orig %s: %v", dst, err)
				return
			}
			defer rc.Close()
			_, err = rc.(*net.UDPConn).WriteToUDPAddrPort(out, src)
			log.Printf("udp q=%s from=%s orig=%s err=%v", r.Question[0].Name, src, dst, err)
		}()
	}
}
