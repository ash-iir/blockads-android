package main

import (
	"fmt"
	"os"
	"time"

	"github.com/miekg/dns"
)

// usage: dnsq <server host:port> <name> [type] [udp|tcp]
func main() {
	srv, name := os.Args[1], os.Args[2]
	t := dns.TypeA
	if len(os.Args) > 3 {
		t = dns.StringToType[os.Args[3]]
	}
	netw := "udp"
	if len(os.Args) > 4 {
		netw = os.Args[4]
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), t)
	c := &dns.Client{Net: netw, Timeout: 5 * time.Second}
	r, rtt, err := c.Exchange(m, srv)
	if err != nil {
		fmt.Printf("%s %s ERR %v\n", srv, name, err)
		os.Exit(1)
	}
	fmt.Printf("%s %s %s rcode=%s rtt=%v\n", srv, name, dns.TypeToString[t], dns.RcodeToString[r.Rcode], rtt)
	for _, a := range r.Answer {
		fmt.Println("  ", a.String())
	}
}
