package tunnel

import (
	"fmt"
	"net"
	"time"

	"github.com/sagernet/sing/common/control"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func getOriginalDst(tcpConn *net.TCPConn) (net.IP, int, error) {
	addrPort, err := control.GetOriginalDestination(tcpConn)
	if err != nil {
		return nil, 0, err
	}
	return net.IP(addrPort.Addr().AsSlice()), int(addrPort.Port()), nil
}

type transparentTCPConn struct {
	net.Conn
	id *stack.TransportEndpointID
}

func (c *transparentTCPConn) ID() *stack.TransportEndpointID {
	return c.id
}

func makeTransparentEndpointID(src, dst net.IP, srcPort, dstPort uint16) *stack.TransportEndpointID {
	addr := func(ip net.IP) tcpip.Address {
		if v4 := ip.To4(); v4 != nil {
			return tcpip.AddrFrom4Slice(v4)
		}
		return tcpip.AddrFrom16Slice(ip.To16())
	}
	return &stack.TransportEndpointID{
		LocalAddress:  addr(dst),
		LocalPort:     dstPort,
		RemoteAddress: addr(src),
		RemotePort:    srcPort,
	}
}

// transparentUIDResolver labels flows of a root-mode transparent listener.
// The engine runs as an ordinary app uid there and cannot resolve the
// owner of a redirected socket, so each listener stands for a policy:
// iptables sends browsers to one port (strict = never auto-bypass) and
// other MITM'd apps (YouTube…) to another; unresolved flows get a
// representative allowed UID of that policy.
type transparentUIDResolver struct {
	base   UIDResolver
	filter *MitmFilter
	strict bool
}

func (r *transparentUIDResolver) ResolveUID(protocol int, localIP string, localPort int, remoteIP string, remotePort int) int {
	if r.base != nil {
		uid := r.base.ResolveUID(protocol, localIP, localPort, remoteIP, remotePort)
		if uid > 0 && (r.filter == nil || r.filter.IsUIDAllowed(uid)) {
			return uid
		}
	}
	if r.filter != nil {
		if uid := r.filter.FirstAllowedUIDForPolicy(r.strict); uid > 0 {
			return uid
		}
	}
	return UIDUnknown
}

type transparentListeners struct {
	l4, l6 net.Listener
	done   chan struct{}
}

func (t *transparentListeners) close() {
	if t == nil {
		return
	}
	if t.l4 != nil {
		_ = t.l4.Close()
	}
	if t.l6 != nil {
		_ = t.l6.Close()
	}
	if t.done != nil {
		close(t.done)
	}
}

// startTransparentListeners listens on 127.0.0.1:port and [::1]:port and
// hands each redirected connection to the MITM handler.
func (e *Engine) startTransparentListeners(port int, strict bool) (*transparentListeners, error) {
	e.mu.Lock()
	certMgr := e.stackCertMgr
	filter := e.stackMitmFilter
	protectFn := e.protectFn
	uidr := &transparentUIDResolver{base: e.uidResolver, filter: filter, strict: strict}
	e.mu.Unlock()

	if certMgr == nil || filter == nil {
		return nil, fmt.Errorf("MITM engine not initialized; call StartStackMitm first")
	}

	addr4 := fmt.Sprintf("127.0.0.1:%d", port)
	l4, err := net.Listen("tcp4", addr4)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr4, err)
	}
	addr6 := fmt.Sprintf("[::1]:%d", port)
	l6, err6 := net.Listen("tcp6", addr6)
	if err6 != nil {
		logf("Transparent MITM IPv6 listen skipped: %v", err6)
		l6 = nil
	}
	t := &transparentListeners{l4: l4, l6: l6, done: make(chan struct{})}
	tcpHandler := newMitmTcpHandler(certMgr, filter, e, uidr, protectFn)

	serve := func(l net.Listener) {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-t.done:
					return
				default:
					time.Sleep(50 * time.Millisecond)
					continue
				}
			}
			tcpConn, ok := conn.(*net.TCPConn)
			if !ok {
				conn.Close()
				continue
			}
			go func(c *net.TCPConn) {
				origIP, origPort, err := getOriginalDst(c)
				if err != nil || origPort == 0 {
					logf("Transparent proxy failed to get original dst: %v", err)
					c.Close()
					return
				}
				remoteAddr := c.RemoteAddr().(*net.TCPAddr)
				tcpHandler(&transparentTCPConn{
					Conn: c,
					id: makeTransparentEndpointID(
						remoteAddr.IP,
						origIP,
						uint16(remoteAddr.Port),
						uint16(origPort),
					),
				})
			}(tcpConn)
		}
	}
	go serve(l4)
	if l6 != nil {
		go serve(l6)
		logf("Transparent MITM proxy (strict=%v) listening on %s and %s", strict, addr4, addr6)
	} else {
		logf("Transparent MITM proxy (strict=%v) listening on %s", strict, addr4)
	}
	return t, nil
}

// StartTransparentMitm starts the transparent TCP MITM proxy on
// 127.0.0.1:port (and [::1]:port) for browsers: a client handshake
// failure there never adds the host to the bypass list.
func (e *Engine) StartTransparentMitm(port int) error {
	e.mu.Lock()
	running := e.standaloneMitmListener != nil
	e.mu.Unlock()
	if running {
		return nil
	}
	t, err := e.startTransparentListeners(port, true)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.standaloneMitmListener = t.l4
	e.standaloneMitmListener6 = t.l6
	e.standaloneMitmDone = t.done
	e.mu.Unlock()
	return nil
}

// StartTransparentMitmNonBrowser starts a second transparent MITM listener
// for the non-browser apps in the MITM set (e.g. YouTube). Flows there
// count as non-browser: when the client rejects the BlockAds certificate
// the host is added to mitm_blacklist.txt (persisted) so the app works on
// its next connection. Requires SetMitmNoAutoBypassUIDs with the browser
// UIDs. Stopped by StopTransparentMitm.
func (e *Engine) StartTransparentMitmNonBrowser(port int) error {
	e.mu.Lock()
	running := e.nonBrowserMitm != nil
	e.mu.Unlock()
	if running {
		return nil
	}
	t, err := e.startTransparentListeners(port, false)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.nonBrowserMitm = t
	e.mu.Unlock()
	return nil
}

// StopTransparentMitm stops the transparent TCP MITM proxies.
func (e *Engine) StopTransparentMitm() {
	e.mu.Lock()
	t := &transparentListeners{l4: e.standaloneMitmListener, l6: e.standaloneMitmListener6, done: e.standaloneMitmDone}
	e.standaloneMitmListener = nil
	e.standaloneMitmListener6 = nil
	e.standaloneMitmDone = nil
	nb := e.nonBrowserMitm
	e.nonBrowserMitm = nil
	e.mu.Unlock()
	t.close()
	nb.close()
}
