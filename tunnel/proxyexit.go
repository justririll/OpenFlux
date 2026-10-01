package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"universal-bypass-tool/utils"
)

// Proxy egress: an exit node that hands the client's connections to a SOCKS5
// proxy instead of putting raw packets on the wire.
//
// The raw-socket exit needs root (or the WinDivert driver on Windows) and a
// host-wide RST drop, and its traffic leaves from the machine's own address.
// In proxy mode the gvisor stack terminates every TCP connection the client
// opens - whatever its destination - and dials that destination through the
// proxy, then splices the two. No privileges, no driver, no RST rule, and the
// traffic exits wherever the proxy does: e.g. a local v2rayN/xray SOCKS port
// that carries it on to a hysteria2 server.

// EgressDialer opens an outbound TCP connection for the exit node.
type EgressDialer func(ctx context.Context, address string) (net.Conn, error)

var egressDialer EgressDialer

// SetEgressProxy switches every exit node created afterwards to proxy egress
// through the SOCKS5 proxy at proxyURL (socks5://host:port).
func SetEgressProxy(proxyURL string) error {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return err
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return fmt.Errorf("unsupported proxy scheme %q (want socks5://host:port)", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("proxy address missing (want socks5://host:port)")
	}
	proxyAddr := u.Host
	egressDialer = func(ctx context.Context, address string) (net.Conn, error) {
		return socks5Connect(ctx, proxyAddr, address)
	}
	return nil
}

const (
	// egressDialTimeout bounds connecting through the proxy; the client's
	// own TCP stack is retransmitting its SYN meanwhile.
	egressDialTimeout = 20 * time.Second
	// egressMaxInFlight caps half-open connections awaiting their dial, the
	// same congestion guard the client side applies.
	egressMaxInFlight = 512
)

// setupProxyExit makes the tunnel NIC accept connections to any address and
// forwards each through egressDialer.
func (t *TCPTunnel) setupProxyExit(tunnelNIC tcpip.NICID) {
	s := t.gvisorStack
	// Accept packets addressed anywhere, and answer from those addresses.
	if err := s.SetPromiscuousMode(tunnelNIC, true); err != nil {
		utils.Debugf("[TUNNEL] promiscuous: %v", err)
	}
	if err := s.SetSpoofing(tunnelNIC, true); err != nil {
		utils.Debugf("[TUNNEL] spoofing: %v", err)
	}
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: tunnelNIC})

	fwd := tcp.NewForwarder(s, 0, egressMaxInFlight, t.forwardViaProxy)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}

// forwardViaProxy runs per incoming connection, on its own goroutine.
func (t *TCPTunnel) forwardViaProxy(r *tcp.ForwarderRequest) {
	id := r.ID()
	target := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))

	// Dial before accepting, so an unreachable destination is refused with a
	// RST just as it would be on the open internet.
	ctx, cancel := context.WithTimeout(context.Background(), egressDialTimeout)
	upstream, err := egressDialer(ctx, target)
	cancel()
	if err != nil {
		utils.Debugf("[EGRESS] %s: %v", target, err)
		r.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		upstream.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)
	downstream := gonet.NewTCPConn(&wq, ep)
	utils.Debugf("[EGRESS] %s connected", target)
	spliceConns(downstream, upstream)
}

// spliceConns copies both ways until either side finishes, then closes both.
func spliceConns(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() {
		a.Close()
		b.Close()
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		once.Do(closeBoth)
	}()
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		once.Do(closeBoth)
	}()
	wg.Wait()
}

// socks5Connect opens target (an IP:port) through a no-auth SOCKS5 proxy.
func socks5Connect(ctx context.Context, proxyAddr, target string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", proxyAddr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	fail := func(err error) (net.Conn, error) {
		conn.Close()
		return nil, err
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fail(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fail(err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return fail(fmt.Errorf("not an IPv4 target: %s", target))
	}

	// Greeting: version 5, one method, no authentication.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fail(err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		return fail(err)
	}
	if sel[0] != 0x05 || sel[1] != 0x00 {
		return fail(fmt.Errorf("proxy refused no-auth (method 0x%02x)", sel[1]))
	}

	req := []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], 0, 0}
	binary.BigEndian.PutUint16(req[8:], uint16(port))
	if _, err := conn.Write(req); err != nil {
		return fail(err)
	}

	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fail(err)
	}
	if head[1] != 0x00 {
		return fail(fmt.Errorf("proxy CONNECT failed (reply 0x%02x)", head[1]))
	}
	// Skip the bound address.
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return fail(err)
		}
		skip = int(l[0])
	default:
		return fail(fmt.Errorf("proxy reply has address type 0x%02x", head[3]))
	}
	if _, err := io.ReadFull(conn, make([]byte, skip+2)); err != nil {
		return fail(err)
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}
