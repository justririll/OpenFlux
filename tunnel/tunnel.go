package tunnel

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/utils"
)

type TCPTunnel struct {
	gvisorStack *stack.Stack
	tunnelEP    *TunnelLinkEndpoint
	transport   transport.Transport
	isExitNode  bool
	rawEP       *RawSocketEndpoint
	startTime   time.Time
	packetCount atomic.Uint64

	// droppedPackets counts packets the transport refused (full write queue,
	// or no connection). These used to vanish silently.
	droppedPackets atomic.Uint64
}

// TCP buffer size range for gvisor stacks. Big by default (exit node on a VPS);
// the memory-constrained iOS Network Extension shrinks these before building
// its stacks (see the packet-tunnel bridge).
var (
	TCPBufMin     = 65536
	TCPBufDefault = 262144
	TCPBufMax     = 1048576
)

// SetTCPBuffers applies the configured TCP send/receive buffer ranges to s.
func SetTCPBuffers(s *stack.Stack) {
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: TCPBufMin, Default: TCPBufDefault, Max: TCPBufMax}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv); err != nil {
		utils.Debugf("[TUNNEL] set recv buffer: %v", err)
	}
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: TCPBufMin, Default: TCPBufDefault, Max: TCPBufMax}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &snd); err != nil {
		utils.Debugf("[TUNNEL] set send buffer: %v", err)
	}
}

func NewTCPTunnel(trans transport.Transport, isExitNode bool) *TCPTunnel {
	t := &TCPTunnel{
		transport:  trans,
		isExitNode: isExitNode,
		startTime:  time.Now(),
	}

	utils.Debugf("[TUNNEL] Net stack init...")
	t.gvisorStack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

        SetTCPBuffers(t.gvisorStack)

	tunnelEP := NewTunnelLinkEndpoint()
	tunnelEP.onOutgoingPacket = t.sendToTransport
	t.tunnelEP = tunnelEP

	tunnelNIC := tcpip.NICID(1)
	if err := t.gvisorStack.CreateNIC(tunnelNIC, tunnelEP); err != nil {
		utils.Debugf("[TUNNEL] CreateNIC tunnel error: %v", err)
	}

	if isExitNode {
		t.setupExitNode(tunnelNIC)
	} else {
		t.setupClient(tunnelNIC)
	}

	trans.Receive(func(data []byte) {
		tunnelEP.InjectInbound(data)
	})

	utils.SafeGo("tunnel.printStats", t.printStats)
	return t
}

func (t *TCPTunnel) setupExitNode(tunnelNIC tcpip.NICID) {
	localIP := getLocalIP()
	utils.Debugf("[TUNNEL] EXIT NODE - Local IP: %s", localIP)

	rawEP, err := NewRawSocketEndpoint(tcpip.NICID(2))
	if err != nil {
		utils.Debugf("[TUNNEL] Raw socket error: %v", err)
		return
	}

	t.rawEP = rawEP
	rawEP.SetTransportSender(t.sendToTransport)

	internetNIC := tcpip.NICID(2)
	if err := t.gvisorStack.CreateNIC(internetNIC, rawEP); err != nil {
		utils.Debugf("[TUNNEL] CreateNIC internet error: %v", err)
		return
	}

	var ipBytes [4]byte
	fmt.Sscanf(localIP, "%d.%d.%d.%d", &ipBytes[0], &ipBytes[1], &ipBytes[2], &ipBytes[3])
	internetAddr := tcpip.AddrFrom4(ipBytes)
	t.gvisorStack.AddProtocolAddress(internetNIC, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   internetAddr,
			PrefixLen: 24,
		},
	}, stack.AddressProperties{})

	t.gvisorStack.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)
	t.gvisorStack.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         internetNIC,
	})

	tunnelSubnet := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom4([4]byte{10, 10, 10, 0}),
		PrefixLen: 24,
	}.Subnet()
	t.gvisorStack.AddRoute(tcpip.Route{
		Destination: tunnelSubnet,
		NIC:         tunnelNIC,
	})
}

func (t *TCPTunnel) setupClient(tunnelNIC tcpip.NICID) {
	clientAddr := tcpip.AddrFrom4([4]byte{10, 10, 10, 2})
	t.gvisorStack.AddProtocolAddress(tunnelNIC, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   clientAddr,
			PrefixLen: 24,
		},
	}, stack.AddressProperties{})

	t.gvisorStack.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         tunnelNIC,
	})
}

func (t *TCPTunnel) DialTCP(address string) (net.Conn, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}

	ip := tcpAddr.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("IPv6 not supported")
	}
	utils.Debugf("[TUNNEL] DialTCP %s -> %s:%d", address, ip.String(), tcpAddr.Port)

	nic := tcpip.NICID(1)
	if t.isExitNode {
		nic = tcpip.NICID(2)
	}

	conn, err := gonet.DialTCP(t.gvisorStack, tcpip.FullAddress{
		NIC:  nic,
		Addr: tcpip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]}),
		Port: uint16(tcpAddr.Port),
	}, ipv4.ProtocolNumber)

	return conn, err
}

func (t *TCPTunnel) ListenTCP(port uint16) (net.Listener, error) {
	return gonet.ListenTCP(t.gvisorStack, tcpip.FullAddress{
		NIC:  1,
		Port: port,
	}, ipv4.ProtocolNumber)
}

// sendToTransport hands one packet to the transport, counting refusals. The
// error used to be discarded at both call sites, so a full write queue or a
// disconnected transport dropped packets with no trace: the tunnel looked
// healthy in the logs while nothing was actually getting through.
func (t *TCPTunnel) sendToTransport(data []byte) {
	if err := t.transport.Send(data); err != nil {
		n := t.droppedPackets.Add(1)
		// First drop, then every hundredth: enough to spot an outage without
		// flooding the log during one.
		if n == 1 || n%100 == 0 {
			utils.Debugf("[TUNNEL] transport send failed (%d dropped so far): %v", n, err)
		}
	}
}

func (t *TCPTunnel) printStats() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := t.gvisorStack.Stats()
		utils.Debugf("[STATS] uptime=%v packets=%d dropped=%d connected=%d established=%d retrans=%d",
			time.Since(t.startTime).Round(time.Second),
			t.packetCount.Load(),
			t.droppedPackets.Load(),
			stats.TCP.CurrentConnected.Value(),
			stats.TCP.CurrentEstablished.Value(),
			stats.TCP.Retransmits.Value(),
		)
	}
}

// localIPOverride, when set, is the address the exit node uses as its egress
// IP (both for source rewriting and the return-packet filter). Point it at a
// dedicated alias IP so the RST-drop iptables rule can be scoped with
// `-s <ip>` instead of dropping RSTs host-wide.
var localIPOverride atomic.Value // string

// cachedLocalIP memoizes the auto-detected egress IP.
var cachedLocalIP atomic.Value // string

// fallbackLocalIP is used only when the address cannot be discovered at all.
const fallbackLocalIP = "192.168.1.100"

// SetLocalIP overrides the auto-detected egress IP for the exit node.
func SetLocalIP(ip string) { localIPOverride.Store(ip) }

// getLocalIP returns the exit node's egress IP.
//
// The result is cached because the raw socket calls this for every packet in
// both directions, and the discovery path opens and closes a UDP socket to
// learn the address. One socket per packet was enough syscall and fd churn to
// hurt an exit node under sustained load.
func getLocalIP() string {
	if ip, ok := localIPOverride.Load().(string); ok && ip != "" {
		return ip
	}
	if ip, ok := cachedLocalIP.Load().(string); ok && ip != "" {
		return ip
	}

	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		// Deliberately not cached: a transient failure must not pin the
		// wrong address for the lifetime of the process.
		return fallbackLocalIP
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP.String()
	cachedLocalIP.Store(ip)
	return ip
}
