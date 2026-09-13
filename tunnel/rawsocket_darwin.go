package tunnel

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"universal-bypass-tool/network"
	"universal-bypass-tool/utils"
)

const (
	// synTTL is how long an unanswered outgoing SYN is remembered. A SYN-ACK
	// arriving later than this is beyond any realistic retry window, so the
	// entry can never be matched again - it would only sit in the map for the
	// life of the process.
	synTTL = 2 * time.Minute

	// portTTL bounds how long a port stays active with no traffic at all. A
	// connection torn down without a FIN or RST (the peer vanished, the
	// tunnel dropped) used to hold its entry forever. Matched to the Linux
	// default TCP keep-alive time so a legitimately idle connection is
	// refreshed long before it expires.
	portTTL = 2 * time.Hour

	// portTouchInterval is the minimum gap between refreshes of one port's
	// last-seen time. sync.Map writes are far costlier than reads and this
	// sits on the per-packet path, so refresh at most once per interval.
	portTouchInterval = time.Minute

	// sweepInterval is how often expired tracking entries are reaped.
	sweepInterval = time.Minute

	// rawRecvBufBytes is the receive buffer requested for the raw socket.
	// Every raw TCP socket on the host gets a copy of every TCP packet, so
	// with several exit nodes on one machine the default (208KB on Linux)
	// overflows in bursts and the kernel silently discards tunnel traffic.
	rawRecvBufBytes = 8 << 20

	// maxConsecutiveReadErrors bounds how long the reader keeps retrying a
	// raw socket that only ever returns errors, so a genuinely dead fd does
	// not become a hot spin loop.
	maxConsecutiveReadErrors = 100
)

type RawSocketEndpoint struct {
	dispatcher      stack.NetworkDispatcher
	sendFd          int
	recvFd          int
	nicID           tcpip.NICID
	packetIn        atomic.Uint64
	packetOut       atomic.Uint64
	outgoingSYNs    sync.Map
	activePorts     sync.Map
	sendToTransport func([]byte)
}

func NewRawSocketEndpoint(nicID tcpip.NICID) (*RawSocketEndpoint, error) {
	sendFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("send socket failed: %v (need root)", err)
	}

	if err := syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(sendFd)
		return nil, fmt.Errorf("IP_HDRINCL: %v", err)
	}

	recvFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		syscall.Close(sendFd)
		return nil, fmt.Errorf("recv socket failed: %v (need root)", err)
	}

	addr := &syscall.SockaddrInet4{
		Addr: [4]byte{0, 0, 0, 0},
		Port: 0,
	}
	if err := syscall.Bind(recvFd, addr); err != nil {
		syscall.Close(sendFd)
		syscall.Close(recvFd)
		return nil, fmt.Errorf("bind failed: %v", err)
	}

	setLargeRecvBuffer(recvFd, nicID)

	ep := &RawSocketEndpoint{
		sendFd: sendFd,
		recvFd: recvFd,
		nicID:  nicID,
	}

	go ep.readLoop()
	go ep.sweepLoop()
	return ep, nil
}

// setLargeRecvBuffer grows the raw socket's receive buffer. Dropped packets
// here are invisible - the kernel just discards them and the tunnel sees
// unexplained loss - so this is worth doing even when it only partly succeeds.
func setLargeRecvBuffer(fd int, nicID tcpip.NICID) {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, rawRecvBufBytes); err != nil {
		utils.Debugf("[RAW-NIC%d] Could not grow the receive buffer: %v", nicID, err)
	}
}

func (e *RawSocketEndpoint) SetTransportSender(sendFunc func([]byte)) {
	e.sendToTransport = sendFunc
}

func (e *RawSocketEndpoint) readLoop() {
	buf := make([]byte, 65535)
	consecutiveErrors := 0

	for {
		n, _, err := syscall.Recvfrom(e.recvFd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			// EINTR just means a signal arrived mid-syscall. Returning on it
			// killed the exit node's entire inbound path for the life of the
			// process: replies stopped being decapsulated, every tunnelled
			// connection hung, and only a restart brought it back.
			if err == syscall.EINTR {
				continue
			}
			if err == syscall.EBADF {
				utils.Debugf("[RAW-NIC%d] Receive socket closed, stopping reader", e.nicID)
				return
			}
			consecutiveErrors++
			if consecutiveErrors > maxConsecutiveReadErrors {
				utils.Debugf("[RAW-NIC%d] Giving up after %d consecutive read errors: %v",
					e.nicID, consecutiveErrors, err)
				return
			}
			utils.Debugf("[RAW-NIC%d] Read error (%d in a row): %v", e.nicID, consecutiveErrors, err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		consecutiveErrors = 0

		if n < 40 {
			continue
		}

		protocol := buf[9]
		flags := buf[33]
		dstIP := net.IP(buf[16:20])
		localIP := getLocalIP()

		if protocol == 6 && dstIP.String() == localIP {
			dstPort := uint16(buf[22])<<8 | uint16(buf[23])

			if _, active := e.activePorts.Load(dstPort); !active {
				continue
			}
			e.touchPort(dstPort)

			if flags == 0x12 {
				ackNum := uint32(buf[28])<<24 | uint32(buf[29])<<16 | uint32(buf[30])<<8 | uint32(buf[31])
				synSeq := ackNum - 1

				if _, ok := e.outgoingSYNs.Load(synSeq); !ok {
					continue
				}
				e.outgoingSYNs.Delete(synSeq)
			}

			pktCopy := make([]byte, n)
			copy(pktCopy, buf[:n])

			copy(pktCopy[16:20], []byte{10, 10, 10, 2})

			pktCopy[10] = 0
			pktCopy[11] = 0
			ipChecksumVal := network.IPChecksum(pktCopy[:20])
			pktCopy[10] = byte(ipChecksumVal >> 8)
			pktCopy[11] = byte(ipChecksumVal & 0xFF)

			ipHeaderLen := int(pktCopy[0]&0x0F) * 4
			tcpHeader := pktCopy[ipHeaderLen:]
			srcIPBytes := [4]byte{pktCopy[12], pktCopy[13], pktCopy[14], pktCopy[15]}
			dstIPBytes := [4]byte{pktCopy[16], pktCopy[17], pktCopy[18], pktCopy[19]}
			tcpHeader[16] = 0
			tcpHeader[17] = 0
			tcpChecksumVal := network.TCPChecksum(tcpHeader, srcIPBytes, dstIPBytes)
			tcpHeader[16] = byte(tcpChecksumVal >> 8)
			tcpHeader[17] = byte(tcpChecksumVal & 0xFF)

			if e.sendToTransport != nil {
				e.sendToTransport(pktCopy)
			}
		}
	}
}

func (e *RawSocketEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		ipPacket := pkt.ToView().ToSlice()
		if len(ipPacket) < 40 {
			continue
		}

		pktCopy := make([]byte, len(ipPacket))
		copy(pktCopy, ipPacket)

		localIP := getLocalIP()
		var localIPBytes [4]byte
		fmt.Sscanf(localIP, "%d.%d.%d.%d", &localIPBytes[0], &localIPBytes[1], &localIPBytes[2], &localIPBytes[3])
		copy(pktCopy[12:16], localIPBytes[:])

		pktCopy[10] = 0
		pktCopy[11] = 0
		ipChecksumVal := network.IPChecksum(pktCopy[:20])
		pktCopy[10] = byte(ipChecksumVal >> 8)
		pktCopy[11] = byte(ipChecksumVal & 0xFF)

		ipHeaderLen := int(pktCopy[0]&0x0F) * 4
		tcpHeader := pktCopy[ipHeaderLen:]
		srcIPBytes := [4]byte{pktCopy[12], pktCopy[13], pktCopy[14], pktCopy[15]}
		dstIPBytes := [4]byte{pktCopy[16], pktCopy[17], pktCopy[18], pktCopy[19]}
		tcpHeader[16] = 0
		tcpHeader[17] = 0
		tcpChecksumVal := network.TCPChecksum(tcpHeader, srcIPBytes, dstIPBytes)
		tcpHeader[16] = byte(tcpChecksumVal >> 8)
		tcpHeader[17] = byte(tcpChecksumVal & 0xFF)

		srcPort := uint16(tcpHeader[0])<<8 | uint16(tcpHeader[1])

		if tcpHeader[13]&0x02 != 0 {
			seqNum := uint32(tcpHeader[4])<<24 | uint32(tcpHeader[5])<<16 | uint32(tcpHeader[6])<<8 | uint32(tcpHeader[7])
			e.outgoingSYNs.Store(seqNum, time.Now())
			e.activePorts.Store(srcPort, time.Now())
		} else {
			e.touchPort(srcPort)
		}

		if tcpHeader[13]&0x01 != 0 || tcpHeader[13]&0x04 != 0 {
			dstPort := uint16(tcpHeader[2])<<8 | uint16(tcpHeader[3])
			e.activePorts.Delete(dstPort)
		}

		var dst [4]byte
		copy(dst[:], pktCopy[16:20])

		addr := &syscall.SockaddrInet4{
			Addr: dst,
			Port: 0,
		}

		if err := syscall.Sendto(e.sendFd, pktCopy, 0, addr); err != nil {
			utils.Debugf("[RAW-NIC%d] Sendto failed: %v", e.nicID, err)
			continue
		}

		e.packetOut.Add(1)
		n++
	}
	return n, nil
}

// touchPort refreshes a live port's last-seen time. It never creates an
// entry: only an outgoing SYN opens a port, so a stray packet cannot resurrect
// one that was closed by a FIN or RST.
func (e *RawSocketEndpoint) touchPort(port uint16) {
	seen, ok := e.activePorts.Load(port)
	if !ok {
		return
	}
	if at, ok := seen.(time.Time); ok && time.Since(at) < portTouchInterval {
		return
	}
	e.activePorts.Store(port, time.Now())
}

// sweepLoop reaps tracking entries that can no longer be matched. Both maps
// used to grow for the life of the process: an outgoing SYN that never drew a
// SYN-ACK was never removed, and a port whose connection died without a FIN or
// RST kept its entry forever. On a long-running exit node that is an unbounded
// leak.
func (e *RawSocketEndpoint) sweepLoop() {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for range ticker.C {
		expire := func(m *sync.Map, ttl time.Duration) int {
			dropped := 0
			m.Range(func(key, value any) bool {
				at, ok := value.(time.Time)
				if !ok || time.Since(at) > ttl {
					m.Delete(key)
					dropped++
				}
				return true
			})
			return dropped
		}

		syns := expire(&e.outgoingSYNs, synTTL)
		ports := expire(&e.activePorts, portTTL)
		if syns > 0 || ports > 0 {
			utils.Debugf("[RAW-NIC%d] swept %d stale SYNs, %d stale ports", e.nicID, syns, ports)
		}
	}
}

func (e *RawSocketEndpoint) MTU() uint32                                 { return 1500 }
func (e *RawSocketEndpoint) MaxHeaderLength() uint16                      { return 0 }
func (e *RawSocketEndpoint) LinkAddress() tcpip.LinkAddress               { return "" }
func (e *RawSocketEndpoint) Capabilities() stack.LinkEndpointCapabilities { return stack.CapabilityNone }
func (e *RawSocketEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}
func (e *RawSocketEndpoint) IsAttached() bool                             { return e.dispatcher != nil }
func (e *RawSocketEndpoint) Wait()                                        {}
func (e *RawSocketEndpoint) ARPHardwareType() header.ARPHardwareType      { return header.ARPHardwareNone }
func (e *RawSocketEndpoint) AddHeader(*stack.PacketBuffer)                {}
func (e *RawSocketEndpoint) Close() {
	syscall.Close(e.sendFd)
	syscall.Close(e.recvFd)
}
func (e *RawSocketEndpoint) SetMTU(uint32)                                {}
func (e *RawSocketEndpoint) SetLinkAddress(tcpip.LinkAddress)             {}
func (e *RawSocketEndpoint) ParseHeader(*stack.PacketBuffer) bool         { return true }
func (e *RawSocketEndpoint) SetOnCloseAction(func())                      {}
