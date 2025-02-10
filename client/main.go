package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"sort"
	"syscall"

	"github.com/on-keyday/dplane_importer/client/routing"
	"golang.org/x/sys/unix"
)

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func createRawSocket(ifIndex int) (fd int, err error) {
	fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return -1, err
	}
	// bind to the interface
	sll := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  ifIndex,
	}
	err = syscall.Bind(fd, &sll)
	if err != nil {
		syscall.Close(fd)
		return -1, err
	}
	// set promiscuous mode
	err = unix.SetsockoptPacketMreq(fd, syscall.SOL_PACKET, syscall.PACKET_ADD_MEMBERSHIP, &unix.PacketMreq{
		Ifindex: int32(ifIndex),
		Type:    syscall.PACKET_MR_PROMISC,
	})
	if err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

type tcpTuple struct {
	src netip.AddrPort
	dst netip.AddrPort
}

type segment struct {
	seqNum uint32
	data   []byte
}

type tcpConn struct {
	state       routing.Tcpstate
	recvBuf     []byte
	recvSegment []segment
	recvSeqNum  uint32
	sendBuf     []byte
	sentIndex   uint32
	sendSeqNum  uint32
}

type routingEntry struct {
	dstNetwork netip.Prefix
	nextHop    netip.Addr
	dev        *Device
}

type RoutingTable struct {
	entries []routingEntry
}

func (r *RoutingTable) Lookup(dst netip.Addr) *routingEntry {
	for _, entry := range r.entries {
		if entry.dstNetwork.Contains(dst) {
			return &entry
		}
	}
	return nil
}

func (r *RoutingTable) AddEntry(dst netip.Prefix, nextHop netip.Addr, dev *Device) {
	r.entries = append(r.entries, routingEntry{
		dstNetwork: dst,
		nextHop:    nextHop,
		dev:        dev,
	})
	// order by longest prefix match
	sort.Slice(r.entries, func(i, j int) bool {
		return r.entries[i].dstNetwork.Bits() > r.entries[j].dstNetwork.Bits()
	})
}

type handler struct {
	tcpConns  map[tcpTuple]*tcpConn
	listening map[netip.AddrPort]struct{}
	w         io.Writer
	devices   []*Device
	routing   *RoutingTable
}

func (conn *tcpConn) addSegment(seqNum uint32, data []byte) {
	conn.recvSegment = append(conn.recvSegment, segment{
		seqNum: seqNum,
		data:   data,
	})

}

func (h *handler) sendTCP(src, dst netip.AddrPort, flags routing.Tcpflags, seq, ack uint32, data []byte) {
	tcp := &routing.Tcpheader{}
	tcp.SrcPort = src.Port()
	tcp.DstPort = dst.Port()
	tcp.SeqNum = seq
	tcp.AckNum = ack
	tcp.Flags = flags
	tcp.WindowSize = 65535
	tcp.UrgentPointer = 0
	enc := tcp.MustEncode()
	enc = append(enc, data...)
	h.writeIP(src.Addr(), dst.Addr(), routing.ProtocolNumber_Tcp, enc)
}

func flags(ack bool, syn bool) routing.Tcpflags {
	var f routing.Tcpflags
	if ack {
		f.SetAck(true)
	}
	if syn {
		f.SetSyn(true)
	}
	return f
}

func (h *handler) handleTCP(ip *routing.Ipv6Header, tcp *routing.Tcpheader, payload []byte) {
	tuple := tcpTuple{
		src: netip.AddrPortFrom(netip.AddrFrom16(ip.SrcAddr), tcp.SrcPort),
		dst: netip.AddrPortFrom(netip.AddrFrom16(ip.DstAddr), tcp.DstPort),
	}
	var conn *tcpConn
	if _, ok := h.tcpConns[tuple]; !ok {
		if _, ok := h.listening[tuple.dst]; !ok {
			fmt.Fprintf(h.w, "unknown connection: %v\n", tuple)
			return
		}
		conn = &tcpConn{
			state: routing.Tcpstate_Listen,
		}
		h.tcpConns[tuple] = conn
	}
	conn = h.tcpConns[tuple]
	switch conn.state {
	case routing.Tcpstate_Listen:
		if tcp.Flags.Syn() {
			conn.state = routing.Tcpstate_SynRcvd
			conn.sendSeqNum = 0
			h.sendTCP(tuple.dst, tuple.src, flags(true, true), 0, conn.recvSeqNum, nil)
		} else {
			fmt.Fprintf(h.w, "unexpected packet: %v\n", tcp)
			delete(h.tcpConns, tuple)
		}
	case routing.Tcpstate_SynSent:
		if tcp.Flags.Syn() && tcp.Flags.Ack() {
			conn.state = routing.Tcpstate_Established
			conn.recvSeqNum = tcp.SeqNum + 1
			h.sendTCP(tuple.dst, tuple.src, flags(true, false), conn.recvSeqNum, tcp.SeqNum+1, nil)
		} else {
			fmt.Fprintf(h.w, "unexpected packet: %v\n", tcp)
			delete(h.tcpConns, tuple)
		}
	case routing.Tcpstate_SynRcvd:
		if tcp.Flags.Ack() {
			conn.state = routing.Tcpstate_Established
		} else {
			fmt.Fprintf(h.w, "unexpected packet: %v\n", tcp)
			delete(h.tcpConns, tuple)
		}
	case routing.Tcpstate_Established:
		if tcp.Flags.Fin() {
			conn.state = routing.Tcpstate_CloseWait
			h.sendTCP(tuple.dst, tuple.src, flags(true, true), 0, tcp.SeqNum+1, nil)
		}
		conn.recvBuf = append(conn.recvBuf, payload...)
		if tcp.Flags.Ack() {
			conn.sendBuf = conn.sendBuf[tcp.AckNum-conn.sentIndex:]
		}
	case routing.Tcpstate_CloseWait:
		if tcp.Flags.Ack() {
			conn.state = routing.Tcpstate_Closed
			delete(h.tcpConns, tuple)
		} else {
			fmt.Fprintf(h.w, "unexpected packet: %v\n", tcp)
			delete(h.tcpConns, tuple)
		}
	default:
		fmt.Fprintf(h.w, "unexpected state: %v\n", conn.state)
		delete(h.tcpConns, tuple)
	}
}

func (h *handler) Listen(addr netip.AddrPort) {
	h.listening[addr] = struct{}{}
}

func (h *handler) Connect(src, dst netip.AddrPort) {
	h.tcpConns[tcpTuple{
		src: src,
		dst: dst,
	}] = &tcpConn{
		state: routing.Tcpstate_SynSent,
	}
	h.sendTCP(src, dst, flags(false, true), 0, 0, nil)
}

func (h *handler) writeEthernet(dst net.HardwareAddr, data []byte) {
	eth := &routing.EthernetFrame{}
	eth.EtherType = uint16(routing.EtherType_Ipv6)
	eth.DstMac = [6]byte(dst)
	eth.SetData(data)

}

func (h *handler) writeIP(src, dst netip.Addr, proto routing.ProtocolNumber, data []byte) {
	hdr := &routing.Ipv6Header{}
	hdr.SrcAddr = src.As16()
	hdr.DstAddr = dst.As16()
	hdr.NextHeader = proto
	hdr.HopLimit = 64
	hdr.PayloadLen = uint16(len(data))
	hdr.SetVersion(6)
	hdr.SetFlowLabel(0)
	hdr.SetTrafficClass(0)
	enc := hdr.MustEncode()
	enc = append(enc, data...)
	et := h.routing.Lookup(dst)
	if et == nil {
		fmt.Fprintf(h.w, "no route to %v\n", dst)
		return
	}
	h.writeEthernet(et.dev.addr, enc)
}

func (h *handler) parsePacket(p []byte) error {
	eth := &routing.EthernetFrame{}
	err := eth.DecodeExact(p)
	if err != nil {
		return err
	}
	data := *eth.Data()
	switch eth.EtherType {
	case uint16(routing.EtherType_Ipv6):
		ipv6 := &routing.Ipv6Header{}
		read, err := ipv6.Decode(data)
		if err != nil {
			return fmt.Errorf("failed to decode IPv6 header: %v", err)
		}
		data = data[read:]
		switch ipv6.NextHeader {
		case routing.ProtocolNumber_RoutingHeader:
			r := &routing.SegmentRouting{}
			read, err := r.Decode(data)
			if err != nil {
				return fmt.Errorf("failed to decode Segment Routing header: %v", err)
			}
			data = data[read:]
			if len(r.SegmentList) > int(r.SegmentsLeft) {
				return fmt.Errorf("invalid segment list: %v", r.SegmentList)
			}
			current := r.SegmentList[r.SegmentsLeft]
			addr := netip.AddrFrom16(current)
			fmt.Fprintf(h.w, "current address: %v\n", addr)
		case routing.ProtocolNumber_Icmpv6:
			r := &routing.Icmpv6Packet{}
			read, err := r.Decode(data)
			if err != nil {
				return fmt.Errorf("failed to decode ICMPv6 packet: %v", err)
			}
			data = data[read:]
		case routing.ProtocolNumber_Tcp:
			tcp := &routing.Tcpheader{}
			read, err := tcp.Decode(data)
			if err != nil {
				return fmt.Errorf("failed to decode TCP header: %v", err)
			}
			data = data[read:]
			h.handleTCP(ipv6, tcp, data)
		}
	}
	return nil
}

type Device struct {
	fd    int
	addr  net.HardwareAddr
	addrs []netip.Addr
}

func NewHandler(devices []*Device, w io.Writer) *handler {
	h := &handler{
		devices:   devices,
		tcpConns:  make(map[tcpTuple]*tcpConn),
		listening: make(map[netip.AddrPort]struct{}),
		w:         w,
		routing:   &RoutingTable{},
	}
	return h
}

var isServer = flag.Bool("server", false, "run as server")
var connectTo = flag.String("connect", "", "connect to address")

func main() {
	flag.Parse()
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("failed to get interfaces:", err)
		return
	}
	epoll, err := syscall.EpollCreate1(0)
	if err != nil {
		fmt.Println("failed to create epoll instance:", err)
		return
	}
	defer syscall.Close(epoll)
	var devs []*Device
	for _, iface := range ifaces {
		fd, err := createRawSocket(iface.Index)
		if err != nil {
			fmt.Println("failed to create raw socket:", err)
			return
		}
		defer syscall.Close(fd)
		event := syscall.EpollEvent{
			Events: syscall.EPOLLIN,
			Fd:     int32(fd),
		}
		err = syscall.EpollCtl(epoll, syscall.EPOLL_CTL_ADD, fd, &event)
		if err != nil {
			fmt.Println("failed to add socket to epoll:", err)
			return
		}
		addr, err := iface.Addrs()
		devs = append(devs, &Device{
			fd:   fd,
			addr: iface.HardwareAddr,
		})
		for _, a := range addr {
			addr, err := netip.ParsePrefix(a.String())
			if err != nil {
				fmt.Println("failed to parse address:", err)
				return
			}
			devs[len(devs)-1].addrs = append(devs[len(devs)-1].addrs, addr.Addr())
		}
	}
	log.Println("starting")
	buf := make([]byte, 65536)
	handler := NewHandler(devs, os.Stdout)
	if *isServer {
		handler.Listen(netip.AddrPortFrom(netip.IPv6Unspecified(), routing.BgpPort))
	} else {
		to, err := netip.ParseAddrPort(*connectTo)
		if err != nil {
			fmt.Println("failed to parse address:", err)
			return
		}
		handler.Connect(netip.AddrPortFrom(netip.IPv6Loopback(), routing.BgpPort), to)
	}
	for {
		events := make([]syscall.EpollEvent, 1)
		_, err := syscall.EpollWait(epoll, events, -1)
		if err != nil {
			fmt.Println("failed to wait for events:", err)
			return
		}
		fd := int(events[0].Fd)
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			fmt.Println("failed to receive packet:", err)
			continue
		}
		err = handler.parsePacket(buf[:n])
		if err != nil {
			fmt.Println("failed to parse packet:", err)
			continue
		}
	}
}
