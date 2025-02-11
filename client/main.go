package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"slices"
	"sort"
	"syscall"
	"time"

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
	handler     func(*tcpConn)
}

type routingEntry struct {
	dstNetwork netip.Prefix
	nextHop    netip.Addr
	dev        *Device
}

type deferredEntry struct {
	callback func(dev *routingEntry)
	dst      netip.Addr
}

type RoutingTable struct {
	entries  []*routingEntry
	deferred []*deferredEntry
}

func (r *RoutingTable) Lookup(dst netip.Addr) *routingEntry {
	for _, entry := range r.entries {
		if entry.dstNetwork.Contains(dst) {
			return entry
		}
	}
	return nil
}

func (r *RoutingTable) Defer(dst netip.Addr, callback func(*routingEntry)) {
	r.deferred = append(r.deferred, &deferredEntry{
		callback: callback,
		dst:      dst,
	})
}

func (r *RoutingTable) AddEntry(log io.Writer, from string, dst netip.Prefix, nextHop netip.Addr, dev *Device) {
	r.entries = append(r.entries, &routingEntry{
		dstNetwork: dst,
		nextHop:    nextHop,
		dev:        dev,
	})
	fmt.Fprintf(log, "add routing entry: %v via %v from %s\n", dst, nextHop, from)
	// order by longest prefix match
	sort.Slice(r.entries, func(i, j int) bool {
		return r.entries[i].dstNetwork.Bits() > r.entries[j].dstNetwork.Bits()
	})
	r.entries = slices.CompactFunc(r.entries, func(i, j *routingEntry) bool {
		return i.dstNetwork.Contains(j.dstNetwork.Addr()) // this means i equals j
	})
	var delete []int
	for i, d := range r.deferred {
		for _, entry := range r.entries {
			if entry.dstNetwork.Contains(d.dst) {
				d.callback(entry)
				delete = append(delete, i)
			}
		}
	}
	for i := len(delete) - 1; i >= 0; i-- {
		r.deferred = append(r.deferred[:delete[i]], r.deferred[delete[i]+1:]...)
	}
}

type neighborEntry struct {
	dst      netip.Addr
	hardAddr net.HardwareAddr
}

type neighborDeferred struct {
	callback func(*neighborEntry)
	dst      netip.Addr
}

type NeighborCache struct {
	entries   map[netip.Addr]*neighborEntry
	deferred  map[netip.Addr][]*neighborDeferred
	searching map[netip.Addr]time.Time
}

func (n *NeighborCache) Lookup(dst netip.Addr) *neighborEntry {
	for _, entry := range n.entries {
		if entry.dst == dst {
			return entry
		}
	}
	return nil
}

func checkSum(check []byte) uint16 {
	var sum uint32
	for i := 0; i < len(check); i += 2 {
		sum += uint32(check[i])<<8 | uint32(check[i+1])
	}
	if len(check)%2 != 0 {
		sum += uint32(check[len(check)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

func makeSolicitedNodeAddr(addr netip.Addr) netip.Addr {
	return netip.AddrFrom16([16]byte{
		0xff, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0xff, addr.As16()[13], addr.As16()[14], addr.As16()[15]})
}

func makeSolicitedNodeMac(addr netip.Addr) net.HardwareAddr {
	return net.HardwareAddr{0x33, 0x33, addr.As16()[12], addr.As16()[13], addr.As16()[14], addr.As16()[15]}
}

func (n *NeighborCache) sendNeighborSolicitation(log io.Writer, dev *Device, target netip.Addr) {
	icmp := &routing.Icmpv6Packet{}
	icmp.Header.Type = uint8(routing.Icmpv6Type_NeighborSolicitation)
	ns := &routing.NdpneighborSolicitation{}
	ns.TargetAddr = target.As16()
	opt := routing.Ndpoption{}
	opt.Type = routing.NdpoptionType_SourceLinkLayerAddress
	opt.Length = 1
	opt.SetLinkLayerAddress(dev.addr)
	ns.Options = append(ns.Options, opt)
	icmp.SetNeighborSolicitation(*ns)
	checkSumTarget := icmp.MustEncode()

	srcAddr := netip.IPv6Unspecified()
	for _, addr := range dev.addrs {
		if addr.Contains(target) {
			fmt.Fprintf(log, "select address %v for %v\n", addr, target)
			srcAddr = addr.Addr()
			break
		}
	}

	dstSol := makeSolicitedNodeAddr(target)

	hdr := makeIPv6Header(srcAddr, dstSol, routing.ProtocolNumber_Icmpv6, 255, checkSumTarget)

	icmp.Header.Checksum = calcPseudoHeaderChecksum(&routing.Ipv6ChecksumPseudoHeader{
		SrcAddr:          hdr.SrcAddr,
		DstAddr:          hdr.DstAddr,
		NextHeader:       hdr.NextHeader,
		UpperLayerLength: uint32(hdr.PayloadLen),
	}, checkSumTarget)

	enc := icmp.MustEncode()
	enc = append(hdr.MustEncode(), enc...)
	dev.writeEthernet(makeSolicitedNodeMac(dstSol), enc)
}

func (n *NeighborCache) Defer(log io.Writer, dst netip.Addr, dev *Device, callback func(*neighborEntry)) {
	if !dst.IsLinkLocalUnicast() {
		fmt.Fprintf(log, "drop non link local address: %v\n", dst)
		return
	}
	if n.deferred == nil {
		n.deferred = make(map[netip.Addr][]*neighborDeferred)
	}
	n.deferred[dst] = append(n.deferred[dst], &neighborDeferred{
		callback: callback,
		dst:      dst,
	})
	if n.searching == nil {
		n.searching = make(map[netip.Addr]time.Time)
	}
	if timer, ok := n.searching[dst]; !ok {
		n.searching[dst] = time.Now()
		fmt.Fprintf(log, "sending neighbor solicitation for %v\n", dst)
		n.sendNeighborSolicitation(log, dev, dst)
	} else if time.Since(timer) > 1*time.Second {
		n.searching[dst] = time.Now()
		fmt.Fprintf(log, "sending neighbor solicitation for %v\n", dst)
		n.sendNeighborSolicitation(log, dev, dst)
	}
}

func (n *NeighborCache) AddEntry(log io.Writer, from string, dst netip.Addr, hardAddr net.HardwareAddr) {
	if n.entries == nil {
		n.entries = make(map[netip.Addr]*neighborEntry)
	}
	if n.searching == nil {
		n.searching = make(map[netip.Addr]time.Time)
	}
	if _, ok := n.entries[dst]; ok {
		return
	}
	if !dst.IsLinkLocalUnicast() {
		return // only link local addresses are supported
	}
	fmt.Fprintf(log, "add link layer address: %v for %v from %s\n", hardAddr, dst, from)
	newEntry := &neighborEntry{
		dst:      dst,
		hardAddr: hardAddr,
	}
	n.entries[dst] = newEntry
	delete(n.searching, dst)
	if n.deferred == nil {
		return
	}
	if deferred, ok := n.deferred[dst]; ok {
		for _, d := range deferred {
			d.callback(newEntry)
		}
		delete(n.deferred, dst)
	}
}

type handler struct {
	tcpConns  map[tcpTuple]*tcpConn
	listening map[netip.AddrPort]func(c *tcpConn)
	w         io.Writer
	devices   []*Device
	routing   *RoutingTable
	neighbors *NeighborCache
	asNumber  uint16
}

func (h *handler) GetSelfDevice(addr netip.Addr) *Device {
	for _, dev := range h.devices {
		for _, a := range dev.addrs {
			if a.Addr() == addr {
				return dev
			}
		}
	}
	return nil
}

func (conn *tcpConn) addSegment(seqNum uint32, data []byte) {
	conn.recvSegment = append(conn.recvSegment, segment{
		seqNum: seqNum,
		data:   data,
	})
	sort.Slice(conn.recvSegment, func(i, j int) bool {
		return conn.recvSegment[i].seqNum < conn.recvSegment[j].seqNum
	})
	if conn.recvSegment[0].seqNum == conn.recvSeqNum {
		conn.recvSeqNum += uint32(len(conn.recvSegment[0].data))
		conn.recvBuf = append(conn.recvBuf, conn.recvSegment[0].data...)
		conn.recvSegment = conn.recvSegment[1:]
		conn.handler(conn)
	}
}

func (h *handler) sendTCP(state routing.Tcpstate, src, dst netip.AddrPort, flags routing.Tcpflags, seq, ack uint32, data []byte) {
	tcp := &routing.Tcpheader{}
	tcp.SrcPort = src.Port()
	tcp.DstPort = dst.Port()
	tcp.SeqNum = seq
	tcp.AckNum = ack
	tcp.Flags = flags
	tcp.WindowSize = 65535
	tcp.UrgentPointer = 0
	tcp.SetDataOffset(5)
	checkSumTarget := tcp.MustEncode()
	checkSumTarget = append(checkSumTarget, data...)

	tcp.Checksum = calcPseudoHeaderChecksum(&routing.Ipv6ChecksumPseudoHeader{
		SrcAddr:          src.Addr().As16(),
		DstAddr:          dst.Addr().As16(),
		NextHeader:       routing.ProtocolNumber_Tcp,
		UpperLayerLength: uint32(len(checkSumTarget)),
	}, checkSumTarget)

	enc := tcp.MustEncode()
	enc = append(enc, data...)
	fmt.Fprintf(h.w, "sending TCP packet from %v to %v (state: %v)\n", src, dst, state)
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

func (h *handler) handleTCP(srcMac [6]byte, ip *routing.Ipv6Header, tcp *routing.Tcpheader, payload []byte) {
	tuple := tcpTuple{
		src: netip.AddrPortFrom(netip.AddrFrom16(ip.SrcAddr), tcp.SrcPort),
		dst: netip.AddrPortFrom(netip.AddrFrom16(ip.DstAddr), tcp.DstPort),
	}
	var conn *tcpConn
	if _, ok := h.tcpConns[tuple]; !ok {
		l, ok := h.listening[tuple.dst]
		if !ok {
			// fmt.Fprintf(h.w, "no listener on %v\n", tuple.dst)
			return
		}
		conn = &tcpConn{
			state:   routing.Tcpstate_Listen,
			handler: l,
		}
		h.tcpConns[tuple] = conn
	}
	conn = h.tcpConns[tuple]
	switch conn.state {
	case routing.Tcpstate_Listen:
		if tcp.Flags.Syn() {
			fmt.Fprintf(h.w, "received SYN packet from %v (dev: %v\n", tuple.src, net.HardwareAddr(srcMac[:]))
			conn.state = routing.Tcpstate_SynRcvd
			conn.sendSeqNum = 0
			h.sendTCP(conn.state, tuple.dst, tuple.src, flags(true, true), 0, conn.recvSeqNum, nil)
		} else {
			fmt.Fprintf(h.w, "unexpected packet: %v\n", tcp)
			delete(h.tcpConns, tuple)
		}
	case routing.Tcpstate_SynSent:
		if tcp.Flags.Syn() && tcp.Flags.Ack() {
			conn.state = routing.Tcpstate_Established
			conn.recvSeqNum = tcp.SeqNum + 1
			h.sendTCP(conn.state, tuple.dst, tuple.src, flags(true, false), conn.recvSeqNum, tcp.SeqNum+1, nil)
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
			h.sendTCP(conn.state, tuple.dst, tuple.src, flags(true, true), 0, tcp.SeqNum+1, nil)
		}
		conn.addSegment(tcp.SeqNum, payload)
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

func (h *handler) BGPHandler(c *tcpConn) {
	log.Println("BGP handler")
}

func (h *handler) Listen(addr netip.AddrPort, handler func(c *tcpConn)) {
	h.listening[addr] = handler
}

func (h *handler) Connect(src, dst netip.AddrPort) {
	h.tcpConns[tcpTuple{
		src: src,
		dst: dst,
	}] = &tcpConn{
		state: routing.Tcpstate_SynSent,
	}
	h.sendTCP(routing.Tcpstate_SynSent, src, dst, flags(false, true), 0, 0, nil)
}

func (h *Device) writeEthernet(dst net.HardwareAddr, data []byte) {
	eth := &routing.EthernetFrame{}
	eth.EtherType = uint16(routing.EtherType_Ipv6)
	eth.DstMac = [6]byte(dst)
	eth.SrcMac = [6]byte(h.addr)
	eth.SetData(data)
	enc := eth.MustEncode()
	_, err := syscall.Write(h.fd, enc)
	if err != nil {
		fmt.Println("failed to write ethernet frame:", err)
	}
}

func makeIPv6Header(src, dst netip.Addr, proto routing.ProtocolNumber, hopLimit uint8, data []byte) *routing.Ipv6Header {
	hdr := &routing.Ipv6Header{}
	hdr.SrcAddr = src.As16()
	hdr.DstAddr = dst.As16()
	hdr.NextHeader = proto
	hdr.HopLimit = hopLimit
	hdr.PayloadLen = uint16(len(data))
	hdr.SetVersion(6)
	hdr.SetFlowLabel(0)
	hdr.SetTrafficClass(0)
	return hdr
}

func calcPseudoHeaderChecksum(pseudo *routing.Ipv6ChecksumPseudoHeader, data []byte) uint16 {
	checkSumTarget := append(pseudo.MustEncode(), data...)
	return checkSum(checkSumTarget)
}

func (h *handler) writeIP(src, dst netip.Addr, proto routing.ProtocolNumber, data []byte) {
	hdr := makeIPv6Header(src, dst, proto, 64, data)
	enc := hdr.MustEncode()
	enc = append(enc, data...)
	doRouting := func(dev *routingEntry) {
		dstMac := h.neighbors.Lookup(dev.nextHop)
		if dstMac == nil {
			fmt.Fprintf(h.w, "deferred neighbor resolution for %v of protocol %v\n", dev.nextHop, proto)
			h.neighbors.Defer(h.w, dev.nextHop, dev.dev, func(neigh *neighborEntry) {
				fmt.Fprintf(h.w, "resolved neighbor %v\n", neigh.hardAddr)
				fmt.Fprintf(h.w, "sending packet to %v as %v\n", dev.nextHop, neigh.hardAddr)
				dev.dev.writeEthernet(neigh.hardAddr, enc)
			})
			return
		}
		fmt.Fprintf(h.w, "sending packet to %v via %v as %v\n", dev.dstNetwork, dev.nextHop, dstMac.hardAddr)
		dev.dev.writeEthernet(dstMac.hardAddr, enc)
	}
	et := h.routing.Lookup(dst)
	if et == nil {
		fmt.Fprintf(h.w, "deferred routing for %v of protocol %v\n", dst, proto)
		h.routing.Defer(dst, doRouting)
		return
	}
	doRouting(et)
}

func (h *handler) sendNeighborAdvertisement(
	ipv6 *routing.Ipv6Header, dev *Device, neigh *routing.NdpneighborSolicitation,
	responseHardwareAddr net.HardwareAddr,
) {
	adv := &routing.NdpneighborAdvertisement{}
	adv.TargetAddr = neigh.TargetAddr
	opt := routing.Ndpoption{}
	opt.Type = routing.NdpoptionType_TargetLinkLayerAddress
	opt.Length = 1
	opt.SetLinkLayerAddress(dev.addr)
	adv.Options = append(adv.Options, opt)
	adv.SetSolicited(true)
	r := &routing.Icmpv6Packet{}
	r.Header.Type = uint8(routing.Icmpv6Type_NeighborAdvertisement)
	r.SetNeighborAdvertisement(*adv)

	checkSumTarget := r.MustEncode()
	addr := netip.AddrFrom16(ipv6.SrcAddr)
	if addr == netip.IPv6Unspecified() {
		addr = netip.IPv6LinkLocalAllNodes()
	}
	v6 := makeIPv6Header(netip.AddrFrom16(adv.TargetAddr), addr, routing.ProtocolNumber_Icmpv6, 255, checkSumTarget)

	r.Header.Checksum = calcPseudoHeaderChecksum(&routing.Ipv6ChecksumPseudoHeader{
		SrcAddr:          v6.SrcAddr,
		DstAddr:          v6.DstAddr,
		NextHeader:       v6.NextHeader,
		UpperLayerLength: uint32(v6.PayloadLen),
	}, checkSumTarget)

	enc := r.MustEncode()
	enc = append(v6.MustEncode(), enc...)
	dev.writeEthernet(responseHardwareAddr, enc)
}

func (h *handler) handleICMPv6(dev *Device, srcMac [6]byte, ipv6 *routing.Ipv6Header, data []byte) error {
	r := &routing.Icmpv6Packet{}
	read, err := r.Decode(data)
	if err != nil {
		return fmt.Errorf("failed to decode ICMPv6 packet: %v", err)
	}
	data = data[read:]
	if neigh := r.NeighborSolicitation(); neigh != nil {
		// handle neighbor solicitation
		targetAddr := netip.AddrFrom16(neigh.TargetAddr)
		//srcAddr := netip.AddrFrom16(ipv6.SrcAddr)

		// fmt.Fprintf(h.w, "neighbor solicitation: found device: %v for %v from %v\n", dev.addr, targetAddr, srcAddr)
		responseHardwareAddr := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		for _, opt := range neigh.Options {
			if opt.Type == routing.NdpoptionType_SourceLinkLayerAddress {
				h.neighbors.AddEntry(h.w, fmt.Sprintf("neighbor solicitation (dev %s)", net.HardwareAddr(srcMac[:])), targetAddr, *opt.LinkLayerAddress())
				responseHardwareAddr = *opt.LinkLayerAddress()
			}
		}
		h.sendNeighborAdvertisement(ipv6, dev, neigh, responseHardwareAddr)
	} else if adv := r.NeighborAdvertisement(); adv != nil {
		// handle neighbor advertisement
		targetAddr := netip.AddrFrom16(adv.TargetAddr)
		//srcAddr := netip.AddrFrom16(ipv6.SrcAddr)
		// fmt.Fprintf(h.w, "neighbor advertisement: %v\n", targetAddr)
		dev := h.GetSelfDevice(targetAddr)
		if dev != nil {
			//fmt.Printf("neighbor advertisement: found device: %v for %v from %v\n", dev.addr, targetAddr, srcAddr)
			for _, opt := range adv.Options {
				if opt.Type == routing.NdpoptionType_TargetLinkLayerAddress {
					h.neighbors.AddEntry(h.w, "neighbor advertisement", targetAddr, *opt.LinkLayerAddress())
				}
			}
		}
	}
	return nil
}

func (h *handler) LookupDevice(fd int) *Device {
	for _, dev := range h.devices {
		if dev.fd == fd {
			return dev
		}
	}
	return nil
}

// https://datatracker.ietf.org/doc/html/rfc4291#section-2.8
/**
 A host is required to recognize the following addresses as
   identifying itself:

      o Its required Link-Local address for each interface.

      o Any additional Unicast and Anycast addresses that have been
        configured for the node's interfaces (manually or
        automatically).

      o The loopback address.

      o The All-Nodes multicast addresses defined in Section 2.7.1.

      o The Solicited-Node multicast address for each of its unicast and
        anycast addresses.

      o Multicast addresses of all other groups to which the node
        belongs.

   A router is required to recognize all addresses that a host is
   required to recognize, plus the following addresses as identifying
   itself:

      o The Subnet-Router Anycast addresses for all interfaces for which
        it is configured to act as a router.

      o All other Anycast addresses with which the router has been
        configured.

      o The All-Routers multicast addresses defined in Section 2.7.1.

**/
// https://narwhale.net/post-97/
// https://datatracker.ietf.org/doc/html/rfc2464#section-7
var solicitedLinkLocal = netip.MustParsePrefix("ff02::1:ff00:0/104")

func (h *handler) isAcceptableAddress(addr netip.Addr, dev *Device, dstMac [6]uint8) bool {
	if addr.IsLoopback() {
		return true
	}
	if addr == netip.IPv6LinkLocalAllNodes() {
		return true
	}
	isSolicited := solicitedLinkLocal.Contains(addr)
	macIsSolicted := dstMac[0] == 0x33 && dstMac[1] == 0x33 && dstMac[2] == 0xff
	if isSolicited != macIsSolicted {
		return false
	}
	addr16 := addr.As16()
	for _, a := range dev.addrs {
		if isSolicited {
			if addr16[13] == dstMac[3] && addr16[14] == dstMac[4] && addr16[15] == dstMac[5] {
				return true
			}
		} else {
			if a.Addr() == addr {
				return true
			}
		}
	}
	return false
}

func (h *handler) isAcceptableMacAddress(dev *Device, dst [6]byte, src [6]byte) bool {
	for _, dev := range h.devices {
		if dev.addr.String() == net.HardwareAddr(src[:]).String() {
			return false // ignore packets from this device
		}
	}
	if dev.addr.String() == net.HardwareAddr(dst[:]).String() {
		return true
	}
	if dst == [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} {
		return true
	}
	if dst[0] == 0x33 && dst[1] == 0x33 {
		return true
	}
	return false
}

func (h *handler) parsePacket(dev *Device, p []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v\n%s", r, debug.Stack())
		}
	}()
	eth := &routing.EthernetFrame{}
	err = eth.DecodeExact(p)
	if err != nil {
		return err
	}
	if eth.EtherType != uint16(routing.EtherType_Ipv6) {
		return nil // ignore non-IPv6 packets
	}
	if !h.isAcceptableMacAddress(dev, eth.DstMac, eth.SrcMac) {
		return nil // ignore packets not addressed to this device
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
		// try adding the source address to the neighbor cache
		h.neighbors.AddEntry(h.w, "incoming packet", netip.AddrFrom16(ipv6.SrcAddr), net.HardwareAddr(eth.SrcMac[:]))
		if !h.isAcceptableAddress(netip.AddrFrom16(ipv6.DstAddr), dev, eth.DstMac) {
			return nil
		}
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
			return h.handleICMPv6(dev, [6]byte(eth.SrcMac), ipv6, data)
		case routing.ProtocolNumber_Tcp:
			tcp := &routing.Tcpheader{}
			read, err := tcp.Decode(data)
			if err != nil {
				return fmt.Errorf("failed to decode TCP header: %v", err)
			}
			data = data[read:]
			h.handleTCP(eth.SrcMac, ipv6, tcp, data)
		}
	}
	return nil
}

type Device struct {
	fd    int
	addr  net.HardwareAddr
	addrs []netip.Prefix
}

var linkLocal = netip.MustParsePrefix("fe80::/10")

func NewHandler(devices []*Device, w io.Writer) *handler {
	h := &handler{
		devices:   devices,
		tcpConns:  make(map[tcpTuple]*tcpConn),
		listening: make(map[netip.AddrPort]func(c *tcpConn)),
		w:         w,
		routing:   &RoutingTable{},
		neighbors: &NeighborCache{},
	}
	for _, dev := range devices {
		localAddr := []netip.Prefix{}
		for _, addr := range dev.addrs {
			if linkLocal.Contains(addr.Addr()) {
				localAddr = append(localAddr, addr)
			}
		}
		for _, addr := range localAddr {
			// skip network and docker created default gateway address
			maskedForm := addr.Masked()
			fmt.Fprintf(w, "DEBUG: %v\n", maskedForm)
			defaultGateway := maskedForm.Addr().Next().Next()
			for _, addr := range dev.addrs {
				h.routing.AddEntry(w, "interface", addr, defaultGateway, dev)
			}
		}
	}
	return h
}

var controlSubnet = netip.MustParsePrefix("2001:db8:0:5::/64")
var controlPlane = netip.MustParsePrefix("2001:db8:0:5::2/128")

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
	var controlAddr *netip.Addr
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
			devs[len(devs)-1].addrs = append(devs[len(devs)-1].addrs, addr)
			if a := addr.Addr(); controlSubnet.Contains(a) {
				controlAddr = &a
			}
		}
	}
	if controlAddr == nil {
		fmt.Println("no control address found")
		return
	}
	buf := make([]byte, 65536)
	handler := NewHandler(devs, os.Stdout)
	log.Println("running as server")
	handler.Listen(netip.AddrPortFrom(*controlAddr, routing.BgpPort), handler.BGPHandler)
	asNumber := 64513 + uint16(controlAddr.As16()[15]) - 1
	log.Printf("AS number: %d\n", asNumber)
	handler.asNumber = asNumber
	for {
		events := make([]syscall.EpollEvent, 1)
		_, err := syscall.EpollWait(epoll, events, -1)
		if err != nil {
			if err != syscall.EINTR {
				fmt.Println("failed to wait for events:", err)
			}
			continue
		}
		fd := int(events[0].Fd)
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			fmt.Println("failed to receive packet:", err)
			continue
		}
		device := handler.LookupDevice(fd)
		if device == nil {
			fmt.Println("failed to find device for fd:", fd)
			continue
		}
		err = handler.parsePacket(device, buf[:n])
		if err != nil {
			fmt.Println("failed to parse packet:", err)
			continue
		}
	}
}
