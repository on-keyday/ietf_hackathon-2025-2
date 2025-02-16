package main

import (
	"context"
	"io"
	"log"
	"net/netip"

	"github.com/on-keyday/dplane_importer/client/router/routing"
	apipb "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

/*
func handleBGPConn(conn net.Conn, asNum uint16) {
	pkt := &bgp.Bgppacket{}
	open := &bgp.Open{}
	open.As = asNum
	open.Version = 4
	open.Hold = 180
	open.Id = 0x01020304
	encoded := open.MustEncode()
	pkt.Header.Type = bgp.Bgptype_Open
	pkt.Header.Length = uint16(len(encoded)) + 19
	pkt.SetOpen(*open)
	err := pkt.Write(conn)
	if err != nil {
		log.Println(err)
		return
	}
	err = pkt.Read(conn)
	if err != nil {
		log.Println(err)
		return
	}
	opened := pkt.Open()
	if opened == nil {
		log.Println("not open")
		return
	}
	for _, opt := range opened.Options {
		log.Println(opt)
	}
	go func() {
		for {
			err := pkt.Read(conn)
			if err != nil {
				log.Println(err)
				return
			}
			switch pkt.Header.Type {
			case bgp.Bgptype_Open:
				log.Println("open")
			case bgp.Bgptype_Update:
				log.Println("update")
			case bgp.Bgptype_Notification:
				log.Println("notification")
			case bgp.Bgptype_Keepalive:
				log.Println("keepalive")
			}
		}
	}()
	sendKeepalive := func() bool {
		pkt.Header.Type = bgp.Bgptype_Keepalive
		pkt.Header.Length = 19
		err := pkt.Write(conn)
		if err != nil {
			log.Println(err)
			return false
		}
		return true
	}
	sendKeepalive()
	timer := time.NewTimer(time.Second * 60)
	for range timer.C {
		if !sendKeepalive() {
			return
		}
		timer.Reset(time.Second * 60)
	}
}

func bgpListen(addr netip.Addr, asNum uint16) error {
	as16 := addr.As16()
	lis, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: as16[:], Port: 179})
	if err != nil {
		return err
	}
	for {
		conn, err := lis.Accept()
		if err != nil {
			return err
		}
		go handleBGPConn(conn, asNum)
	}
}
*/

type FilterContext struct {
	Length   uint64
	ProtoNum routing.ProtocolNumber
	Pkt      *routing.Ipv6Header
	Tcp      *routing.Tcpheader
	Udp      *routing.Udpheader
	Icmp     *routing.Icmpheader
}

type FlowSpecFilter func(*FilterContext) bool

func Compare(op routing.FlowSpecOp, got uint64, expected uint64) bool {
	switch op {
	case routing.FlowSpecOp_Equal:
		return got == expected
	case routing.FlowSpecOp_NotEqual:
		return got != expected
	case routing.FlowSpecOp_Less:
		return got < expected
	case routing.FlowSpecOp_LessEqual:
		return got <= expected
	case routing.FlowSpecOp_Greater:
		return got > expected
	case routing.FlowSpecOp_GreaterEqual:
		return got >= expected
	default:
		return false
	}
}

type andT struct{}
type orT struct{}

func createFilter(component *apipb.FlowSpecComponent) FlowSpecFilter {
	var filters []any
	for _, item := range component.Items {
		op := &routing.FlowSpecOpByte{}
		op.Decode([]byte{byte(item.Op)})
		var curFilter FlowSpecFilter
		if op.Op() == routing.FlowSpecOp_TrueValue || op.Op() == routing.FlowSpecOp_FalseValue {
			curFilter = func(ctx *FilterContext) bool {
				return op.Op() == routing.FlowSpecOp_TrueValue
			}
		} else {
			switch routing.BgpflowSpecType(component.Type) {
			case routing.BgpflowSpecType_Port:
				portNum := item.Value
				curFilter = func(fc *FilterContext) bool {
					if fc.Tcp != nil {
						return Compare(op.Op(), uint64(fc.Tcp.DstPort), portNum) || Compare(op.Op(), uint64(fc.Tcp.SrcPort), portNum)
					}
					if fc.Udp != nil {
						return Compare(op.Op(), uint64(fc.Udp.DstPort), portNum) || Compare(op.Op(), uint64(fc.Udp.SrcPort), portNum)
					}
					return false
				}
			case routing.BgpflowSpecType_DstPort:
				portNum := item.Value
				curFilter = func(fc *FilterContext) bool {
					if fc.Tcp != nil {
						return Compare(op.Op(), uint64(fc.Tcp.DstPort), portNum)
					}
					if fc.Udp != nil {
						return Compare(op.Op(), uint64(fc.Udp.DstPort), portNum)
					}
					return false
				}
			case routing.BgpflowSpecType_SrcPort:
				portNum := item.Value
				curFilter = func(fc *FilterContext) bool {
					if fc.Tcp != nil {
						return Compare(op.Op(), uint64(fc.Tcp.SrcPort), portNum)
					}
					if fc.Udp != nil {
						return Compare(op.Op(), uint64(fc.Udp.SrcPort), portNum)
					}
					return false
				}
			case routing.BgpflowSpecType_IcmpType:
				icmpType := item.Value
				curFilter = func(fc *FilterContext) bool {
					if fc.Icmp != nil {
						return Compare(op.Op(), uint64(fc.Icmp.Type), icmpType)
					}
					return false
				}
			case routing.BgpflowSpecType_IcmpCode:
				icmpCode := item.Value
				curFilter = func(fc *FilterContext) bool {
					if fc.Icmp != nil {
						return Compare(op.Op(), uint64(fc.Icmp.Code), icmpCode)
					}
					return false
				}
			case routing.BgpflowSpecType_TcpFlag:
				tcpFlag := item.Value
				curFilter = func(fc *FilterContext) bool {
					if fc.Tcp != nil {
						return Compare(op.Op(), uint64(fc.Tcp.Flags.MustEncode()[0]), tcpFlag)
					}
					return false
				}
			case routing.BgpflowSpecType_PktLen:
				pktLen := item.Value
				curFilter = func(fc *FilterContext) bool {
					return Compare(op.Op(), fc.Length, pktLen)
				}
			case routing.BgpflowSpecType_IpProto:
				ipProto := item.Value
				curFilter = func(fc *FilterContext) bool {
					return Compare(op.Op(), uint64(fc.ProtoNum), ipProto)
				}
			default:
				return nil // unsupported type
			}
		}
		if len(filters) == 0 {
			filters = append(filters, curFilter)
		} else {
			if op.AndBit() {
				filters = append(filters, andT{}, curFilter)
			} else {
				filters = append(filters, orT{}, curFilter)
			}
		}
	}
	type flowDepth struct {
		left  FlowSpecFilter
		and   bool
		depth int
	}
	var stack []*flowDepth
	depth := 0
	var filter FlowSpecFilter
	for depth < 3 {
		if len(stack) > 0 {
			if stack[len(stack)-1].depth == depth {
				left := stack[len(stack)-1].left
				right := filter
				stack = stack[:len(stack)-1]
				if stack[len(stack)-1].and {
					filter = func(ctx *FilterContext) bool {
						return left(ctx) && right(ctx)
					}
				} else {
					filter = func(ctx *FilterContext) bool {
						return left(ctx) || right(ctx)
					}
				}
			}
		}
		if depth == 0 {
			filter = filters[0].(FlowSpecFilter)
			filters = filters[1:]
		} else if depth == 1 {
			if len(filters) != 0 {
				if _, isAnd := filters[0].(andT); isAnd {
					stack = append(stack, &flowDepth{left: filter, and: true, depth: depth})
					filters = filters[1:]
					depth = 0
					continue
				}
			}
		} else {
			if len(filters) != 0 {
				if _, isOr := filters[0].(orT); isOr {
					stack = append(stack, &flowDepth{left: filter, and: false, depth: depth})
					filters = filters[1:]
					depth = 0
					continue
				}
			}
		}
		depth++
	}
	return filter
}

func bgpListen(addr netip.Addr, _ uint16) error {
	conn, err := grpc.NewClient(netip.AddrPortFrom(addr, 50051).String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Println(err)
		return err
	}
	defer conn.Close()
	client := apipb.NewGobgpApiClient(conn)
	for {
		list, err := client.ListPath(context.Background(), &apipb.ListPathRequest{
			TableType: apipb.TableType_GLOBAL,
			Family:    &apipb.Family{Afi: apipb.Family_AFI_IP6, Safi: apipb.Family_SAFI_UNICAST},
		})
		if err != nil {
			log.Println(err)
			return err
		}
		for {
			resp, err := list.Recv()
			if err != nil {
				if err == io.EOF {
					break
				}
				log.Println(err)
				break
			}
			for _, p := range resp.Destination.Paths {
				attrs := p.GetPattrs()
				for _, a := range attrs {
					val, err := a.UnmarshalNew()
					if err != nil {
						log.Println(err)
						continue
					}
					switch v := val.(type) {
					case *apipb.MpReachNLRIAttribute:
						for _, nlri := range v.Nlris {
							val, err := nlri.UnmarshalNew()
							if err != nil {
								log.Println(err)
								continue
							}
							switch v := val.(type) {
							case *apipb.FlowSpecNLRI:
								for _, r := range v.Rules {
									n, err := r.UnmarshalNew()
									if err != nil {
										log.Println(err)
										continue
									}
									switch n := n.(type) {
									case *apipb.FlowSpecComponent:
										log.Println(n)
										filter := createFilter(n)
									case *apipb.FlowSpecIPPrefix:
										log.Println(n)
									case *apipb.FlowSpecMAC:
										log.Println(n)
									}
								}
							}
						}
					case *apipb.ExtendedCommunitiesAttribute:
						for _, ec := range v.Communities {
							val, err := ec.UnmarshalNew()
							if err != nil {
								log.Println(err)
								continue
							}
							switch v := val.(type) {
							case *apipb.ColorExtended:
								log.Println(v)
							}
						}
					}
				}
			}
		}
	}
}
