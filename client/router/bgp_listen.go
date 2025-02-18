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
	"google.golang.org/protobuf/types/known/anypb"
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

func mapKind(t routing.BgpflowSpecType) BgpflowSpecTypeAndOp {
	switch t {
	case routing.BgpflowSpecType_Port:
		return BgpflowSpecTypeAndOp_Port
	case routing.BgpflowSpecType_DstPort:
		return BgpflowSpecTypeAndOp_DstPort
	case routing.BgpflowSpecType_SrcPort:
		return BgpflowSpecTypeAndOp_SrcPort
	case routing.BgpflowSpecType_IcmpType:
		return BgpflowSpecTypeAndOp_IcmpType
	case routing.BgpflowSpecType_IcmpCode:
		return BgpflowSpecTypeAndOp_IcmpCode
	case routing.BgpflowSpecType_TcpFlag:
		return BgpflowSpecTypeAndOp_TcpFlag
	case routing.BgpflowSpecType_PktLen:
		return BgpflowSpecTypeAndOp_PktLen
	case routing.BgpflowSpecType_IpProto:
		return BgpflowSpecTypeAndOp_IpProto
	default:
		return BgpflowSpecTypeAndOp_Unknown
	}
}

func mapOp(t routing.FlowSpecOp) BgpflowSpecTypeAndOp {
	switch t {
	case routing.FlowSpecOp_Equal:
		return BgpflowSpecTypeAndOp_Eq
	case routing.FlowSpecOp_NotEqual:
		return BgpflowSpecTypeAndOp_Neq
	case routing.FlowSpecOp_Less:
		return BgpflowSpecTypeAndOp_Ls
	case routing.FlowSpecOp_LessEqual:
		return BgpflowSpecTypeAndOp_Lse
	case routing.FlowSpecOp_Greater:
		return BgpflowSpecTypeAndOp_Gt
	case routing.FlowSpecOp_GreaterEqual:
		return BgpflowSpecTypeAndOp_Gte
	default:
		return BgpflowSpecTypeAndOp_Unknown
	}
}

func createPrefixFilter(component *apipb.FlowSpecIPPrefix) []*Code {
	var filters []*Code
	switch routing.BgpflowSpecType(component.Type) {
	case routing.BgpflowSpecType_DstPrefix:
		addr, err := netip.ParseAddr(component.Prefix)
		if err != nil {
			log.Println(err)
			return nil
		}
		prefixed := netip.PrefixFrom(addr, int(component.PrefixLen))
		requireLen := (component.PrefixLen + 7) / 8
		filters = append(filters, &Code{Code: BgpflowSpecTypeAndOp_DstPrefix})
		filters = append(filters, &Code{Code: BgpflowSpecTypeAndOp_Eq}) // this means, prefix match, not strict equal
		code := &Code{Code: BgpflowSpecTypeAndOp_PrefixValue}
		code.SetPrefixValue(PrefixValue{PrefixLen: uint8(component.PrefixLen), Prefix: prefixed.Addr().AsSlice()[:requireLen]})
		filters = append(filters, code)
	case routing.BgpflowSpecType_SrcPrefix:
		addr, err := netip.ParseAddr(component.Prefix)
		if err != nil {
			log.Println(err)
			return nil
		}
		prefixed := netip.PrefixFrom(addr, int(component.PrefixLen))
		requireLen := (component.PrefixLen + 7) / 8
		filters = append(filters, &Code{Code: BgpflowSpecTypeAndOp_SrcPrefix})
		filters = append(filters, &Code{Code: BgpflowSpecTypeAndOp_Eq}) // this means, prefix match, not strict equal
		code := &Code{Code: BgpflowSpecTypeAndOp_PrefixValue}
		code.SetPrefixValue(PrefixValue{PrefixLen: uint8(component.PrefixLen), Prefix: prefixed.Addr().AsSlice()[:requireLen]})
		filters = append(filters, code)
	default:
		return nil
	}
	return filters
}

func createFilterCode(component *apipb.FlowSpecComponent) []*Code {
	var filters []*Code
	filters = append(filters, &Code{Code: mapKind(routing.BgpflowSpecType(component.Type))}) // kind
	for _, item := range component.Items {
		op := &routing.FlowSpecOpByte{}
		op.Decode([]byte{byte(item.Op)})
		if len(filters) != 0 {
			if op.AndBit() {
				filters = append(filters, &Code{Code: BgpflowSpecTypeAndOp_And})
			} else {
			}
		}
		if op.Op() == routing.FlowSpecOp_TrueValue {
			filters = append(filters, &Code{Code: BgpflowSpecTypeAndOp_True})
		} else if op.Op() == routing.FlowSpecOp_FalseValue {
			filters = append(filters, &Code{Code: BgpflowSpecTypeAndOp_False})
		} else {
			val := &Code{Code: BgpflowSpecTypeAndOp_Value}
			val.SetValue(Value{Value: uint16(item.Value)})
			filters = append(filters, &Code{Code: mapOp(op.Op())}) // relation
			filters = append(filters, val)                         // value
		}
	}
	// 前置記法に変換
	type flowDepth struct {
		left  []*Code
		op    *Code
		depth int
	}
	var stack []*flowDepth
	depth := 0
	// 0: value
	// 1: eq, neq, ls, lse, gt, gte
	// 2: and
	// 3: or
	var current []*Code
	for depth < 4 {
		if len(stack) > 0 {
			if stack[len(stack)-1].depth == depth {
				left := stack[len(stack)-1].left
				op := stack[len(stack)-1].op
				stack = stack[:len(stack)-1]
				newCurrent := append([]*Code{op}, left...)
				newCurrent = append(newCurrent, current...)
				current = newCurrent
			}
		}
		if depth == 0 {
			if len(filters) == 0 {
				return nil // invalid
			}
			current = append(current, filters[0])
			filters = filters[1:]
		} else if depth == 1 {
			if len(filters) > 0 {
				if filters[0].Code == BgpflowSpecTypeAndOp_Eq || filters[0].Code == BgpflowSpecTypeAndOp_Neq ||
					filters[0].Code == BgpflowSpecTypeAndOp_Ls || filters[0].Code == BgpflowSpecTypeAndOp_Lse ||
					filters[0].Code == BgpflowSpecTypeAndOp_Gt || filters[0].Code == BgpflowSpecTypeAndOp_Gte {
					stack = append(stack, &flowDepth{left: current, op: filters[0], depth: depth})
					filters = filters[1:]
					depth = 0
					continue
				}
			}
		} else if depth == 2 {
			if len(filters) > 0 {
				if filters[0].Code == BgpflowSpecTypeAndOp_And {
					stack = append(stack, &flowDepth{left: current, op: filters[0], depth: depth})
					filters = filters[1:]
					depth = 0
					continue
				}
			}
		} else if depth == 3 {
			if len(filters) > 0 {
				if filters[0].Code == BgpflowSpecTypeAndOp_Or {
					stack = append(stack, &flowDepth{left: current, op: filters[0], depth: depth})
					filters = filters[1:]
					depth = 0
					continue
				}
			}
		}
	}
	if len(stack) != 0 || len(filters) != 0 {
		return nil // invalid
	}
	return current
}

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

type SID struct {
	SID    *Sid
	Behave routing.EndpointBehavior
}

type SRPolicyFilter struct {
	Rule     FlowSpecFilter
	RuleCode []*Code
	SIDs     []*SID
	TailEnd  netip.Addr
	Color    uint32
}

const PolicyTest = 1
const TestColor = 1

func makeFlowSpecOp(and bool, op routing.FlowSpecOp, val uint64) *apipb.FlowSpecComponentItem {
	b := routing.FlowSpecOpByte{}
	b.SetAndBit(and)
	b.SetOp(op)
	b.SetLen(8)
	return &apipb.FlowSpecComponentItem{
		Op:    uint32(b.MustEncode()[0]),
		Value: val,
	}
}

func addRoutingInfo(client apipb.GobgpApiClient) {
	c, err := client.AddPathStream(context.Background())
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Println("adding path")
	err = c.Send(&apipb.AddPathStreamRequest{
		Paths: []*apipb.Path{
			{
				Family: &apipb.Family{Afi: apipb.Family_AFI_IP6, Safi: apipb.Family_SAFI_FLOW_SPEC_UNICAST},
				/*
					Nlri: mustAny(&apipb.SRPolicyNLRI{
						Distinguisher: PolicyTest,
						Color:         1,
						Length:        64,
						Endpoint:      netip.MustParseAddr("2001:db8:0:1::3").AsSlice(),
					}),
				*/
				/*
					Nlri: mustAny(
						&apipb.MpReachNLRIAttribute{
							Family: &apipb.Family{Afi: apipb.Family_AFI_IP6, Safi: apipb.Family_SAFI_FLOW_SPEC_UNICAST},
							Nlris: []*anypb.Any{
								mustAny(&apipb.FlowSpecNLRI{
									Rules: []*anypb.Any{
										mustAny(&apipb.FlowSpecComponent{
											Type: uint32(routing.BgpflowSpecType_DstPort),
											Items: []*apipb.FlowSpecComponentItem{
												makeFlowSpecOp(false, routing.FlowSpecOp_Equal, 8080),
											},
										}),
										mustAny(&apipb.FlowSpecIPPrefix{
											Type:      uint32(routing.BgpflowSpecType_DstPrefix),
											Prefix:    "2001:db8:0:2::",
											PrefixLen: 64,
										}),
									},
								}),
							},
						},
					),
				*/
				Nlri: mustAny(&apipb.FlowSpecNLRI{
					Rules: []*anypb.Any{
						mustAny(&apipb.FlowSpecComponent{
							Type: uint32(routing.BgpflowSpecType_DstPort),
							Items: []*apipb.FlowSpecComponentItem{
								makeFlowSpecOp(false, routing.FlowSpecOp_Equal, 8080),
							},
						}),
						mustAny(&apipb.FlowSpecIPPrefix{
							Type:      uint32(routing.BgpflowSpecType_DstPrefix),
							Prefix:    "2001:db8:0:2::",
							PrefixLen: 64,
						}),
					},
				}),
				Pattrs: []*anypb.Any{
					mustAny(&apipb.PrefixSID{
						Tlvs: []*anypb.Any{
							mustAny(&apipb.SRv6L3ServiceTLV{
								SubTlvs: map[uint32]*apipb.SRv6TLV{
									1: {
										Tlv: []*anypb.Any{
											mustAny(
												&apipb.SRv6InformationSubTLV{
													Sid:              []byte{0, 0, 0, 0, 0, 0, 0, 1},
													EndpointBehavior: uint32(apipb.SRv6Behavior_END),
													SubSubTlvs: map[uint32]*apipb.SRv6TLV{
														1: {
															Tlv: []*anypb.Any{
																mustAny(&apipb.SRv6StructureSubSubTLV{
																	LocatorBlockLength: 32,
																	LocatorNodeLength:  32,
																	FunctionLength:     16,
																	ArgumentLength:     48,
																}),
															},
														},
													},
												}),
										},
									},
								},
							}),
						},
					}),
					mustAny(&apipb.ExtendedCommunitiesAttribute{
						Communities: []*anypb.Any{
							mustAny(&apipb.ColorExtended{
								Color: TestColor,
							}),
						},
					}),
					mustAny(&apipb.OriginAttribute{
						Origin: uint32(apipb.RouteOriginType_ORIGIN_IGP),
					}),
					mustAny(&apipb.NextHopAttribute{
						NextHop: "2001:db8:0:1::3",
					}),
					mustAny(&apipb.IP6ExtendedCommunitiesAttribute{
						Communities: []*anypb.Any{
							mustAny(&apipb.RedirectIPv6AddressSpecificExtended{
								Address: "2001:db8:0:1::3",
							}),
						},
					}),
				},
			},
		},
	})
	if err != nil {
		log.Fatal("add path fail", err)
		return
	}
	_, err = c.CloseAndRecv()
	if err != nil {
		log.Fatal("close fail", err)
	}
}

func bgpListen(_ netip.Addr, _ uint16, applyFilter func([]*SRPolicyFilter)) error {
	conn, err := grpc.NewClient(netip.AddrPortFrom(netip.IPv6Loopback(), 50051).String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Println(err)
		return err
	}
	defer conn.Close()
	client := apipb.NewGobgpApiClient(conn)
	log.Println("connected")
	if *mode == "src" {
		addRoutingInfo(client)
	}
	for {
		list, err := client.ListPath(context.Background(), &apipb.ListPathRequest{
			TableType: apipb.TableType_GLOBAL,
			Family:    &apipb.Family{Afi: apipb.Family_AFI_IP6, Safi: apipb.Family_SAFI_FLOW_SPEC_UNICAST},
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
			log.Printf("%+v\n", resp)
			var filters []*SRPolicyFilter
			for _, p := range resp.Destination.Paths {
				attrs := p.GetPattrs()
				if p.Family.Afi != apipb.Family_AFI_IP6 || p.Family.Safi != apipb.Family_SAFI_FLOW_SPEC_UNICAST {
					continue
				}
				f := &SRPolicyFilter{}
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
							var filter FlowSpecFilter
							var filterCode []*Code
							switch v := val.(type) {
							case *apipb.SRPolicyNLRI:
							case *apipb.FlowSpecNLRI:
								for _, r := range v.Rules {
									n, err := r.UnmarshalNew()
									if err != nil {
										log.Println(err)
										continue
									}
									switch n := n.(type) {
									case *apipb.FlowSpecComponent:
										newFilter := createFilter(n)
										if filter == nil {
											filter = newFilter
										} else {
											oldFilter := filter
											filter = func(ctx *FilterContext) bool {
												return oldFilter(ctx) && newFilter(ctx)
											}
										}
										code := createFilterCode(n)
										if code != nil {
											if len(filterCode) == 0 {
												filterCode = code
											} else {
												newFilter := append([]*Code{{Code: BgpflowSpecTypeAndOp_And}}, filterCode...)
												newFilter = append(newFilter, code...)
												filterCode = newFilter
											}
										}
									case *apipb.FlowSpecIPPrefix:
										var newFilter FlowSpecFilter
										switch routing.BgpflowSpecType(n.Type) {
										case routing.BgpflowSpecType_DstPrefix:
											addr, err := netip.ParseAddr(n.Prefix)
											if err != nil {
												log.Println(err)
												continue
											}
											prefixed := netip.PrefixFrom(addr, int(n.PrefixLen))
											newFilter = func(ctx *FilterContext) bool {
												return prefixed.Contains(netip.AddrFrom16(ctx.Pkt.DstAddr))
											}
											code := createPrefixFilter(n)
											if code != nil {
												if len(filterCode) == 0 {
													filterCode = code
												} else {
													newFilter := append([]*Code{{Code: BgpflowSpecTypeAndOp_And}}, filterCode...)
													newFilter = append(newFilter, code...)
													filterCode = newFilter
												}
											}
										case routing.BgpflowSpecType_SrcPrefix:
											addr, err := netip.ParseAddr(n.Prefix)
											if err != nil {
												log.Println(err)
												continue
											}
											prefixed := netip.PrefixFrom(addr, int(n.PrefixLen))
											newFilter = func(ctx *FilterContext) bool {
												return prefixed.Contains(netip.AddrFrom16(ctx.Pkt.SrcAddr))
											}
											code := createPrefixFilter(n)
											if code != nil {
												if len(filterCode) == 0 {
													filterCode = code
												} else {
													newFilter := append([]*Code{{Code: BgpflowSpecTypeAndOp_And}}, filterCode...)
													newFilter = append(newFilter, code...)
													filterCode = newFilter
												}
											}
										default:
											log.Println(n)
											continue
										}
										if filter == nil {
											filter = newFilter
										} else {
											oldFilter := filter
											filter = func(ctx *FilterContext) bool {
												return oldFilter(ctx) && newFilter(ctx)
											}
										}
									case *apipb.FlowSpecMAC:
										log.Println(n)
									}
								}
							}
							f.Rule = filter
							f.RuleCode = filterCode
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
								f.Color = v.Color
							}
						}
					case *apipb.RedirectIPv6AddressSpecificExtended:
						addr, err := netip.ParseAddr(v.Address)
						if err != nil {
							log.Println(err)
							continue
						}
						f.TailEnd = addr
					case *apipb.PrefixSID:
						for _, tlv := range v.Tlvs {
							n, err := tlv.UnmarshalNew()
							if err != nil {
								log.Println(err)
								continue
							}
							switch n := n.(type) {
							case *apipb.SRv6L3ServiceTLV:
								for _, s := range n.SubTlvs {
									var sids []*SID
									for _, tlv := range s.Tlv {
										n, err := tlv.UnmarshalNew()
										if err != nil {
											log.Println(err)
											continue
										}
										switch n := n.(type) {
										case *apipb.SRv6InformationSubTLV:
											log.Println(n)
											behave := routing.EndpointBehavior(n.EndpointBehavior)
											sid := &Sid{}
											sid.DecodeExact(n.Sid)
											sids = append(sids, &SID{SID: sid, Behave: behave})
										}
									}
									f.SIDs = sids
								}
							}
						}
					}
				}
				filters = append(filters, f)
			}
			// log.Printf("%+v", filters[0].RuleCode)
			applyFilter(filters)
		}
	}
}
