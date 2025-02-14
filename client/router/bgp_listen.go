package main

import (
	"context"
	"io"
	"log"
	"net/netip"

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
									case *apipb.FlowSpecIPPrefix:
										log.Println(n)
									case *apipb.FlowSpecMAC:
										log.Println(n)
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
