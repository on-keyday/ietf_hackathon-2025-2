package main

import (
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/on-keyday/dplane_importer/client/router/routing"
)

func handleBGPConn(conn net.Conn, asNum uint16) {
	pkt := &routing.Bgppacket{}
	open := &routing.Open{}
	open.As = asNum
	open.Version = 4
	open.Hold = 180
	open.Id = 0x01020304
	encoded := open.MustEncode()
	pkt.Header.Type = routing.Bgptype_Open
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
			case routing.Bgptype_Open:
				log.Println("open")
			case routing.Bgptype_Update:
				log.Println("update")
			case routing.Bgptype_Notification:
				log.Println("notification")
			case routing.Bgptype_Keepalive:
				log.Println("keepalive")
			}
		}
	}()
	sendKeepalive := func() bool {
		pkt.Header.Type = routing.Bgptype_Keepalive
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
