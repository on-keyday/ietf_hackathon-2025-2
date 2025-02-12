package bpf

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var globalProgram *bpfObjects
var globalAttach link.Link

func init() {
	err := rlimit.RemoveMemlock()
	if err != nil {
		log.Fatal(err)
	}
	objs, err := LoadBpfObjects()
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Println("cannot load bpf objects")
			for _, err := range verr.Log {
				fmt.Printf("%s\n", err)
			}
			log.Fatal("cannot loaded")
		} else {
			log.Fatal("can't load bpf objects: ", err)
		}
	}
	path, err := DetectCgroupPath()
	if err != nil {
		log.Fatal(err)
	}
	cg, err := link.AttachCgroup(link.CgroupOptions{
		Path:    path,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.FilterTcpRstByKernel,
	})
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		for range ticker.C {
			iter := objs.RecentPackets.Iterate()
			key := new(uint32)
			value := &bpfRecentV6Packet{}
			for iter.Next(key, value) {
				fmt.Printf("%s", fmt.Sprintf("%v\n", value))
			}
		}
	}()
	globalProgram = objs
	globalAttach = cg
	fmt.Printf("bpf program loaded and attached to cgroup %s\n", path)
}
