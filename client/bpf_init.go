package main

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/on-keyday/dplane_importer/bpf"
)

var globalProgram *ebpf.Program
var globalAttach link.Link

func init() {
	filterTcpRstByKernel, err := bpf.LoadBpfObjects()
	if err != nil {
		panic(err)
	}
	path, err := bpf.DetectCgroupPath()
	if err != nil {
		panic(err)
	}
	cg, err := link.AttachCgroup(link.CgroupOptions{
		Path:    path,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: filterTcpRstByKernel,
	})
	if err != nil {
		panic(err)
	}
	globalProgram = filterTcpRstByKernel
	globalAttach = cg
	fmt.Printf("bpf program loaded and attached to cgroup %s\n", path)
}
