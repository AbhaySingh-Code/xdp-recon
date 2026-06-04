package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func attachXDPLink(ifindex int, prog *ebpf.Program) (interface{ Close() error }, error) {
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
		Flags:     link.XDPGenericMode, // works on any interface including VMs
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}