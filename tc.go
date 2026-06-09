package main 

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

func attachTC(ifindex int, prog *ebpf.Program) (interface{ Close() error}, error) {
	return link.AttachTCX(link.TCXOptions{
		Program: prog,
		Attach:  ebpf.AttachTCXEgress,
		Interface: ifindex,
	})
}


func runTCMonitor(ifaceName string, showTraffic bool){

	// Load the bpf object
	spec, err := ebpf.LoadCollectionSpec("tc_monitor/tc.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load TC BPF object: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create TC Collection: %v", err)
	}
	defer coll.Close()

	//Attach TC egress
	prog := coll.Programs["tc_egress"]
	if prog == nil {
		log.Fatalf("tc_egress program not found in BPF Object")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interface %s not found, Error: %v", ifaceName, err)
	}

	tcLink, err := attachTC(iface.Index, prog)
	if err != nil {
		log.Fatalf("Failed to attach TC: %v", err)
	}
	defer tcLink.Close()

	fmt.Printf("TC egress monitor attached to %s\n", ifaceName)
	fmt.Printf("Watching Outbound traffic ...... \n")
	fmt.Println("------------------------------------------------------------")

	// Open egress ring buffer
	rd, err := ringbuf.NewReader(coll.Maps["egress_events"])
	if err != nil {
		log.Fatalf("Failed to open egress ringbuf: %v", err)
	}
	defer rd.Close()

	//Read the egress events
	for {
		record, err := rd.Read()
		if err != nil {
			break
		}

		var event PktEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}

		if showTraffic {
			fmt.Printf("[EGRESS]")
			printEvent(&event)
		}
	}
}