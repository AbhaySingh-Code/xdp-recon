package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// Must match struct pkt_event in common.h exactly
// Field order, sizes, and padding must be identical
type PktEvent struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	IPVer    uint8
	TCPFlags uint8
	Pad      uint8
	PktLen   uint32
}

// scan config
type ScanConfig struct {
	TimeWindowNs uint64
	Threshold uint32
	AutoBlock uint8
	Pad [3]uint8
}

// TCP flag masks — must match common.h
const (
	TCP_FIN = 0x01
	TCP_SYN = 0x02
	TCP_RST = 0x04
	TCP_PSH = 0x08
	TCP_ACK = 0x10
	TCP_URG = 0x20
)

// Protocol numbers
const (
	PROTO_ICMP   = 1
	PROTO_TCP    = 6
	PROTO_UDP    = 17
	PROTO_ICMPv6 = 58
)

// 4.5 Code to block certain ip's
type BlockKey struct {
	PrefixLen uint32
	Addr uint32
}

// intToIP converts a uint32 (network byte order) to a net.IP
// Network byte order is big-endian, so we convert accordingly
func intToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip
}

// protoName returns a human-readable protocol name
func protoName(proto uint8) string {
	switch proto {
	case PROTO_ICMP:
		return "ICMP"
	case PROTO_TCP:
		return "TCP "
	case PROTO_UDP:
		return "UDP "
	case PROTO_ICMPv6:
		return "ICMPv6"
	default:
		return fmt.Sprintf("PROTO(%d)", proto)
	}
}

// tcpFlagString converts the packed flags byte into a readable string
// e.g. "[SYN ACK]"
func tcpFlagString(flags uint8) string {
	if flags == 0 {
		return ""
	}
	result := "["
	if flags&TCP_FIN != 0 {
		result += "FIN "
	}
	if flags&TCP_SYN != 0 {
		result += "SYN "
	}
	if flags&TCP_RST != 0 {
		result += "RST "
	}
	if flags&TCP_PSH != 0 {
		result += "PSH "
	}
	if flags&TCP_ACK != 0 {
		result += "ACK "
	}
	if flags&TCP_URG != 0 {
		result += "URG "
	}
	result += "]"
	return result
}

func main() {
	// Setting defaults values for scan config 
	timeWindow := 30  //seconds
	threshold := 20 // ports
	autoBlock := false
	ifaceName := "eth0"
	showTraffic := false
	showStats := false

	// Passing commmand line arguments
	for i, arg := range os.Args[1:]{
		switch arg {
		case "--auto-block-network-scan":
			autoBlock = true
		case "--show-traffic":
			showTraffic = true
		case "--show-stats":
			showStats = true
		case "--time":
			if i+2 < len(os.Args){
				fmt.Scanf(os.Args[i+2], "%d", &timeWindow)
			}
		case "--threshold":
			if i+2 < len(os.Args) {
				fmt.Scanf(os.Args[i+2], "%d", &threshold)
			}
		default:
			if arg[0] != '-' {
				ifaceName = arg
			}
		}
	}
	fmt.Printf("Config: interface=%s time=%ds threshold=%d auto-block=%v\n", ifaceName, timeWindow, threshold, autoBlock)

	// -------------------------------------------------------
	// 1. Load the BPF object file
	// -------------------------------------------------------
	spec, err := ebpf.LoadCollectionSpec("network_monitor/monitor.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load BPF object: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create BPF collection: %v", err)
	}
	defer coll.Close()

	// -------------------------------------------------------
	// 2. Attach XDP program to the network interface
	// -------------------------------------------------------
	//ifaceName := "eth0" // change this to match your interface
	//if len(os.Args) > 1 {
	//	ifaceName = os.Args[1] // accept interface as CLI argument
	//}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interface %s not found: %v", ifaceName, err)
	}

	prog := coll.Programs["xdp_monitor"]
	if prog == nil {
		log.Fatal("xdp_monitor program not found in BPF object")
	}

	// Attach XDP in generic mode (works everywhere, no special NIC needed)
	link, err := attachXDP(iface.Index, prog)
	if err != nil {
		log.Fatalf("Failed to attach XDP: %v", err)
	}
	defer link.Close()

	fmt.Printf("XDP monitor attached to %s\n", ifaceName)
	fmt.Println("Listening for packets... (Ctrl+C to stop)")
	if showTraffic {
		fmt.Println("─────────────────────────────────────────────────────────")
		fmt.Printf("%-6s %-21s %-21s %-8s %-16s\n",
			"PROTO", "SRC", "DST", "LEN", "FLAGS")
		fmt.Println("─────────────────────────────────────────────────────────")
	}

	// Writing the config into a BPF map
	var autoBlockVal uint8
	if autoBlock{
		autoBlockVal = 1
	}

	cfg := ScanConfig{
		TimeWindowNs: uint64(timeWindow) * 1_000_000_000, //convert to nanoseconds
		Threshold: uint32(threshold),
		AutoBlock: autoBlockVal,
	}

	cfgKey := uint32(0)

	// Add tc monitor execution
	go runTCMonitor(ifaceName, showTraffic, &cfg)

	if err := coll.Maps["block_config"].Put(
		unsafe.Pointer(&cfgKey),
		unsafe.Pointer(&cfg),
	); err != nil {
		log.Fatalf("Failed to write config: %v", err)
	}


	// block an IP
	err = blockCidr("8.8.8.8/32", coll.Maps["blocklist"])
	if err != nil {
		log.Fatalf("block: %v", err)
	}
	//fmt.Println("Blocked 1.1.1.1")

	// -------------------------------------------------------
	// 3. Open ringbuf reader
	// -------------------------------------------------------
	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		log.Fatal("events map not found in BPF object")
	}

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		log.Fatalf("Failed to open ringbuf reader: %v", err)
	}
	defer rd.Close()

	// -------------------------------------------------------
	// 4. Handle Ctrl+C gracefully — detach XDP on exit
	// -------------------------------------------------------
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\nDetaching XDP and exiting...")
		rd.Close()
	}()
	

	// -------------------------------------------------------
	// 5. Stats goroutine — print summary every 10 seconds
	// -------------------------------------------------------
	protoStats := coll.Maps["proto_stats"]
	if showStats{
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				printStats(protoStats)
			}
		}()
	}

	// ----------------------------------------------------------
	// 5.5 Alert reader - prints message when IP is auto blocked
	// ----------------------------------------------------------
	alertsMap := coll.Maps["alerts"]
	go func() {
		ard, err := ringbuf.NewReader(alertsMap)
		if err != nil {
			log.Fatalf("alerts ringbuf: %v", err)
		}
		defer ard.Close()

		for {
			record, err := ard.Read()
			if err != nil {
				break
			}

			var srcIP uint32
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &srcIP); err != nil {
				continue
			}

			ip := intToIP(srcIP)
			if autoBlock == false {
			       fmt.Printf("\n ** ALERT : PORT SCAN DETECTED from %s - NOT BLOCKED ****\n", ip)
			} else {
				fmt.Printf("\n ** ALERT : PORT SCAN DETECTED from %s - AUTO BLOCKED ****\n", ip)
			}
		}
	}()

	// -------------------------------------------------------
	// 6. Main loop — read events from ringbuf and print them
	// -------------------------------------------------------
	for {
		record, err := rd.Read()
		if err != nil {
			// ringbuf was closed (Ctrl+C) — exit cleanly
			break
		}

		// Parse raw bytes into our PktEvent struct
		var event PktEvent
		if err := binary.Read(bytes.NewReader(record.RawSample),
			binary.LittleEndian, &event); err != nil {
			log.Printf("Failed to parse event: %v", err)
			continue
		}
		if showTraffic {
			printEvent(&event)
		}
	}

	fmt.Println("Done.")
}

// printEvent formats and prints a single packet event
func printEvent(e *PktEvent) {
	src := intToIP(e.SrcIP)
	dst := intToIP(e.DstIP)
	proto := protoName(e.Protocol)

	var srcStr, dstStr string

	// ICMP has no ports
	if e.Protocol == PROTO_ICMP || e.Protocol == PROTO_ICMPv6 {
		srcStr = src.String()
		dstStr = dst.String()
	} else {
		srcStr = fmt.Sprintf("%s:%d", src, e.SrcPort)
		dstStr = fmt.Sprintf("%s:%d", dst, e.DstPort)
	}

	flags := ""
	if e.Protocol == PROTO_TCP {
		flags = tcpFlagString(e.TCPFlags)
	}

	fmt.Printf("%-6s %-21s %-21s %-8d %-16s\n",
		proto, srcStr, dstStr, e.PktLen, flags)
}

// printStats reads proto_stats map and prints a summary
func printStats(m *ebpf.Map) {
	fmt.Println("\n── Protocol Stats ──────────────────")
	protocols := map[uint32]string{
		1:  "ICMP",
		6:  "TCP",
		17: "UDP",
		58: "ICMPv6",
	}
	for key, name := range protocols {
		var value uint64
		if err := m.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
			continue
		}
		if value > 0 {
			fmt.Printf("  %-8s %d packets\n", name, value)
		}
	}
	fmt.Println("────────────────────────────────────")
}

// attachXDP attaches an XDP program to a network interface
// Returns a closer you must call to detach
func attachXDP(ifindex int, prog *ebpf.Program) (interface{ Close() error }, error) {
	// Use netlink to attach XDP
	// cilium/ebpf provides this via the link package
	return attachXDPLink(ifindex, prog)
}


func blockCidr(cidr string, blocklist *ebpf.Map) error {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Println("Invalid cidr %v", err)
	}

	prefixLen, _ := network.Mask.Size()

	var key BlockKey
	key.PrefixLen = uint32(prefixLen)
	key.Addr = binary.BigEndian.Uint32(ip.To4())

	value := uint64(1)
	return blocklist.Put(unsafe.Pointer(&key), unsafe.Pointer(&value))
}