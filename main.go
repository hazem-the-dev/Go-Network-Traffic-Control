package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Stats struct {
	sync.Mutex
	Packets int
	Bytes   int
	TCP     int
	UDP     int
	ICMP    int
	Others  int
}

func main() {
	// List all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Available devices: ")
	for i, device := range devices {
		fmt.Printf("[%d] %s (%s)\n", i, device.Name, device.Description)
	}

	device := devices[0].Name

	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	stats := &Stats{}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			time.Sleep(1 * time.Second)
			stats.Lock()
			clearTerminal()
			fmt.Println("Traffic Stats (1s refresh)")
			fmt.Println("-______________________________________")
			fmt.Printf("Total packets: %d\n", stats.Packets)
			fmt.Printf("Total Bytes  : %d\n", stats.Bytes)
			fmt.Printf("TCP          : %d\n", stats.TCP)
			fmt.Printf("UDP          : %d\n", stats.UDP)
			fmt.Printf("ICMP         : %d\n", stats.ICMP)
			fmt.Printf("Others        : %d\n", stats.Others)
			fmt.Println("_______________________________________")
			stats.Unlock()
		}
	}()

	for {
		select {
		case packet := <-packetSource.Packets():
			stats.Lock()
			stats.Packets++
			stats.Bytes += len(packet.Data())

			if netLayer := packet.NetworkLayer(); netLayer != nil {
				if transportLayer := packet.TransportLayer(); transportLayer != nil {
					switch transportLayer.LayerType() {
					case layers.LayerTypeTCP:
						stats.TCP++
					case layers.LayerTypeUDP:
						stats.UDP++
					default:
						stats.Others++
					}
				} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
					stats.ICMP++
				} else {
					stats.Others++
				}
			}
			stats.Unlock()
		case <-stop:
			fmt.Println("Exiting...")
			return
		}

	}

}

func clearTerminal() {
	fmt.Print("\033[H\033[2J")
}
