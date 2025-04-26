package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/eiannone/keyboard"
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
	stats := &Stats{}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	device := pickDevice()
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	go listenForKeys(stats)
	// signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			time.Sleep(1 * time.Second)
			stats.Lock()
			clearTerminal()
			fmt.Println("Traffic Stats (press 'd' to discover Devices")
			fmt.Println("-_ _ _ _ _ _ _ _______________________________")
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

func pickDevice() string {
	devices, err := pcap.FindAllDevs()
	if err != nil || len(devices) == 0 {
		log.Fatal("No network interfaces found.")
	}
	fmt.Println("Using device: ", devices[0].Name)
	return devices[0].Name
}

func listenForKeys(stats *Stats) {
	if err := keyboard.Open(); err != nil {
		log.Fatal(err)
	}
	defer keyboard.Close()

	for {
		char, key, err := keyboard.GetKey()
		if err != nil {
			continue
		}

		if key == keyboard.KeyCtrlC {
			os.Exit(0)
		}

		if char == 'd' || char == 'D' {
			stats.Lock()
			fmt.Println("Discovering devices on your network...")
			cidr, _ := getLocalSubnet()
			active := scanNetwork(cidr)
			fmt.Println(("Devices found : "))

			for _, ip := range active {
				fmt.Println(" -", ip)
			}
			fmt.Println(("Press any key to return to live stats."))
			keyboard.GetKey()
			stats.Unlock()
		}
	}
}
func clearTerminal() {
	fmt.Print("\033[H\033[2J")
}
