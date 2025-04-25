package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

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

	pocketSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("Listening on: ", device)

	for packet := range pocketSource.Packets() {
		fmt.Println("Packet captured at", packet.Metadata().Timestamp.Format(time.RFC3339))
		fmt.Println(packet)
	}
}
