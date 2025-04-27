package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type Device struct {
	IP       string
	Hostname string
}

func getLocalSubnet() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue // skip down or loopback interfaces
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				return ipnet.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no valid network interface found")
}

func scanNetwork(cidr string) []Device {
	ports := []string{"80", "443", "22"}
	var active []Device

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Println("Invalid CIDR:", err)
		return active
	}

	fmt.Println("🌐 Scanning subnet:", ipnet.String())

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ipStr := ip.String()

		if isSpecialIP(ipStr) {
			continue
		}

		for _, port := range ports {
			address := net.JoinHostPort(ipStr, port)
			conn, err := net.DialTimeout("tcp", address, 300*time.Millisecond)
			if err == nil {
				hostname := lookupHostname(ipStr)
				active = appendIfMissingDevice(active, Device{IP: ipStr, Hostname: hostname})
				conn.Close()
				break // Found open port, no need to scan more ports for this IP
			}
		}
	}

	return active
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isSpecialIP(ip string) bool {
	return strings.HasSuffix(ip, ".0") || strings.HasSuffix(ip, ".255")
}

func appendIfMissingDevice(slice []Device, item Device) []Device {
	for _, existing := range slice {
		if existing == item {
			return slice
		}
	}
	return append(slice, item)
}

func lookupHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return "(unkown)"
	}
	return strings.TrimSuffix(names[0], ".")
}

// func pingIP(ip string) bool {
// 	pinger, err := ping.NewPinger(ip)
// 	if err != nil {
// 		return false
// 	}
// 	pinger.SetPrivileged(true)
// 	pinger.Count = 1
// 	pinger.Timeout = 500 * time.Millisecond

// 	err = pinger.Run()
// 	if err != nil {
// 		return false
// 	}

// 	stats := pinger.Statistics()
// 	return stats.PacketRecv > 0
// }
