package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// getLocalSubnet tries to find your local network CIDR, like "192.168.1.0/24"
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

// scanNetwork scans the entire subnet and tries to connect on common ports
func scanNetwork(cidr string) []string {
	ports := []string{"80", "443", "22"} // HTTP, HTTPS, SSH
	var active []string

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
				active = appendIfMissing(active, ipStr)
				conn.Close()
				break // Found open port, no need to scan more ports for this IP
			}
		}
	}

	return active
}

// incIP increments an IP address by 1
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// isSpecialIP skips IPs ending in .0 or .255
func isSpecialIP(ip string) bool {
	return strings.HasSuffix(ip, ".0") || strings.HasSuffix(ip, ".255")
}

// appendIfMissing avoids duplicate entries
func appendIfMissing(slice []string, item string) []string {
	for _, existing := range slice {
		if existing == item {
			return slice
		}
	}
	return append(slice, item)
}
