package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

func getLocalSubnet() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			var ipNet *net.IPNet

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				ipNet = v
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() || !ip.To4().IsGlobalUnicast() {
				continue
			}

			if ipNet != nil {
				return ipNet.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no active network interface found")
}

func scanNetwork(cidr string, port string) []string {
	var activeHosts []string
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIp(ip) {
		ipStr := ip.String()
		if strings.HasSuffix(ipStr, ".0") || strings.HasSuffix(ipStr, ".255") {
			continue
		}

		conn, err := net.DialTimeout("tcp", ipStr+":"+port, 200*time.Millisecond)
		if err != nil {
			activeHosts = append(activeHosts, ipStr)
			conn.Close()
		}
	}
	return activeHosts
}

func incIp(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
