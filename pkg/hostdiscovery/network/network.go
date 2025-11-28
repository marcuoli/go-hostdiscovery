// Package network provides IP enumeration and network utilities.
package network

import (
	"net"
)

// EnumerateIPs returns all usable host IPs in a CIDR (excludes network and broadcast).
func EnumerateIPs(cidr string) ([]net.IP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return enumerateIPsFromNet(ipnet), nil
}

// EnumerateIPStrings returns all usable host IPs in a CIDR as strings.
func EnumerateIPStrings(cidr string) ([]string, error) {
	ips, err := EnumerateIPs(cidr)
	if err != nil {
		return nil, err
	}
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result, nil
}

func enumerateIPsFromNet(n *net.IPNet) []net.IP {
	var res []net.IP
	base := n.IP.To4()
	if base == nil {
		return res // IPv6 not supported for enumeration currently
	}
	mask := net.IP(n.Mask).To4()
	if mask == nil {
		return res
	}
	network := ipToUint32(base) & ipToUint32(mask)
	broadcast := network | ^ipToUint32(mask)
	for u := network + 1; u < broadcast; u++ {
		res = append(res, uint32ToIP(u))
	}
	return res
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(u uint32) net.IP {
	return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}

// IsPrivateIP checks if an IP address is in private (RFC 1918) address space.
func IsPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// Check RFC 1918 ranges
		return ip4[0] == 10 || // 10.0.0.0/8
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) || // 172.16.0.0/12
			(ip4[0] == 192 && ip4[1] == 168) // 192.168.0.0/16
	}
	return false
}

// IsLoopback checks if an IP address is a loopback address.
func IsLoopback(ip net.IP) bool {
	return ip.IsLoopback()
}

// ParseCIDR parses a CIDR string and returns the IP and network.
func ParseCIDR(cidr string) (net.IP, *net.IPNet, error) {
	return net.ParseCIDR(cidr)
}
