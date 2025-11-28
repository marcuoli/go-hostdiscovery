// Package hostdiscovery: IP enumeration and TCP probe utilities.
package hostdiscovery

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
