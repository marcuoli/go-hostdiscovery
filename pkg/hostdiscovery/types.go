// Package hostdiscovery provides multi-protocol host and hostname discovery
// for local networks. It supports TCP connect scans, reverse DNS, NetBIOS,
// mDNS, LLMNR, and SSDP/UPnP discovery methods.
//
// Platform coverage:
//   - Windows: NetBIOS, LLMNR, mDNS, DHCP hostname
//   - Linux: mDNS (Avahi), LLMNR (systemd-resolved), DHCP hostname
//   - macOS: mDNS (Bonjour), DHCP hostname
//   - Android: mDNS, SSDP, DHCP hostname, sometimes LLMNR
//   - IoT devices: mDNS, SSDP/UPnP, DHCP hostname
package hostdiscovery

import (
	"net"
	"time"
)

// DiscoveryMethod identifies the protocol used for discovery.
type DiscoveryMethod string

const (
	MethodTCP     DiscoveryMethod = "tcp"
	MethodDNS     DiscoveryMethod = "dns"
	MethodNetBIOS DiscoveryMethod = "netbios"
	MethodMDNS    DiscoveryMethod = "mdns"
	MethodLLMNR   DiscoveryMethod = "llmnr"
	MethodSSDP    DiscoveryMethod = "ssdp"
	MethodDHCP    DiscoveryMethod = "dhcp"   // DHCP hostname (via DNS or direct)
	MethodFinger  DiscoveryMethod = "finger" // Finger Protocol (RFC 1288)
	MethodARP     DiscoveryMethod = "arp"    // ARP for MAC address discovery
	MethodVendor  DiscoveryMethod = "vendor" // MAC vendor lookup (OUI)
)

// HostInfo contains consolidated information about a discovered host.
type HostInfo struct {
	IP        net.IP
	Hostnames []HostnameInfo
	MAC       string
	Services  []ServiceInfo
}

// HostnameInfo represents a hostname discovered via a specific method.
type HostnameInfo struct {
	Name   string
	Method DiscoveryMethod
}

// ServiceInfo represents a discovered service on a host.
type ServiceInfo struct {
	Name   string
	Type   string
	Port   int
	Method DiscoveryMethod
	Extra  map[string]string
}

// DefaultTimeout is used when no timeout is specified.
const DefaultTimeout = 2 * time.Second

// DefaultWorkers is the default concurrency level.
const DefaultWorkers = 256
