// Package hostdiscovery: Backward compatibility layer.
// This file provides type aliases and wrapper functions for backward compatibility
// with code that imports the hostdiscovery package directly.
// New code should prefer importing the specific subpackages.
package hostdiscovery

import (
	"net"

	"github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery/arp"
	"github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery/dhcp"
	"github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery/dns"
	"github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery/finger"
	"github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery/llmnr"
	"github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery/mdns"
	"github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery/netbios"
	"github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery/network"
	"github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery/oui"
	"github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery/ssdp"
)

// =============================================================================
// DNS Discovery - Backward Compatibility
// =============================================================================

// DNSResult is an alias for dns.Result for backward compatibility.
type DNSResult = dns.Result

// DNSDiscovery is an alias for dns.Discovery for backward compatibility.
type DNSDiscovery = dns.Discovery

// NewDNSDiscovery creates a new DNS discovery helper.
// Deprecated: Use dns.NewDiscovery() instead.
func NewDNSDiscovery() *DNSDiscovery {
	return dns.NewDiscovery()
}

// =============================================================================
// NetBIOS Discovery - Backward Compatibility
// =============================================================================

// NetBIOSResult is an alias for netbios.Result for backward compatibility.
type NetBIOSResult = netbios.Result

// NetBIOSName is an alias for netbios.Name for backward compatibility.
type NetBIOSName = netbios.Name

// NetBIOSDiscovery is an alias for netbios.Discovery for backward compatibility.
type NetBIOSDiscovery = netbios.Discovery

// NewNetBIOSDiscovery creates a new NetBIOS discovery helper.
// Deprecated: Use netbios.NewDiscovery() instead.
func NewNetBIOSDiscovery() *NetBIOSDiscovery {
	return netbios.NewDiscovery()
}

// =============================================================================
// mDNS Discovery - Backward Compatibility
// =============================================================================

// MDNSResult is an alias for mdns.Result for backward compatibility.
type MDNSResult = mdns.Result

// MDNSService is an alias for mdns.Service for backward compatibility.
type MDNSService = mdns.Service

// MDNSDiscovery is an alias for mdns.Discovery for backward compatibility.
type MDNSDiscovery = mdns.Discovery

// NewMDNSDiscovery creates a new mDNS discovery helper.
// Deprecated: Use mdns.NewDiscovery() instead.
func NewMDNSDiscovery() *MDNSDiscovery {
	return mdns.NewDiscovery()
}

// =============================================================================
// LLMNR Discovery - Backward Compatibility
// =============================================================================

// LLMNRResult is an alias for llmnr.Result for backward compatibility.
type LLMNRResult = llmnr.Result

// LLMNRDiscovery is an alias for llmnr.Discovery for backward compatibility.
type LLMNRDiscovery = llmnr.Discovery

// NewLLMNRDiscovery creates a new LLMNR discovery helper.
// Deprecated: Use llmnr.NewDiscovery() instead.
func NewLLMNRDiscovery() *LLMNRDiscovery {
	return llmnr.NewDiscovery()
}

// =============================================================================
// SSDP Discovery - Backward Compatibility
// =============================================================================

// SSDPResult is an alias for ssdp.Result for backward compatibility.
type SSDPResult = ssdp.Result

// SSDPDiscovery is an alias for ssdp.Discovery for backward compatibility.
type SSDPDiscovery = ssdp.Discovery

// NewSSDPDiscovery creates a new SSDP discovery helper.
// Deprecated: Use ssdp.NewDiscovery() instead.
func NewSSDPDiscovery() *SSDPDiscovery {
	return ssdp.NewDiscovery()
}

// SSDP search targets - re-export from ssdp package
const (
	SSDPAll           = ssdp.All
	SSDPRootDevice    = ssdp.RootDevice
	SSDPMediaRenderer = ssdp.MediaRenderer
	SSDPMediaServer   = ssdp.MediaServer
	SSDPBasicDevice   = ssdp.BasicDevice
)

// =============================================================================
// DHCP Discovery - Backward Compatibility
// =============================================================================

// DHCPInformResult is an alias for dhcp.InformResult for backward compatibility.
type DHCPInformResult = dhcp.InformResult

// DHCPDiscovery is an alias for dhcp.Discovery for backward compatibility.
type DHCPDiscovery = dhcp.Discovery

// NewDHCPDiscovery creates a new DHCP discovery helper.
// Deprecated: Use dhcp.NewDiscovery() instead.
func NewDHCPDiscovery() *DHCPDiscovery {
	return dhcp.NewDiscovery()
}

// =============================================================================
// Finger Discovery - Backward Compatibility
// =============================================================================

// FingerResult is an alias for finger.Result for backward compatibility.
type FingerResult = finger.Result

// FingerUser is an alias for finger.User for backward compatibility.
type FingerUser = finger.User

// FingerDiscovery is an alias for finger.Discovery for backward compatibility.
type FingerDiscovery = finger.Discovery

// NewFingerDiscovery creates a new Finger discovery helper.
// Deprecated: Use finger.NewDiscovery() instead.
func NewFingerDiscovery() *FingerDiscovery {
	return finger.NewDiscovery()
}

// =============================================================================
// ARP Discovery - Backward Compatibility
// =============================================================================

// ARPResult is an alias for arp.Result for backward compatibility.
type ARPResult = arp.Result

// ARPDiscovery is an alias for arp.Discovery for backward compatibility.
type ARPDiscovery = arp.Discovery

// NewARPDiscovery creates a new ARP discovery helper.
// Deprecated: Use arp.NewDiscovery() instead.
func NewARPDiscovery() *ARPDiscovery {
	return arp.NewDiscovery()
}

// ARP errors - re-export from arp package
var (
	ErrARPNotSupported  = arp.ErrNotSupported
	ErrARPInvalidIP     = arp.ErrInvalidIP
	ErrARPIPv6NotSupported = arp.ErrIPv6NotSupported
)

// =============================================================================
// OUI/Vendor Lookup - Backward Compatibility
// =============================================================================

// VendorInfo is an alias for oui.VendorInfo for backward compatibility.
type VendorInfo = oui.VendorInfo

// LookupVendor looks up vendor information for a MAC address.
// Deprecated: Use oui.Lookup() instead.
func LookupVendor(mac string) (*VendorInfo, error) {
	return oui.Lookup(mac)
}

// LookupVendorName returns just the manufacturer name for a MAC address.
// Deprecated: Use oui.LookupName() instead.
func LookupVendorName(mac string) string {
	return oui.LookupName(mac)
}

// SetOUIDatabase sets a custom path for the OUI database file.
// Deprecated: Use oui.SetDatabase() instead.
func SetOUIDatabase(path string) error {
	return oui.SetDatabase(path)
}

// GetOUIDatabase returns the current OUI database path.
// Deprecated: Use oui.GetDatabasePath() instead.
func GetOUIDatabase() string {
	return oui.GetDatabasePath()
}

// ReloadOUIDatabase forces a reload of the OUI database.
// Deprecated: Use oui.Reload() instead.
func ReloadOUIDatabase() error {
	return oui.Reload()
}

// IsOUILoaded returns true if the OUI database has been loaded.
// Deprecated: Use oui.IsLoaded() instead.
func IsOUILoaded() bool {
	return oui.IsLoaded()
}

// =============================================================================
// Network Utilities - Backward Compatibility
// =============================================================================

// EnumerateIPs returns all usable host IPs in a CIDR.
// Deprecated: Use network.EnumerateIPs() instead.
func EnumerateIPs(cidr string) ([]net.IP, error) {
	return network.EnumerateIPs(cidr)
}

// =============================================================================
// Discovery Error - Backward Compatibility (moved from arp files)
// =============================================================================

// DiscoveryError represents an error during discovery.
type DiscoveryError struct {
	Method  DiscoveryMethod
	Message string
}

func (e *DiscoveryError) Error() string {
	return string(e.Method) + ": " + e.Message
}

// =============================================================================
// Setup debug logging wiring for subpackages
// =============================================================================

// initSubpackageLogging sets up debug logging for all subpackages.
// This is called automatically when the package is loaded.
func init() {
	// Wire up debug logging for all subpackages
	dns.DebugLogger = func(format string, args ...interface{}) {
		debugLog(MethodDNS, format, args...)
	}
	netbios.DebugLogger = func(format string, args ...interface{}) {
		debugLog(MethodNetBIOS, format, args...)
	}
	mdns.DebugLogger = func(format string, args ...interface{}) {
		debugLog(MethodMDNS, format, args...)
	}
	llmnr.DebugLogger = func(format string, args ...interface{}) {
		debugLog(MethodLLMNR, format, args...)
	}
	ssdp.DebugLogger = func(format string, args ...interface{}) {
		debugLog(MethodSSDP, format, args...)
	}
	dhcp.DebugLogger = func(format string, args ...interface{}) {
		debugLog(MethodDHCP, format, args...)
	}
	finger.DebugLogger = func(format string, args ...interface{}) {
		debugLog(MethodFinger, format, args...)
	}
	arp.DebugLogger = func(format string, args ...interface{}) {
		debugLog(MethodARP, format, args...)
	}
	oui.DebugLogger = func(format string, args ...interface{}) {
		debugLog(MethodVendor, format, args...)
	}
}
