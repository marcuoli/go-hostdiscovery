// Package hostdiscovery: Unified multi-protocol host discovery.
package hostdiscovery

import (
	"context"
	"net"
	"sync"
	"time"
)

// MultiDiscoveryOptions configures the unified discovery behavior.
type MultiDiscoveryOptions struct {
	// EnableTCP enables TCP port scanning for host discovery
	EnableTCP bool
	// EnableDNS enables reverse DNS lookups
	EnableDNS bool
	// EnableNetBIOS enables NetBIOS name lookups (Windows)
	EnableNetBIOS bool
	// EnableMDNS enables mDNS lookups (Apple/Linux/IoT)
	EnableMDNS bool
	// EnableLLMNR enables LLMNR lookups (Windows/Linux)
	EnableLLMNR bool
	// EnableSSDP enables SSDP/UPnP discovery (IoT/Media)
	EnableSSDP bool
	// EnableARP enables ARP-based MAC address discovery
	EnableARP bool

	// TCPPorts for TCP scanning (default: 80,443,22,3389)
	TCPPorts []int
	// Timeout per protocol operation
	Timeout time.Duration
	// Workers for concurrent operations
	Workers int
}

// DefaultMultiDiscoveryOptions returns options with all protocols enabled.
func DefaultMultiDiscoveryOptions() MultiDiscoveryOptions {
	return MultiDiscoveryOptions{
		EnableTCP:     true,
		EnableDNS:     true,
		EnableNetBIOS: true,
		EnableMDNS:    true,
		EnableLLMNR:   true,
		EnableSSDP:    true,
		EnableARP:     true,
		TCPPorts:      []int{80, 443, 22, 3389},
		Timeout:       2 * time.Second,
		Workers:       256,
	}
}

// MultiDiscoveryResult contains consolidated discovery results for a host.
type MultiDiscoveryResult struct {
	IP        string
	IsUp      bool
	Hostnames map[DiscoveryMethod]string
	MAC       string
	Services  []ServiceInfo
	Errors    map[DiscoveryMethod]error
}

// PrimaryHostname returns the best hostname found, preferring certain methods.
func (r *MultiDiscoveryResult) PrimaryHostname() string {
	// Preference order: DNS > NetBIOS > mDNS > LLMNR
	for _, method := range []DiscoveryMethod{MethodDNS, MethodNetBIOS, MethodMDNS, MethodLLMNR} {
		if name, ok := r.Hostnames[method]; ok && name != "" {
			return name
		}
	}
	return ""
}

// MultiDiscovery performs comprehensive host discovery using multiple protocols.
type MultiDiscovery struct {
	Options MultiDiscoveryOptions
}

// NewMultiDiscovery creates a new unified discovery helper with defaults.
func NewMultiDiscovery() *MultiDiscovery {
	return &MultiDiscovery{Options: DefaultMultiDiscoveryOptions()}
}

// DiscoverCIDR discovers all hosts in a CIDR range using enabled protocols.
func (m *MultiDiscovery) DiscoverCIDR(ctx context.Context, cidr string) ([]*MultiDiscoveryResult, error) {
	// First, enumerate all IPs
	allIPs, err := EnumerateIPs(cidr)
	if err != nil {
		return nil, err
	}

	// Phase 1: Find live hosts via TCP if enabled
	var liveIPs []net.IP
	if m.Options.EnableTCP {
		tcp := NewTCPDiscovery()
		tcp.Options.Ports = m.Options.TCPPorts
		tcp.Options.Timeout = m.Options.Timeout
		tcp.Options.Workers = m.Options.Workers
		liveIPs, _ = tcp.Discover(ctx, cidr)
	} else {
		liveIPs = allIPs // Assume all are live
	}

	if len(liveIPs) == 0 {
		return nil, nil
	}

	// Convert to string IPs
	ipStrings := make([]string, len(liveIPs))
	for i, ip := range liveIPs {
		ipStrings[i] = ip.String()
	}

	// Phase 2: Resolve hostnames using all enabled protocols
	return m.ResolveBatch(ctx, ipStrings)
}

// ResolveBatch performs hostname resolution on a batch of IPs using all enabled protocols.
func (m *MultiDiscovery) ResolveBatch(ctx context.Context, ips []string) ([]*MultiDiscoveryResult, error) {
	debugLog("multi", "ResolveBatch starting for %d IPs", len(ips))

	results := make([]*MultiDiscoveryResult, len(ips))
	var mu sync.Mutex // Protect concurrent writes to results
	for i, ip := range ips {
		results[i] = &MultiDiscoveryResult{
			IP:        ip,
			IsUp:      true,
			Hostnames: make(map[DiscoveryMethod]string),
			Errors:    make(map[DiscoveryMethod]error),
		}
	}

	var wg sync.WaitGroup

	// DNS lookups
	if m.Options.EnableDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			debugLog(MethodDNS, "Starting reverse DNS lookups for %d IPs", len(ips))
			dns := NewDNSDiscovery()
			dns.Timeout = m.Options.Timeout
			dnsResults := dns.LookupMultiple(ctx, ips)
			mu.Lock()
			found := 0
			for i, r := range dnsResults {
				if r != nil && r.Hostname != "" {
					results[i].Hostnames[MethodDNS] = r.Hostname
					found++
					debugLogVerbose(MethodDNS, "%s -> %s", ips[i], r.Hostname)
				}
				if r != nil && r.Error != nil {
					results[i].Errors[MethodDNS] = r.Error
					debugLogVerbose(MethodDNS, "%s: error: %v", ips[i], r.Error)
				}
			}
			debugLog(MethodDNS, "Completed: %d/%d hostnames found", found, len(ips))
			mu.Unlock()
		}()
	}

	// NetBIOS lookups
	if m.Options.EnableNetBIOS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			debugLog(MethodNetBIOS, "Starting NetBIOS lookups for %d IPs", len(ips))
			nb := NewNetBIOSDiscovery()
			nb.Timeout = m.Options.Timeout
			nbResults := nb.LookupMultiple(ctx, ips)
			mu.Lock()
			found := 0
			for i, r := range nbResults {
				if r != nil && r.Hostname != "" {
					results[i].Hostnames[MethodNetBIOS] = r.Hostname
					found++
					if r.MACAddress != "" {
						results[i].MAC = r.MACAddress
						debugLogVerbose(MethodNetBIOS, "%s -> %s (MAC: %s)", ips[i], r.Hostname, r.MACAddress)
					} else {
						debugLogVerbose(MethodNetBIOS, "%s -> %s", ips[i], r.Hostname)
					}
				}
			}
			debugLog(MethodNetBIOS, "Completed: %d/%d hostnames found", found, len(ips))
			mu.Unlock()
		}()
	}

	// mDNS lookups
	if m.Options.EnableMDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			debugLog(MethodMDNS, "Starting mDNS lookups for %d IPs", len(ips))
			mdns := NewMDNSDiscovery()
			mdns.Timeout = m.Options.Timeout
			mdnsResults := mdns.LookupMultiple(ctx, ips)
			mu.Lock()
			found := 0
			for i, r := range mdnsResults {
				if r != nil && r.Hostname != "" {
					results[i].Hostnames[MethodMDNS] = r.Hostname
					found++
					debugLogVerbose(MethodMDNS, "%s -> %s", ips[i], r.Hostname)
				}
				if r != nil && r.Error != nil {
					results[i].Errors[MethodMDNS] = r.Error
					debugLogVerbose(MethodMDNS, "%s: error: %v", ips[i], r.Error)
				}
			}
			debugLog(MethodMDNS, "Completed: %d/%d hostnames found", found, len(ips))
			mu.Unlock()
		}()
	}

	// LLMNR lookups
	if m.Options.EnableLLMNR {
		wg.Add(1)
		go func() {
			defer wg.Done()
			debugLog(MethodLLMNR, "Starting LLMNR lookups for %d IPs", len(ips))
			llmnr := NewLLMNRDiscovery()
			llmnr.Timeout = m.Options.Timeout
			llmnrResults := llmnr.LookupMultiple(ctx, ips)
			mu.Lock()
			found := 0
			for i, r := range llmnrResults {
				if r != nil && r.Hostname != "" {
					results[i].Hostnames[MethodLLMNR] = r.Hostname
					found++
					debugLogVerbose(MethodLLMNR, "%s -> %s", ips[i], r.Hostname)
				}
				if r != nil && r.Error != nil {
					results[i].Errors[MethodLLMNR] = r.Error
					debugLogVerbose(MethodLLMNR, "%s: error: %v", ips[i], r.Error)
				}
			}
			debugLog(MethodLLMNR, "Completed: %d/%d hostnames found", found, len(ips))
			mu.Unlock()
		}()
	}

	// ARP lookups for MAC addresses
	if m.Options.EnableARP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			debugLog(MethodARP, "Starting ARP lookups for %d IPs", len(ips))
			arp := NewARPDiscovery()
			arp.Timeout = m.Options.Timeout
			arpResults := arp.LookupMultiple(ctx, ips)
			mu.Lock()
			found := 0
			for i, r := range arpResults {
				if r != nil && r.MACAddress != "" && results[i].MAC == "" {
					results[i].MAC = r.MACAddress
					found++
					debugLogVerbose(MethodARP, "%s -> MAC: %s", ips[i], r.MACAddress)
				}
				if r != nil && r.Error != nil {
					results[i].Errors[MethodARP] = r.Error
					debugLogVerbose(MethodARP, "%s: error: %v", ips[i], r.Error)
				}
			}
			debugLog(MethodARP, "Completed: %d/%d MAC addresses found", found, len(ips))
			mu.Unlock()
		}()
	}

	wg.Wait()
	debugLog("multi", "ResolveBatch completed for %d IPs", len(ips))
	return results, nil
}

// DiscoverSSDP performs SSDP/UPnP discovery on the local network.
// This is separate because SSDP uses multicast and doesn't target specific IPs.
func (m *MultiDiscovery) DiscoverSSDP(ctx context.Context) ([]*SSDPResult, error) {
	if !m.Options.EnableSSDP {
		return nil, nil
	}
	ssdp := NewSSDPDiscovery()
	ssdp.Timeout = m.Options.Timeout
	return ssdp.Discover(ctx, "ssdp:all")
}

// Resolve performs hostname resolution on a single IP using all enabled protocols.
func (m *MultiDiscovery) Resolve(ctx context.Context, ip string) *MultiDiscoveryResult {
	debugLog("multi", "Resolve starting for %s", ip)
	results, _ := m.ResolveBatch(ctx, []string{ip})
	if len(results) > 0 {
		r := results[0]
		debugLog("multi", "Resolve completed for %s: %d methods succeeded, primary=%q",
			ip, len(r.Hostnames), r.PrimaryHostname())
		return r
	}
	debugLog("multi", "Resolve completed for %s: no results", ip)
	return &MultiDiscoveryResult{
		IP:        ip,
		Hostnames: make(map[DiscoveryMethod]string),
		Errors:    make(map[DiscoveryMethod]error),
	}
}
