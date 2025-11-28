// Package hostdiscovery: DHCP hostname discovery utilities.
// DHCP hostnames are typically registered with DNS servers that support
// dynamic DNS updates (DDNS). This file provides methods to discover
// hostnames that were registered via DHCP.
//
// The DHCP hostname can be discovered through:
// 1. Reverse DNS (if DHCP server updates DNS) - covered in dns.go
// 2. Querying the DHCP server's lease database (requires access)
// 3. DHCP INFORM request (requires raw sockets/elevated privileges)
//
// For most environments, reverse DNS is the primary method since
// enterprise DHCP servers typically update DNS records automatically.
package hostdiscovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	dhcpTimeout = 2 * time.Second
)

// DHCPResult contains information about a host's DHCP registration.
type DHCPResult struct {
	IP           string
	Hostname     string
	Domain       string
	FQDN         string // Fully Qualified Domain Name
	LeaseSource  string // "dns" or "dhcp-server"
	Error        error
}

// DHCPDiscovery performs DHCP-related hostname discovery.
// Note: Without elevated privileges, this primarily uses reverse DNS
// to discover hostnames that were registered via DHCP dynamic updates.
type DHCPDiscovery struct {
	Timeout    time.Duration
	DNSServers []string // Custom DNS servers to query (e.g., DHCP server with DNS)
}

// NewDHCPDiscovery creates a new DHCP discovery helper with defaults.
func NewDHCPDiscovery() *DHCPDiscovery {
	return &DHCPDiscovery{Timeout: dhcpTimeout}
}

// LookupAddr attempts to discover the DHCP-registered hostname for an IP.
// This works by querying reverse DNS, which is typically updated by DHCP servers
// that support dynamic DNS (DDNS).
func (d *DHCPDiscovery) LookupAddr(ctx context.Context, ip string) (*DHCPResult, error) {
	res := &DHCPResult{IP: ip}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		res.Error = fmt.Errorf("invalid IP address: %s", ip)
		return res, res.Error
	}

	// Use custom resolver if DNS servers specified
	var resolver *net.Resolver
	if len(d.DNSServers) > 0 {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := net.Dialer{Timeout: d.Timeout}
				// Try each DNS server
				for _, server := range d.DNSServers {
					if !strings.Contains(server, ":") {
						server = server + ":53"
					}
					conn, err := dialer.DialContext(ctx, "udp", server)
					if err == nil {
						return conn, nil
					}
				}
				// Fallback to default
				return dialer.DialContext(ctx, network, address)
			},
		}
	} else {
		resolver = net.DefaultResolver
	}

	// Perform reverse DNS lookup
	lookupCtx, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()

	names, err := resolver.LookupAddr(lookupCtx, ip)
	if err != nil || len(names) == 0 {
		res.Error = fmt.Errorf("no reverse DNS record (DHCP may not update DNS): %w", err)
		return res, res.Error
	}

	// Parse the FQDN
	fqdn := strings.TrimSuffix(names[0], ".")
	res.FQDN = fqdn
	res.LeaseSource = "dns"

	// Extract hostname and domain
	parts := strings.SplitN(fqdn, ".", 2)
	res.Hostname = parts[0]
	if len(parts) > 1 {
		res.Domain = parts[1]
	}

	return res, nil
}

// LookupMultiple performs DHCP lookups on multiple IPs concurrently.
func (d *DHCPDiscovery) LookupMultiple(ctx context.Context, ips []string) []*DHCPResult {
	if len(ips) == 0 {
		return nil
	}

	results := make([]*DHCPResult, len(ips))
	done := make(chan struct{})

	for i, ip := range ips {
		go func(idx int, ipAddr string) {
			results[idx], _ = d.LookupAddr(ctx, ipAddr)
			select {
			case done <- struct{}{}:
			default:
			}
		}(i, ip)
	}

	for range ips {
		select {
		case <-done:
		case <-ctx.Done():
			return results
		}
	}

	return results
}

// WithDNSServer configures a specific DNS server to query.
// Useful when the DHCP server is also the DNS server.
func (d *DHCPDiscovery) WithDNSServer(server string) *DHCPDiscovery {
	d.DNSServers = append(d.DNSServers, server)
	return d
}

// Note: Direct DHCP lease querying would require:
// 1. Access to DHCP server's lease file (dhcpd.leases on ISC DHCP)
// 2. SNMP access to DHCP server
// 3. DHCP server API (Windows DHCP, Kea, etc.)
// 4. Raw socket DHCP INFORM (requires elevated privileges)
//
// These are not implemented as they require either:
// - Network access to the DHCP server infrastructure
// - Elevated privileges on the local machine
// - Vendor-specific API access
