// Package mdns provides mDNS (Multicast DNS / Bonjour / Avahi) discovery.
// mDNS is commonly used by:
//   - macOS/iOS (Bonjour)
//   - Linux (Avahi)
//   - Android
//   - IoT devices (Chromecast, smart home devices, printers)
//
// Uses codeberg.org/miekg/dns for proper DNS packet handling.
package mdns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
)

const (
	// Port is the mDNS port
	Port = 5353
	// MulticastAddr is the mDNS multicast address
	MulticastAddr = "224.0.0.251"
	// DefaultTimeout is the default timeout for mDNS lookups
	DefaultTimeout = 3 * time.Second
)

// DebugLogger is a callback for debug logging.
// Set this to receive debug messages from mDNS operations.
var DebugLogger func(format string, args ...interface{})

func debugLog(format string, args ...interface{}) {
	if DebugLogger != nil {
		DebugLogger(format, args...)
	}
}

// Result contains the result of an mDNS lookup.
type Result struct {
	IP       string
	Hostname string
	Services []Service
	Error    error
}

// Service represents a discovered mDNS service.
type Service struct {
	Instance string            // e.g., "Living Room Speaker"
	Service  string            // e.g., "_googlecast._tcp"
	Domain   string            // e.g., "local"
	Port     int               // Service port
	TXT      map[string]string // TXT record key-value pairs
}

// Discovery performs mDNS-based hostname and service discovery.
type Discovery struct {
	Timeout time.Duration
}

// NewDiscovery creates a new mDNS discovery helper with defaults.
func NewDiscovery() *Discovery {
	return &Discovery{Timeout: DefaultTimeout}
}

// LookupAddr queries a specific IP for its mDNS hostname.
// It tries both multicast (for Avahi/Bonjour) and unicast queries.
func (m *Discovery) LookupAddr(ctx context.Context, ip string) (*Result, error) {
	res := &Result{IP: ip}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		res.Error = fmt.Errorf("invalid IP address: %s", ip)
		return res, res.Error
	}

	ip4 := parsedIP.To4()
	if ip4 == nil {
		res.Error = fmt.Errorf("IPv6 not supported for mDNS reverse lookup")
		return res, res.Error
	}

	// Build reverse DNS name for PTR query (must end with dot for miekg/dns)
	// e.g., 192.168.1.100 -> 100.1.168.192.in-addr.arpa.
	reverseName := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ip4[3], ip4[2], ip4[1], ip4[0])

	// Try multicast first (works with Avahi on Linux, Bonjour on macOS)
	if hostname := m.queryMulticast(ctx, reverseName, parsedIP); hostname != "" {
		res.Hostname = hostname
		debugLog("%s -> %s (multicast)", ip, hostname)
		return res, nil
	}

	// Fallback to unicast query directly to the host
	if hostname := m.queryUnicast(ctx, reverseName, parsedIP); hostname != "" {
		res.Hostname = hostname
		debugLog("%s -> %s (unicast)", ip, hostname)
		return res, nil
	}

	res.Error = fmt.Errorf("no mDNS response from %s", ip)
	debugLog("%s: no response", ip)
	return res, res.Error
}

// queryMulticast sends an mDNS query to the multicast address and filters responses by IP.
func (m *Discovery) queryMulticast(ctx context.Context, reverseName string, targetIP net.IP) string {
	// Create PTR query message
	msg := new(dns.Msg)
	msg.Question = append(msg.Question, &dns.PTR{Hdr: dns.Header{Name: reverseName, Class: dns.ClassINET}})
	msg.RecursionDesired = false // mDNS doesn't use recursion

	if err := msg.Pack(); err != nil {
		return ""
	}
	data := msg.Data

	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Use shorter timeout for multicast since we need to wait for responses
	timeout := m.Timeout
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	// Send to multicast address
	mcastAddr := &net.UDPAddr{IP: net.ParseIP(MulticastAddr), Port: Port}
	if _, err := conn.WriteTo(data, mcastAddr); err != nil {
		return ""
	}

	// Read responses until timeout, looking for one from our target IP
	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}

		// Check if response is from our target IP
		if udpAddr, ok := from.(*net.UDPAddr); ok {
			if udpAddr.IP.Equal(targetIP) {
				if hostname := m.parsePTRResponse(buf[:n]); hostname != "" {
					return hostname
				}
			}
		}
	}
	return ""
}

// queryUnicast sends an mDNS query directly to the target host.
func (m *Discovery) queryUnicast(ctx context.Context, reverseName string, targetIP net.IP) string {
	msg := new(dns.Msg)
	msg.Question = append(msg.Question, &dns.PTR{Hdr: dns.Header{Name: reverseName, Class: dns.ClassINET}})
	msg.RecursionDesired = false

	if err := msg.Pack(); err != nil {
		return ""
	}
	data := msg.Data

	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return ""
	}
	defer conn.Close()

	deadline := time.Now().Add(m.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	// Send unicast query directly to the host
	addr := &net.UDPAddr{IP: targetIP, Port: Port}
	if _, err := conn.WriteTo(data, addr); err != nil {
		return ""
	}

	buf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return ""
	}

	return m.parsePTRResponse(buf[:n])
}

// parsePTRResponse parses an mDNS PTR response using miekg/dns.
func (m *Discovery) parsePTRResponse(data []byte) string {
	msg := &dns.Msg{Data: data}
	if err := msg.Unpack(); err != nil {
		return ""
	}

	// Look for PTR records in answers
	for _, rr := range msg.Answer {
		if ptr, ok := rr.(*dns.PTR); ok {
			hostname := ptr.Ptr
			// Remove trailing dot
			if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
				hostname = hostname[:len(hostname)-1]
			}
			return hostname
		}
	}

	return ""
}

// BrowseServices discovers services of a specific type on the local network.
// Common service types:
//   - "_http._tcp" - Web servers
//   - "_googlecast._tcp" - Chromecast
//   - "_airplay._tcp" - Apple AirPlay
//   - "_printer._tcp" - Printers
//   - "_ssh._tcp" - SSH servers
//   - "_smb._tcp" - SMB/Windows shares
func (m *Discovery) BrowseServices(ctx context.Context, serviceType string) ([]Service, error) {
	// Ensure proper DNS format with trailing dot
	if !strings.HasSuffix(serviceType, ".local.") {
		if strings.HasSuffix(serviceType, ".local") {
			serviceType = serviceType + "."
		} else {
			serviceType = serviceType + ".local."
		}
	}

	msg := new(dns.Msg)
	msg.Question = append(msg.Question, &dns.PTR{Hdr: dns.Header{Name: serviceType, Class: dns.ClassINET}})
	msg.RecursionDesired = false

	if err := msg.Pack(); err != nil {
		return nil, fmt.Errorf("pack query: %w", err)
	}
	data := msg.Data

	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, fmt.Errorf("udp listen: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(m.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	// Send to multicast address
	mcastAddr := &net.UDPAddr{IP: net.ParseIP(MulticastAddr), Port: Port}
	if _, err := conn.WriteTo(data, mcastAddr); err != nil {
		return nil, fmt.Errorf("send query: %w", err)
	}

	// Collect responses until timeout
	var services []Service
	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break // Timeout or error
		}

		respMsg := &dns.Msg{Data: buf[:n]}
		if err := respMsg.Unpack(); err != nil {
			continue
		}

		// Extract service instances from PTR records
		for _, rr := range respMsg.Answer {
			if ptr, ok := rr.(*dns.PTR); ok {
				instanceName := strings.TrimSuffix(ptr.Ptr, ".")
				services = append(services, Service{
					Instance: instanceName,
					Service:  strings.TrimSuffix(serviceType, "."),
					Domain:   "local",
				})
			}
		}

		// Also look for SRV records for port info
		for _, rr := range respMsg.Extra {
			if srv, ok := rr.(*dns.SRV); ok {
				// Find and update matching service
				for i := range services {
					if strings.Contains(srv.Hdr.Name, services[i].Instance) {
						services[i].Port = int(srv.Port)
					}
				}
			}
			// Parse TXT records
			if txt, ok := rr.(*dns.TXT); ok {
				for i := range services {
					if strings.Contains(txt.Hdr.Name, services[i].Instance) {
						if services[i].TXT == nil {
							services[i].TXT = make(map[string]string)
						}
						for _, t := range txt.Txt {
							if parts := strings.SplitN(t, "=", 2); len(parts) == 2 {
								services[i].TXT[parts[0]] = parts[1]
							}
						}
					}
				}
			}
		}
	}

	return services, nil
}

// LookupMultiple performs mDNS lookups on multiple IPs concurrently.
func (m *Discovery) LookupMultiple(ctx context.Context, ips []string) []*Result {
	if len(ips) == 0 {
		return nil
	}

	results := make([]*Result, len(ips))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50) // Limit concurrency for mDNS

	for i, ip := range ips {
		wg.Add(1)
		go func(idx int, ipAddr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx], _ = m.LookupAddr(ctx, ipAddr)
		}(i, ip)
	}

	wg.Wait()
	return results
}
