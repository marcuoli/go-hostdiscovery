// Package llmnr provides LLMNR (Link-Local Multicast Name Resolution) discovery.
// LLMNR is commonly used by:
//   - Windows Vista and later
//   - Linux with systemd-resolved
//   - Some Android devices
//
// It resolves hostnames on the local network without a DNS server.
// Uses github.com/miekg/dns for proper DNS packet handling.
package llmnr

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// Port is the LLMNR port
	Port = 5355
	// MulticastAddr is the LLMNR multicast address
	MulticastAddr = "224.0.0.252"
	// DefaultTimeout is the default timeout for LLMNR lookups
	DefaultTimeout = 2 * time.Second
)

// DebugLogger is a callback for debug logging.
// Set this to receive debug messages from LLMNR operations.
var DebugLogger func(format string, args ...interface{})

func debugLog(format string, args ...interface{}) {
	if DebugLogger != nil {
		DebugLogger(format, args...)
	}
}

// Result contains the result of an LLMNR lookup.
type Result struct {
	IP       string
	Hostname string
	Error    error
}

// Discovery performs LLMNR-based hostname discovery.
type Discovery struct {
	Timeout time.Duration
}

// NewDiscovery creates a new LLMNR discovery helper with defaults.
func NewDiscovery() *Discovery {
	return &Discovery{Timeout: DefaultTimeout}
}

// LookupAddr performs a reverse LLMNR lookup for the given IP address.
// LLMNR doesn't natively support reverse lookups, so we use multiple strategies:
// 1. Multicast PTR query (some implementations respond)
// 2. Direct unicast query to the host
func (l *Discovery) LookupAddr(ctx context.Context, ip string) (*Result, error) {
	res := &Result{IP: ip}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		res.Error = fmt.Errorf("invalid IP address: %s", ip)
		return res, res.Error
	}

	ip4 := parsedIP.To4()
	if ip4 == nil {
		res.Error = fmt.Errorf("IPv6 not supported")
		return res, res.Error
	}

	// Build reverse name for PTR query (must end with dot for miekg/dns)
	reverseName := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ip4[3], ip4[2], ip4[1], ip4[0])

	// Try multicast PTR query first
	if hostname := l.queryMulticastPTR(ctx, reverseName, parsedIP); hostname != "" {
		res.Hostname = hostname
		debugLog("%s -> %s (multicast)", ip, hostname)
		return res, nil
	}

	// Try unicast PTR query directly to host
	if hostname := l.queryUnicastPTR(ctx, reverseName, parsedIP); hostname != "" {
		res.Hostname = hostname
		debugLog("%s -> %s (unicast)", ip, hostname)
		return res, nil
	}

	res.Error = fmt.Errorf("no LLMNR response from %s", ip)
	debugLog("%s: no response", ip)
	return res, res.Error
}

// queryMulticastPTR sends a PTR query to the LLMNR multicast address using miekg/dns.
func (l *Discovery) queryMulticastPTR(ctx context.Context, reverseName string, targetIP net.IP) string {
	// Create PTR query message
	msg := new(dns.Msg)
	msg.SetQuestion(reverseName, dns.TypePTR)
	msg.RecursionDesired = false // LLMNR doesn't use recursion

	data, err := msg.Pack()
	if err != nil {
		return ""
	}

	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return ""
	}
	defer conn.Close()

	timeout := l.Timeout
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	// Send to multicast
	mcastAddr := &net.UDPAddr{IP: net.ParseIP(MulticastAddr), Port: Port}
	if _, err := conn.WriteTo(data, mcastAddr); err != nil {
		return ""
	}

	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}

		// Check if response is from our target IP
		if udpAddr, ok := from.(*net.UDPAddr); ok {
			if udpAddr.IP.Equal(targetIP) {
				if hostname := l.parsePTRResponse(buf[:n]); hostname != "" {
					return hostname
				}
			}
		}
	}
	return ""
}

// queryUnicastPTR sends a PTR query directly to the target host.
func (l *Discovery) queryUnicastPTR(ctx context.Context, reverseName string, targetIP net.IP) string {
	msg := new(dns.Msg)
	msg.SetQuestion(reverseName, dns.TypePTR)
	msg.RecursionDesired = false

	data, err := msg.Pack()
	if err != nil {
		return ""
	}

	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return ""
	}
	defer conn.Close()

	deadline := time.Now().Add(l.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	addr := &net.UDPAddr{IP: targetIP, Port: Port}
	if _, err := conn.WriteTo(data, addr); err != nil {
		return ""
	}

	buf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return ""
	}

	return l.parsePTRResponse(buf[:n])
}

// parsePTRResponse parses an LLMNR PTR response using miekg/dns.
func (l *Discovery) parsePTRResponse(data []byte) string {
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		return ""
	}

	// Check if this is a response
	if !msg.Response {
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

// LookupName resolves a hostname to an IP using LLMNR multicast.
func (l *Discovery) LookupName(ctx context.Context, name string) ([]net.IP, error) {
	// Ensure name ends with dot for DNS
	if len(name) > 0 && name[len(name)-1] != '.' {
		name = name + "."
	}

	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	msg.RecursionDesired = false

	data, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack query: %w", err)
	}

	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, fmt.Errorf("udp listen: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(l.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	mcastAddr := &net.UDPAddr{IP: net.ParseIP(MulticastAddr), Port: Port}
	if _, err := conn.WriteTo(data, mcastAddr); err != nil {
		return nil, fmt.Errorf("send query: %w", err)
	}

	var ips []net.IP
	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}

		respMsg := new(dns.Msg)
		if err := respMsg.Unpack(buf[:n]); err != nil {
			continue
		}

		if !respMsg.Response {
			continue
		}

		for _, rr := range respMsg.Answer {
			if a, ok := rr.(*dns.A); ok {
				ips = append(ips, a.A)
			}
		}
	}

	return ips, nil
}

// LookupMultiple performs LLMNR lookups on multiple IPs concurrently.
func (l *Discovery) LookupMultiple(ctx context.Context, ips []string) []*Result {
	if len(ips) == 0 {
		return nil
	}

	results := make([]*Result, len(ips))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for i, ip := range ips {
		wg.Add(1)
		go func(idx int, ipAddr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx], _ = l.LookupAddr(ctx, ipAddr)
		}(i, ip)
	}

	wg.Wait()
	return results
}
