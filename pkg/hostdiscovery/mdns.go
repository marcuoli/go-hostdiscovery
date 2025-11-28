// Package hostdiscovery: mDNS (Multicast DNS / Bonjour / Avahi) discovery.
// mDNS is commonly used by:
//   - macOS/iOS (Bonjour)
//   - Linux (Avahi)
//   - Android
//   - IoT devices (Chromecast, smart home devices, printers)
package hostdiscovery

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	mdnsPort          = 5353
	mdnsMulticastAddr = "224.0.0.251"
	mdnsTimeout       = 3 * time.Second
)

// MDNSResult contains the result of an mDNS lookup.
type MDNSResult struct {
	IP       string
	Hostname string
	Services []MDNSService
	Error    error
}

// MDNSService represents a discovered mDNS service.
type MDNSService struct {
	Instance string            // e.g., "Living Room Speaker"
	Service  string            // e.g., "_googlecast._tcp"
	Domain   string            // e.g., "local"
	Port     int               // Service port
	TXT      map[string]string // TXT record key-value pairs
}

// MDNSDiscovery performs mDNS-based hostname and service discovery.
type MDNSDiscovery struct {
	Timeout time.Duration
}

// NewMDNSDiscovery creates a new mDNS discovery helper with defaults.
func NewMDNSDiscovery() *MDNSDiscovery {
	return &MDNSDiscovery{Timeout: mdnsTimeout}
}

// LookupAddr queries a specific IP for its mDNS hostname using a unicast query.
func (m *MDNSDiscovery) LookupAddr(ctx context.Context, ip string) (*MDNSResult, error) {
	res := &MDNSResult{IP: ip}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		res.Error = fmt.Errorf("invalid IP address: %s", ip)
		return res, res.Error
	}

	// Build reverse DNS name for PTR query
	// e.g., 192.168.1.100 -> 100.1.168.192.in-addr.arpa
	ip4 := parsedIP.To4()
	if ip4 == nil {
		res.Error = fmt.Errorf("IPv6 not supported for mDNS reverse lookup")
		return res, res.Error
	}
	reverseName := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", ip4[3], ip4[2], ip4[1], ip4[0])

	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		res.Error = fmt.Errorf("udp listen: %w", err)
		return res, res.Error
	}
	defer conn.Close()

	deadline := time.Now().Add(m.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	// Send unicast query directly to the host
	addr := &net.UDPAddr{IP: parsedIP, Port: mdnsPort}
	query := buildMDNSQuery(reverseName, 12) // Type PTR = 12
	if _, err := conn.WriteTo(query, addr); err != nil {
		res.Error = fmt.Errorf("send query: %w", err)
		return res, res.Error
	}

	// Read response
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		res.Error = fmt.Errorf("read response: %w", err)
		return res, res.Error
	}

	hostname := parseMDNSPTRResponse(buf[:n])
	if hostname != "" {
		// Clean up .local suffix if present for display
		res.Hostname = strings.TrimSuffix(hostname, ".")
	}

	return res, nil
}

// BrowseServices discovers services of a specific type on the local network.
// Common service types:
//   - "_http._tcp" - Web servers
//   - "_googlecast._tcp" - Chromecast
//   - "_airplay._tcp" - Apple AirPlay
//   - "_printer._tcp" - Printers
//   - "_ssh._tcp" - SSH servers
//   - "_smb._tcp" - SMB/Windows shares
func (m *MDNSDiscovery) BrowseServices(ctx context.Context, serviceType string) ([]MDNSService, error) {
	if !strings.HasSuffix(serviceType, ".local") {
		serviceType = serviceType + ".local"
	}

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
	mcastAddr := &net.UDPAddr{IP: net.ParseIP(mdnsMulticastAddr), Port: mdnsPort}
	query := buildMDNSQuery(serviceType, 12) // Type PTR = 12
	if _, err := conn.WriteTo(query, mcastAddr); err != nil {
		return nil, fmt.Errorf("send query: %w", err)
	}

	// Collect responses until timeout
	var services []MDNSService
	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break // Timeout or error
		}
		if svc := parseMDNSServiceResponse(buf[:n]); svc != nil {
			services = append(services, *svc)
		}
	}

	return services, nil
}

// LookupMultiple performs mDNS lookups on multiple IPs concurrently.
func (m *MDNSDiscovery) LookupMultiple(ctx context.Context, ips []string) []*MDNSResult {
	if len(ips) == 0 {
		return nil
	}

	results := make([]*MDNSResult, len(ips))
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

// buildMDNSQuery creates a simple DNS query packet.
func buildMDNSQuery(name string, qtype uint16) []byte {
	var buf bytes.Buffer

	// Transaction ID (random-ish for unicast, 0 for multicast)
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x0001))
	// Flags: standard query
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x0000))
	// Questions: 1
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	// Answer, Authority, Additional: 0
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))

	// Encode DNS name
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 {
			continue
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0) // End of name

	// Type and Class
	_ = binary.Write(&buf, binary.BigEndian, qtype)
	_ = binary.Write(&buf, binary.BigEndian, uint16(1)) // Class IN

	return buf.Bytes()
}

// parseMDNSPTRResponse extracts a PTR hostname from a DNS response.
func parseMDNSPTRResponse(data []byte) string {
	if len(data) < 12 {
		return ""
	}

	// Skip header, find answer section
	// Simple parsing: look for PTR record type (12) in answers
	ancount := binary.BigEndian.Uint16(data[6:8])
	if ancount == 0 {
		return ""
	}

	// Skip question section (simplified: assume one question)
	offset := 12
	for offset < len(data) && data[offset] != 0 {
		labelLen := int(data[offset])
		offset += labelLen + 1
	}
	offset += 5 // null byte + QTYPE (2) + QCLASS (2)

	// Parse first answer
	if offset >= len(data) {
		return ""
	}

	// Skip name (may be compressed)
	offset = skipDNSName(data, offset)
	if offset+10 > len(data) {
		return ""
	}

	rtype := binary.BigEndian.Uint16(data[offset : offset+2])
	if rtype != 12 { // Not PTR
		return ""
	}
	offset += 8 // Type(2) + Class(2) + TTL(4)
	rdlength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+rdlength > len(data) {
		return ""
	}

	// Extract PTR name
	return extractDNSName(data, offset)
}

// parseMDNSServiceResponse parses a service discovery response.
func parseMDNSServiceResponse(data []byte) *MDNSService {
	if len(data) < 12 {
		return nil
	}

	ancount := binary.BigEndian.Uint16(data[6:8])
	if ancount == 0 {
		return nil
	}

	// Simple extraction: find instance name from PTR record
	offset := 12
	for offset < len(data) && data[offset] != 0 {
		offset += int(data[offset]) + 1
	}
	offset += 5

	if offset >= len(data) {
		return nil
	}

	offset = skipDNSName(data, offset)
	if offset+10 > len(data) {
		return nil
	}

	rtype := binary.BigEndian.Uint16(data[offset : offset+2])
	if rtype != 12 {
		return nil
	}
	offset += 8
	rdlength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+rdlength > len(data) {
		return nil
	}

	instanceName := extractDNSName(data, offset)
	if instanceName == "" {
		return nil
	}

	return &MDNSService{
		Instance: instanceName,
		Domain:   "local",
	}
}

func skipDNSName(data []byte, offset int) int {
	for offset < len(data) {
		if data[offset] == 0 {
			return offset + 1
		}
		if data[offset]&0xC0 == 0xC0 { // Compression pointer
			return offset + 2
		}
		offset += int(data[offset]) + 1
	}
	return offset
}

func extractDNSName(data []byte, offset int) string {
	var parts []string
	for offset < len(data) && data[offset] != 0 {
		if data[offset]&0xC0 == 0xC0 { // Compression pointer
			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2])) & 0x3FFF
			return strings.Join(append(parts, extractDNSName(data, ptr)), ".")
		}
		labelLen := int(data[offset])
		offset++
		if offset+labelLen > len(data) {
			break
		}
		parts = append(parts, string(data[offset:offset+labelLen]))
		offset += labelLen
	}
	return strings.Join(parts, ".")
}
