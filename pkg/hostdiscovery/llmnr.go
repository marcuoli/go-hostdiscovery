// Package hostdiscovery: LLMNR (Link-Local Multicast Name Resolution) discovery.
// LLMNR is commonly used by:
//   - Windows Vista and later
//   - Linux with systemd-resolved
//   - Some Android devices
//
// It resolves hostnames on the local network without a DNS server.
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
	llmnrPort          = 5355
	llmnrMulticastAddr = "224.0.0.252"
	llmnrTimeout       = 2 * time.Second
)

// LLMNRResult contains the result of an LLMNR lookup.
type LLMNRResult struct {
	IP       string
	Hostname string
	Error    error
}

// LLMNRDiscovery performs LLMNR-based hostname discovery.
type LLMNRDiscovery struct {
	Timeout time.Duration
}

// NewLLMNRDiscovery creates a new LLMNR discovery helper with defaults.
func NewLLMNRDiscovery() *LLMNRDiscovery {
	return &LLMNRDiscovery{Timeout: llmnrTimeout}
}

// LookupAddr performs a reverse LLMNR lookup for the given IP address.
// Note: LLMNR primarily resolves names to IPs, not IPs to names.
// This sends a unicast query to the target asking for its name.
func (l *LLMNRDiscovery) LookupAddr(ctx context.Context, ip string) (*LLMNRResult, error) {
	res := &LLMNRResult{IP: ip}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		res.Error = fmt.Errorf("invalid IP address: %s", ip)
		return res, res.Error
	}

	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		res.Error = fmt.Errorf("udp listen: %w", err)
		return res, res.Error
	}
	defer conn.Close()

	deadline := time.Now().Add(l.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	// Build reverse lookup query (similar to mDNS PTR)
	ip4 := parsedIP.To4()
	if ip4 == nil {
		res.Error = fmt.Errorf("IPv6 not supported")
		return res, res.Error
	}

	// Try direct unicast query with "*" wildcard name
	addr := &net.UDPAddr{IP: parsedIP, Port: llmnrPort}
	query := buildLLMNRQuery("*", 255) // Type ANY
	if _, err := conn.WriteTo(query, addr); err != nil {
		res.Error = fmt.Errorf("send query: %w", err)
		return res, res.Error
	}

	buf := make([]byte, 2048)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		res.Error = fmt.Errorf("read response: %w", err)
		return res, res.Error
	}

	hostname := parseLLMNRResponse(buf[:n])
	if hostname != "" {
		res.Hostname = hostname
	}

	return res, nil
}

// LookupName resolves a hostname to an IP using LLMNR multicast.
func (l *LLMNRDiscovery) LookupName(ctx context.Context, name string) ([]net.IP, error) {
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

	mcastAddr := &net.UDPAddr{IP: net.ParseIP(llmnrMulticastAddr), Port: llmnrPort}
	query := buildLLMNRQuery(name, 1) // Type A
	if _, err := conn.WriteTo(query, mcastAddr); err != nil {
		return nil, fmt.Errorf("send query: %w", err)
	}

	var ips []net.IP
	buf := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		if ip := parseLLMNRARecord(buf[:n]); ip != nil {
			ips = append(ips, ip)
		}
	}

	return ips, nil
}

// LookupMultiple performs LLMNR lookups on multiple IPs concurrently.
func (l *LLMNRDiscovery) LookupMultiple(ctx context.Context, ips []string) []*LLMNRResult {
	if len(ips) == 0 {
		return nil
	}

	results := make([]*LLMNRResult, len(ips))
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

func buildLLMNRQuery(name string, qtype uint16) []byte {
	var buf bytes.Buffer

	// Transaction ID
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x4242))
	// Flags: standard query, recursion not desired for LLMNR
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x0000))
	// Questions: 1
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	// Answer, Authority, Additional: 0
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))

	// Encode DNS-style name
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 {
			continue
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)

	// Type and Class
	_ = binary.Write(&buf, binary.BigEndian, qtype)
	_ = binary.Write(&buf, binary.BigEndian, uint16(1)) // Class IN

	return buf.Bytes()
}

func parseLLMNRResponse(data []byte) string {
	if len(data) < 12 {
		return ""
	}

	// Check if this is a response (QR bit set)
	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&0x8000 == 0 {
		return "" // Not a response
	}

	ancount := binary.BigEndian.Uint16(data[6:8])
	if ancount == 0 {
		return ""
	}

	// Extract name from question section
	offset := 12
	var parts []string
	for offset < len(data) && data[offset] != 0 {
		labelLen := int(data[offset])
		offset++
		if offset+labelLen > len(data) {
			break
		}
		parts = append(parts, string(data[offset:offset+labelLen]))
		offset += labelLen
	}

	if len(parts) > 0 {
		return strings.Join(parts, ".")
	}
	return ""
}

func parseLLMNRARecord(data []byte) net.IP {
	if len(data) < 12 {
		return nil
	}

	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&0x8000 == 0 {
		return nil
	}

	ancount := binary.BigEndian.Uint16(data[6:8])
	if ancount == 0 {
		return nil
	}

	// Skip question
	offset := 12
	for offset < len(data) && data[offset] != 0 {
		offset += int(data[offset]) + 1
	}
	offset += 5 // null + type + class

	// Skip answer name (may be compressed)
	if offset >= len(data) {
		return nil
	}
	if data[offset]&0xC0 == 0xC0 {
		offset += 2
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}

	if offset+10 > len(data) {
		return nil
	}

	rtype := binary.BigEndian.Uint16(data[offset : offset+2])
	if rtype != 1 { // Not A record
		return nil
	}
	offset += 8 // type + class + ttl
	rdlength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if rdlength == 4 && offset+4 <= len(data) {
		return net.IPv4(data[offset], data[offset+1], data[offset+2], data[offset+3])
	}

	return nil
}
