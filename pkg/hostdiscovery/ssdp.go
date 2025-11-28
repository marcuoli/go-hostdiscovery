// Package hostdiscovery: SSDP/UPnP discovery for IoT and media devices.
// SSDP (Simple Service Discovery Protocol) is commonly used by:
//   - Smart TVs (Samsung, LG, etc.)
//   - Media players (Roku, Apple TV, Fire TV)
//   - IoT devices (smart home hubs, cameras)
//   - Game consoles (Xbox, PlayStation)
//   - Network printers
//   - NAS devices
package hostdiscovery

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	ssdpPort          = 1900
	ssdpMulticastAddr = "239.255.255.250"
	ssdpTimeout       = 3 * time.Second
)

// SSDPResult contains the result of an SSDP discovery.
type SSDPResult struct {
	IP           string
	Location     string // URL to device description
	Server       string // Server header (OS/device info)
	USN          string // Unique Service Name
	ST           string // Search Target (device type)
	FriendlyName string // Parsed from device description if available
	Error        error
}

// SSDPDiscovery performs SSDP-based device discovery.
type SSDPDiscovery struct {
	Timeout time.Duration
}

// NewSSDPDiscovery creates a new SSDP discovery helper with defaults.
func NewSSDPDiscovery() *SSDPDiscovery {
	return &SSDPDiscovery{Timeout: ssdpTimeout}
}

// Discover performs SSDP M-SEARCH to find all devices on the network.
// searchTarget can be:
//   - "ssdp:all" - All devices
//   - "upnp:rootdevice" - Root devices only
//   - "urn:schemas-upnp-org:device:MediaRenderer:1" - Media renderers
//   - "urn:dial-multiscreen-org:service:dial:1" - DIAL/Chromecast
func (s *SSDPDiscovery) Discover(ctx context.Context, searchTarget string) ([]*SSDPResult, error) {
	if searchTarget == "" {
		searchTarget = "ssdp:all"
	}

	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, fmt.Errorf("udp listen: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(s.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	// Build M-SEARCH request
	request := buildMSearchRequest(searchTarget)

	// Send to multicast address
	mcastAddr := &net.UDPAddr{IP: net.ParseIP(ssdpMulticastAddr), Port: ssdpPort}
	if _, err := conn.WriteTo([]byte(request), mcastAddr); err != nil {
		return nil, fmt.Errorf("send M-SEARCH: %w", err)
	}

	// Collect responses
	var results []*SSDPResult
	seen := make(map[string]bool)
	buf := make([]byte, 4096)

	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			break // Timeout
		}

		res := parseSSDPResponse(buf[:n])
		if res == nil {
			continue
		}

		// Extract IP from sender
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			res.IP = udpAddr.IP.String()
		}

		// Deduplicate by USN
		key := res.USN
		if key == "" {
			key = res.IP + res.Location
		}
		if seen[key] {
			continue
		}
		seen[key] = true

		results = append(results, res)
	}

	return results, nil
}

// LookupAddr sends unicast M-SEARCH to a specific IP.
func (s *SSDPDiscovery) LookupAddr(ctx context.Context, ip string) (*SSDPResult, error) {
	res := &SSDPResult{IP: ip}

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

	deadline := time.Now().Add(s.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	request := buildMSearchRequest("ssdp:all")
	addr := &net.UDPAddr{IP: parsedIP, Port: ssdpPort}
	if _, err := conn.WriteTo([]byte(request), addr); err != nil {
		res.Error = fmt.Errorf("send M-SEARCH: %w", err)
		return res, res.Error
	}

	buf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		res.Error = fmt.Errorf("read response: %w", err)
		return res, res.Error
	}

	parsed := parseSSDPResponse(buf[:n])
	if parsed != nil {
		res.Location = parsed.Location
		res.Server = parsed.Server
		res.USN = parsed.USN
		res.ST = parsed.ST
	}

	return res, nil
}

// GetDeviceInfo fetches and parses the device description XML from the Location URL.
// Returns a friendly name if found.
func (s *SSDPDiscovery) GetDeviceInfo(ctx context.Context, locationURL string) (string, error) {
	if locationURL == "" {
		return "", fmt.Errorf("no location URL")
	}

	client := &http.Client{Timeout: s.Timeout}
	req, err := http.NewRequestWithContext(ctx, "GET", locationURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Simple XML parsing: look for <friendlyName>...</friendlyName>
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "<friendlyName>") {
			start := strings.Index(line, "<friendlyName>") + len("<friendlyName>")
			end := strings.Index(line, "</friendlyName>")
			if start > 0 && end > start {
				return strings.TrimSpace(line[start:end]), nil
			}
		}
	}

	return "", nil
}

func buildMSearchRequest(searchTarget string) string {
	return fmt.Sprintf("M-SEARCH * HTTP/1.1\r\n"+
		"HOST: %s:%d\r\n"+
		"MAN: \"ssdp:discover\"\r\n"+
		"MX: 2\r\n"+
		"ST: %s\r\n"+
		"USER-AGENT: go-hostdiscovery/1.0\r\n"+
		"\r\n",
		ssdpMulticastAddr, ssdpPort, searchTarget)
}

func parseSSDPResponse(data []byte) *SSDPResult {
	lines := strings.Split(string(data), "\r\n")
	if len(lines) < 2 {
		return nil
	}

	// Check for HTTP response
	if !strings.HasPrefix(lines[0], "HTTP/") {
		return nil
	}

	res := &SSDPResult{}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch key {
		case "LOCATION":
			res.Location = value
		case "SERVER":
			res.Server = value
		case "USN":
			res.USN = value
		case "ST":
			res.ST = value
		}
	}

	return res
}
