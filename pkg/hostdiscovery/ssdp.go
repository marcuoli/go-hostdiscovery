// Package hostdiscovery: SSDP/UPnP discovery for IoT and media devices.
// SSDP (Simple Service Discovery Protocol) is commonly used by:
//   - Smart TVs (Samsung, LG, Sony, etc.)
//   - Media players (Roku, Apple TV, Fire TV, Chromecast)
//   - Voice assistants (Google Home, Amazon Alexa/Echo)
//   - IoT devices (smart home hubs, cameras, thermostats)
//   - Game consoles (Xbox, PlayStation)
//   - Network printers and scanners
//   - NAS devices (Synology, QNAP)
//   - Routers and network equipment
//
// This implementation uses github.com/koron/go-ssdp for robust SSDP handling.
package hostdiscovery

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/koron/go-ssdp"
)

const (
	ssdpTimeout = 3 * time.Second
)

// Common SSDP search targets
const (
	// SSDPAll searches for all devices and services
	SSDPAll = ssdp.All // "ssdp:all"

	// SSDPRootDevice searches for UPnP root devices only
	SSDPRootDevice = ssdp.RootDevice // "upnp:rootdevice"

	// SSDPMediaRenderer searches for media renderers (TVs, speakers)
	SSDPMediaRenderer = "urn:schemas-upnp-org:device:MediaRenderer:1"

	// SSDPMediaServer searches for media servers (NAS, DLNA servers)
	SSDPMediaServer = "urn:schemas-upnp-org:device:MediaServer:1"

	// SSDPDialMultiscreen searches for DIAL/Chromecast devices
	SSDPDialMultiscreen = "urn:dial-multiscreen-org:service:dial:1"

	// SSDPBasicDevice searches for basic UPnP devices
	SSDPBasicDevice = "urn:schemas-upnp-org:device:Basic:1"

	// SSDPInternetGateway searches for routers/gateways
	SSDPInternetGateway = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"

	// SSDPPrinter searches for UPnP printers
	SSDPPrinter = "urn:schemas-upnp-org:service:PrintBasic:1"
)

// SSDPResult contains the result of an SSDP discovery.
type SSDPResult struct {
	IP           string
	Location     string // URL to device description XML
	Server       string // Server header (OS/device info)
	USN          string // Unique Service Name
	ST           string // Search Target (device type)
	MaxAge       int    // Cache control max-age
	FriendlyName string // Parsed from device description if available
	Manufacturer string // Parsed from device description
	ModelName    string // Parsed from device description
	Error        error
}

// SSDPDiscovery performs SSDP-based device discovery using koron/go-ssdp.
type SSDPDiscovery struct {
	Timeout    time.Duration
	Interfaces []net.Interface // Specific interfaces to use (nil = all)
}

// NewSSDPDiscovery creates a new SSDP discovery helper with defaults.
func NewSSDPDiscovery() *SSDPDiscovery {
	return &SSDPDiscovery{Timeout: ssdpTimeout}
}

// Discover performs SSDP M-SEARCH to find all devices on the network.
// searchTarget can be:
//   - SSDPAll ("ssdp:all") - All devices
//   - SSDPRootDevice ("upnp:rootdevice") - Root devices only
//   - SSDPMediaRenderer - Smart TVs, speakers, media players
//   - SSDPMediaServer - NAS, DLNA servers
//   - SSDPDialMultiscreen - Chromecast, DIAL-enabled devices
//   - SSDPInternetGateway - Routers
//   - Custom URN strings
func (s *SSDPDiscovery) Discover(ctx context.Context, searchTarget string) ([]*SSDPResult, error) {
	if searchTarget == "" {
		searchTarget = SSDPAll
	}

	// Configure interfaces if specified
	if len(s.Interfaces) > 0 {
		ssdp.Interfaces = s.Interfaces
		defer func() { ssdp.Interfaces = nil }()
	}

	// Calculate wait time in seconds (minimum 1)
	waitSec := int(s.Timeout.Seconds())
	if waitSec < 1 {
		waitSec = 1
	}

	// Use context for cancellation
	resultCh := make(chan []ssdp.Service, 1)
	errCh := make(chan error, 1)

	go func() {
		services, err := ssdp.Search(searchTarget, waitSec, "")
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- services
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errCh:
		return nil, fmt.Errorf("SSDP search: %w", err)
	case services := <-resultCh:
		return s.convertServices(services), nil
	}
}

// DiscoverAll performs multiple searches to find various device types.
// Returns a combined, deduplicated list of all discovered devices.
func (s *SSDPDiscovery) DiscoverAll(ctx context.Context) ([]*SSDPResult, error) {
	searchTargets := []string{
		SSDPAll,
		SSDPRootDevice,
		SSDPMediaRenderer,
		SSDPDialMultiscreen,
	}

	seen := make(map[string]bool)
	var results []*SSDPResult
	var mu sync.Mutex

	for _, st := range searchTargets {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		found, err := s.Discover(ctx, st)
		if err != nil {
			continue // Best effort
		}

		mu.Lock()
		for _, r := range found {
			key := r.USN
			if key == "" {
				key = r.IP + r.Location
			}
			if !seen[key] {
				seen[key] = true
				results = append(results, r)
			}
		}
		mu.Unlock()
	}

	return results, nil
}

// LookupAddr checks if a specific IP has SSDP-enabled devices.
// Note: SSDP is typically multicast-based, so this sends a unicast M-SEARCH
// which may not be supported by all devices.
func (s *SSDPDiscovery) LookupAddr(ctx context.Context, ip string) (*SSDPResult, error) {
	res := &SSDPResult{IP: ip}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		res.Error = fmt.Errorf("invalid IP address: %s", ip)
		return res, res.Error
	}

	// Do a full discovery and filter by IP
	results, err := s.Discover(ctx, SSDPAll)
	if err != nil {
		res.Error = err
		return res, err
	}

	for _, r := range results {
		if r.IP == ip {
			return r, nil
		}
	}

	res.Error = fmt.Errorf("no SSDP response from %s", ip)
	return res, res.Error
}

// Monitor starts monitoring for SSDP alive/bye announcements.
// Returns channels for alive messages, bye messages, and a stop function.
func (s *SSDPDiscovery) Monitor(ctx context.Context) (<-chan *SSDPResult, <-chan string, error) {
	aliveCh := make(chan *SSDPResult, 100)
	byeCh := make(chan string, 100) // USN of device going offline

	monitor := &ssdp.Monitor{
		Alive: func(m *ssdp.AliveMessage) {
			result := &SSDPResult{
				Location: m.Location,
				Server:   m.Server,
				USN:      m.USN,
				ST:       m.Type,
				MaxAge:   m.MaxAge(),
			}
			// Extract IP from sender
			if m.From != nil {
				if udpAddr, ok := m.From.(*net.UDPAddr); ok {
					result.IP = udpAddr.IP.String()
				} else {
					host, _, _ := net.SplitHostPort(m.From.String())
					result.IP = host
				}
			}
			select {
			case aliveCh <- result:
			default: // Don't block if channel full
			}
		},
		Bye: func(m *ssdp.ByeMessage) {
			select {
			case byeCh <- m.USN:
			default:
			}
		},
	}

	if err := monitor.Start(); err != nil {
		close(aliveCh)
		close(byeCh)
		return nil, nil, fmt.Errorf("start monitor: %w", err)
	}

	// Handle context cancellation
	go func() {
		<-ctx.Done()
		monitor.Close()
		close(aliveCh)
		close(byeCh)
	}()

	return aliveCh, byeCh, nil
}

// GetDeviceInfo fetches and parses the device description XML from the Location URL.
// Returns detailed device information including friendly name, manufacturer, model.
func (s *SSDPDiscovery) GetDeviceInfo(ctx context.Context, locationURL string) (*SSDPResult, error) {
	if locationURL == "" {
		return nil, fmt.Errorf("no location URL")
	}

	client := &http.Client{Timeout: s.Timeout}
	req, err := http.NewRequestWithContext(ctx, "GET", locationURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result := &SSDPResult{Location: locationURL}

	// Simple XML parsing: look for key elements
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		if name := extractXMLValue(line, "friendlyName"); name != "" {
			result.FriendlyName = name
		}
		if mfr := extractXMLValue(line, "manufacturer"); mfr != "" {
			result.Manufacturer = mfr
		}
		if model := extractXMLValue(line, "modelName"); model != "" {
			result.ModelName = model
		}
	}

	return result, nil
}

// EnrichResults fetches device info for each result's Location URL.
// This populates FriendlyName, Manufacturer, and ModelName fields.
func (s *SSDPDiscovery) EnrichResults(ctx context.Context, results []*SSDPResult) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5) // Limit concurrent requests

	for _, r := range results {
		if r.Location == "" {
			continue
		}

		wg.Add(1)
		go func(result *SSDPResult) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			info, err := s.GetDeviceInfo(ctx, result.Location)
			if err == nil && info != nil {
				result.FriendlyName = info.FriendlyName
				result.Manufacturer = info.Manufacturer
				result.ModelName = info.ModelName
			}
		}(r)
	}

	wg.Wait()
}

// convertServices converts go-ssdp Service slice to our SSDPResult slice
func (s *SSDPDiscovery) convertServices(services []ssdp.Service) []*SSDPResult {
	results := make([]*SSDPResult, 0, len(services))

	for _, svc := range services {
		result := &SSDPResult{
			Location: svc.Location,
			Server:   svc.Server,
			USN:      svc.USN,
			ST:       svc.Type,
			MaxAge:   svc.MaxAge(),
		}

		// Extract IP from Location URL
		if svc.Location != "" {
			result.IP = extractIPFromURL(svc.Location)
		}

		results = append(results, result)
	}

	return results
}

// extractIPFromURL extracts the IP address from a URL like "http://192.168.1.1:8080/desc.xml"
func extractIPFromURL(url string) string {
	// Remove scheme
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")

	// Get host:port part
	if idx := strings.Index(url, "/"); idx > 0 {
		url = url[:idx]
	}

	// Remove port
	host, _, err := net.SplitHostPort(url)
	if err != nil {
		// No port, try as-is
		host = url
	}

	// Validate it's an IP
	if ip := net.ParseIP(host); ip != nil {
		return host
	}

	return ""
}

// extractXMLValue extracts the value from a simple XML tag like <tagName>value</tagName>
func extractXMLValue(line, tagName string) string {
	openTag := "<" + tagName + ">"
	closeTag := "</" + tagName + ">"

	start := strings.Index(line, openTag)
	if start < 0 {
		return ""
	}
	start += len(openTag)

	end := strings.Index(line, closeTag)
	if end < 0 || end <= start {
		return ""
	}

	return strings.TrimSpace(line[start:end])
}
