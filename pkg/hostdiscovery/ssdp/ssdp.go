// Package ssdp provides SSDP/UPnP discovery for IoT and media devices.
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
package ssdp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	gossdp "github.com/koron/go-ssdp"
)

// DebugLogger is the callback function for debug logging.
// Set this to enable debug output for SSDP operations.
var DebugLogger func(format string, args ...interface{})

func debugLog(format string, args ...interface{}) {
	if DebugLogger != nil {
		DebugLogger(format, args...)
	}
}

const (
	// DefaultTimeout is the default timeout for SSDP discovery
	DefaultTimeout = 3 * time.Second
)

// Common SSDP search targets
const (
	// All searches for all devices and services
	All = gossdp.All // "ssdp:all"

	// RootDevice searches for UPnP root devices only
	RootDevice = gossdp.RootDevice // "upnp:rootdevice"

	// MediaRenderer searches for media renderers (TVs, speakers)
	MediaRenderer = "urn:schemas-upnp-org:device:MediaRenderer:1"

	// MediaServer searches for media servers (NAS, DLNA servers)
	MediaServer = "urn:schemas-upnp-org:device:MediaServer:1"

	// DialMultiscreen searches for DIAL/Chromecast devices
	DialMultiscreen = "urn:dial-multiscreen-org:service:dial:1"

	// BasicDevice searches for basic UPnP devices
	BasicDevice = "urn:schemas-upnp-org:device:Basic:1"

	// InternetGateway searches for routers/gateways
	InternetGateway = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"

	// Printer searches for UPnP printers
	Printer = "urn:schemas-upnp-org:service:PrintBasic:1"
)

// Result contains the result of an SSDP discovery.
type Result struct {
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

// Discovery performs SSDP-based device discovery using koron/go-ssdp.
type Discovery struct {
	Timeout    time.Duration
	Interfaces []net.Interface // Specific interfaces to use (nil = all)
}

// NewDiscovery creates a new SSDP discovery helper with defaults.
func NewDiscovery() *Discovery {
	return &Discovery{Timeout: DefaultTimeout}
}

// Discover performs SSDP M-SEARCH to find all devices on the network.
// searchTarget can be:
//   - All ("ssdp:all") - All devices
//   - RootDevice ("upnp:rootdevice") - Root devices only
//   - MediaRenderer - Smart TVs, speakers, media players
//   - MediaServer - NAS, DLNA servers
//   - DialMultiscreen - Chromecast, DIAL-enabled devices
//   - InternetGateway - Routers
//   - Custom URN strings
func (s *Discovery) Discover(ctx context.Context, searchTarget string) ([]*Result, error) {
	if searchTarget == "" {
		searchTarget = All
	}
	debugLog("SSDP Discover target=%s timeout=%v", searchTarget, s.Timeout)

	// Configure interfaces if specified
	if len(s.Interfaces) > 0 {
		gossdp.Interfaces = s.Interfaces
		defer func() { gossdp.Interfaces = nil }()
	}

	// Calculate wait time in seconds (minimum 1)
	waitSec := int(s.Timeout.Seconds())
	if waitSec < 1 {
		waitSec = 1
	}

	// Use context for cancellation
	resultCh := make(chan []gossdp.Service, 1)
	errCh := make(chan error, 1)

	go func() {
		services, err := gossdp.Search(searchTarget, waitSec, "")
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
		results := s.convertServices(services)
		debugLog("SSDP Discover found %d devices", len(results))
		return results, nil
	}
}

// DiscoverAll performs multiple searches to find various device types.
// Returns a combined, deduplicated list of all discovered devices.
func (s *Discovery) DiscoverAll(ctx context.Context) ([]*Result, error) {
	debugLog("SSDP DiscoverAll starting")
	searchTargets := []string{
		All,
		RootDevice,
		MediaRenderer,
		DialMultiscreen,
	}

	seen := make(map[string]bool)
	var results []*Result
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

	debugLog("SSDP DiscoverAll found %d unique devices", len(results))
	return results, nil
}

// LookupAddr checks if a specific IP has SSDP-enabled devices.
// Note: SSDP is typically multicast-based, so this sends a unicast M-SEARCH
// which may not be supported by all devices.
func (s *Discovery) LookupAddr(ctx context.Context, ip string) (*Result, error) {
	res := &Result{IP: ip}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		res.Error = fmt.Errorf("invalid IP address: %s", ip)
		return res, res.Error
	}

	// Do a full discovery and filter by IP
	results, err := s.Discover(ctx, All)
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
func (s *Discovery) Monitor(ctx context.Context) (<-chan *Result, <-chan string, error) {
	aliveCh := make(chan *Result, 100)
	byeCh := make(chan string, 100) // USN of device going offline

	monitor := &gossdp.Monitor{
		Alive: func(m *gossdp.AliveMessage) {
			result := &Result{
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
		Bye: func(m *gossdp.ByeMessage) {
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
func (s *Discovery) GetDeviceInfo(ctx context.Context, locationURL string) (*Result, error) {
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

	result := &Result{Location: locationURL}

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
func (s *Discovery) EnrichResults(ctx context.Context, results []*Result) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5) // Limit concurrent requests

	for _, r := range results {
		if r.Location == "" {
			continue
		}

		wg.Add(1)
		go func(result *Result) {
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

// convertServices converts go-ssdp Service slice to our Result slice
func (s *Discovery) convertServices(services []gossdp.Service) []*Result {
	results := make([]*Result, 0, len(services))

	for _, svc := range services {
		result := &Result{
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
