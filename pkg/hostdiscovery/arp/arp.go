//go:build linux || darwin || freebsd || netbsd || openbsd

// Package arp provides ARP-based host and MAC address discovery.
// ARP discovery can detect hosts even when they don't respond to TCP/ICMP probes.
// Note: On some systems, ARP operations may require elevated privileges.
// Platform support: Linux and BSD only (not Windows).
package arp

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/j-keck/arping"
)

const (
	// DefaultTimeout is the default timeout for ARP lookups.
	DefaultTimeout = 1 * time.Second
)

// Errors
var (
	// ErrNotSupported is returned when ARP is called on unsupported platforms.
	ErrNotSupported = errors.New("ARP discovery is not supported on this platform")
	// ErrInvalidIP is returned when an invalid IP address is provided.
	ErrInvalidIP = errors.New("invalid IP address")
	// ErrIPv6NotSupported is returned when attempting ARP on an IPv6 address.
	ErrIPv6NotSupported = errors.New("ARP is not supported for IPv6 addresses")
)

// DebugLogger is a callback for debug logging.
// Set this to receive debug messages from ARP operations.
var DebugLogger func(format string, args ...interface{})

func debugLog(format string, args ...interface{}) {
	if DebugLogger != nil {
		DebugLogger(format, args...)
	}
}

// Result contains the result of an ARP lookup.
type Result struct {
	IP         string
	MACAddress string
	IsUp       bool
	Duration   time.Duration
	Error      error
}

// Discovery performs ARP-based host discovery.
type Discovery struct {
	Timeout time.Duration
}

// NewDiscovery creates a new ARP discovery helper with defaults.
func NewDiscovery() *Discovery {
	return &Discovery{Timeout: DefaultTimeout}
}

// LookupAddr performs an ARP lookup to discover the MAC address of a host.
// Returns the MAC address if the host responds to ARP, otherwise returns an error.
func (a *Discovery) LookupAddr(ctx context.Context, ip string) (*Result, error) {
	result := &Result{IP: ip}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		result.Error = ErrInvalidIP
		return result, ErrInvalidIP
	}

	// Only IPv4 is supported for ARP
	if parsedIP.To4() == nil {
		result.Error = ErrIPv6NotSupported
		return result, ErrIPv6NotSupported
	}

	debugLog("Looking up ARP for %s", ip)

	// Set timeout for arping
	arping.SetTimeout(a.Timeout)

	start := time.Now()

	// Create a channel to receive the result
	type arpResponse struct {
		mac net.HardwareAddr
		dur time.Duration
		err error
	}
	responseChan := make(chan arpResponse, 1)

	go func() {
		mac, dur, err := arping.Ping(parsedIP)
		responseChan <- arpResponse{mac: mac, dur: dur, err: err}
	}()

	// Wait for either context cancellation or ARP response
	select {
	case <-ctx.Done():
		result.Duration = time.Since(start)
		result.Error = ctx.Err()
		debugLog("%s: context cancelled", ip)
		return result, ctx.Err()
	case resp := <-responseChan:
		result.Duration = resp.dur
		if resp.err != nil {
			result.Error = resp.err
			debugLog("%s: error: %v", ip, resp.err)
			return result, resp.err
		}
		result.MACAddress = resp.mac.String()
		result.IsUp = true
		debugLog("%s -> MAC: %s (%.2fms)", ip, result.MACAddress, float64(resp.dur.Microseconds())/1000)
		return result, nil
	}
}

// LookupMultiple performs ARP lookups on multiple IPs concurrently.
// Returns results in the same order as the input IPs.
func (a *Discovery) LookupMultiple(ctx context.Context, ips []string) []*Result {
	results := make([]*Result, len(ips))
	var wg sync.WaitGroup

	// Use a semaphore to limit concurrency (ARP can be rate-limited by the OS)
	sem := make(chan struct{}, 32)

	for i, ip := range ips {
		wg.Add(1)
		go func(idx int, ipAddr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result, _ := a.LookupAddr(ctx, ipAddr)
			results[idx] = result
		}(i, ip)
	}

	wg.Wait()
	return results
}

// PingMAC performs an ARP lookup and returns just the MAC address.
// This is a convenience method for quick MAC lookups.
func (a *Discovery) PingMAC(ctx context.Context, ip string) (string, error) {
	result, err := a.LookupAddr(ctx, ip)
	if err != nil {
		return "", err
	}
	return result.MACAddress, nil
}

// DiscoverLiveHosts uses ARP to find all live hosts in a list of IPs.
// ARP can detect hosts that don't respond to TCP/ICMP probes.
// Returns a slice of Results for hosts that responded.
func (a *Discovery) DiscoverLiveHosts(ctx context.Context, ips []string) ([]*Result, error) {
	debugLog("Starting ARP discovery for %d IPs", len(ips))

	// Perform ARP lookups
	allResults := a.LookupMultiple(ctx, ips)

	// Filter to only live hosts
	var liveHosts []*Result
	for _, r := range allResults {
		if r != nil && r.IsUp {
			liveHosts = append(liveHosts, r)
		}
	}

	debugLog("ARP discovery complete: %d/%d hosts responded", len(liveHosts), len(ips))
	return liveHosts, nil
}

// IsSupported returns true if ARP is supported on this platform.
func IsSupported() bool {
	return true
}
