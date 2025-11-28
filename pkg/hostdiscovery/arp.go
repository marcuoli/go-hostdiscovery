//go:build linux || darwin || freebsd || netbsd || openbsd

// Package hostdiscovery: ARP-based host and MAC address discovery.
// This file provides ARP lookups using the j-keck/arping library.
// ARP discovery can detect hosts even when they don't respond to TCP/ICMP probes.
// Note: On some systems, ARP operations may require elevated privileges.
// Platform support: Linux and BSD only (not Windows).
package hostdiscovery

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/j-keck/arping"
)

const (
	arpDefaultTimeout = 1 * time.Second
)

// ARPResult contains the result of an ARP lookup.
type ARPResult struct {
	IP         string
	MACAddress string
	IsUp       bool
	Duration   time.Duration
	Error      error
}

// ARPDiscovery performs ARP-based host discovery.
type ARPDiscovery struct {
	Timeout time.Duration
}

// NewARPDiscovery creates a new ARP discovery helper with defaults.
func NewARPDiscovery() *ARPDiscovery {
	return &ARPDiscovery{Timeout: arpDefaultTimeout}
}

// LookupAddr performs an ARP lookup to discover the MAC address of a host.
// Returns the MAC address if the host responds to ARP, otherwise returns an error.
func (a *ARPDiscovery) LookupAddr(ctx context.Context, ip string) (*ARPResult, error) {
	result := &ARPResult{IP: ip}

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

	debugLog(MethodARP, "Looking up ARP for %s", ip)

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
		debugLogVerbose(MethodARP, "%s: context cancelled", ip)
		return result, ctx.Err()
	case resp := <-responseChan:
		result.Duration = resp.dur
		if resp.err != nil {
			result.Error = resp.err
			debugLogVerbose(MethodARP, "%s: error: %v", ip, resp.err)
			return result, resp.err
		}
		result.MACAddress = resp.mac.String()
		result.IsUp = true
		debugLogVerbose(MethodARP, "%s -> MAC: %s (%.2fms)", ip, result.MACAddress, float64(resp.dur.Microseconds())/1000)
		return result, nil
	}
}

// LookupMultiple performs ARP lookups on multiple IPs concurrently.
// Returns results in the same order as the input IPs.
func (a *ARPDiscovery) LookupMultiple(ctx context.Context, ips []string) []*ARPResult {
	results := make([]*ARPResult, len(ips))
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
func (a *ARPDiscovery) PingMAC(ctx context.Context, ip string) (string, error) {
	result, err := a.LookupAddr(ctx, ip)
	if err != nil {
		return "", err
	}
	return result.MACAddress, nil
}

// DiscoverLiveHosts uses ARP to find all live hosts in a CIDR range.
// ARP can detect hosts that don't respond to TCP/ICMP probes.
// Returns a slice of ARPResults for hosts that responded.
func (a *ARPDiscovery) DiscoverLiveHosts(ctx context.Context, cidr string) ([]*ARPResult, error) {
	ips, err := EnumerateIPs(cidr)
	if err != nil {
		return nil, err
	}

	debugLog(MethodARP, "Starting ARP discovery for %d IPs in %s", len(ips), cidr)

	// Convert to string IPs
	ipStrings := make([]string, len(ips))
	for i, ip := range ips {
		ipStrings[i] = ip.String()
	}

	// Perform ARP lookups
	allResults := a.LookupMultiple(ctx, ipStrings)

	// Filter to only live hosts
	var liveHosts []*ARPResult
	for _, r := range allResults {
		if r != nil && r.IsUp {
			liveHosts = append(liveHosts, r)
		}
	}

	debugLog(MethodARP, "ARP discovery complete: %d/%d hosts responded", len(liveHosts), len(ips))
	return liveHosts, nil
}

// ErrInvalidIP is returned when an invalid IP address is provided.
var ErrInvalidIP = &DiscoveryError{Method: MethodARP, Message: "invalid IP address"}

// ErrIPv6NotSupported is returned when attempting ARP on an IPv6 address.
var ErrIPv6NotSupported = &DiscoveryError{Method: MethodARP, Message: "ARP is not supported for IPv6 addresses"}

// DiscoveryError represents an error during discovery.
type DiscoveryError struct {
	Method  DiscoveryMethod
	Message string
}

func (e *DiscoveryError) Error() string {
	return string(e.Method) + ": " + e.Message
}
