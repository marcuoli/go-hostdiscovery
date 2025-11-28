//go:build windows

// Package hostdiscovery: ARP stub for Windows.
// ARP discovery is not supported on Windows with the current implementation.
// This provides stub types and functions that return appropriate errors.
package hostdiscovery

import (
	"context"
	"errors"
	"time"
)

// ErrARPNotSupported is returned when ARP is called on unsupported platforms.
var ErrARPNotSupported = errors.New("ARP discovery is not supported on Windows")

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

// NewARPDiscovery creates a new ARP discovery helper.
// On Windows, this returns a stub that always returns ErrARPNotSupported.
func NewARPDiscovery() *ARPDiscovery {
	return &ARPDiscovery{Timeout: time.Second}
}

// LookupAddr performs an ARP lookup. On Windows, always returns ErrARPNotSupported.
func (a *ARPDiscovery) LookupAddr(ctx context.Context, ip string) (*ARPResult, error) {
	return &ARPResult{IP: ip, Error: ErrARPNotSupported}, ErrARPNotSupported
}

// LookupMultiple performs ARP lookups on multiple IPs. On Windows, returns empty results.
func (a *ARPDiscovery) LookupMultiple(ctx context.Context, ips []string) []*ARPResult {
	results := make([]*ARPResult, len(ips))
	for i, ip := range ips {
		results[i] = &ARPResult{IP: ip, Error: ErrARPNotSupported}
	}
	return results
}

// PingMAC performs an ARP lookup. On Windows, always returns ErrARPNotSupported.
func (a *ARPDiscovery) PingMAC(ctx context.Context, ip string) (string, error) {
	return "", ErrARPNotSupported
}

// DiscoverLiveHosts uses ARP to find all live hosts. On Windows, always returns ErrARPNotSupported.
func (a *ARPDiscovery) DiscoverLiveHosts(ctx context.Context, cidr string) ([]*ARPResult, error) {
	return nil, ErrARPNotSupported
}
