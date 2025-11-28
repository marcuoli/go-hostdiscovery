//go:build windows

// Package arp provides ARP-based host and MAC address discovery.
// This file provides stubs for Windows where ARP discovery is not supported
// with the current implementation.
package arp

import (
	"context"
	"errors"
	"time"
)

const (
	// DefaultTimeout is the default timeout for ARP lookups.
	DefaultTimeout = 1 * time.Second
)

// Errors
var (
	// ErrNotSupported is returned when ARP is called on unsupported platforms.
	ErrNotSupported = errors.New("ARP discovery is not supported on Windows")
	// ErrInvalidIP is returned when an invalid IP address is provided.
	ErrInvalidIP = errors.New("invalid IP address")
	// ErrIPv6NotSupported is returned when attempting ARP on an IPv6 address.
	ErrIPv6NotSupported = errors.New("ARP is not supported for IPv6 addresses")
)

// DebugLogger is a callback for debug logging.
// Set this to receive debug messages from ARP operations.
var DebugLogger func(format string, args ...interface{})

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

// NewDiscovery creates a new ARP discovery helper.
// On Windows, this returns a stub that always returns ErrNotSupported.
func NewDiscovery() *Discovery {
	return &Discovery{Timeout: DefaultTimeout}
}

// LookupAddr performs an ARP lookup. On Windows, always returns ErrNotSupported.
func (a *Discovery) LookupAddr(ctx context.Context, ip string) (*Result, error) {
	return &Result{IP: ip, Error: ErrNotSupported}, ErrNotSupported
}

// LookupMultiple performs ARP lookups on multiple IPs. On Windows, returns error results.
func (a *Discovery) LookupMultiple(ctx context.Context, ips []string) []*Result {
	results := make([]*Result, len(ips))
	for i, ip := range ips {
		results[i] = &Result{IP: ip, Error: ErrNotSupported}
	}
	return results
}

// PingMAC performs an ARP lookup. On Windows, always returns ErrNotSupported.
func (a *Discovery) PingMAC(ctx context.Context, ip string) (string, error) {
	return "", ErrNotSupported
}

// DiscoverLiveHosts uses ARP to find all live hosts. On Windows, always returns ErrNotSupported.
func (a *Discovery) DiscoverLiveHosts(ctx context.Context, ips []string) ([]*Result, error) {
	return nil, ErrNotSupported
}

// IsSupported returns true if ARP is supported on this platform.
func IsSupported() bool {
	return false
}
