//go:build !windows
// +build !windows

// Package osdetect: TCP/IP fingerprinting stub for non-Windows platforms.
// Full raw socket implementation requires additional libraries on Linux/macOS.
package osdetect

import (
	"context"
)

// RawTCPFPDiscovery performs fingerprinting (stub for non-Windows).
type RawTCPFPDiscovery struct {
	*TCPFPDiscovery
	useRaw bool
}

// NewRawTCPFPDiscovery creates a fingerprinting helper.
func NewRawTCPFPDiscovery() *RawTCPFPDiscovery {
	return &RawTCPFPDiscovery{
		TCPFPDiscovery: NewTCPFPDiscovery(),
		useRaw:         false,
	}
}

// FingerprintWithRaw falls back to heuristic method on non-Windows.
func (r *RawTCPFPDiscovery) FingerprintWithRaw(ctx context.Context, host string, port int) (*TCPFPResult, error) {
	// On non-Windows, use the heuristic method
	// Full implementation would use libpcap or raw sockets with CAP_NET_RAW
	return r.Fingerprint(ctx, host, port)
}

// parseTCPOptions parses TCP options from raw bytes.
func parseTCPOptions(fp *TCPFingerprint, options []byte) {
	// Implementation in tcpfp.go uses this on all platforms
}
