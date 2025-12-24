// Package llmnr tests for LLMNR discovery.
package llmnr

import (
	"context"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func TestNewDiscovery(t *testing.T) {
	d := NewDiscovery()
	if d == nil {
		t.Fatal("NewDiscovery returned nil")
	}
	if d.Timeout != DefaultTimeout {
		t.Errorf("Expected timeout %v, got %v", DefaultTimeout, d.Timeout)
	}
}

func TestConstants(t *testing.T) {
	if Port != 5355 {
		t.Errorf("Expected Port 5355, got %d", Port)
	}
	if MulticastAddr != "224.0.0.252" {
		t.Errorf("Expected MulticastAddr 224.0.0.252, got %s", MulticastAddr)
	}
	if DefaultTimeout != 2*time.Second {
		t.Errorf("Expected DefaultTimeout 2s, got %v", DefaultTimeout)
	}
}

func TestResult_Structure(t *testing.T) {
	result := &Result{
		IP:       "192.168.1.100",
		Hostname: "DESKTOP-PC",
		Error:    nil,
	}

	if result.IP != "192.168.1.100" {
		t.Errorf("Expected IP 192.168.1.100, got %s", result.IP)
	}
	if result.Hostname != "DESKTOP-PC" {
		t.Errorf("Expected Hostname DESKTOP-PC, got %s", result.Hostname)
	}
}

func TestLookupAddr_InvalidIP(t *testing.T) {
	d := NewDiscovery()
	d.Timeout = 100 * time.Millisecond

	result, err := d.LookupAddr(context.Background(), "invalid-ip")
	if err == nil {
		t.Error("Expected error for invalid IP")
	}
	if result.Error == nil {
		t.Error("Expected result.Error to be set")
	}
}

func TestLookupAddr_IPv6(t *testing.T) {
	d := NewDiscovery()
	d.Timeout = 100 * time.Millisecond

	result, err := d.LookupAddr(context.Background(), "::1")
	if err == nil {
		t.Error("Expected error for IPv6")
	}
	if result.Error == nil {
		t.Error("Expected result.Error to be set for IPv6")
	}
}

func TestLookupMultiple_Empty(t *testing.T) {
	d := NewDiscovery()
	results := d.LookupMultiple(context.Background(), []string{})
	if results != nil {
		t.Errorf("Expected nil for empty input, got %v", results)
	}
}

func TestDebugLogger(t *testing.T) {
	var logMessages []string
	originalLogger := DebugLogger

	DebugLogger = func(format string, args ...interface{}) {
		logMessages = append(logMessages, format)
	}
	defer func() { DebugLogger = originalLogger }()

	debugLog("test message %s", "arg")

	if len(logMessages) != 1 {
		t.Errorf("Expected 1 log message, got %d", len(logMessages))
	}
}

func TestDebugLogger_Nil(t *testing.T) {
	originalLogger := DebugLogger
	DebugLogger = nil
	defer func() { DebugLogger = originalLogger }()

	// Should not panic when DebugLogger is nil
	debugLog("test message %s", "arg")
}

func TestParsePTRResponse_Invalid(t *testing.T) {
	d := NewDiscovery()

	// Empty data
	hostname := d.parsePTRResponse([]byte{})
	if hostname != "" {
		t.Errorf("Expected empty hostname for empty data, got %s", hostname)
	}

	// Too short
	hostname = d.parsePTRResponse([]byte{0x00, 0x01})
	if hostname != "" {
		t.Errorf("Expected empty hostname for short data, got %s", hostname)
	}
}

func TestParsePTRResponse_ValidPTR(t *testing.T) {
	d := NewDiscovery()

	rr := &dns.PTR{
		Hdr: dns.Header{
			Name:  "100.1.168.192.in-addr.arpa.",
			Class: dns.ClassINET,
			TTL:   120,
		},
		PTR: rdata.PTR{Ptr: "DESKTOP-PC."},
	}

	msg := &dns.Msg{
		MsgHeader: dns.MsgHeader{Response: true},
		Answer:    []dns.RR{rr},
	}
	if err := msg.Pack(); err != nil {
		t.Fatalf("msg.Pack: %v", err)
	}

	hostname := d.parsePTRResponse(msg.Data)
	if hostname != "DESKTOP-PC" {
		t.Fatalf("expected hostname DESKTOP-PC, got %q", hostname)
	}
}

func TestParsePTRResponse_NonResponseIgnored(t *testing.T) {
	d := NewDiscovery()

	rr := &dns.PTR{
		Hdr: dns.Header{
			Name:  "100.1.168.192.in-addr.arpa.",
			Class: dns.ClassINET,
			TTL:   120,
		},
		PTR: rdata.PTR{Ptr: "DESKTOP-PC."},
	}

	msg := &dns.Msg{
		MsgHeader: dns.MsgHeader{Response: false},
		Answer:    []dns.RR{rr},
	}
	if err := msg.Pack(); err != nil {
		t.Fatalf("msg.Pack: %v", err)
	}

	hostname := d.parsePTRResponse(msg.Data)
	if hostname != "" {
		t.Fatalf("expected empty hostname for non-response message, got %q", hostname)
	}
}



func TestLookupAddr_ContextTimeout(t *testing.T) {
	d := NewDiscovery()
	d.Timeout = 100 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Should respect context timeout
	result, _ := d.LookupAddr(ctx, "192.168.1.1")
	// Result should have the IP set at minimum
	if result.IP != "192.168.1.1" {
		t.Errorf("Expected IP to be set, got %s", result.IP)
	}
}

func TestLookupName_InvalidHostname(t *testing.T) {
	d := NewDiscovery()
	d.Timeout = 100 * time.Millisecond

	// Test with empty hostname
	ips, err := d.LookupName(context.Background(), "")
	if err == nil && len(ips) > 0 {
		t.Error("Expected no results for empty hostname")
	}
}

func TestLookupName_ContextTimeout(t *testing.T) {
	d := NewDiscovery()
	d.Timeout = 100 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// Should return quickly with context timeout
	_, _ = d.LookupName(ctx, "TESTPC")
	// Just verify it doesn't hang
}

// TestLLMNRWindowsIntegration documents LLMNR behavior with Windows
func TestLLMNRWindowsIntegration_Documentation(t *testing.T) {
	// LLMNR is primarily used by Windows Vista+ when DNS fails
	// It sends queries to multicast address 224.0.0.252:5355
	// Windows responds with its hostname when queried

	// LLMNR packet structure follows DNS format with some differences:
	// - No recursion (RD/RA flags are 0)
	// - Uses UDP port 5355 instead of 53
	// - Uses multicast instead of unicast for queries

	t.Log("LLMNR (Link-Local Multicast Name Resolution):")
	t.Log("  - Port: UDP/5355")
	t.Log("  - Multicast: 224.0.0.252 (IPv4), ff02::1:3 (IPv6)")
	t.Log("  - Primarily Windows Vista+")
	t.Log("  - Also systemd-resolved on Linux")
}

// Benchmark tests
func BenchmarkNewDiscovery(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewDiscovery()
	}
}
