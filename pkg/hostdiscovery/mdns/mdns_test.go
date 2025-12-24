// Package mdns tests for mDNS discovery.
package mdns

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
	if Port != 5353 {
		t.Errorf("Expected Port 5353, got %d", Port)
	}
	if MulticastAddr != "224.0.0.251" {
		t.Errorf("Expected MulticastAddr 224.0.0.251, got %s", MulticastAddr)
	}
	if DefaultTimeout != 3*time.Second {
		t.Errorf("Expected DefaultTimeout 3s, got %v", DefaultTimeout)
	}
}

func TestResult_Structure(t *testing.T) {
	result := &Result{
		IP:       "192.168.1.100",
		Hostname: "macbook.local",
		Services: []Service{
			{Instance: "Test Service", Service: "_http._tcp", Domain: "local", Port: 8080},
		},
		Error: nil,
	}

	if result.IP != "192.168.1.100" {
		t.Errorf("Expected IP 192.168.1.100, got %s", result.IP)
	}
	if result.Hostname != "macbook.local" {
		t.Errorf("Expected Hostname macbook.local, got %s", result.Hostname)
	}
	if len(result.Services) != 1 {
		t.Errorf("Expected 1 service, got %d", len(result.Services))
	}
}

func TestService_Structure(t *testing.T) {
	svc := Service{
		Instance: "Living Room Speaker",
		Service:  "_googlecast._tcp",
		Domain:   "local",
		Port:     8008,
		TXT:      map[string]string{"fn": "Living Room", "md": "Chromecast"},
	}

	if svc.Instance != "Living Room Speaker" {
		t.Errorf("Expected Instance 'Living Room Speaker', got %s", svc.Instance)
	}
	if svc.Service != "_googlecast._tcp" {
		t.Errorf("Expected Service '_googlecast._tcp', got %s", svc.Service)
	}
	if svc.Port != 8008 {
		t.Errorf("Expected Port 8008, got %d", svc.Port)
	}
	if svc.TXT["fn"] != "Living Room" {
		t.Errorf("Expected TXT['fn'] 'Living Room', got %s", svc.TXT["fn"])
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
			Name:   "100.1.168.192.in-addr.arpa.",
			Class:  dns.ClassINET,
			TTL:    120,
		},
		PTR: rdata.PTR{Ptr: "host.local."},
	}

	msg := &dns.Msg{
		MsgHeader: dns.MsgHeader{Response: true},
		Answer:    []dns.RR{rr},
	}
	if err := msg.Pack(); err != nil {
		t.Fatalf("msg.Pack: %v", err)
	}

	hostname := d.parsePTRResponse(msg.Data)
	if hostname != "host.local" {
		t.Fatalf("expected hostname host.local, got %q", hostname)
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

// CommonMDNSServices documents common mDNS service types for reference
func TestCommonMDNSServices_Documentation(t *testing.T) {
	services := map[string]string{
		"_http._tcp":       "Web servers",
		"_https._tcp":      "Secure web servers",
		"_printer._tcp":    "Network printers",
		"_ipp._tcp":        "Internet Printing Protocol",
		"_smb._tcp":        "SMB file sharing",
		"_afpovertcp._tcp": "Apple File Protocol",
		"_ssh._tcp":        "SSH servers",
		"_sftp-ssh._tcp":   "SFTP servers",
		"_googlecast._tcp": "Chromecast devices",
		"_airplay._tcp":    "AirPlay receivers",
		"_raop._tcp":       "AirTunes/AirPlay audio",
		"_spotify-connect": "Spotify Connect",
	}

	t.Logf("Common mDNS service types: %d defined", len(services))
	for svc, desc := range services {
		t.Logf("  %s: %s", svc, desc)
	}
}

// Benchmark tests
func BenchmarkNewDiscovery(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewDiscovery()
	}
}
