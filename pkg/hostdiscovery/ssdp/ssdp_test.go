// Package ssdp tests for SSDP discovery.
package ssdp

import (
	"context"
	"testing"
	"time"
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
	if DefaultTimeout != 3*time.Second {
		t.Errorf("Expected DefaultTimeout 3s, got %v", DefaultTimeout)
	}

	// Test search target constants
	if All != "ssdp:all" {
		t.Errorf("Expected All 'ssdp:all', got %s", All)
	}
	if RootDevice != "upnp:rootdevice" {
		t.Errorf("Expected RootDevice 'upnp:rootdevice', got %s", RootDevice)
	}
	if MediaRenderer != "urn:schemas-upnp-org:device:MediaRenderer:1" {
		t.Errorf("Unexpected MediaRenderer value: %s", MediaRenderer)
	}
	if MediaServer != "urn:schemas-upnp-org:device:MediaServer:1" {
		t.Errorf("Unexpected MediaServer value: %s", MediaServer)
	}
}

func TestResult_Structure(t *testing.T) {
	result := &Result{
		IP:           "192.168.1.50",
		Location:     "http://192.168.1.50:8080/desc.xml",
		Server:       "Linux/3.10 UPnP/1.0 IpBridge/1.0",
		USN:          "uuid:2f402f80-da50-11e1-9b23-001788255acc::upnp:rootdevice",
		ST:           "upnp:rootdevice",
		MaxAge:       1800,
		FriendlyName: "Philips Hue Bridge",
		Manufacturer: "Philips",
		ModelName:    "BSB002",
		Error:        nil,
	}

	if result.IP != "192.168.1.50" {
		t.Errorf("Expected IP 192.168.1.50, got %s", result.IP)
	}
	if result.FriendlyName != "Philips Hue Bridge" {
		t.Errorf("Expected FriendlyName 'Philips Hue Bridge', got %s", result.FriendlyName)
	}
	if result.MaxAge != 1800 {
		t.Errorf("Expected MaxAge 1800, got %d", result.MaxAge)
	}
}

func TestExtractIPFromURL(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"http://192.168.1.1:8080/desc.xml", "192.168.1.1"},
		{"http://192.168.1.100/device.xml", "192.168.1.100"},
		{"https://10.0.0.1:443/upnp/desc.xml", "10.0.0.1"},
		{"http://172.16.0.50:49152/", "172.16.0.50"},
		{"http://hostname.local:8080/", ""}, // Not an IP
		{"invalid", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractIPFromURL(tt.url)
			if got != tt.expected {
				t.Errorf("extractIPFromURL(%q) = %q, want %q", tt.url, got, tt.expected)
			}
		})
	}
}

func TestExtractXMLValue(t *testing.T) {
	tests := []struct {
		line    string
		tagName string
		want    string
	}{
		{"<friendlyName>Living Room TV</friendlyName>", "friendlyName", "Living Room TV"},
		{"<manufacturer>Samsung</manufacturer>", "manufacturer", "Samsung"},
		{"<modelName>UN55NU8000</modelName>", "modelName", "UN55NU8000"},
		{"  <friendlyName>  Trimmed  </friendlyName>  ", "friendlyName", "Trimmed"},
		{"<other>value</other>", "friendlyName", ""},
		{"no tags here", "friendlyName", ""},
		{"<unclosed>value", "unclosed", ""},
		{"", "friendlyName", ""},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got := extractXMLValue(tt.line, tt.tagName)
			if got != tt.want {
				t.Errorf("extractXMLValue(%q, %q) = %q, want %q", tt.line, tt.tagName, got, tt.want)
			}
		})
	}
}

func TestDiscover_EmptyTarget(t *testing.T) {
	d := NewDiscovery()
	d.Timeout = 100 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Empty search target should default to All
	_, err := d.Discover(ctx, "")
	// Just verify it doesn't panic
	t.Logf("Discover with empty target: err=%v", err)
}

func TestDiscover_ContextCancellation(t *testing.T) {
	d := NewDiscovery()
	d.Timeout = 5 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := d.Discover(ctx, All)
	if err != context.Canceled {
		t.Logf("Expected context.Canceled, got %v", err)
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

func TestConvertServices_Empty(t *testing.T) {
	d := NewDiscovery()
	results := d.convertServices(nil)
	if len(results) != 0 {
		t.Errorf("Expected empty results for nil input, got %d", len(results))
	}
}

// TestSSDPDeviceTypes documents common SSDP device types for reference
func TestSSDPDeviceTypes_Documentation(t *testing.T) {
	deviceTypes := map[string]string{
		"ssdp:all":          "All devices",
		"upnp:rootdevice":   "Root devices only",
		MediaRenderer:       "Smart TVs, speakers, media players",
		MediaServer:         "NAS, DLNA servers",
		DialMultiscreen:     "Chromecast, DIAL-enabled devices",
		BasicDevice:         "Basic UPnP devices",
		InternetGateway:     "Routers, gateways",
		Printer:             "Network printers",
	}

	t.Logf("SSDP Device Types: %d defined", len(deviceTypes))
	for st, desc := range deviceTypes {
		t.Logf("  %s: %s", st, desc)
	}
}

// TestSSDPProtocol documents SSDP protocol details
func TestSSDPProtocol_Documentation(t *testing.T) {
	t.Log("SSDP (Simple Service Discovery Protocol):")
	t.Log("  - Multicast Address: 239.255.255.250:1900")
	t.Log("  - Part of UPnP specification")
	t.Log("  - M-SEARCH: Actively search for devices")
	t.Log("  - NOTIFY (ssdp:alive): Device announcement")
	t.Log("  - NOTIFY (ssdp:byebye): Device leaving")
	t.Log("  - Used by: Chromecast, Smart TVs, NAS, Routers, etc.")
}

// Benchmark tests
func BenchmarkExtractIPFromURL(b *testing.B) {
	url := "http://192.168.1.100:8080/device/desc.xml"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractIPFromURL(url)
	}
}

func BenchmarkExtractXMLValue(b *testing.B) {
	line := "<friendlyName>Samsung Smart TV</friendlyName>"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractXMLValue(line, "friendlyName")
	}
}
