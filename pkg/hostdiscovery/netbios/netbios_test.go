// Package netbios tests for NetBIOS discovery.
package netbios

import (
	"bytes"
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

func TestResult_Structure(t *testing.T) {
	result := &Result{
		IP:         "192.168.1.100",
		Hostname:   "WORKSTATION",
		MACAddress: "00-11-22-33-44-55",
		Names: []Name{
			{Name: "WORKSTATION", Suffix: 0x00, Type: "Workstation", IsGroup: false, IsActive: true},
			{Name: "WORKGROUP", Suffix: 0x00, Type: "Workstation", IsGroup: true, IsActive: true},
		},
	}

	if result.IP != "192.168.1.100" {
		t.Errorf("Expected IP 192.168.1.100, got %s", result.IP)
	}
	if result.Hostname != "WORKSTATION" {
		t.Errorf("Expected Hostname WORKSTATION, got %s", result.Hostname)
	}
	if result.MACAddress != "00-11-22-33-44-55" {
		t.Errorf("Expected MAC 00-11-22-33-44-55, got %s", result.MACAddress)
	}
	if len(result.Names) != 2 {
		t.Errorf("Expected 2 names, got %d", len(result.Names))
	}
}

func TestName_Structure(t *testing.T) {
	name := Name{
		Name:     "TESTPC",
		Suffix:   0x20,
		Type:     "File Server",
		IsGroup:  false,
		IsActive: true,
	}

	if name.Name != "TESTPC" {
		t.Errorf("Expected Name TESTPC, got %s", name.Name)
	}
	if name.Suffix != 0x20 {
		t.Errorf("Expected Suffix 0x20, got 0x%02X", name.Suffix)
	}
}

func TestBuildNBSTATRequest(t *testing.T) {
	req := buildNBSTATRequest()

	// Minimum size check
	if len(req) < 50 {
		t.Errorf("Request too short: %d bytes", len(req))
	}

	// Check transaction ID position (bytes 0-1)
	if req[0] != 0x13 || req[1] != 0x37 {
		t.Errorf("Unexpected transaction ID: %02X%02X", req[0], req[1])
	}

	// Check QDCOUNT (bytes 4-5) = 1
	if req[4] != 0x00 || req[5] != 0x01 {
		t.Errorf("Unexpected QDCOUNT: %02X%02X", req[4], req[5])
	}

	// Check encoded name length (byte 12) = 32
	if req[12] != 32 {
		t.Errorf("Expected encoded name length 32, got %d", req[12])
	}

	// Check QTYPE = NBSTAT (0x0021) 
	// Position after encoded name (32 bytes) + length byte + null terminator
	qtypePos := 12 + 1 + 32 + 1
	if req[qtypePos] != 0x00 || req[qtypePos+1] != 0x21 {
		t.Errorf("Unexpected QTYPE: %02X%02X", req[qtypePos], req[qtypePos+1])
	}

	// Check QCLASS = IN (0x0001)
	if req[qtypePos+2] != 0x00 || req[qtypePos+3] != 0x01 {
		t.Errorf("Unexpected QCLASS: %02X%02X", req[qtypePos+2], req[qtypePos+3])
	}
}

func TestParseNBSTATResponse_TooShort(t *testing.T) {
	result := &Result{}
	shortData := make([]byte, 50) // Less than 57 bytes

	err := parseNBSTATResponse(shortData, result)
	if err == nil {
		t.Error("Expected error for short response")
	}
}

func TestParseNBSTATResponse_NoNames(t *testing.T) {
	result := &Result{}
	// Create response with numNames = 0
	data := make([]byte, 63)
	data[56] = 0 // numNames = 0

	err := parseNBSTATResponse(data, result)
	if err == nil {
		t.Error("Expected error for response with no names")
	}
}

func TestParseNBSTATResponse_ValidResponse(t *testing.T) {
	result := &Result{}

	// Build a valid NBSTAT response with one name
	data := make([]byte, 63+18+6) // header + 1 name entry + MAC

	// Set number of names
	data[56] = 1

	// Name entry at offset 57
	// Name: "TESTPC" padded to 15 bytes
	name := "TESTPC         " // 15 chars
	copy(data[57:72], []byte(name))

	// Suffix at offset 72
	data[72] = 0x00 // Workstation suffix

	// Flags at offset 73-74 (active, not group)
	data[73] = 0x04 // Active flag
	data[74] = 0x00

	// MAC address at offset 75-80
	data[75] = 0x00
	data[76] = 0x11
	data[77] = 0x22
	data[78] = 0x33
	data[79] = 0x44
	data[80] = 0x55

	err := parseNBSTATResponse(data, result)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Hostname != "TESTPC" {
		t.Errorf("Expected hostname TESTPC, got %s", result.Hostname)
	}

	if len(result.Names) != 1 {
		t.Errorf("Expected 1 name, got %d", len(result.Names))
	}

	if result.MACAddress != "00-11-22-33-44-55" {
		t.Errorf("Expected MAC 00-11-22-33-44-55, got %s", result.MACAddress)
	}
}

func TestSuffixDescription(t *testing.T) {
	tests := []struct {
		suffix   byte
		expected string
	}{
		{0x00, "Workstation"},
		{0x03, "Messenger"},
		{0x06, "RAS Server"},
		{0x1B, "Domain Master Browser"},
		{0x1C, "Domain Controller"},
		{0x1D, "Local Master Browser"},
		{0x1E, "Browser Election"},
		{0x1F, "NetDDE"},
		{0x20, "File Server"},
		{0x21, "RAS Client"},
		{0xBE, "Network Monitor Agent"},
		{0xBF, "Network Monitor Utility"},
		{0x99, "Unknown (0x99)"}, // Unknown suffix
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := suffixDescription(tt.suffix)
			if got != tt.expected {
				t.Errorf("suffixDescription(0x%02X) = %q, want %q", tt.suffix, got, tt.expected)
			}
		})
	}
}

func TestHexPreview(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	// Normal case
	preview := hexPreview(data, 10)
	if preview != "deadbeef" {
		t.Errorf("Expected 'deadbeef', got %q", preview)
	}

	// Truncated case
	preview = hexPreview(data, 2)
	if preview != "dead" {
		t.Errorf("Expected 'dead', got %q", preview)
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

func TestLookupMultiple_Empty(t *testing.T) {
	d := NewDiscovery()
	results := d.LookupMultiple(nil, []string{})
	if results != nil {
		t.Errorf("Expected nil for empty input, got %v", results)
	}
}

func TestBuildNBSTATRequest_WildcardEncoding(t *testing.T) {
	req := buildNBSTATRequest()

	// The wildcard name '*' (0x2A) is encoded in NetBIOS format
	// Each byte is split into two nibbles, each added to 'A' (0x41)
	// '*' = 0x2A, high nibble = 2, low nibble = A
	// Encoded: 'A'+2, 'A'+10 = 'C', 'K'
	// First two encoded bytes at offset 13 should be 'C' and 'K'
	if len(req) >= 15 {
		if req[13] != 'C' || req[14] != 'K' {
			t.Errorf("Wildcard encoding wrong: got %c%c, expected CK", req[13], req[14])
		}
	}
}

func TestConstant_Port(t *testing.T) {
	if Port != 137 {
		t.Errorf("Expected Port 137, got %d", Port)
	}
}

func TestConstant_DefaultTimeout(t *testing.T) {
	expected := 2 * time.Second
	if DefaultTimeout != expected {
		t.Errorf("Expected DefaultTimeout %v, got %v", expected, DefaultTimeout)
	}
}

// TestParseNBSTATResponse_MultipleNames tests parsing responses with multiple NetBIOS names
func TestParseNBSTATResponse_MultipleNames(t *testing.T) {
	result := &Result{}

	// Build response with 2 names
	data := make([]byte, 63+36+6) // header + 2 name entries + MAC

	// Set number of names
	data[56] = 2

	// First name entry at offset 57: "TESTPC" (workstation)
	copy(data[57:72], []byte("TESTPC         "))
	data[72] = 0x00 // Workstation suffix
	data[73] = 0x04 // Active
	data[74] = 0x00

	// Second name entry at offset 75: "WORKGROUP" (group)
	copy(data[75:90], []byte("WORKGROUP      "))
	data[90] = 0x00 // Suffix
	data[91] = 0x84 // Active + Group flag (0x80)
	data[92] = 0x00

	// MAC address at offset 93
	copy(data[93:99], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})

	err := parseNBSTATResponse(data, result)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(result.Names) != 2 {
		t.Errorf("Expected 2 names, got %d", len(result.Names))
	}

	// First non-group name with suffix 0x00 should be hostname
	if result.Hostname != "TESTPC" {
		t.Errorf("Expected hostname TESTPC, got %s", result.Hostname)
	}
}

// TestParseNBSTATResponse_GroupNameOnly tests when only group names are present
func TestParseNBSTATResponse_GroupNameOnly(t *testing.T) {
	result := &Result{}

	data := make([]byte, 63+18+6)
	data[56] = 1

	// Group name only
	copy(data[57:72], []byte("WORKGROUP      "))
	data[72] = 0x00
	data[73] = 0x84 // Group flag
	data[74] = 0x00

	// MAC
	copy(data[75:81], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})

	err := parseNBSTATResponse(data, result)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should not set hostname from group name
	if result.Hostname != "" {
		t.Errorf("Expected empty hostname for group-only response, got %s", result.Hostname)
	}
}

// Benchmark tests
func BenchmarkBuildNBSTATRequest(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = buildNBSTATRequest()
	}
}

func BenchmarkParseNBSTATResponse(b *testing.B) {
	// Pre-build valid response
	data := make([]byte, 63+18+6)
	data[56] = 1
	copy(data[57:72], []byte("TESTPC         "))
	data[72] = 0x00
	data[73] = 0x04
	copy(data[75:81], bytes.Repeat([]byte{0x11}, 6))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := &Result{}
		_ = parseNBSTATResponse(data, result)
	}
}
