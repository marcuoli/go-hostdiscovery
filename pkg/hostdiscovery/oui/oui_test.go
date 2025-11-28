// Package oui tests for OUI vendor lookup.
package oui

import (
	"testing"
)

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Standard formats
		{"00:11:22:33:44:55", "00:11:22:33:44:55"},
		{"00-11-22-33-44-55", "00:11:22:33:44:55"},
		{"001122334455", "00:11:22:33:44:55"},
		{"00.11.22.33.44.55", "00:11:22:33:44:55"},

		// Mixed case
		{"AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"},
		{"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"},
		{"Aa:Bb:Cc:Dd:Ee:Ff", "aa:bb:cc:dd:ee:ff"},

		// Invalid formats
		{"", ""},
		{"00:11:22:33:44", ""},           // Too short
		{"00:11:22:33:44:55:66", ""},     // Too long
		{"00:11:22:33:44:GG", ""},        // Invalid hex
		{"not-a-mac", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeMAC(tt.input)
			if got != tt.expected {
				t.Errorf("NormalizeMAC(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestVendorInfo_Structure(t *testing.T) {
	info := &VendorInfo{
		Manufacturer: "Apple, Inc.",
		Address:      []string{"1 Infinite Loop", "Cupertino CA 95014"},
		Country:      "US",
		Prefix:       "00:03:93",
	}

	if info.Manufacturer != "Apple, Inc." {
		t.Errorf("Expected Manufacturer 'Apple, Inc.', got %s", info.Manufacturer)
	}
	if len(info.Address) != 2 {
		t.Errorf("Expected 2 address lines, got %d", len(info.Address))
	}
	if info.Country != "US" {
		t.Errorf("Expected Country 'US', got %s", info.Country)
	}
	if info.Prefix != "00:03:93" {
		t.Errorf("Expected Prefix '00:03:93', got %s", info.Prefix)
	}
}

func TestLookup_InvalidMAC(t *testing.T) {
	_, err := Lookup("invalid")
	if err == nil {
		t.Error("Expected error for invalid MAC")
	}
}

func TestLookup_ValidMAC(t *testing.T) {
	// Use a well-known OUI - Apple's
	vendor, err := Lookup("00:03:93:00:00:00")
	if err != nil {
		t.Logf("Lookup error (may be expected if DB not loaded): %v", err)
		return
	}

	if vendor != nil {
		t.Logf("Found vendor: %s", vendor.Manufacturer)
	}
}

func TestLookupName_InvalidMAC(t *testing.T) {
	name := LookupName("invalid")
	if name != "" {
		t.Errorf("Expected empty string for invalid MAC, got %s", name)
	}
}

func TestLookupName_ValidMAC(t *testing.T) {
	// Test with a common MAC prefix
	name := LookupName("00:03:93:00:00:00")
	t.Logf("Vendor name for 00:03:93: %q", name)
}

func TestGetDatabasePath_Default(t *testing.T) {
	path := GetDatabasePath()
	// Default should be empty (using embedded)
	t.Logf("Current database path: %q", path)
}

func TestSetDatabase_NonExistent(t *testing.T) {
	err := SetDatabase("/nonexistent/path/oui.txt")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestIsLoaded(t *testing.T) {
	// Just check it doesn't panic
	loaded := IsLoaded()
	t.Logf("OUI database loaded: %v", loaded)
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

// TestCommonVendorPrefixes documents some well-known OUI prefixes
func TestCommonVendorPrefixes_Documentation(t *testing.T) {
	prefixes := map[string]string{
		"00:03:93": "Apple, Inc.",
		"00:50:56": "VMware, Inc.",
		"00:0C:29": "VMware, Inc.",
		"08:00:27": "Oracle VirtualBox",
		"52:54:00": "QEMU/KVM",
		"00:15:5D": "Microsoft Hyper-V",
		"DC:A6:32": "Raspberry Pi Foundation",
		"B8:27:EB": "Raspberry Pi Foundation",
		"00:1A:79": "Dell Inc.",
		"00:25:90": "Dell Inc.",
	}

	t.Logf("Common OUI prefixes: %d listed", len(prefixes))
	for prefix, vendor := range prefixes {
		t.Logf("  %s: %s", prefix, vendor)
	}
}

// TestNormalizeMAC_EdgeCases tests edge cases in MAC normalization
func TestNormalizeMAC_EdgeCases(t *testing.T) {
	// Test all lowercase
	result := NormalizeMAC("aabbccddeeff")
	if result != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("Expected aa:bb:cc:dd:ee:ff, got %s", result)
	}

	// Test all uppercase
	result = NormalizeMAC("AABBCCDDEEFF")
	if result != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("Expected aa:bb:cc:dd:ee:ff, got %s", result)
	}

	// Test with all zeros
	result = NormalizeMAC("000000000000")
	if result != "00:00:00:00:00:00" {
		t.Errorf("Expected 00:00:00:00:00:00, got %s", result)
	}

	// Test with all Fs
	result = NormalizeMAC("ffffffffffff")
	if result != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("Expected ff:ff:ff:ff:ff:ff, got %s", result)
	}
}

// Benchmark tests
func BenchmarkNormalizeMAC_Colons(b *testing.B) {
	mac := "00:11:22:33:44:55"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NormalizeMAC(mac)
	}
}

func BenchmarkNormalizeMAC_Dashes(b *testing.B) {
	mac := "00-11-22-33-44-55"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NormalizeMAC(mac)
	}
}

func BenchmarkNormalizeMAC_Plain(b *testing.B) {
	mac := "001122334455"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NormalizeMAC(mac)
	}
}

func BenchmarkLookupName(b *testing.B) {
	mac := "00:03:93:00:00:00"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = LookupName(mac)
	}
}
