// Package network tests for network utilities.
package network

import (
	"net"
	"testing"
)

func TestEnumerateIPs(t *testing.T) {
	tests := []struct {
		cidr     string
		expected int
	}{
		{"192.168.1.0/30", 2},   // 4 total - network - broadcast = 2
		{"192.168.1.0/29", 6},   // 8 total - network - broadcast = 6
		{"192.168.1.0/28", 14},  // 16 total - network - broadcast = 14
		{"192.168.1.0/27", 30},  // 32 total - network - broadcast = 30
		{"192.168.1.0/26", 62},  // 64 total - network - broadcast = 62
		{"192.168.1.0/24", 254}, // 256 total - network - broadcast = 254
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			ips, err := EnumerateIPs(tt.cidr)
			if err != nil {
				t.Fatalf("EnumerateIPs(%s) failed: %v", tt.cidr, err)
			}
			if len(ips) != tt.expected {
				t.Errorf("EnumerateIPs(%s) returned %d IPs, expected %d", tt.cidr, len(ips), tt.expected)
			}

			// Verify first and last IP are not network/broadcast
			if len(ips) > 0 {
				first := ips[0]
				last := ips[len(ips)-1]

				// First IP should be .1 for /24
				// Last IP should be .254 for /24
				if tt.cidr == "192.168.1.0/24" {
					firstOctet := first.To4()[3]
					lastOctet := last.To4()[3]
					if firstOctet != 1 {
						t.Errorf("Expected first IP to end in .1, got %s", first)
					}
					if lastOctet != 254 {
						t.Errorf("Expected last IP to end in .254, got %s", last)
					}
				}
			}
		})
	}
}

func TestEnumerateIPs_Invalid(t *testing.T) {
	invalid := []string{
		"invalid",
		"192.168.1.0",     // No mask
		"192.168.1.0/abc", // Invalid mask
		"",
	}

	for _, cidr := range invalid {
		t.Run(cidr, func(t *testing.T) {
			_, err := EnumerateIPs(cidr)
			if err == nil {
				t.Errorf("Expected error for invalid CIDR %q", cidr)
			}
		})
	}
}

func TestEnumerateIPStrings(t *testing.T) {
	ips, err := EnumerateIPStrings("192.168.1.0/30")
	if err != nil {
		t.Fatalf("EnumerateIPStrings failed: %v", err)
	}
	if len(ips) != 2 {
		t.Errorf("Expected 2 IPs, got %d", len(ips))
	}

	// Should return strings
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			t.Errorf("Invalid IP string: %s", ip)
		}
	}
}

func TestEnumerateIPStrings_Invalid(t *testing.T) {
	_, err := EnumerateIPStrings("invalid")
	if err == nil {
		t.Error("Expected error for invalid CIDR")
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		// Private ranges
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},

		// Not private
		{"172.15.0.1", false},   // Below 172.16
		{"172.32.0.1", false},   // Above 172.31
		{"8.8.8.8", false},      // Google DNS
		{"1.1.1.1", false},      // Cloudflare
		{"192.169.0.1", false},  // Close but not 192.168

		// Edge cases
		{"127.0.0.1", false}, // Loopback
		{"0.0.0.0", false},   // All zeros
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			got := IsPrivateIP(ip)
			if got != tt.private {
				t.Errorf("IsPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
			}
		})
	}
}

func TestIsPrivateIP_IPv6(t *testing.T) {
	// IPv6 addresses should return false (not handled)
	ip := net.ParseIP("::1")
	if IsPrivateIP(ip) {
		t.Error("IPv6 loopback should not be considered private (IPv4 only)")
	}

	ip = net.ParseIP("2001:db8::1")
	if IsPrivateIP(ip) {
		t.Error("IPv6 documentation prefix should not be considered private")
	}
}

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		ip       string
		loopback bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"127.255.255.255", true},
		{"::1", true},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := IsLoopback(ip)
			if got != tt.loopback {
				t.Errorf("IsLoopback(%s) = %v, want %v", tt.ip, got, tt.loopback)
			}
		})
	}
}

func TestParseCIDR(t *testing.T) {
	ip, ipNet, err := ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}
	if ip == nil {
		t.Error("Expected non-nil IP")
	}
	if ipNet == nil {
		t.Error("Expected non-nil IPNet")
	}
}

func TestParseCIDR_Invalid(t *testing.T) {
	_, _, err := ParseCIDR("invalid")
	if err == nil {
		t.Error("Expected error for invalid CIDR")
	}
}

func TestIPToUint32(t *testing.T) {
	tests := []struct {
		ip       string
		expected uint32
	}{
		{"0.0.0.0", 0},
		{"0.0.0.1", 1},
		{"0.0.1.0", 256},
		{"0.1.0.0", 65536},
		{"1.0.0.0", 16777216},
		{"192.168.1.1", 3232235777},
		{"255.255.255.255", 4294967295},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := ipToUint32(ip)
			if got != tt.expected {
				t.Errorf("ipToUint32(%s) = %d, want %d", tt.ip, got, tt.expected)
			}
		})
	}
}

func TestUint32ToIP(t *testing.T) {
	tests := []struct {
		value    uint32
		expected string
	}{
		{0, "0.0.0.0"},
		{1, "0.0.0.1"},
		{256, "0.0.1.0"},
		{3232235777, "192.168.1.1"},
		{4294967295, "255.255.255.255"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			ip := uint32ToIP(tt.value)
			if ip.String() != tt.expected {
				t.Errorf("uint32ToIP(%d) = %s, want %s", tt.value, ip.String(), tt.expected)
			}
		})
	}
}

func TestRoundTrip_IPConversion(t *testing.T) {
	// Test round-trip conversion
	original := "192.168.1.100"
	ip := net.ParseIP(original)
	u := ipToUint32(ip)
	result := uint32ToIP(u)
	if result.String() != original {
		t.Errorf("Round trip failed: %s -> %d -> %s", original, u, result)
	}
}

// Benchmark tests
func BenchmarkEnumerateIPs_Small(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = EnumerateIPs("192.168.1.0/28")
	}
}

func BenchmarkEnumerateIPs_Medium(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = EnumerateIPs("192.168.1.0/24")
	}
}

func BenchmarkIsPrivateIP(b *testing.B) {
	ip := net.ParseIP("192.168.1.100")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsPrivateIP(ip)
	}
}

func BenchmarkIPToUint32(b *testing.B) {
	ip := net.ParseIP("192.168.1.100")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ipToUint32(ip)
	}
}
