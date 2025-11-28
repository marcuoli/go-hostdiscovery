// Package hostdiscovery tests for multi-protocol hostname discovery.
// These tests use real network hosts and require network connectivity.
//
// Configuration is loaded from testdata/.env file (not tracked by git).
// Copy testdata/.env.example to testdata/.env and update with your network values.
//
// Supported variables:
//   - TEST_WINDOWS_IP: IP of a Windows host with NetBIOS enabled
//   - TEST_WINDOWS_HOSTNAME: Expected NetBIOS hostname (optional, skips validation if empty)
//   - TEST_WINDOWS_MAC: Expected MAC address (optional, skips validation if empty)
//   - TEST_LINUX_IP: IP of a Linux host without NetBIOS (optional)
//   - TEST_DHCP_LOCAL_IP: Local interface IP for DHCP tests
//   - TEST_DHCP_SERVER_IP: DHCP server IP for DHCP tests
//
// If TEST_WINDOWS_IP is not set, tests requiring a Windows host are skipped.
package hostdiscovery

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Test configuration loaded from testdata/.env or environment variables
var (
	testWindowsIP       string
	testWindowsHostname string
	testWindowsMAC      string
	testLinuxIP         string
	testDHCPLocalIP     string
	testDHCPServerIP    string
)

func init() {
	// Load test configuration from .env file
	loadTestEnv()
}

// loadTestEnv loads test configuration from testdata/.env file.
// Environment variables take precedence over .env file values.
func loadTestEnv() {
	// Find the testdata directory relative to this test file
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		dir := filepath.Dir(filename)
		envPath := filepath.Join(dir, "testdata", ".env")
		if file, err := os.Open(envPath); err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				// Skip empty lines and comments
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				// Parse KEY=VALUE
				if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					value := strings.TrimSpace(parts[1])
					// Only set if not already in environment
					if os.Getenv(key) == "" {
						os.Setenv(key, value)
					}
				}
			}
		}
	}

	// Load from environment (includes values from .env file)
	testWindowsIP = os.Getenv("TEST_WINDOWS_IP")
	testWindowsHostname = os.Getenv("TEST_WINDOWS_HOSTNAME")
	testWindowsMAC = os.Getenv("TEST_WINDOWS_MAC")
	testLinuxIP = os.Getenv("TEST_LINUX_IP")
	testDHCPLocalIP = os.Getenv("TEST_DHCP_LOCAL_IP")
	testDHCPServerIP = os.Getenv("TEST_DHCP_SERVER_IP")
}

const testTimeout = 10 * time.Second

// skipIfNoNetwork skips the test if the test host is not reachable
func skipIfNoNetwork(t *testing.T, ip string) {
	if ip == "" {
		t.Skip("Skipping test: no test IP configured (set TEST_WINDOWS_IP environment variable)")
	}
	conn, err := net.DialTimeout("udp4", ip+":137", 1*time.Second)
	if err != nil {
		t.Skipf("Skipping test: network host %s not reachable", ip)
	}
	conn.Close()
}

// skipIfNoLinuxHost skips the test if no Linux host is configured
func skipIfNoLinuxHost(t *testing.T) {
	if testLinuxIP == "" {
		t.Skip("Skipping test: no Linux test IP configured (set TEST_LINUX_IP environment variable)")
	}
}

// ============================================================================
// NetBIOS Tests
// ============================================================================

func TestNetBIOSDiscovery_LookupAddr(t *testing.T) {
	skipIfNoNetwork(t, testWindowsIP)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	nb := NewNetBIOSDiscovery()
	result, err := nb.LookupAddr(ctx, testWindowsIP)

	if err != nil {
		t.Fatalf("NetBIOS lookup failed: %v", err)
	}

	if result.Hostname == "" {
		t.Error("Expected hostname, got empty string")
	}

	// Validate hostname if expected value is configured
	if testWindowsHostname != "" && !strings.EqualFold(result.Hostname, testWindowsHostname) {
		t.Errorf("Expected hostname %q, got %q", testWindowsHostname, result.Hostname)
	}

	if result.MACAddress == "" {
		t.Error("Expected MAC address, got empty string")
	}

	// Validate MAC if expected value is configured
	if testWindowsMAC != "" {
		gotMAC := strings.ToUpper(strings.ReplaceAll(result.MACAddress, ":", "-"))
		if gotMAC != testWindowsMAC {
			t.Errorf("Expected MAC %q, got %q", testWindowsMAC, gotMAC)
		}
	}

	if len(result.Names) == 0 {
		t.Error("Expected NetBIOS names, got none")
	}

	t.Logf("NetBIOS result: hostname=%s, MAC=%s, names=%d",
		result.Hostname, result.MACAddress, len(result.Names))
}

func TestNetBIOSDiscovery_LookupAddr_NoNetBIOS(t *testing.T) {
	skipIfNoLinuxHost(t)
	skipIfNoNetwork(t, testLinuxIP)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nb := NewNetBIOSDiscovery()
	nb.Timeout = 2 * time.Second
	result, err := nb.LookupAddr(ctx, testLinuxIP)

	// Should timeout or return empty - Linux hosts don't have NetBIOS
	if err == nil && result.Hostname != "" {
		t.Logf("Unexpected NetBIOS response from Linux host: %s", result.Hostname)
	}
}

func TestNetBIOSDiscovery_LookupMultiple(t *testing.T) {
	skipIfNoNetwork(t, testWindowsIP)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	nb := NewNetBIOSDiscovery()

	// Build IP list dynamically
	ips := []string{testWindowsIP}
	if testLinuxIP != "" {
		ips = append(ips, testLinuxIP)
	}

	results := nb.LookupMultiple(ctx, ips)

	if len(results) != len(ips) {
		t.Fatalf("Expected %d results, got %d", len(ips), len(results))
	}

	// First result (Windows) should have hostname
	if results[0] == nil || results[0].Hostname == "" {
		t.Error("Expected Windows host to have NetBIOS hostname")
	}

	t.Logf("Multiple lookup: %d IPs processed", len(results))
}

// ============================================================================
// DNS Tests
// ============================================================================

func TestDNSDiscovery_LookupAddr(t *testing.T) {
	skipIfNoNetwork(t, testWindowsIP)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	dns := NewDNSDiscovery()
	result, err := dns.LookupAddr(ctx, testWindowsIP)

	if err != nil {
		t.Fatalf("DNS lookup failed: %v", err)
	}

	if result.Hostname == "" {
		t.Error("Expected hostname from reverse DNS, got empty string")
	}

	// Validate hostname prefix if expected value is configured
	if testWindowsHostname != "" {
		lowerHostname := strings.ToLower(result.Hostname)
		lowerExpected := strings.ToLower(testWindowsHostname)
		if !strings.HasPrefix(lowerHostname, lowerExpected) {
			t.Errorf("Expected DNS hostname to start with %q, got %q", testWindowsHostname, result.Hostname)
		}
	}

	t.Logf("DNS result: hostname=%s", result.Hostname)
}

func TestDNSDiscovery_LookupMultiple(t *testing.T) {
	skipIfNoNetwork(t, testWindowsIP)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	dns := NewDNSDiscovery()
	ips := []string{testWindowsIP}
	results := dns.LookupMultiple(ctx, ips)

	if len(results) != len(ips) {
		t.Fatalf("Expected %d results, got %d", len(ips), len(results))
	}

	if results[0] == nil || results[0].Hostname == "" {
		t.Error("Expected DNS result for Windows host")
	}
}

// ============================================================================
// mDNS Tests
// ============================================================================

func TestMDNSDiscovery_LookupAddr(t *testing.T) {
	skipIfNoNetwork(t, testWindowsIP)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mdns := NewMDNSDiscovery()
	mdns.Timeout = 3 * time.Second
	result, _ := mdns.LookupAddr(ctx, testWindowsIP)

	// mDNS may not be available on all hosts - just verify no crash
	t.Logf("mDNS result: hostname=%q, error=%v", result.Hostname, result.Error)
}

func TestMDNSDiscovery_BrowseServices(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mdns := NewMDNSDiscovery()
	mdns.Timeout = 3 * time.Second

	// Try to discover HTTP services
	services, err := mdns.BrowseServices(ctx, "_http._tcp")
	if err != nil {
		t.Logf("Service browse returned error (may be expected): %v", err)
	}

	t.Logf("mDNS found %d HTTP services", len(services))
	for _, svc := range services {
		t.Logf("  - %s (port %d)", svc.Instance, svc.Port)
	}
}

// ============================================================================
// LLMNR Tests
// ============================================================================

func TestLLMNRDiscovery_LookupAddr(t *testing.T) {
	skipIfNoNetwork(t, testWindowsIP)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	llmnr := NewLLMNRDiscovery()
	llmnr.Timeout = 3 * time.Second
	result, _ := llmnr.LookupAddr(ctx, testWindowsIP)

	// LLMNR may not respond to reverse lookups - just verify no crash
	t.Logf("LLMNR result: hostname=%q, error=%v", result.Hostname, result.Error)
}

func TestLLMNRDiscovery_LookupName(t *testing.T) {
	if testWindowsHostname == "" {
		t.Skip("Skipping test: TEST_WINDOWS_HOSTNAME not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	llmnr := NewLLMNRDiscovery()
	llmnr.Timeout = 3 * time.Second

	// Try to resolve the Windows hostname
	ips, err := llmnr.LookupName(ctx, testWindowsHostname)
	if err != nil {
		t.Logf("LLMNR name lookup returned error (may be expected): %v", err)
	}

	t.Logf("LLMNR resolved %q to %d IPs", testWindowsHostname, len(ips))
	for _, ip := range ips {
		t.Logf("  - %s", ip)
	}
}

// ============================================================================
// SSDP Tests
// ============================================================================

func TestSSDPDiscovery_Discover(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ssdp := NewSSDPDiscovery()
	ssdp.Timeout = 3 * time.Second

	results, err := ssdp.Discover(ctx, SSDPAll)
	if err != nil {
		t.Logf("SSDP discovery returned error (may be expected): %v", err)
	}

	t.Logf("SSDP found %d devices", len(results))
	for _, r := range results {
		t.Logf("  - %s at %s (%s)", r.Server, r.Location, r.ST)
	}
}

func TestSSDPDiscovery_DiscoverRootDevices(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ssdp := NewSSDPDiscovery()
	ssdp.Timeout = 3 * time.Second

	results, err := ssdp.Discover(ctx, SSDPRootDevice)
	if err != nil {
		t.Logf("SSDP root device discovery error: %v", err)
		return
	}

	t.Logf("SSDP found %d root devices", len(results))
	for _, r := range results {
		t.Logf("  - IP=%s Server=%s USN=%s", r.IP, r.Server, r.USN)
	}
}

func TestSSDPDiscovery_DiscoverWithDeviceInfo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ssdp := NewSSDPDiscovery()
	ssdp.Timeout = 3 * time.Second

	results, err := ssdp.Discover(ctx, SSDPRootDevice)
	if err != nil {
		t.Logf("SSDP discovery error: %v", err)
		return
	}

	if len(results) == 0 {
		t.Log("No SSDP devices found")
		return
	}

	// Enrich with device info
	ssdp.EnrichResults(ctx, results)

	t.Logf("SSDP devices with info:")
	for _, r := range results {
		t.Logf("  - %s", r.IP)
		t.Logf("      FriendlyName: %s", r.FriendlyName)
		t.Logf("      Manufacturer: %s", r.Manufacturer)
		t.Logf("      Model: %s", r.ModelName)
		t.Logf("      Server: %s", r.Server)
	}
}

// ============================================================================
// Finger Tests
// ============================================================================

func TestFingerDiscovery_LookupAddr(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	finger := NewFingerDiscovery()
	finger.Timeout = 3 * time.Second

	// Test against a host - Finger is rarely enabled nowadays
	result, err := finger.LookupAddr(ctx, testWindowsIP)
	if err != nil {
		t.Logf("Finger lookup returned error (expected - finger rarely enabled): %v", err)
		return
	}

	t.Logf("Finger result:")
	if result.Hostname != "" {
		t.Logf("  Hostname: %s", result.Hostname)
	}
	if len(result.Users) > 0 {
		t.Logf("  Users: %v", result.Users)
	}
	if result.Response != "" {
		t.Logf("  Response length: %d bytes", len(result.Response))
	}
}

func TestFingerDiscovery_IsAvailable(t *testing.T) {
	skipIfNoNetwork(t, testWindowsIP)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	finger := NewFingerDiscovery()
	finger.Timeout = 2 * time.Second

	available := finger.IsAvailable(ctx, testWindowsIP)
	t.Logf("Finger available on %s: %v", testWindowsIP, available)
}

// ============================================================================
// DHCP Tests
// ============================================================================

func TestDHCPDiscovery_SendDHCPInform(t *testing.T) {
	if testDHCPLocalIP == "" {
		t.Skip("Skipping test: TEST_DHCP_LOCAL_IP not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dhcp := NewDHCPDiscovery()
	dhcp.Timeout = 3 * time.Second

	result, err := dhcp.SendInform(ctx, testDHCPLocalIP)
	if err != nil {
		// May fail due to permissions or no DHCP server on network
		t.Logf("DHCP INFORM returned error (may be expected): %v", err)
		return
	}

	t.Logf("DHCP INFORM result from server %s:", result.ServerIP)
	t.Logf("  Hostname: %s", result.Hostname)
	t.Logf("  Domain: %s", result.DomainName)
	t.Logf("  Subnet Mask: %s", result.SubnetMask)
	t.Logf("  Routers: %v", result.Routers)
	t.Logf("  DNS Servers: %v", result.DNSServers)
	t.Logf("  Broadcast: %s", result.BroadcastAddr)
}

func TestDHCPDiscovery_SendDHCPInformToServer(t *testing.T) {
	if testDHCPLocalIP == "" || testDHCPServerIP == "" {
		t.Skip("Skipping test: TEST_DHCP_LOCAL_IP or TEST_DHCP_SERVER_IP not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dhcp := NewDHCPDiscovery()
	dhcp.Timeout = 3 * time.Second

	result, err := dhcp.SendInformToServer(ctx, testDHCPLocalIP, testDHCPServerIP)
	if err != nil {
		t.Logf("DHCP INFORM to server returned error (may be expected): %v", err)
		return
	}

	t.Logf("DHCP INFORM result from server %s:", result.ServerIP)
	t.Logf("  Hostname: %s", result.Hostname)
	t.Logf("  Domain: %s", result.DomainName)
	t.Logf("  DNS Servers: %v", result.DNSServers)
}

// ============================================================================
// Multi-Protocol Tests
// ============================================================================

func TestMultiDiscovery_Resolve(t *testing.T) {
	skipIfNoNetwork(t, testWindowsIP)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	multi := NewMultiDiscovery()
	result := multi.Resolve(ctx, testWindowsIP)

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if result.IP != testWindowsIP {
		t.Errorf("Expected IP %q, got %q", testWindowsIP, result.IP)
	}

	// Should have at least DNS or NetBIOS hostname
	if len(result.Hostnames) == 0 {
		t.Error("Expected at least one hostname from multi-protocol discovery")
	}

	// Check for DNS result (validate if expected hostname is configured)
	if testWindowsHostname != "" {
		if dnsName, ok := result.Hostnames[MethodDNS]; ok {
			lowerDNS := strings.ToLower(dnsName)
			lowerExpected := strings.ToLower(testWindowsHostname)
			if !strings.HasPrefix(lowerDNS, lowerExpected) {
				t.Errorf("DNS hostname should start with %q, got %q", testWindowsHostname, dnsName)
			}
		}

		// Check for NetBIOS result
		if nbName, ok := result.Hostnames[MethodNetBIOS]; ok {
			if !strings.EqualFold(nbName, testWindowsHostname) {
				t.Errorf("NetBIOS hostname mismatch: expected %q, got %q", testWindowsHostname, nbName)
			}
		}
	}

	// Check MAC address from NetBIOS (validate if expected MAC is configured)
	if testWindowsMAC != "" && result.MAC != "" {
		gotMAC := strings.ToUpper(strings.ReplaceAll(result.MAC, ":", "-"))
		if gotMAC != testWindowsMAC {
			t.Errorf("MAC mismatch: expected %q, got %q", testWindowsMAC, gotMAC)
		}
	}

	// Test PrimaryHostname()
	primary := result.PrimaryHostname()
	if primary == "" {
		t.Error("PrimaryHostname() returned empty string")
	}

	t.Logf("Multi-protocol result:")
	t.Logf("  IP: %s", result.IP)
	t.Logf("  Primary hostname: %s", primary)
	t.Logf("  MAC: %s", result.MAC)
	t.Logf("  Hostnames by method:")
	for method, name := range result.Hostnames {
		t.Logf("    [%s] %s", method, name)
	}
}

func TestMultiDiscovery_ResolveBatch(t *testing.T) {
	skipIfNoNetwork(t, testWindowsIP)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	multi := NewMultiDiscovery()

	// Build IP list dynamically
	ips := []string{testWindowsIP}
	if testLinuxIP != "" {
		ips = append(ips, testLinuxIP)
	}

	results, err := multi.ResolveBatch(ctx, ips)

	if err != nil {
		t.Fatalf("ResolveBatch failed: %v", err)
	}

	if len(results) != len(ips) {
		t.Fatalf("Expected %d results, got %d", len(ips), len(results))
	}

	// Windows host should have hostnames
	if len(results[0].Hostnames) == 0 {
		t.Error("Expected hostnames for Windows host")
	}

	t.Logf("Batch resolved %d IPs", len(results))
	for i, r := range results {
		t.Logf("  %s: primary=%q, methods=%d",
			ips[i], r.PrimaryHostname(), len(r.Hostnames))
	}
}

// ============================================================================
// IP Enumeration Tests
// ============================================================================

func TestEnumerateIPs(t *testing.T) {
	// EnumerateIPs excludes network and broadcast addresses
	// So /30 has 2 usable, /29 has 6 usable, etc.
	tests := []struct {
		cidr     string
		expected int
	}{
		{"192.168.1.0/30", 2},   // 4 total - network - broadcast = 2
		{"192.168.1.0/29", 6},   // 8 total - network - broadcast = 6
		{"192.168.1.0/28", 14},  // 16 total - network - broadcast = 14
		{"192.168.1.0/24", 254}, // 256 total - network - broadcast = 254
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			ips, err := EnumerateIPs(tt.cidr)
			if err != nil {
				t.Fatalf("EnumerateIPs(%s) failed: %v", tt.cidr, err)
			}
			if len(ips) != tt.expected {
				t.Errorf("Expected %d IPs, got %d", tt.expected, len(ips))
			}
		})
	}
}

func TestEnumerateIPs_Invalid(t *testing.T) {
	_, err := EnumerateIPs("invalid")
	if err == nil {
		t.Error("Expected error for invalid CIDR")
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkNetBIOSLookup(b *testing.B) {
	ctx := context.Background()
	nb := NewNetBIOSDiscovery()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = nb.LookupAddr(ctx, testWindowsIP)
	}
}

func BenchmarkDNSLookup(b *testing.B) {
	ctx := context.Background()
	dns := NewDNSDiscovery()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = dns.LookupAddr(ctx, testWindowsIP)
	}
}

func BenchmarkMultiResolve(b *testing.B) {
	ctx := context.Background()
	multi := NewMultiDiscovery()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = multi.Resolve(ctx, testWindowsIP)
	}
}
