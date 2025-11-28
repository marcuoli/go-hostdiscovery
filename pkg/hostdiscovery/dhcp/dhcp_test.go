// Package dhcp tests for DHCP discovery.
package dhcp

import (
	"encoding/binary"
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
	if DefaultTimeout != 2*time.Second {
		t.Errorf("Expected DefaultTimeout 2s, got %v", DefaultTimeout)
	}
	if ServerPort != 67 {
		t.Errorf("Expected ServerPort 67, got %d", ServerPort)
	}
	if ClientPort != 68 {
		t.Errorf("Expected ClientPort 68, got %d", ClientPort)
	}
	if MagicCookie != 0x63825363 {
		t.Errorf("Expected MagicCookie 0x63825363, got 0x%08X", MagicCookie)
	}
	if MaxMsgSize != 576 {
		t.Errorf("Expected MaxMsgSize 576, got %d", MaxMsgSize)
	}
}

func TestInformResult_Structure(t *testing.T) {
	result := &InformResult{
		ServerIP:      "192.168.1.1",
		Hostname:      "workstation",
		DomainName:    "example.com",
		DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
		Routers:       []string{"192.168.1.1"},
		SubnetMask:    "255.255.255.0",
		BroadcastAddr: "192.168.1.255",
		Error:         nil,
	}

	if result.ServerIP != "192.168.1.1" {
		t.Errorf("Expected ServerIP 192.168.1.1, got %s", result.ServerIP)
	}
	if result.Hostname != "workstation" {
		t.Errorf("Expected Hostname workstation, got %s", result.Hostname)
	}
	if result.DomainName != "example.com" {
		t.Errorf("Expected DomainName example.com, got %s", result.DomainName)
	}
	if len(result.DNSServers) != 2 {
		t.Errorf("Expected 2 DNS servers, got %d", len(result.DNSServers))
	}
}

func TestBuildInform_BasicStructure(t *testing.T) {
	d := NewDiscovery()

	clientIP := []byte{192, 168, 1, 100}
	mac := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	packet := d.buildInform(clientIP, mac)

	// Check minimum size
	if len(packet) < 240 {
		t.Fatalf("Packet too short: %d bytes", len(packet))
	}

	// Check BOOTP header fields
	if packet[0] != 1 { // Op = BOOTREQUEST
		t.Errorf("Expected Op 1 (BOOTREQUEST), got %d", packet[0])
	}
	if packet[1] != 1 { // Htype = Ethernet
		t.Errorf("Expected Htype 1 (Ethernet), got %d", packet[1])
	}
	if packet[2] != 6 { // Hlen = 6
		t.Errorf("Expected Hlen 6, got %d", packet[2])
	}

	// Check client IP (ciaddr at offset 12-15)
	ciaddr := packet[12:16]
	if ciaddr[0] != 192 || ciaddr[1] != 168 || ciaddr[2] != 1 || ciaddr[3] != 100 {
		t.Errorf("Unexpected ciaddr: %v", ciaddr)
	}

	// Check MAC address (chaddr at offset 28-33)
	chaddr := packet[28:34]
	for i, b := range mac {
		if chaddr[i] != b {
			t.Errorf("MAC byte %d: expected 0x%02X, got 0x%02X", i, b, chaddr[i])
		}
	}

	// Check magic cookie at offset 236-239
	cookie := binary.BigEndian.Uint32(packet[236:240])
	if cookie != MagicCookie {
		t.Errorf("Expected magic cookie 0x%08X, got 0x%08X", MagicCookie, cookie)
	}
}

func TestBuildInform_MessageType(t *testing.T) {
	d := NewDiscovery()

	packet := d.buildInform([]byte{192, 168, 1, 100}, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})

	// Find DHCP Message Type option (53)
	found := false
	for i := 240; i < len(packet)-2; i++ {
		if packet[i] == 53 { // Option 53 = Message Type
			if packet[i+1] != 1 { // Length should be 1
				t.Errorf("Message Type option length should be 1, got %d", packet[i+1])
			}
			if packet[i+2] != 8 { // 8 = DHCPINFORM
				t.Errorf("Message Type should be 8 (INFORM), got %d", packet[i+2])
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("DHCP Message Type option not found")
	}
}

func TestParseOptions_Empty(t *testing.T) {
	d := NewDiscovery()
	result := &InformResult{}

	// Packet too short
	d.parseOptions(make([]byte, 100), result)

	// Should not panic, result should be empty
	if result.Hostname != "" {
		t.Error("Expected empty hostname for short packet")
	}
}

func TestParseOptions_ValidResponse(t *testing.T) {
	d := NewDiscovery()
	result := &InformResult{}

	// Build a minimal valid DHCP response packet
	packet := make([]byte, 300)

	// Magic cookie at 236
	binary.BigEndian.PutUint32(packet[236:240], MagicCookie)

	// Options start at 240
	idx := 240

	// Option 1: Subnet Mask
	packet[idx] = 1
	packet[idx+1] = 4
	packet[idx+2], packet[idx+3], packet[idx+4], packet[idx+5] = 255, 255, 255, 0
	idx += 6

	// Option 12: Hostname
	hostname := "testhost"
	packet[idx] = 12
	packet[idx+1] = byte(len(hostname))
	copy(packet[idx+2:], []byte(hostname))
	idx += 2 + len(hostname)

	// Option 15: Domain Name
	domain := "test.local"
	packet[idx] = 15
	packet[idx+1] = byte(len(domain))
	copy(packet[idx+2:], []byte(domain))
	idx += 2 + len(domain)

	// Option 3: Router
	packet[idx] = 3
	packet[idx+1] = 4
	packet[idx+2], packet[idx+3], packet[idx+4], packet[idx+5] = 192, 168, 1, 1
	idx += 6

	// Option 6: DNS Servers (2 servers)
	packet[idx] = 6
	packet[idx+1] = 8
	packet[idx+2], packet[idx+3], packet[idx+4], packet[idx+5] = 8, 8, 8, 8
	packet[idx+6], packet[idx+7], packet[idx+8], packet[idx+9] = 8, 8, 4, 4
	idx += 10

	// Option 255: End
	packet[idx] = 255

	d.parseOptions(packet, result)

	if result.SubnetMask != "255.255.255.0" {
		t.Errorf("Expected SubnetMask 255.255.255.0, got %s", result.SubnetMask)
	}
	if result.Hostname != "testhost" {
		t.Errorf("Expected Hostname testhost, got %s", result.Hostname)
	}
	if result.DomainName != "test.local" {
		t.Errorf("Expected DomainName test.local, got %s", result.DomainName)
	}
	if len(result.Routers) != 1 || result.Routers[0] != "192.168.1.1" {
		t.Errorf("Unexpected Routers: %v", result.Routers)
	}
	if len(result.DNSServers) < 1 {
		t.Errorf("Expected at least 1 DNS server, got %v", result.DNSServers)
	}
}

func TestParseOptions_PadAndEnd(t *testing.T) {
	d := NewDiscovery()
	result := &InformResult{}

	packet := make([]byte, 250)
	binary.BigEndian.PutUint32(packet[236:240], MagicCookie)

	// Options: PAD, PAD, Hostname, PAD, END
	idx := 240
	packet[idx] = 0   // PAD
	packet[idx+1] = 0 // PAD
	idx += 2

	packet[idx] = 12 // Hostname
	packet[idx+1] = 4
	copy(packet[idx+2:], []byte("test"))
	idx += 6

	packet[idx] = 0   // PAD
	packet[idx+1] = 255 // END

	d.parseOptions(packet, result)

	if result.Hostname != "test" {
		t.Errorf("Expected Hostname 'test', got %s", result.Hostname)
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

// TestDHCPMessageTypes documents DHCP message types
func TestDHCPMessageTypes_Documentation(t *testing.T) {
	types := map[int]string{
		1: "DHCPDISCOVER - Client broadcast to locate servers",
		2: "DHCPOFFER - Server response to DISCOVER",
		3: "DHCPREQUEST - Client message to request/renew lease",
		4: "DHCPDECLINE - Client rejects offered address",
		5: "DHCPACK - Server confirms lease",
		6: "DHCPNAK - Server denies request",
		7: "DHCPRELEASE - Client releases its lease",
		8: "DHCPINFORM - Client requests configuration (has IP already)",
	}

	t.Logf("DHCP Message Types: %d defined", len(types))
	for code, desc := range types {
		t.Logf("  %d: %s", code, desc)
	}
}

// TestDHCPOptions documents common DHCP options
func TestDHCPOptions_Documentation(t *testing.T) {
	options := map[int]string{
		1:  "Subnet Mask",
		3:  "Router/Gateway",
		6:  "DNS Servers",
		12: "Hostname",
		15: "Domain Name",
		28: "Broadcast Address",
		50: "Requested IP Address",
		51: "IP Address Lease Time",
		53: "DHCP Message Type",
		54: "Server Identifier",
		55: "Parameter Request List",
		57: "Maximum DHCP Message Size",
		61: "Client Identifier",
	}

	t.Logf("Common DHCP Options: %d listed", len(options))
	for code, name := range options {
		t.Logf("  Option %d: %s", code, name)
	}
}

// Benchmark tests
func BenchmarkBuildInform(b *testing.B) {
	d := NewDiscovery()
	clientIP := []byte{192, 168, 1, 100}
	mac := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.buildInform(clientIP, mac)
	}
}

func BenchmarkParseOptions(b *testing.B) {
	d := NewDiscovery()
	packet := make([]byte, 300)
	binary.BigEndian.PutUint32(packet[236:240], MagicCookie)
	packet[240] = 12 // Hostname
	packet[241] = 8
	copy(packet[242:], []byte("testhost"))
	packet[250] = 255 // End

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := &InformResult{}
		d.parseOptions(packet, result)
	}
}
