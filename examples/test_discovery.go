//go:build ignore
// +build ignore

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	hd "github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery"
)

// findLocalAddrFor returns the local IP address that should be used to reach the target IP.
// This is important on multi-homed hosts where different interfaces reach different networks.
func findLocalAddrFor(targetIP net.IP) string {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: targetIP, Port: 137})
	if err != nil {
		return "0.0.0.0"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// IP address to test - pass as argument or use from environment
	var ip string
	if len(os.Args) > 1 {
		ip = os.Args[1]
	} else if envIP := os.Getenv("TEST_WINDOWS_IP"); envIP != "" {
		ip = envIP
	} else {
		fmt.Println("Usage: go run test_discovery.go <ip>")
		fmt.Println("  or set TEST_WINDOWS_IP environment variable")
		fmt.Println("Example: go run test_discovery.go 192.168.1.100")
		os.Exit(1)
	}
	fmt.Printf("Testing hostname discovery for %s\n\n", ip)

	// Test NetBIOS with raw debug
	fmt.Println("=== NetBIOS Raw Test (UDP/137) ===")
	testNetBIOSRaw(ip)
	fmt.Println()

	// Test NetBIOS via library
	fmt.Println("=== NetBIOS via Library ===")
	nb := hd.NewNetBIOSDiscovery()
	nb.Timeout = 5 * time.Second
	nbRes, err := nb.LookupAddr(ctx, ip)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Hostname: %s\n", nbRes.Hostname)
		fmt.Printf("MAC: %s\n", nbRes.MACAddress)
		for _, n := range nbRes.Names {
			groupStr := ""
			if n.IsGroup {
				groupStr = "<GROUP>"
			}
			activeStr := ""
			if n.IsActive {
				activeStr = "<ACTIVE>"
			}
			fmt.Printf("  %-15s <%.2X> - %7s M %s (%s)\n", n.Name, n.Suffix, groupStr, activeStr, n.Type)
		}
	}
	fmt.Println()

	// Test Reverse DNS
	fmt.Println("=== Reverse DNS ===")
	dns := hd.NewDNSDiscovery()
	dns.Timeout = 3 * time.Second
	dnsRes, err := dns.LookupAddr(ctx, ip)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Hostname: %s\n", dnsRes.Hostname)
		if len(dnsRes.All) > 1 {
			fmt.Printf("All: %v\n", dnsRes.All)
		}
	}
	fmt.Println()

	// Test LLMNR
	fmt.Println("=== LLMNR (UDP/5355) ===")
	llmnr := hd.NewLLMNRDiscovery()
	llmnr.Timeout = 3 * time.Second
	llmnrRes, err := llmnr.LookupAddr(ctx, ip)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Hostname: %s\n", llmnrRes.Hostname)
	}
	fmt.Println()

	// Test mDNS
	fmt.Println("=== mDNS (UDP/5353) ===")
	mdns := hd.NewMDNSDiscovery()
	mdns.Timeout = 3 * time.Second
	mdnsRes, err := mdns.LookupAddr(ctx, ip)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Hostname: %s\n", mdnsRes.Hostname)
	}
	fmt.Println()

	// Test Finger
	fmt.Println("=== Finger (TCP/79) ===")
	finger := hd.NewFingerDiscovery()
	finger.Timeout = 3 * time.Second
	fingerRes, err := finger.LookupAddr(ctx, ip)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		if fingerRes.Hostname != "" {
			fmt.Printf("Hostname: %s\n", fingerRes.Hostname)
		}
		if len(fingerRes.Users) > 0 {
			fmt.Printf("Users: %v\n", fingerRes.Users)
		}
		if fingerRes.Response != "" && len(fingerRes.Response) < 500 {
			fmt.Printf("Response:\n%s\n", fingerRes.Response)
		} else if fingerRes.Response != "" {
			fmt.Printf("Response: (%d bytes)\n", len(fingerRes.Response))
		}
	}
	fmt.Println()

	// Test Multi-protocol
	fmt.Println("=== Multi-Protocol Summary ===")
	multi := hd.NewMultiDiscovery()
	multi.Options.Timeout = 5 * time.Second
	multi.Options.EnableSSDP = false // Skip SSDP for single host
	result := multi.Resolve(ctx, ip)
	fmt.Printf("IP: %s\n", result.IP)
	fmt.Printf("Primary Hostname: %s\n", result.PrimaryHostname())
	fmt.Printf("MAC: %s\n", result.MAC)
	fmt.Println("Hostnames by method:")
	for method, name := range result.Hostnames {
		fmt.Printf("  [%s] %s\n", method, name)
	}
}

// testNetBIOSRaw sends a raw NetBIOS packet and shows the hex response for debugging
func testNetBIOSRaw(ip string) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		fmt.Println("Invalid IP")
		return
	}

	// Find local address to bind to for proper routing on multi-homed hosts
	localAddr := findLocalAddrFor(parsedIP)
	fmt.Printf("Binding to local address: %s\n", localAddr)

	conn, err := net.ListenPacket("udp4", localAddr+":0")
	if err != nil {
		fmt.Printf("Failed to create socket: %v\n", err)
		return
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Build NBSTAT request (same as nmblookup -A)
	request := []byte{
		0x13, 0x37, // Transaction ID
		0x00, 0x00, // Flags
		0x00, 0x01, // Questions
		0x00, 0x00, // Answers
		0x00, 0x00, // Authority
		0x00, 0x00, // Additional
		0x20,     // Name length (32 encoded bytes)
		'C', 'K', // '*' (0x2A) encoded
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		0x00,       // Name terminator
		0x00, 0x21, // Type: NBSTAT
		0x00, 0x01, // Class: IN
	}

	fmt.Printf("Sending %d bytes to %s:137\n", len(request), ip)
	fmt.Printf("Request: %s\n", hex.EncodeToString(request))

	addr := &net.UDPAddr{IP: parsedIP, Port: 137}
	n, err := conn.WriteTo(request, addr)
	if err != nil {
		fmt.Printf("Send error: %v\n", err)
		return
	}
	fmt.Printf("Sent %d bytes\n", n)

	buf := make([]byte, 2048)
	nRead, from, err := conn.ReadFrom(buf)
	if err != nil {
		fmt.Printf("Read error (timeout or blocked): %v\n", err)
		return
	}

	fmt.Printf("Received %d bytes from %v\n", nRead, from)
	fmt.Printf("Response: %s\n", hex.EncodeToString(buf[:nRead]))
}
