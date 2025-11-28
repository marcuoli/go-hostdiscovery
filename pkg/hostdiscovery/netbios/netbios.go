// Package netbios provides NetBIOS-based hostname discovery utilities.
// This package provides Node Status (NBSTAT) lookups over UDP/137 similar to
// nmblookup -A. Works without elevated privileges.
package netbios

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	// Port is the UDP port for NetBIOS Name Service
	Port = 137
	// DefaultTimeout is the default timeout for NetBIOS lookups
	DefaultTimeout = 2 * time.Second
)

// DebugLogger is a callback for debug logging.
// Set this to receive debug messages from NetBIOS operations.
var DebugLogger func(format string, args ...interface{})

func debugLog(format string, args ...interface{}) {
	if DebugLogger != nil {
		DebugLogger(format, args...)
	}
}

// Name represents a discovered NetBIOS name entry.
type Name struct {
	Name     string
	Suffix   byte
	Type     string
	IsGroup  bool
	IsActive bool
}

// Result contains the result of a NetBIOS Node Status lookup.
type Result struct {
	IP         string
	Names      []Name
	MACAddress string
	Hostname   string // Primary hostname (first workstation name found)
}

// Discovery performs NetBIOS-based hostname discovery.
type Discovery struct {
	Timeout time.Duration
}

// NewDiscovery creates a new NetBIOS discovery helper with defaults.
func NewDiscovery() *Discovery {
	return &Discovery{Timeout: DefaultTimeout}
}

// LookupAddr performs a NetBIOS Node Status query (NBSTAT) to a specific IPv4 address.
// It tries the optimal interface first, then falls back to other interfaces if needed.
func (n *Discovery) LookupAddr(ctx context.Context, ip string) (*Result, error) {
	res := &Result{IP: ip}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return res, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Get all candidate local addresses to try
	localAddrs := getLocalAddrsForSubnet(parsedIP)
	if len(localAddrs) == 0 {
		localAddrs = []string{":0"} // fallback to any
	}

	var lastErr error
	for _, localAddr := range localAddrs {
		result, err := n.lookupFromInterface(ctx, parsedIP, localAddr)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}

	return res, lastErr
}

// lookupFromInterface performs the actual NetBIOS lookup from a specific local address.
func (n *Discovery) lookupFromInterface(ctx context.Context, targetIP net.IP, localAddr string) (*Result, error) {
	res := &Result{IP: targetIP.String()}

	conn, err := net.ListenPacket("udp4", localAddr)
	if err != nil {
		return res, fmt.Errorf("udp listen: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(n.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	addr := &net.UDPAddr{IP: targetIP, Port: Port}
	req := buildNBSTATRequest()
	if _, err := conn.WriteTo(req, addr); err != nil {
		debugLog("%s: send failed: %v", targetIP, err)
		return res, fmt.Errorf("send request: %w", err)
	}

	buf := make([]byte, 2048)
	nRead, _, err := conn.ReadFrom(buf)
	if err != nil {
		debugLog("%s: read failed: %v", targetIP, err)
		return res, fmt.Errorf("read response: %w", err)
	}
	if nRead == 0 {
		return res, fmt.Errorf("empty response")
	}

	if err := parseNBSTATResponse(buf[:nRead], res); err != nil {
		debugLog("%s: parse failed: %v", targetIP, err)
		return res, fmt.Errorf("parse response: %w", err)
	}
	if res.Hostname != "" {
		debugLog("%s -> %s (MAC: %s)", targetIP, res.Hostname, res.MACAddress)
	}
	return res, nil
}

// getLocalAddrsForSubnet returns all local addresses that are in the same subnet as the target.
// It prioritizes the "default route" address first, then adds other addresses in the same /24.
func getLocalAddrsForSubnet(targetIP net.IP) []string {
	var addrs []string

	// First, try the OS-determined best route
	if conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: targetIP, Port: Port}); err == nil {
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		addrs = append(addrs, localAddr.IP.String()+":0")
		conn.Close()
	}

	// Get all local interfaces and find ones in the same /24 subnet
	targetPrefix := targetIP.To4()[:3]

	ifaces, err := net.Interfaces()
	if err != nil {
		return addrs
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		ifAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range ifAddrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue
			}

			// Check if same /24 subnet
			if ip4[0] == targetPrefix[0] && ip4[1] == targetPrefix[1] && ip4[2] == targetPrefix[2] {
				localStr := ip4.String() + ":0"
				// Don't add duplicates
				found := false
				for _, a := range addrs {
					if a == localStr {
						found = true
						break
					}
				}
				if !found {
					addrs = append(addrs, localStr)
				}
			}
		}
	}

	return addrs
}

// LookupMultiple performs NetBIOS lookups on multiple IPs concurrently.
func (n *Discovery) LookupMultiple(ctx context.Context, ips []string) []*Result {
	if len(ips) == 0 {
		return nil
	}
	out := make([]*Result, len(ips))
	done := make(chan struct{})
	for i, ip := range ips {
		go func(idx int, ipAddr string) {
			r, _ := n.LookupAddr(ctx, ipAddr)
			out[idx] = r
			select {
			case done <- struct{}{}:
			default:
			}
		}(i, ip)
	}
	for range ips {
		select {
		case <-done:
		case <-ctx.Done():
			return out
		}
	}
	return out
}

// buildNBSTATRequest constructs a Node Status request for the wildcard name.
func buildNBSTATRequest() []byte {
	var buf bytes.Buffer
	// Transaction ID
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x1337))
	// Flags
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x0000))
	// QDCOUNT=1
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	// ANCOUNT, NSCOUNT, ARCOUNT = 0
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))

	// Encoded wildcard name '*' padded to 16 bytes then encoded (RFC 1001/1002)
	buf.WriteByte(32) // length of encoded name
	name := make([]byte, 16)
	name[0] = '*'
	for _, b := range name {
		hi := (b >> 4) & 0x0F
		lo := b & 0x0F
		buf.WriteByte('A' + hi)
		buf.WriteByte('A' + lo)
	}
	buf.WriteByte(0) // null terminator

	// Type: NBSTAT (0x0021), Class: IN (0x0001)
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x0021))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x0001))
	return buf.Bytes()
}

// parseNBSTATResponse parses a Node Status response into Result.
func parseNBSTATResponse(data []byte, result *Result) error {
	if len(data) < 57 {
		return fmt.Errorf("response too short: %d bytes", len(data))
	}

	numNames := int(data[56])
	off := 57
	if numNames <= 0 {
		return fmt.Errorf("no names in response")
	}

	for i := 0; i < numNames && off+18 <= len(data); i++ {
		entry := data[off : off+18]
		name := strings.TrimRight(string(entry[0:15]), " \x00")
		suffix := entry[15]
		flags := binary.BigEndian.Uint16(entry[16:18])
		nb := Name{
			Name:     name,
			Suffix:   suffix,
			Type:     suffixDescription(suffix),
			IsGroup:  (flags & 0x8000) != 0,
			IsActive: (flags & 0x0400) != 0,
		}
		result.Names = append(result.Names, nb)
		if result.Hostname == "" && suffix == 0x00 && !nb.IsGroup {
			result.Hostname = name
		}
		off += 18
	}

	// MAC address is 6 bytes following name table, if present
	if off+6 <= len(data) {
		mac := net.HardwareAddr(data[off : off+6])
		result.MACAddress = strings.ToUpper(mac.String())
		// Standardize delimiter to '-'
		result.MACAddress = strings.ToUpper(strings.ReplaceAll(result.MACAddress, ":", "-"))
	}

	return nil
}

func suffixDescription(suffix byte) string {
	switch suffix {
	case 0x00:
		return "Workstation"
	case 0x03:
		return "Messenger"
	case 0x06:
		return "RAS Server"
	case 0x1B:
		return "Domain Master Browser"
	case 0x1C:
		return "Domain Controller"
	case 0x1D:
		return "Local Master Browser"
	case 0x1E:
		return "Browser Election"
	case 0x1F:
		return "NetDDE"
	case 0x20:
		return "File Server"
	case 0x21:
		return "RAS Client"
	case 0xBE:
		return "Network Monitor Agent"
	case 0xBF:
		return "Network Monitor Utility"
	default:
		return fmt.Sprintf("Unknown (0x%02X)", suffix)
	}
}

// hexPreview returns a short hex dump useful for debugging.
func hexPreview(b []byte, limit int) string {
	if len(b) > limit {
		b = b[:limit]
	}
	return hex.EncodeToString(b)
}
