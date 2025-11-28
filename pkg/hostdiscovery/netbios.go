// Package hostdiscovery: NetBIOS-based hostname discovery utilities.
// This file provides Node Status (NBSTAT) lookups over UDP/137 similar to
// nmblookup -A. Works without elevated privileges.
package hostdiscovery

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
    // UDP port for NetBIOS Name Service
    netBIOSPort    = 137
    netBIOSTimeout = 2 * time.Second
)

// NetBIOSName represents a discovered NetBIOS name entry.
type NetBIOSName struct {
    Name    string
    Suffix  byte
    Type    string
    IsGroup bool
    IsActive bool
}

// NetBIOSResult contains the result of a NetBIOS Node Status lookup.
type NetBIOSResult struct {
    IP         string
    Names      []NetBIOSName
    MACAddress string
    Hostname   string // Primary hostname (first workstation name found)
}

// NetBIOSDiscovery performs NetBIOS-based hostname discovery.
type NetBIOSDiscovery struct {
    Timeout time.Duration
}

// NewNetBIOSDiscovery creates a new NetBIOS discovery helper with defaults.
func NewNetBIOSDiscovery() *NetBIOSDiscovery {
    return &NetBIOSDiscovery{Timeout: netBIOSTimeout}
}

// LookupAddr performs a NetBIOS Node Status query (NBSTAT) to a specific IPv4 address.
func (n *NetBIOSDiscovery) LookupAddr(ctx context.Context, ip string) (*NetBIOSResult, error) {
    res := &NetBIOSResult{IP: ip}

    parsedIP := net.ParseIP(ip)
    if parsedIP == nil {
        return res, fmt.Errorf("invalid IP address: %s", ip)
    }

    conn, err := net.ListenPacket("udp4", ":0")
    if err != nil {
        return res, fmt.Errorf("udp listen: %w", err)
    }
    defer conn.Close()

    deadline := time.Now().Add(n.Timeout)
    if d, ok := ctx.Deadline(); ok && d.Before(deadline) { deadline = d }
    _ = conn.SetDeadline(deadline)

    addr := &net.UDPAddr{IP: parsedIP, Port: netBIOSPort}
    req := buildNBSTATRequest()
    if _, err := conn.WriteTo(req, addr); err != nil {
        return res, fmt.Errorf("send request: %w", err)
    }

    buf := make([]byte, 2048)
    nRead, _, err := conn.ReadFrom(buf)
    if err != nil {
        return res, fmt.Errorf("read response: %w", err)
    }
    if nRead == 0 {
        return res, fmt.Errorf("empty response")
    }

    if err := parseNBSTATResponse(buf[:nRead], res); err != nil {
        return res, fmt.Errorf("parse response: %w", err)
    }
    return res, nil
}

// LookupMultiple performs NetBIOS lookups on multiple IPs concurrently.
func (n *NetBIOSDiscovery) LookupMultiple(ctx context.Context, ips []string) []*NetBIOSResult {
    if len(ips) == 0 { return nil }
    out := make([]*NetBIOSResult, len(ips))
    done := make(chan struct{})
    for i, ip := range ips {
        go func(idx int, ipAddr string) {
            r, _ := n.LookupAddr(ctx, ipAddr)
            out[idx] = r
            select { case done <- struct{}{}: default: }
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

// parseNBSTATResponse parses a Node Status response into NetBIOSResult.
func parseNBSTATResponse(data []byte, result *NetBIOSResult) error {
    if len(data) < 57 {
        return fmt.Errorf("response too short: %d bytes", len(data))
    }

    // For debugging/diagnostics: ensure it's a response by checking the flags QR bit
    // Not strictly necessary for basic parsing; left as a minimal sanity check.
    // flags := binary.BigEndian.Uint16(data[2:4])
    // if (flags & 0x8000) == 0 { return fmt.Errorf("not a response packet") }

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
        nb := NetBIOSName{
            Name: name,
            Suffix: suffix,
            Type: suffixDescription(suffix),
            IsGroup: (flags & 0x8000) != 0,
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
    if len(b) > limit { b = b[:limit] }
    return hex.EncodeToString(b)
}
