// Package hostdiscovery: DHCP hostname discovery utilities.
// This file provides methods to discover hostnames using the DHCP protocol directly.
//
// The primary method is DHCP INFORM request which queries the DHCP server
// directly for configuration parameters including hostname and domain.
//
// Note: DHCP INFORM requires binding to UDP port 68 which may need
// elevated privileges on some systems.
package hostdiscovery

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
)

const (
	dhcpTimeout     = 2 * time.Second
	dhcpServerPort  = 67
	dhcpClientPort  = 68
	dhcpMagicCookie = 0x63825363
	dhcpMaxMsgSize  = 576

	// DHCP Message Types
	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpDecline  = 4
	dhcpAck      = 5
	dhcpNak      = 6
	dhcpRelease  = 7
	dhcpInform   = 8

	// DHCP Options
	optPad          = 0
	optSubnetMask   = 1
	optRouter       = 3
	optDNS          = 6
	optHostname     = 12
	optDomainName   = 15
	optBroadcast    = 28
	optRequestedIP  = 50
	optLeaseTime    = 51
	optMessageType  = 53
	optServerID     = 54
	optParamRequest = 55
	optMaxMsgSize   = 57
	optClientID     = 61
	optEnd          = 255
)

// DHCPDiscovery performs DHCP protocol-based hostname discovery.
// Uses DHCP INFORM packets to query DHCP servers directly for configuration.
type DHCPDiscovery struct {
	Timeout time.Duration
}

// NewDHCPDiscovery creates a new DHCP discovery helper with defaults.
func NewDHCPDiscovery() *DHCPDiscovery {
	return &DHCPDiscovery{Timeout: dhcpTimeout}
}

// ============================================================================
// DHCP INFORM Implementation
// ============================================================================

// DHCPInformResult contains information from a DHCP INFORM response.
type DHCPInformResult struct {
	ServerIP      string   // DHCP server that responded
	Hostname      string   // Option 12: Host Name
	DomainName    string   // Option 15: Domain Name
	DNSServers    []string // Option 6: DNS Server(s)
	Routers       []string // Option 3: Router(s)
	SubnetMask    string   // Option 1: Subnet Mask
	BroadcastAddr string   // Option 28: Broadcast Address
	Error         error
}

// dhcpPacket represents a DHCP message structure.
type dhcpPacket struct {
	Op      byte      // Message op code: 1 = BOOTREQUEST, 2 = BOOTREPLY
	Htype   byte      // Hardware address type: 1 = Ethernet
	Hlen    byte      // Hardware address length: 6 for Ethernet
	Hops    byte      // Optionally used by relay agents
	Xid     uint32    // Transaction ID
	Secs    uint16    // Seconds elapsed since client began process
	Flags   uint16    // Flags (broadcast bit)
	Ciaddr  net.IP    // Client IP address (if known)
	Yiaddr  net.IP    // 'Your' (client) IP address
	Siaddr  net.IP    // Next server IP address
	Giaddr  net.IP    // Relay agent IP address
	Chaddr  [16]byte  // Client hardware address
	Sname   [64]byte  // Server host name
	File    [128]byte // Boot file name
	Options []byte    // Optional parameters field
}

// SendDHCPInform sends a DHCPINFORM packet and returns server configuration.
// DHCPINFORM is used when a client already has an IP address and only needs
// additional configuration parameters from the DHCP server.
//
// Note: This requires binding to UDP port 68 which may need elevated privileges
// on some systems. On Windows, it typically works without admin rights.
func (d *DHCPDiscovery) SendDHCPInform(ctx context.Context, clientIP string) (*DHCPInformResult, error) {
	result := &DHCPInformResult{}

	parsedIP := net.ParseIP(clientIP)
	if parsedIP == nil {
		result.Error = fmt.Errorf("invalid IP address: %s", clientIP)
		return result, result.Error
	}
	parsedIP = parsedIP.To4()
	if parsedIP == nil {
		result.Error = fmt.Errorf("IPv6 not supported for DHCP INFORM: %s", clientIP)
		return result, result.Error
	}

	// Get local interface for this IP
	localAddr, mac, err := d.getInterfaceForIP(clientIP)
	if err != nil {
		result.Error = fmt.Errorf("failed to find interface for IP %s: %w", clientIP, err)
		return result, result.Error
	}

	// Build DHCPINFORM packet
	packet := d.buildDHCPInform(parsedIP, mac)

	// Send the packet
	timeout := d.Timeout
	if timeout == 0 {
		timeout = dhcpTimeout
	}

	response, serverAddr, err := d.sendDHCPPacket(ctx, localAddr, packet, timeout)
	if err != nil {
		result.Error = err
		return result, err
	}

	result.ServerIP = serverAddr

	// Parse DHCP options from response
	d.parseDHCPOptions(response, result)

	return result, nil
}

// getInterfaceForIP finds the local interface and MAC address for a given IP.
func (d *DHCPDiscovery) getInterfaceForIP(targetIP string) (string, net.HardwareAddr, error) {
	target := net.ParseIP(targetIP)
	if target == nil {
		return "", nil, fmt.Errorf("invalid IP: %s", targetIP)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			if ipNet.IP.To4() == nil {
				continue // Skip IPv6
			}

			if ipNet.Contains(target) || ipNet.IP.Equal(target) {
				return ipNet.IP.String(), iface.HardwareAddr, nil
			}
		}
	}

	return "", nil, fmt.Errorf("no interface found for IP %s", targetIP)
}

// buildDHCPInform creates a DHCPINFORM packet.
func (d *DHCPDiscovery) buildDHCPInform(clientIP net.IP, mac net.HardwareAddr) []byte {
	packet := make([]byte, dhcpMaxMsgSize)

	// BOOTP header
	packet[0] = 1 // Op: BOOTREQUEST
	packet[1] = 1 // Htype: Ethernet
	packet[2] = 6 // Hlen: 6 bytes for Ethernet MAC
	packet[3] = 0 // Hops

	// Transaction ID (random)
	xid := rand.Uint32()
	binary.BigEndian.PutUint32(packet[4:8], xid)

	// Secs and Flags
	binary.BigEndian.PutUint16(packet[8:10], 0)  // Secs
	binary.BigEndian.PutUint16(packet[10:12], 0) // Flags (no broadcast needed for INFORM)

	// Client IP address (required for DHCPINFORM)
	copy(packet[12:16], clientIP.To4())

	// Yiaddr, Siaddr, Giaddr - all zeros
	// packet[16:28] already zero

	// Client hardware address
	if len(mac) >= 6 {
		copy(packet[28:34], mac)
	}

	// Sname and File - leave as zeros
	// packet[34:236] already zero

	// DHCP Magic Cookie
	binary.BigEndian.PutUint32(packet[236:240], dhcpMagicCookie)

	// DHCP Options start at byte 240
	optIdx := 240

	// Option 53: DHCP Message Type = DHCPINFORM (8)
	packet[optIdx] = optMessageType
	packet[optIdx+1] = 1
	packet[optIdx+2] = dhcpInform
	optIdx += 3

	// Option 55: Parameter Request List
	packet[optIdx] = optParamRequest
	packet[optIdx+1] = 7 // Length
	packet[optIdx+2] = optSubnetMask
	packet[optIdx+3] = optRouter
	packet[optIdx+4] = optDNS
	packet[optIdx+5] = optHostname
	packet[optIdx+6] = optDomainName
	packet[optIdx+7] = optBroadcast
	packet[optIdx+8] = optServerID
	optIdx += 9

	// Option 57: Maximum DHCP Message Size
	packet[optIdx] = optMaxMsgSize
	packet[optIdx+1] = 2
	binary.BigEndian.PutUint16(packet[optIdx+2:optIdx+4], dhcpMaxMsgSize)
	optIdx += 4

	// Option 61: Client Identifier (type + MAC)
	if len(mac) >= 6 {
		packet[optIdx] = optClientID
		packet[optIdx+1] = 7 // 1 (type) + 6 (MAC)
		packet[optIdx+2] = 1 // Ethernet type
		copy(packet[optIdx+3:optIdx+9], mac)
		optIdx += 9
	}

	// Option 255: End
	packet[optIdx] = optEnd
	optIdx++

	return packet[:optIdx]
}

// sendDHCPPacket sends a DHCP packet and waits for a response.
func (d *DHCPDiscovery) sendDHCPPacket(ctx context.Context, localIP string, packet []byte, timeout time.Duration) ([]byte, string, error) {
	// Try to bind to DHCP client port (68)
	// Note: This may require elevated privileges on some systems
	localAddr := &net.UDPAddr{
		IP:   net.ParseIP(localIP),
		Port: dhcpClientPort,
	}

	// First try binding to specific IP:68
	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		// If that fails, try binding to 0.0.0.0:68
		localAddr.IP = net.IPv4zero
		conn, err = net.ListenUDP("udp4", localAddr)
		if err != nil {
			// If still failing, try an ephemeral port (won't get broadcast responses)
			localAddr.Port = 0
			localAddr.IP = net.ParseIP(localIP)
			conn, err = net.ListenUDP("udp4", localAddr)
			if err != nil {
				return nil, "", fmt.Errorf("failed to create UDP socket: %w", err)
			}
		}
	}
	defer conn.Close()

	// Set deadline
	deadline := time.Now().Add(timeout)
	conn.SetDeadline(deadline)

	// Send to broadcast first
	broadcastAddr := &net.UDPAddr{
		IP:   net.IPv4bcast,
		Port: dhcpServerPort,
	}

	_, err = conn.WriteTo(packet, broadcastAddr)
	if err != nil {
		// Try limited broadcast on the local subnet
		// This is a fallback if global broadcast fails
		return nil, "", fmt.Errorf("failed to send DHCP packet: %w", err)
	}

	// Read response
	response := make([]byte, dhcpMaxMsgSize)
	xid := binary.BigEndian.Uint32(packet[4:8])

	for {
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		default:
		}

		n, remoteAddr, err := conn.ReadFromUDP(response)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return nil, "", fmt.Errorf("DHCP INFORM timeout - no server response")
			}
			return nil, "", fmt.Errorf("failed to read DHCP response: %w", err)
		}

		if n < 240 {
			continue // Too short to be valid DHCP
		}

		// Verify transaction ID
		respXid := binary.BigEndian.Uint32(response[4:8])
		if respXid != xid {
			continue // Not our response
		}

		// Verify magic cookie
		cookie := binary.BigEndian.Uint32(response[236:240])
		if cookie != dhcpMagicCookie {
			continue // Not a DHCP packet
		}

		return response[:n], remoteAddr.IP.String(), nil
	}
}

// parseDHCPOptions extracts relevant options from a DHCP response.
func (d *DHCPDiscovery) parseDHCPOptions(packet []byte, result *DHCPInformResult) {
	if len(packet) < 241 {
		return
	}

	// Options start at byte 240
	options := packet[240:]

	for i := 0; i < len(options); {
		opt := options[i]

		if opt == optPad {
			i++
			continue
		}

		if opt == optEnd {
			break
		}

		if i+1 >= len(options) {
			break
		}

		optLen := int(options[i+1])
		if i+2+optLen > len(options) {
			break
		}

		optData := options[i+2 : i+2+optLen]

		switch opt {
		case optSubnetMask:
			if len(optData) == 4 {
				result.SubnetMask = net.IP(optData).String()
			}

		case optRouter:
			for j := 0; j+3 < len(optData); j += 4 {
				result.Routers = append(result.Routers, net.IP(optData[j:j+4]).String())
			}
			if len(optData) >= 4 && len(result.Routers) == 0 {
				result.Routers = append(result.Routers, net.IP(optData[:4]).String())
			}

		case optDNS:
			for j := 0; j+3 < len(optData); j += 4 {
				result.DNSServers = append(result.DNSServers, net.IP(optData[j:j+4]).String())
			}
			if len(optData) >= 4 && len(result.DNSServers) == 0 {
				result.DNSServers = append(result.DNSServers, net.IP(optData[:4]).String())
			}

		case optHostname:
			result.Hostname = string(optData)

		case optDomainName:
			result.DomainName = string(optData)

		case optBroadcast:
			if len(optData) == 4 {
				result.BroadcastAddr = net.IP(optData).String()
			}

		case optServerID:
			if len(optData) == 4 {
				result.ServerIP = net.IP(optData).String()
			}
		}

		i += 2 + optLen
	}
}

// SendDHCPInformToServer sends a DHCPINFORM directly to a known DHCP server.
// This is more reliable than broadcast when you know the server address.
func (d *DHCPDiscovery) SendDHCPInformToServer(ctx context.Context, clientIP, serverIP string) (*DHCPInformResult, error) {
	result := &DHCPInformResult{}

	parsedClientIP := net.ParseIP(clientIP)
	if parsedClientIP == nil {
		result.Error = fmt.Errorf("invalid client IP: %s", clientIP)
		return result, result.Error
	}
	parsedClientIP = parsedClientIP.To4()

	parsedServerIP := net.ParseIP(serverIP)
	if parsedServerIP == nil {
		result.Error = fmt.Errorf("invalid server IP: %s", serverIP)
		return result, result.Error
	}

	// Get local interface for this IP
	localAddr, mac, err := d.getInterfaceForIP(clientIP)
	if err != nil {
		result.Error = fmt.Errorf("failed to find interface for IP %s: %w", clientIP, err)
		return result, result.Error
	}

	// Build DHCPINFORM packet
	packet := d.buildDHCPInform(parsedClientIP, mac)

	// Create UDP connection
	timeout := d.Timeout
	if timeout == 0 {
		timeout = dhcpTimeout
	}

	localUDPAddr := &net.UDPAddr{
		IP:   net.ParseIP(localAddr),
		Port: 0, // Let OS assign port for unicast
	}

	conn, err := net.ListenUDP("udp4", localUDPAddr)
	if err != nil {
		result.Error = fmt.Errorf("failed to create UDP socket: %w", err)
		return result, result.Error
	}
	defer conn.Close()

	// Set deadline
	deadline := time.Now().Add(timeout)
	conn.SetDeadline(deadline)

	// Send to specific server
	serverAddr := &net.UDPAddr{
		IP:   parsedServerIP,
		Port: dhcpServerPort,
	}

	_, err = conn.WriteTo(packet, serverAddr)
	if err != nil {
		result.Error = fmt.Errorf("failed to send DHCP packet: %w", err)
		return result, result.Error
	}

	// Read response
	response := make([]byte, dhcpMaxMsgSize)
	xid := binary.BigEndian.Uint32(packet[4:8])

	for {
		select {
		case <-ctx.Done():
			result.Error = ctx.Err()
			return result, ctx.Err()
		default:
		}

		n, _, err := conn.ReadFromUDP(response)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				result.Error = fmt.Errorf("DHCP INFORM timeout from server %s", serverIP)
				return result, result.Error
			}
			result.Error = fmt.Errorf("failed to read DHCP response: %w", err)
			return result, result.Error
		}

		if n < 240 {
			continue
		}

		// Verify transaction ID
		respXid := binary.BigEndian.Uint32(response[4:8])
		if respXid != xid {
			continue
		}

		// Verify magic cookie
		cookie := binary.BigEndian.Uint32(response[236:240])
		if cookie != dhcpMagicCookie {
			continue
		}

		result.ServerIP = serverIP
		d.parseDHCPOptions(response[:n], result)
		return result, nil
	}
}
