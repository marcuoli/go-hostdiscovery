//go:build windows
// +build windows

// Package osdetect: TCP/IP fingerprinting using Windows raw sockets.
// This implementation uses Windows-specific APIs to capture TCP/IP characteristics.
package osdetect

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

const (
	// Windows socket constants
	IPPROTO_IP   = 0
	IPPROTO_TCP  = 6
	IP_HDRINCL   = 2
	SIO_RCVALL   = 0x98000001
)

var (
	ws2_32           = syscall.NewLazyDLL("ws2_32.dll")
	procWSAIoctl     = ws2_32.NewProc("WSAIoctl")
)

// RawTCPFPDiscovery performs fingerprinting using raw sockets (requires admin).
type RawTCPFPDiscovery struct {
	*TCPFPDiscovery
	useRaw bool
}

// NewRawTCPFPDiscovery creates a fingerprinting helper that attempts raw socket access.
func NewRawTCPFPDiscovery() *RawTCPFPDiscovery {
	return &RawTCPFPDiscovery{
		TCPFPDiscovery: NewTCPFPDiscovery(),
		useRaw:         false, // Will be set to true if raw sockets work
	}
}

// FingerprintWithRaw attempts fingerprinting with raw socket capture.
// Falls back to heuristic method if raw sockets are not available.
func (r *RawTCPFPDiscovery) FingerprintWithRaw(ctx context.Context, host string, port int) (*TCPFPResult, error) {
	result := &TCPFPResult{
		IP:   host,
		Port: port,
	}

	// Try raw socket approach first
	fp, err := r.captureHandshake(ctx, host, port)
	if err == nil && fp != nil {
		result.Fingerprint = fp
		r.matchSignatures(result)
		return result, nil
	}

	// Fall back to heuristic method
	if r.DebugLogger != nil {
		r.DebugLogger("Raw socket capture failed (%v), using heuristic method", err)
	}
	return r.Fingerprint(ctx, host, port)
}

// captureHandshake attempts to capture the TCP handshake using raw sockets.
func (r *RawTCPFPDiscovery) captureHandshake(ctx context.Context, host string, port int) (*TCPFingerprint, error) {
	// Resolve host
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("failed to resolve host: %w", err)
		}
		ip = ips[0]
	}

	// Create raw socket (requires administrator privileges)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket (need admin): %w", err)
	}
	defer syscall.Closesocket(fd)

	// Set socket options for capturing
	err = syscall.SetsockoptInt(fd, IPPROTO_IP, IP_HDRINCL, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to set IP_HDRINCL: %w", err)
	}

	// Bind to local interface
	localAddr := &syscall.SockaddrInet4{Port: 0}
	copy(localAddr.Addr[:], net.IPv4zero.To4())
	err = syscall.Bind(fd, localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind: %w", err)
	}

	// Enable promiscuous mode
	var bytesReturned uint32
	inBuf := uint32(1) // RCVALL_ON
	_, _, errno := syscall.SyscallN(procWSAIoctl.Addr(),
		uintptr(fd),
		SIO_RCVALL,
		uintptr(unsafe.Pointer(&inBuf)),
		4,
		0,
		0,
		uintptr(unsafe.Pointer(&bytesReturned)),
		0,
		0,
	)
	if errno != 0 {
		return nil, fmt.Errorf("WSAIoctl RCVALL failed: %v", errno)
	}

	// Start a goroutine to initiate the TCP connection
	targetAddr := &net.TCPAddr{IP: ip, Port: port}
	connChan := make(chan *net.TCPConn)
	errChan := make(chan error)

	go func() {
		dialer := &net.Dialer{Timeout: r.Timeout}
		conn, err := dialer.DialContext(ctx, "tcp", targetAddr.String())
		if err != nil {
			errChan <- err
			return
		}
		connChan <- conn.(*net.TCPConn)
	}()

	// Capture packets
	buf := make([]byte, 65535)
	fp := &TCPFingerprint{}

	// Set read deadline
	deadline := time.Now().Add(r.Timeout)

	for time.Now().Before(deadline) {
		// Check for connection completion or error
		select {
		case conn := <-connChan:
			conn.Close()
			// Connection complete, we should have captured the SYN-ACK
			if fp.TTL > 0 {
				fp.EstimatedTTL = estimateOriginalTTL(fp.TTL)
				return fp, nil
			}
		case err := <-errChan:
			return nil, err
		default:
		}

		// Try to read a packet
		setRawSocketTimeout(fd, deadline)
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			continue
		}

		if n < 40 { // Minimum IP + TCP header
			continue
		}

		// Parse IP header
		ipVersion := (buf[0] >> 4) & 0x0F
		if ipVersion != 4 {
			continue
		}

		ipHeaderLen := int((buf[0] & 0x0F) * 4)
		if n < ipHeaderLen+20 { // Need at least TCP header
			continue
		}

		// Check if this is from our target
		srcIP := net.IP(buf[12:16])
		if !srcIP.Equal(ip.To4()) {
			continue
		}

		// Check protocol (TCP = 6)
		if buf[9] != 6 {
			continue
		}

		// Extract IP header info
		fp.TTL = buf[8]
		fp.DF = (buf[6] & 0x40) != 0
		ipID := binary.BigEndian.Uint16(buf[4:6])
		fp.IPIDZero = ipID == 0

		// Parse TCP header
		tcpStart := ipHeaderLen
		srcPort := binary.BigEndian.Uint16(buf[tcpStart : tcpStart+2])
		if int(srcPort) != port {
			continue
		}

		tcpFlags := buf[tcpStart+13]
		// Looking for SYN-ACK (SYN + ACK flags)
		if (tcpFlags & (tcpSYN | tcpACK)) != (tcpSYN | tcpACK) {
			continue
		}

		fp.Flags = tcpFlags
		fp.WindowSize = binary.BigEndian.Uint16(buf[tcpStart+14 : tcpStart+16])

		// Parse TCP options
		tcpHeaderLen := int((buf[tcpStart+12] >> 4) * 4)
		if tcpHeaderLen > 20 {
			optionsStart := tcpStart + 20
			optionsEnd := tcpStart + tcpHeaderLen
			if optionsEnd <= n {
				fp.OptionsRaw = buf[optionsStart:optionsEnd]
				parseTCPOptions(fp, fp.OptionsRaw)
			}
		}

		fp.EstimatedTTL = estimateOriginalTTL(fp.TTL)
		return fp, nil
	}

	return nil, fmt.Errorf("timeout waiting for SYN-ACK")
}

// parseTCPOptions parses TCP options from raw bytes.
func parseTCPOptions(fp *TCPFingerprint, options []byte) {
	fp.OptLayout = make([]string, 0)
	i := 0

	for i < len(options) {
		kind := options[i]

		switch kind {
		case tcpOptEnd:
			fp.OptLayout = append(fp.OptLayout, "E")
			return
		case tcpOptNOP:
			fp.OptLayout = append(fp.OptLayout, "N")
			i++
		case tcpOptMSS:
			fp.OptLayout = append(fp.OptLayout, "M")
			if i+4 <= len(options) {
				fp.MSS = binary.BigEndian.Uint16(options[i+2 : i+4])
			}
			i += 4
		case tcpOptWScale:
			fp.OptLayout = append(fp.OptLayout, "W")
			if i+3 <= len(options) {
				fp.WScale = options[i+2]
			}
			i += 3
		case tcpOptSACKPerm:
			fp.OptLayout = append(fp.OptLayout, "S")
			fp.SACKPerm = true
			i += 2
		case tcpOptTimestamp:
			fp.OptLayout = append(fp.OptLayout, "T")
			fp.Timestamp = true
			if i+10 <= len(options) {
				fp.TSVal = binary.BigEndian.Uint32(options[i+2 : i+6])
				fp.TSecr = binary.BigEndian.Uint32(options[i+6 : i+10])
			}
			i += 10
		default:
			// Unknown option, skip by length
			if i+1 < len(options) {
				optLen := int(options[i+1])
				if optLen < 2 {
					return // Invalid length
				}
				i += optLen
			} else {
				return
			}
		}
	}
}

// SetDeadline is a helper for raw sockets (not directly available in syscall).
// This is a placeholder - in practice we use non-blocking sockets.
func setRawSocketTimeout(fd syscall.Handle, deadline time.Time) error {
	timeout := int(time.Until(deadline).Milliseconds())
	if timeout < 0 {
		timeout = 0
	}
	// SO_RCVTIMEO = 0x1006 on Windows
	const SO_RCVTIMEO = 0x1006
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, SO_RCVTIMEO, timeout)
}
