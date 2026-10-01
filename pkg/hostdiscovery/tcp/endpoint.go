// Package tcp describes the outcome of a TCP connection attempt. It performs no
// host scan, ICMP probe, application handshake, logging, or additional retry.
package tcp

import (
	"context"
	"errors"
	"net"
	"time"
)

// Status describes observed transport evidence, not whether a host is powered on.
type Status string

const (
	Connected        Status = "connected"
	Refused          Status = "refused"
	TimedOut         Status = "timed_out"
	ResolutionFailed Status = "resolution_failed"
	Unreachable      Status = "unreachable"
	Cancelled        Status = "cancelled"
	Failed           Status = "failed"
)

// Result describes one DialContext call, including DNS and any address attempts
// made by net.Dialer. Elapsed is observed time, never a configured timeout.
type Result struct {
	Network       string
	Address       string
	LocalAddress  string
	RemoteAddress string
	Elapsed       time.Duration
	Status        Status
}

// DialContext uses the supplied dialer's settings and context unchanged. A nil
// dialer uses net.Dialer's defaults. Only tcp, tcp4 and tcp6 are accepted.
//
// Success returns the original, open socket for the caller to use and close;
// failure returns the original error so errors.Is/As and net.Error still work.
// No wrapper is placed around the socket, preserving *net.TCPConn capabilities.
func DialContext(ctx context.Context, dialer *net.Dialer, network, address string) (net.Conn, Result, error) {
	started := time.Now()
	result := Result{Network: network, Address: address}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		result.Status, result.Elapsed = Failed, time.Since(started)
		return nil, result, net.UnknownNetworkError(network)
	}
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	conn, err := dialer.DialContext(ctx, network, address)
	result.Elapsed, result.Status = time.Since(started), Classify(err)
	if conn != nil {
		result.LocalAddress, result.RemoteAddress = conn.LocalAddr().String(), conn.RemoteAddr().String()
	}
	return conn, result, err
}

// Classify uses typed errors only. An unrecognized failure stays Failed rather
// than guessing from localized operating-system messages. A DNS timeout remains
// a resolution failure because it does not establish that TCP reached a host.
func Classify(err error) Status {
	if err == nil {
		return Connected
	}
	if errors.Is(err, context.Canceled) {
		return Cancelled
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return ResolutionFailed
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return TimedOut
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return TimedOut
	}
	return socketStatus(err)
}
