// Package hostdiscovery: TCP connect-based host discovery.
package hostdiscovery

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// TCPOptions configures TCP-based host discovery behavior.
type TCPOptions struct {
	// Ports to probe on each host. At least one port is required.
	Ports []int
	// Timeout per TCP dial attempt.
	Timeout time.Duration
	// Workers controls the concurrency level.
	Workers int
}

// TCPDiscovery performs TCP connect-based host discovery.
type TCPDiscovery struct {
	Options TCPOptions
}

// NewTCPDiscovery creates a new TCP discovery helper with defaults.
func NewTCPDiscovery() *TCPDiscovery {
	return &TCPDiscovery{
		Options: TCPOptions{
			Ports:   []int{80, 443, 22, 3389},
			Timeout: 800 * time.Millisecond,
			Workers: DefaultWorkers,
		},
	}
}

// Discover performs a TCP connect-based host discovery over the given CIDR.
// A host is considered up if any of the provided ports accepts a TCP connection
// within the timeout. The scan stops early for a host once one port is reachable.
func (t *TCPDiscovery) Discover(ctx context.Context, cidr string) ([]net.IP, error) {
	ips, err := EnumerateIPs(cidr)
	if err != nil {
		return nil, fmt.Errorf("enumerate IPs: %w", err)
	}
	if len(ips) == 0 {
		return nil, nil
	}
	if len(t.Options.Ports) == 0 {
		return nil, fmt.Errorf("no ports provided")
	}

	workers := t.Options.Workers
	if workers <= 0 {
		workers = DefaultWorkers
	}
	timeout := t.Options.Timeout
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}

	jobs := make(chan net.IP, len(ips))
	results := make(chan net.IP, len(ips))
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for ip := range jobs {
			if t.probeHost(ctx, ip, timeout) {
				results <- ip
			}
		}
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}

enqueue:
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			break enqueue
		case jobs <- ip:
		}
	}
	close(jobs)
	wg.Wait()
	close(results)

	var up []net.IP
	for ip := range results {
		up = append(up, ip)
	}
	return up, nil
}

func (t *TCPDiscovery) probeHost(ctx context.Context, ip net.IP, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	for _, p := range t.Options.Ports {
		addr := fmt.Sprintf("%s:%d", ip.String(), p)
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// --- Legacy API for backward compatibility ---

// Options is an alias for TCPOptions for backward compatibility.
type Options = TCPOptions

// Discover is a convenience function that wraps TCPDiscovery for backward compatibility.
func Discover(ctx context.Context, cidr string, opts Options) ([]net.IP, error) {
	t := &TCPDiscovery{Options: opts}
	return t.Discover(ctx, cidr)
}
