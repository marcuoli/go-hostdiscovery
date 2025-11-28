// Package dns provides reverse DNS (PTR) lookup utilities.
package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout is the default timeout for DNS lookups.
const DefaultTimeout = 2 * time.Second

// DefaultWorkers is the default number of concurrent workers.
const DefaultWorkers = 256

// DebugLogger is a callback for debug logging.
// Set this to receive debug messages from DNS operations.
var DebugLogger func(format string, args ...interface{})

func debugLog(format string, args ...interface{}) {
	if DebugLogger != nil {
		DebugLogger(format, args...)
	}
}

// Result contains the result of a reverse DNS lookup.
type Result struct {
	IP       string
	Hostname string   // Primary hostname (first result)
	All      []string // All returned hostnames
	Error    error
}

// Discovery performs reverse DNS lookups.
type Discovery struct {
	Timeout time.Duration
	Workers int
}

// NewDiscovery creates a new DNS discovery helper with defaults.
func NewDiscovery() *Discovery {
	return &Discovery{
		Timeout: DefaultTimeout,
		Workers: DefaultWorkers,
	}
}

// LookupAddr performs a reverse DNS (PTR) lookup for the given IP address.
func (d *Discovery) LookupAddr(ctx context.Context, ip string) (*Result, error) {
	res := &Result{IP: ip}

	// Use custom resolver with timeout
	resolver := &net.Resolver{}
	lookupCtx, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()

	names, err := resolver.LookupAddr(lookupCtx, ip)
	if err != nil {
		res.Error = err
		debugLog("%s: lookup failed: %v", ip, err)
		return res, err
	}

	// Clean up trailing dots from DNS names
	for i, name := range names {
		names[i] = strings.TrimSuffix(name, ".")
	}

	res.All = names
	if len(names) > 0 {
		res.Hostname = names[0]
		debugLog("%s -> %s", ip, res.Hostname)
	}
	return res, nil
}

// LookupMultiple performs reverse DNS lookups on multiple IPs concurrently.
func (d *Discovery) LookupMultiple(ctx context.Context, ips []string) []*Result {
	if len(ips) == 0 {
		return nil
	}

	workers := d.Workers
	if workers <= 0 {
		workers = DefaultWorkers
	}

	results := make([]*Result, len(ips))
	jobs := make(chan int, len(ips))
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for idx := range jobs {
			results[idx], _ = d.LookupAddr(ctx, ips[idx])
		}
	}

	for i := 0; i < workers && i < len(ips); i++ {
		wg.Add(1)
		go worker()
	}

	for i := range ips {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results
		}
	}
	close(jobs)
	wg.Wait()

	return results
}
