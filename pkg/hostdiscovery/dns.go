// Package hostdiscovery: Reverse DNS (PTR) lookup utilities.
package hostdiscovery

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// DNSResult contains the result of a reverse DNS lookup.
type DNSResult struct {
	IP       string
	Hostname string   // Primary hostname (first result)
	All      []string // All returned hostnames
	Error    error
}

// DNSDiscovery performs reverse DNS lookups.
type DNSDiscovery struct {
	Timeout time.Duration
	Workers int
}

// NewDNSDiscovery creates a new DNS discovery helper with defaults.
func NewDNSDiscovery() *DNSDiscovery {
	return &DNSDiscovery{
		Timeout: DefaultTimeout,
		Workers: DefaultWorkers,
	}
}

// LookupAddr performs a reverse DNS (PTR) lookup for the given IP address.
func (d *DNSDiscovery) LookupAddr(ctx context.Context, ip string) (*DNSResult, error) {
	res := &DNSResult{IP: ip}

	// Use custom resolver with timeout
	resolver := &net.Resolver{}
	lookupCtx, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()

	names, err := resolver.LookupAddr(lookupCtx, ip)
	if err != nil {
		res.Error = err
		return res, err
	}

	// Clean up trailing dots from DNS names
	for i, name := range names {
		names[i] = strings.TrimSuffix(name, ".")
	}

	res.All = names
	if len(names) > 0 {
		res.Hostname = names[0]
	}
	return res, nil
}

// LookupMultiple performs reverse DNS lookups on multiple IPs concurrently.
func (d *DNSDiscovery) LookupMultiple(ctx context.Context, ips []string) []*DNSResult {
	if len(ips) == 0 {
		return nil
	}

	workers := d.Workers
	if workers <= 0 {
		workers = DefaultWorkers
	}

	results := make([]*DNSResult, len(ips))
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
