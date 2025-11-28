package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery"
)

func parsePorts(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("ports list is empty")
	}
	parts := strings.Split(s, ",")
	ports := make([]int, 0, len(parts))
	for _, p := range parts {
		var v int
		_, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &v)
		if err != nil || v <= 0 || v > 65535 {
			return nil, fmt.Errorf("invalid port: %q", p)
		}
		ports = append(ports, v)
	}
	return ports, nil
}

func main() {
	var (
		cidr     string
		portsStr string
		timeout  time.Duration
		workers  int
		verbose  bool
	)

	flag.StringVar(&cidr, "cidr", "", "CIDR to scan (e.g. 192.168.1.0/24)")
	flag.StringVar(&portsStr, "ports", "80,443,22,3389", "Comma-separated TCP ports to probe")
	flag.DurationVar(&timeout, "timeout", 800*time.Millisecond, "Per-port dial timeout")
	flag.IntVar(&workers, "workers", 256, "Number of concurrent workers")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.Parse()

	if cidr == "" {
		fmt.Fprintln(os.Stderr, "error: -cidr is required")
		flag.Usage()
		os.Exit(2)
	}

	if _, _, err := net.ParseCIDR(cidr); err != nil {
		fmt.Fprintf(os.Stderr, "invalid CIDR: %v\n", err)
		os.Exit(2)
	}

	ports, err := parsePorts(portsStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid ports: %v\n", err)
		os.Exit(2)
	}

	ctx := context.Background()
	opts := hostdiscovery.Options{Ports: ports, Timeout: timeout, Workers: workers, Verbose: verbose}
	ips, err := hostdiscovery.Discover(ctx, cidr, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		os.Exit(1)
	}

	sort.Slice(ips, func(i, j int) bool { return bytesCompareIP(ips[i], ips[j]) < 0 })
	for _, ip := range ips {
		fmt.Println(ip.String())
	}
}

// bytesCompareIP provides a stable ordering for net.IP values.
func bytesCompareIP(a, b net.IP) int {
	aa := a.To16()
	bb := b.To16()
	for i := 0; i < len(aa) && i < len(bb); i++ {
		if aa[i] < bb[i] {
			return -1
		}
		if aa[i] > bb[i] {
			return 1
		}
	}
	if len(aa) == len(bb) {
		return 0
	}
	if len(aa) < len(bb) {
		return -1
	}
	return 1
}
