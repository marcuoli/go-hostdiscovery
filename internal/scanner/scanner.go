package scanner

import (
    "context"
    "fmt"
    "net"
    "sync"
    "time"
)

type Options struct {
    Ports   []int
    Timeout time.Duration
    Workers int
    Verbose bool
}

// Discover performs a simple TCP connect-based host discovery over the given CIDR.
// A host is considered up if any of the provided ports accepts a TCP connection
// within the timeout. This works without raw sockets or admin privileges.
func Discover(ctx context.Context, cidr string, opts Options) ([]net.IP, error) {
    _, ipnet, err := net.ParseCIDR(cidr)
    if err != nil {
        return nil, fmt.Errorf("parse CIDR: %w", err)
    }
    if len(opts.Ports) == 0 {
        return nil, fmt.Errorf("no ports provided")
    }
    if opts.Workers <= 0 {
        opts.Workers = 256
    }
    if opts.Timeout <= 0 {
        opts.Timeout = 800 * time.Millisecond
    }

    ips := enumerateIPs(ipnet)
    if len(ips) == 0 {
        return nil, nil
    }

    jobs := make(chan net.IP, len(ips))
    results := make(chan net.IP, len(ips))
    var wg sync.WaitGroup

    worker := func() {
        defer wg.Done()
        for ip := range jobs {
            if probeHost(ctx, ip, opts.Ports, opts.Timeout) {
                results <- ip
            }
        }
    }

    for i := 0; i < opts.Workers; i++ {
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

func enumerateIPs(n *net.IPNet) []net.IP {
    var res []net.IP
    // Only IPv4 ranges are supported for sweep simplicity.
    base := n.IP.To4()
    if base == nil {
        return res
    }
    mask := net.IP(n.Mask).To4()
    if mask == nil {
        return res
    }
    network := ipToUint32(base) & ipToUint32(mask)
    broadcast := network | ^ipToUint32(mask)

    // Skip network and broadcast addresses
    for u := network + 1; u < broadcast; u++ {
        res = append(res, uint32ToIP(u))
    }
    return res
}

func probeHost(ctx context.Context, ip net.IP, ports []int, timeout time.Duration) bool {
    d := net.Dialer{Timeout: timeout}
    for _, p := range ports {
        addr := fmt.Sprintf("%s:%d", ip.String(), p)
        conn, err := d.DialContext(ctx, "tcp", addr)
        if err == nil {
            conn.Close()
            return true
        }
    }
    return false
}

func ipToUint32(ip net.IP) uint32 {
    ip = ip.To4()
    return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(u uint32) net.IP {
    return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}
