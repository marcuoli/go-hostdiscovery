# go-hostdiscovery

A simple, fast host discovery tool written in Go. It performs a TCP connect sweep over a CIDR and reports IPs that accept a connection on any of the specified ports. This works without admin privileges or raw sockets, making it suitable for Windows, macOS, and Linux.

## Usage

Build the binary and run:

```bash
# Build
go build -o bin/hostdiscovery ./cmd/hostdiscovery

# Scan common ports on a /24 range
./bin/hostdiscovery -cidr 192.168.1.0/24

# Customize ports, timeout and workers
./bin/hostdiscovery -cidr 10.0.0.0/24 -ports 80,443,22 -timeout 1s -workers 512
```

## Library usage

Import the package and call `Discover`:

```go
package main

import (
	"context"
	"fmt"
	"time"

	hd "github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery"
)

func main() {
	opts := hd.Options{Ports: []int{80, 443, 22}, Timeout: 800 * time.Millisecond, Workers: 256}
	ips, err := hd.Discover(context.Background(), "192.168.1.0/24", opts)
	if err != nil {
		panic(err)
	}
	for _, ip := range ips {
		fmt.Println(ip.String())
	}
}
```

Get the module:

```bash
go get github.com/marcuoli/go-hostdiscovery
```

### NetBIOS hostname discovery

Use the NetBIOS discovery helper to resolve hostnames via NBSTAT (UDP/137):

```go
package main

import (
	"context"
	"fmt"
	hd "github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery"
)

func main() {
	nb := hd.NewNetBIOSDiscovery()
	res, err := nb.LookupAddr(context.Background(), "192.168.1.50")
	if err != nil { panic(err) }
	fmt.Println("Hostname:", res.Hostname)
	fmt.Println("MAC:", res.MACAddress)
	for _, n := range res.Names {
		fmt.Printf("%-15s <%.2X> group=%v active=%v (%s)\n", n.Name, n.Suffix, n.IsGroup, n.IsActive, n.Type)
	}
}
```

Notes:
- Requires UDP reachability to port 137 on the target.
- Works best on Windows networks with NetBIOS enabled.
- Timeout defaults to 2s; adjust via `NetBIOSDiscovery{Timeout: ...}` if needed.

Flags:
- `-cidr`: CIDR to scan (required), e.g., `192.168.1.0/24`.
- `-ports`: Comma-separated TCP ports to probe. Default: `80,443,22,3389`.
- `-timeout`: Per-port dial timeout. Default: `800ms`.
- `-workers`: Concurrent workers. Default: `256`.
- `-v`: Verbose output (reserved for future use).

## Notes
- This is a host discovery sweep (not a full port scan). A host is considered up if any listed port accepts a TCP connection within the timeout.
- ICMP/ARP discovery would require elevated privileges on many systems. TCP connect works unprivileged.
- Large CIDRs can produce significant traffic. Use responsibly and only on networks you own or have permission to scan.

## Development

```bash
# Lint and test (if you add tests)
go vet ./...
go test ./...
```