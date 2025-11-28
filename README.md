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