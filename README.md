# go-hostdiscovery

[![Go Reference](https://pkg.go.dev/badge/github.com/marcuoli/go-hostdiscovery.svg)](https://pkg.go.dev/github.com/marcuoli/go-hostdiscovery)
[![Go Report Card](https://goreportcard.com/badge/github.com/marcuoli/go-hostdiscovery)](https://goreportcard.com/report/github.com/marcuoli/go-hostdiscovery)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/github/v/release/marcuoli/go-hostdiscovery)](https://github.com/marcuoli/go-hostdiscovery/releases)

A comprehensive, multi-protocol host and hostname discovery library for Go. Discover live hosts and resolve their hostnames using various protocols - all without admin privileges or raw sockets.

**Version:** 1.0.0

## Features

| Protocol | Port | Best For | Platforms |
|----------|------|----------|-----------|
| **TCP Connect** | Various | Host discovery | All |
| **Reverse DNS** | 53 | Standard hostname lookup | All |
| **NetBIOS** | UDP/137 | Windows hostnames | 🔵 Windows |
| **mDNS** | UDP/5353 | Apple/Linux/IoT devices | 🍎 macOS, 🟢 Linux, 🟠 Android, 🔶 IoT |
| **LLMNR** | UDP/5355 | Windows/Linux local names | 🔵 Windows, 🟢 Linux |
| **SSDP/UPnP** | UDP/1900 | Smart devices, media players | 🔶 IoT, 📺 TVs, 🎮 Consoles |

### Platform Discovery Matrix

| Platform | Recommended Protocols |
|----------|----------------------|
| 🔵 **Windows** | NetBIOS, LLMNR, mDNS, DNS |
| 🟢 **Linux** | mDNS (Avahi), LLMNR (systemd-resolved), DNS |
| 🍎 **macOS** | mDNS (Bonjour), DNS |
| 🟠 **Android** | mDNS, SSDP, LLMNR |
| 🔶 **IoT Devices** | mDNS, SSDP/UPnP |

## Installation

```bash
go get github.com/marcuoli/go-hostdiscovery
```

## Quick Start

### Multi-Protocol Discovery (Recommended)

Discover hosts and resolve hostnames using all available protocols:

```go
package main

import (
    "context"
    "fmt"
    "time"

    hd "github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // Create multi-protocol discovery with all methods enabled
    discovery := hd.NewMultiDiscovery()
    
    // Discover all hosts in CIDR and resolve their hostnames
    results, err := discovery.DiscoverCIDR(ctx, "192.168.1.0/24")
    if err != nil {
        panic(err)
    }

    for _, host := range results {
        hostname := host.PrimaryHostname()
        if hostname == "" {
            hostname = "(unknown)"
        }
        fmt.Printf("%-15s  %s\n", host.IP, hostname)
        
        // Show all discovered hostnames by protocol
        for method, name := range host.Hostnames {
            fmt.Printf("    [%s] %s\n", method, name)
        }
    }

    // Also discover SSDP devices (smart TVs, IoT, etc.)
    ssdpDevices, _ := discovery.DiscoverSSDP(ctx)
    for _, dev := range ssdpDevices {
        fmt.Printf("SSDP: %s - %s (%s)\n", dev.IP, dev.Server, dev.ST)
    }
}
```

## Individual Protocol Usage

### TCP Host Discovery

Find live hosts by TCP connect scanning:

```go
tcp := hd.NewTCPDiscovery()
tcp.Options.Ports = []int{80, 443, 22, 3389, 445}
tcp.Options.Timeout = 800 * time.Millisecond
tcp.Options.Workers = 256

ips, err := tcp.Discover(ctx, "192.168.1.0/24")
for _, ip := range ips {
    fmt.Println(ip.String())
}
```

### Reverse DNS Lookup

Standard PTR record lookups:

```go
dns := hd.NewDNSDiscovery()
result, err := dns.LookupAddr(ctx, "8.8.8.8")
fmt.Println("Hostname:", result.Hostname) // dns.google

// Batch lookup
results := dns.LookupMultiple(ctx, []string{"8.8.8.8", "1.1.1.1"})
```

### NetBIOS Discovery (Windows)

Resolve Windows hostnames via NBSTAT:

```go
nb := hd.NewNetBIOSDiscovery()
result, err := nb.LookupAddr(ctx, "192.168.1.50")
fmt.Println("Hostname:", result.Hostname)
fmt.Println("MAC:", result.MACAddress)

for _, name := range result.Names {
    fmt.Printf("  %-15s <%.2X> %s\n", name.Name, name.Suffix, name.Type)
}
```

### mDNS Discovery (Apple/Linux/IoT)

Discover devices using Multicast DNS (Bonjour/Avahi):

```go
mdns := hd.NewMDNSDiscovery()

// Lookup specific IP
result, _ := mdns.LookupAddr(ctx, "192.168.1.100")
fmt.Println("Hostname:", result.Hostname) // e.g., "macbook.local"

// Browse for services
services, _ := mdns.BrowseServices(ctx, "_http._tcp")
for _, svc := range services {
    fmt.Printf("Service: %s\n", svc.Instance)
}
```

Common mDNS service types:
- `_http._tcp` - Web servers
- `_ssh._tcp` - SSH servers
- `_printer._tcp` - Printers
- `_airplay._tcp` - AirPlay devices
- `_googlecast._tcp` - Chromecast
- `_smb._tcp` - SMB/Windows shares
- `_homekit._tcp` - HomeKit devices

### LLMNR Discovery (Windows/Linux)

Link-Local Multicast Name Resolution:

```go
llmnr := hd.NewLLMNRDiscovery()

// Reverse lookup
result, _ := llmnr.LookupAddr(ctx, "192.168.1.50")
fmt.Println("Hostname:", result.Hostname)

// Forward lookup (resolve name to IP)
ips, _ := llmnr.LookupName(ctx, "DESKTOP-ABC123")
for _, ip := range ips {
    fmt.Println("IP:", ip)
}
```

### SSDP/UPnP Discovery (IoT/Media)

Discover smart devices, media players, and IoT:

```go
ssdp := hd.NewSSDPDiscovery()

// Discover all devices
devices, _ := ssdp.Discover(ctx, "ssdp:all")
for _, dev := range devices {
    fmt.Printf("%s - %s\n", dev.IP, dev.Server)
    fmt.Printf("  Location: %s\n", dev.Location)
    fmt.Printf("  Type: %s\n", dev.ST)
}

// Get friendly name from device description
if dev.Location != "" {
    name, _ := ssdp.GetDeviceInfo(ctx, dev.Location)
    fmt.Println("Friendly Name:", name)
}
```

SSDP search targets:
- `ssdp:all` - All devices
- `upnp:rootdevice` - Root devices only
- `urn:schemas-upnp-org:device:MediaRenderer:1` - Media renderers
- `urn:dial-multiscreen-org:service:dial:1` - DIAL/Chromecast

## CLI Usage

```bash
# Build
go build -o bin/hostdiscovery ./cmd/hostdiscovery

# Basic TCP scan
./hostdiscovery -cidr 192.168.1.0/24

# Custom ports and timeout
./hostdiscovery -cidr 10.0.0.0/24 -ports 80,443,22,445 -timeout 1s -workers 512
```

Flags:
- `-cidr`: CIDR to scan (required)
- `-ports`: Comma-separated TCP ports (default: `80,443,22,3389`)
- `-timeout`: Per-connection timeout (default: `800ms`)
- `-workers`: Concurrent workers (default: `256`)

## Package Structure

```
pkg/hostdiscovery/
├── version.go        # Version information
├── types.go          # Common types and constants
├── ip.go             # IP enumeration utilities
├── hostdiscovery.go  # TCP connect discovery
├── dns.go            # Reverse DNS (PTR) lookups
├── netbios.go        # NetBIOS NBSTAT lookups
├── mdns.go           # mDNS/Bonjour discovery
├── llmnr.go          # LLMNR discovery
├── ssdp.go           # SSDP/UPnP discovery
├── dhcp.go           # DHCP INFORM discovery
├── finger.go         # Finger protocol (RFC 1288)
└── multi.go          # Unified multi-protocol discovery
```

## Notes

- **No privileges required**: All protocols work without admin/root access
- **Cross-platform**: Works on Windows, macOS, and Linux
- **Network considerations**: Large CIDRs produce significant traffic
- **Firewall awareness**: Some protocols may be blocked by firewalls
- **Legal**: Only scan networks you own or have permission to scan

## License

MIT
