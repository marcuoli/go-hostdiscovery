# go-hostdiscovery

[![Go Reference](https://pkg.go.dev/badge/github.com/marcuoli/go-hostdiscovery.svg)](https://pkg.go.dev/github.com/marcuoli/go-hostdiscovery)
[![Go Report Card](https://goreportcard.com/badge/github.com/marcuoli/go-hostdiscovery)](https://goreportcard.com/report/github.com/marcuoli/go-hostdiscovery)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/github/v/release/marcuoli/go-hostdiscovery)](https://github.com/marcuoli/go-hostdiscovery/releases)
[![Tests](https://github.com/marcuoli/go-hostdiscovery/actions/workflows/test.yml/badge.svg)](https://github.com/marcuoli/go-hostdiscovery/actions/workflows/test.yml)

A comprehensive, multi-protocol host discovery and operating system detection library for Go. Discover live hosts, resolve hostnames, detect operating systems, and identify devices across your network using 9+ protocols—all without requiring administrative privileges or raw sockets.

**Version:** 1.3.1 | **Go:** 1.25.4+

## 🎯 Why go-hostdiscovery?

- **Multi-protocol support** - Use multiple discovery methods simultaneously for maximum coverage
- **No root/admin required** - Pure Go implementation using standard network APIs
- **Cross-platform** - Windows, macOS, Linux, and other POSIX systems
- **OS fingerprinting** - Passive TCP/IP stack analysis to detect operating systems
- **Comprehensive testing** - 100+ unit tests covering all discovery protocols
- **Production-ready** - Used in network inventory, monitoring, and security tools

## 📋 Features Overview

| Feature | Protocols | Use Cases |
|---------|-----------|-----------|
| **Host Discovery** | TCP, UDP, ARP | Find live hosts on network |
| **Hostname Resolution** | DNS (PTR), NetBIOS, mDNS, LLMNR, Finger | Identify devices by name |
| **Device Detection** | SSDP/UPnP, mDNS | Find smart TVs, IoT, media servers |
| **OS Fingerprinting** | TCP/IP stack analysis | Detect Windows, Linux, macOS, network gear |
| **MAC Vendor Lookup** | OUI database | Identify device manufacturers |

## 🔌 Supported Protocols

| Protocol | Port | Type | Best For | Platforms |
|----------|------|------|----------|-----------|
| **TCP Connect** | Various | TCP | Live host discovery | All |
| **DNS (PTR)** | UDP/53 | UDP | Standard hostname lookup | All |
| **NetBIOS** | UDP/137 | UDP | Windows hostnames | 🔵 Windows |
| **mDNS** | UDP/5353 | UDP | Apple/Linux/IoT | 🍎 macOS, 🟢 Linux, 🟠 Android |
| **LLMNR** | UDP/5355 | UDP | Local network names | 🔵 Windows, 🟢 Linux |
| **SSDP/UPnP** | UDP/1900 | UDP | Smart devices, media | 🔶 IoT, 📺 TVs, 🎮 Consoles |
| **DHCP** | UDP/67,68 | UDP | Dynamic host info | All |
| **Finger** | TCP/79 | TCP | User info (deprecated) | 🟢 Linux, Unix |
| **ARP** | Layer 2 | Layer 2 | MAC address discovery | Local network |
| **TCP/IP FP** | Various | TCP | OS detection | All |

### Platform Discovery Matrix

| Platform | Recommended Protocols |
|----------|----------------------|
| 🔵 **Windows** | NetBIOS, LLMNR, mDNS, DNS, TCP/IP FP |
| 🟢 **Linux** | mDNS (Avahi), LLMNR (systemd-resolved), DNS, TCP/IP FP |
| 🍎 **macOS** | mDNS (Bonjour), DNS, TCP/IP FP |
| 🟠 **Android** | mDNS, SSDP, LLMNR, TCP/IP FP |
| 🔶 **IoT Devices** | mDNS, SSDP/UPnP, TCP/IP FP |
| 📺 **Smart TVs** | SSDP/UPnP, mDNS, TCP/IP FP |
| 🎮 **Game Consoles** | SSDP/UPnP, LLMNR, TCP/IP FP |

## 🏗️ Architecture

### Discovery Methods

**Multi-Discovery** (Recommended)
: Unified interface for all discovery methods, combining results from multiple protocols for maximum accuracy.

**Single-Protocol**
: Individual discovery types for focused use cases (DNS-only, NetBIOS-only, etc.).

### Data Flow

```
User Query (IP or CIDR)
    ↓
Multi-Discovery Orchestrator
    ├─→ TCP Connect Discovery
    ├─→ Reverse DNS (PTR)
    ├─→ NetBIOS (NBSTAT)
    ├─→ mDNS/Bonjour
    ├─→ LLMNR
    ├─→ DHCP INFORM
    ├─→ Finger Protocol
    ├─→ TCP/IP Fingerprinting (OS Detection)
    ├─→ ARP Resolution
    └─→ OUI Vendor Lookup
         ↓
    Aggregated Results
    (hostnames, MAC, OS, vendor)
```

## 📦 Installation

```bash
go get github.com/marcuoli/go-hostdiscovery
```

Minimum Go version: **1.25.4**

## 🚀 Quick Start

### Multi-Protocol Discovery (Recommended)

Discover all hosts in a network with full details:

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

    // Create multi-discovery with all protocols enabled
    discovery := hd.NewMultiDiscovery()
    
    // Enable OS fingerprinting (optional, adds latency)
    discovery.Options.EnableTCPFP = true
    
    // Discover hosts and resolve hostnames
    results, err := discovery.DiscoverCIDR(ctx, "192.168.1.0/24")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        return
    }

    // Process results
    for _, host := range results {
        fmt.Printf("IP: %-15s MAC: %s\n", host.IP, host.MAC)
        
        // Primary hostname (best available)
        if hostname := host.PrimaryHostname(); hostname != "" {
            fmt.Printf("  Hostname: %s\n", hostname)
        }
        
        // OS detection
        if host.OS != "" {
            fmt.Printf("  OS: %s %s (confidence: %d%%)\n",
                host.OS, host.OSVersion, int(host.OSConfidence*100))
        }
        
        // Vendor/manufacturer
        if host.Vendor != "" {
            fmt.Printf("  Vendor: %s\n", host.Vendor)
        }
        
        // All discovered hostnames by protocol
        for protocol, hostname := range host.Hostnames {
            fmt.Printf("  [%s] %s\n", protocol, hostname)
        }
        fmt.Println()
    }
}
```

### Discover SSDP Devices (Smart TVs, IoT, Media)

```go
discovery := hd.NewMultiDiscovery()
devices, err := discovery.DiscoverSSDP(ctx)
for _, dev := range devices {
    fmt.Printf("Device: %s\n", dev.IP)
    fmt.Printf("  Server: %s\n", dev.Server)
    fmt.Printf("  Type: %s\n", dev.ST)
    
    // Get friendly name from XML
    if dev.Location != "" {
        name, _ := hd.NewSSDPDiscovery().GetDeviceInfo(ctx, dev.Location)
        fmt.Printf("  Friendly Name: %s\n", name)
    }
}
```

## 🔍 Individual Protocol Usage

### TCP Host Discovery

Find live hosts via TCP connection scanning:

```go
tcp := hd.NewTCPDiscovery()
tcp.Options.Ports = []int{80, 443, 22, 3389, 445}
tcp.Options.Timeout = 800 * time.Millisecond
tcp.Options.Workers = 256

ips, err := tcp.Discover(ctx, "192.168.1.0/24")
if err != nil {
    panic(err)
}

for _, ip := range ips {
    fmt.Println("Host:", ip.String())
}
```

### DNS (Reverse PTR Lookup)

Standard DNS hostname resolution:

```go
dns := hd.NewDNSDiscovery()

// Single lookup
result, err := dns.LookupAddr(ctx, "8.8.8.8")
if err == nil {
    fmt.Println("Hostname:", result.Hostname) // dns.google
}

// Batch lookup
results := dns.LookupMultiple(ctx, []string{"8.8.8.8", "1.1.1.1"})
for _, res := range results {
    fmt.Printf("%s → %s\n", res.IP, res.Hostname)
}
```

### NetBIOS Discovery (Windows Hostnames)

Resolve Windows hostnames via NBSTAT:

```go
nb := hd.NewNetBIOSDiscovery()
nb.Timeout = 5 * time.Second

result, err := nb.LookupAddr(ctx, "192.168.1.50")
if err != nil {
    fmt.Println("Error:", err)
    return
}

fmt.Printf("Hostname: %s\n", result.Hostname)
fmt.Printf("MAC Address: %s\n", result.MACAddress)

// All NetBIOS names with suffixes and types
for _, name := range result.Names {
    fmt.Printf("  Name: %-15s Suffix: <%.2X> Type: %s\n",
        name.Name, name.Suffix, name.Type)
}
```

NetBIOS name types:
- `WORKSTATION` - Computer name (primary)
- `MESSENGER` - Messenger service
- `FILE_SERVER` - File sharing service
- `RAS_CLIENT` - Remote access client
- `DOMAIN_CONTROLLER` - Active Directory domain controller

### mDNS Discovery (Bonjour/Avahi)

Discover Apple, Linux, and IoT devices using Multicast DNS:

```go
mdns := hd.NewMDNSDiscovery()

// Reverse lookup (IP → hostname)
result, _ := mdns.LookupAddr(ctx, "192.168.1.100")
if result != nil {
    fmt.Println("Hostname:", result.Hostname) // e.g., "macbook.local"
}

// Browse for specific services
services, _ := mdns.BrowseServices(ctx, "_http._tcp")
for _, svc := range services {
    fmt.Printf("Service: %s\n", svc.Instance)
}
```

Common mDNS service types:
| Service | Type | Usage |
|---------|------|-------|
| Web Servers | `_http._tcp` | HTTP websites |
| SSH Servers | `_ssh._tcp` | Remote shell |
| Printers | `_printer._tcp`, `_ipp._tcp` | Network printers |
| AirPlay | `_airplay._tcp` | AirPlay receivers |
| Chromecast | `_googlecast._tcp` | Google Cast devices |
| SMB/Windows | `_smb._tcp` | Windows file sharing |
| HomeKit | `_homekit._tcp` | Apple HomeKit devices |
| AppleTV | `_afpovertcp._tcp` | Apple File Protocol |

### LLMNR Discovery (Windows/Linux)

Link-Local Multicast Name Resolution for local networks:

```go
llmnr := hd.NewLLMNRDiscovery()
llmnr.Timeout = 5 * time.Second

// Reverse lookup (IP → hostname)
result, _ := llmnr.LookupAddr(ctx, "192.168.1.50")
if result != nil {
    fmt.Println("Hostname:", result.Hostname)
}

// Forward lookup (hostname → IPs)
ips, _ := llmnr.LookupName(ctx, "DESKTOP-ABC123")
for _, ip := range ips {
    fmt.Println("IP:", ip)
}
```

### TCP/IP Fingerprinting (OS Detection)

Passive OS detection via TCP stack analysis:

```go
fp := hd.NewTCPFPDiscovery()
fp.Timeout = 3 * time.Second

// Fingerprint specific port
result, err := fp.Fingerprint(ctx, "192.168.1.100", 80)
if err == nil {
    fmt.Printf("OS Guess: %s\n", result.OSGuess)
    fmt.Printf("OS Family: %s\n", result.OSFamily)
    fmt.Printf("Device Type: %s\n", result.DeviceType)
    fmt.Printf("Confidence: %d%%\n", result.Confidence)
}

// Try multiple ports for best result
result, err = fp.FingerprintBest(ctx, "192.168.1.100")
if err == nil {
    fmt.Printf("Best OS match: %s\n", result.OSGuess)
}
```

Analyzed TCP characteristics:
- **TTL** - Default values vary by OS (Linux=64, Windows=128, Cisco=255)
- **TCP Window Size** - Initial window size reveals stack behavior
- **MSS** - Maximum Segment Size often correlates with OS
- **Window Scale** - TCP window scaling support and values
- **SACK** - Selective ACK support
- **Timestamps** - TCP timestamp option presence
- **DF Bit** - Don't Fragment flag behavior

Detectable OS families:
- Windows (XP, Vista, 7, 8, 10, 11)
- Linux (various kernel versions)
- macOS / iOS / BSD
- Network equipment (Cisco, Juniper, etc.)

### SSDP/UPnP Discovery (Smart Devices)

Discover SSDP devices (Smart TVs, media servers, routers, game consoles):

```go
ssdp := hd.NewSSDPDiscovery()
ssdp.Timeout = 5 * time.Second

// Discover all devices
devices, _ := ssdp.Discover(ctx, "ssdp:all")
for _, dev := range devices {
    fmt.Printf("IP: %s\n", dev.IP)
    fmt.Printf("  Server: %s\n", dev.Server)
    fmt.Printf("  USN: %s\n", dev.USN)
    fmt.Printf("  Location: %s\n", dev.Location)
    fmt.Printf("  Device Type: %s\n", dev.ST)
}

// Discover specific device types
devices, _ := ssdp.Discover(ctx, "upnp:rootdevice")
devices, _ := ssdp.Discover(ctx, "urn:schemas-upnp-org:device:MediaRenderer:1")
devices, _ := ssdp.Discover(ctx, "urn:dial-multiscreen-org:service:dial:1")
```

SSDP search targets:
- `ssdp:all` - All devices
- `upnp:rootdevice` - Root devices only
- `urn:schemas-upnp-org:device:MediaRenderer:1` - Media players/Smart TVs
- `urn:schemas-upnp-org:device:MediaServer:1` - NAS/DLNA servers
- `urn:dial-multiscreen-org:service:dial:1` - DIAL/Chromecast devices
- `urn:schemas-upnp-org:device:InternetGatewayDevice:1` - Routers/gateways
- `urn:schemas-upnp-org:service:PrintBasic:1` - Network printers

### DHCP Discovery

Query DHCP servers for configuration and host information:

```go
dhcp := hd.NewDHCPDiscovery()
dhcp.Timeout = 3 * time.Second

// Send DHCP INFORM to get local server configuration
result, err := dhcp.SendInform(ctx, "192.168.1.10")
if err == nil {
    fmt.Println("DHCP Server:", result.ServerID)
    fmt.Println("Offered IP:", result.OfferedIP)
    if result.Options != nil {
        fmt.Println("Options:", result.Options)
    }
}
```

### Finger Protocol (Legacy)

Lookup user information on systems with Finger enabled (rare):

```go
finger := hd.NewFingerDiscovery()
finger.Timeout = 2 * time.Second

// List all users
result, err := finger.LookupAddr(ctx, "192.168.1.50")
if err == nil {
    fmt.Println("Users:", result.Users)
}

// Check if service is available
available, _ := finger.IsAvailable(ctx, "192.168.1.50")
fmt.Println("Finger available:", available)
```

### ARP Discovery

MAC address discovery on local network:

```go
arp := hd.NewARPDiscovery()
arp.Timeout = 2 * time.Second

result, err := arp.Lookup(ctx, "192.168.1.50")
if err == nil {
    fmt.Println("MAC Address:", result.MAC)
}
```

### OUI/MAC Vendor Lookup

Identify device manufacturer from MAC address:

```go
oui := hd.NewOUIDiscovery()

// Lookup vendor by MAC
vendor, _ := oui.Lookup("1C:FD:08")
fmt.Println("Vendor:", vendor.Company) // "Dell Inc."

// Or by MAC string
name, _ := oui.LookupName("1C-FD-08-78-77-4B")
fmt.Println("Vendor Name:", name)
```

Common vendor prefixes:
| MAC Prefix | Vendor |
|-----------|--------|
| `00:03:93` | Apple Inc. |
| `00:0C:29` | VMware |
| `00:15:5D` | Microsoft Hyper-V |
| `08:00:27` | Oracle VirtualBox |
| `52:54:00` | QEMU/KVM |
| `B8:27:EB` | Raspberry Pi Foundation |
| `DC:A6:32` | Raspberry Pi Foundation |

## 🛠️ Advanced Usage

### Debug Logging

Enable debug output for all protocols:

```go
// Set global debug logger
hd.DebugLogger = func(format string, args ...interface{}) {
    fmt.Printf("[DEBUG] " + format + "\n", args...)
}

// Disable debug
hd.DebugLogger = nil
```

### Custom Configuration

```go
discovery := hd.NewMultiDiscovery()

// Configure TCP options
discovery.Options.TCPPorts = []int{80, 443, 22, 3389}
discovery.Options.TCPTimeout = 1 * time.Second
discovery.Options.TCPWorkers = 512

// Configure protocol-specific timeouts
discovery.Options.DNSTimeout = 2 * time.Second
discovery.Options.NetBIOSTimeout = 3 * time.Second
discovery.Options.MDNSTimeout = 2 * time.Second
discovery.Options.LLMNRTimeout = 2 * time.Second
discovery.Options.SSPDTimeout = 3 * time.Second

// Enable/disable specific protocols
discovery.Options.EnableTCP = true
discovery.Options.EnableDNS = true
discovery.Options.EnableNetBIOS = true
discovery.Options.EnableMDNS = true
discovery.Options.EnableLLMNR = true
discovery.Options.EnableSSDP = true
discovery.Options.EnableDHCP = true
discovery.Options.EnableFinger = false // Disabled by default
discovery.Options.EnableARP = true
discovery.Options.EnableTCPFP = true // OS fingerprinting
```

### Handling Large Networks

For large CIDR ranges, use workers and filtering:

```go
discovery := hd.NewMultiDiscovery()
discovery.Options.TCPWorkers = 1024 // Increase concurrency
discovery.Options.TCPTimeout = 500 * time.Millisecond // Shorter timeout

// Batch processing with progress
cidrs := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
for _, cidr := range cidrs {
    results, _ := discovery.DiscoverCIDR(ctx, cidr)
    for _, host := range results {
        // Process results as they come in
        fmt.Println(host.IP)
    }
}
```

## 📚 Package Structure

```
pkg/hostdiscovery/
├── types.go           # Core types (Host, Result, Options)
├── version.go         # Version constants
├── compat.go          # Debug logging infrastructure
│
├── Discovery Methods:
├── hostdiscovery.go   # TCP connect discovery
├── dns.go             # DNS (PTR) reverse lookups
├── netbios.go         # NetBIOS (NBSTAT) for Windows
├── mdns.go            # Multicast DNS (Bonjour/Avahi)
├── llmnr.go           # Link-Local Multicast Name Resolution
├── ssdp.go            # SSDP/UPnP device discovery
├── dhcp.go            # DHCP INFORM queries
├── finger.go          # Finger protocol (legacy)
├── arp.go             # ARP address resolution
├── oui.go             # MAC vendor lookups
├── osdetect.go        # TCP/IP fingerprinting
│
├── Multi-Protocol:
├── multi.go           # Unified discovery interface
│
└── Utilities:
├── ip.go              # IP enumeration (CIDR expansion)
├── network/           # Network utilities (if applicable)
└── testdata/          # Test fixtures
    ├── test.example.env      # Example test configuration
    ├── test.local.env        # Local test configuration (git-ignored)
    └── *.txt                 # Test data fixtures
```

## 🧪 Testing

The library includes 100+ comprehensive unit tests:

```bash
# Run all tests
go test ./pkg/hostdiscovery/...

# Run with verbose output
go test ./pkg/hostdiscovery/... -v

# Run with coverage report
go test ./pkg/hostdiscovery/... -cover

# Run specific protocol tests
go test ./pkg/hostdiscovery/dns -v
go test ./pkg/hostdiscovery/netbios -v
go test ./pkg/hostdiscovery/mdns -v
go test ./pkg/hostdiscovery/ssdp -v

# Generate coverage profile
go test ./pkg/hostdiscovery/... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Test Configuration

Integration tests require local network setup. Configure test parameters:

```bash
# Copy example configuration to local
cp pkg/hostdiscovery/testdata/test.example.env \
   pkg/hostdiscovery/testdata/test.local.env

# Edit with your network values
nano pkg/hostdiscovery/testdata/test.local.env
```

Configuration variables:
- `TEST_WINDOWS_IP` - Windows host IP for NetBIOS tests
- `TEST_WINDOWS_HOSTNAME` - Expected NetBIOS hostname
- `TEST_WINDOWS_MAC` - Expected MAC address (XX-XX-XX-XX-XX-XX format)
- `TEST_LINUX_IP` - Linux host IP (optional)
- `TEST_DHCP_LOCAL_IP` - Your local machine IP on the network
- `TEST_DHCP_SERVER_IP` - DHCP server IP (usually your router)

**Note**: The `test.local.env` file is git-ignored to keep network details private.

## 📦 Dependencies

- `github.com/j-keck/arping` - ARP functionality
- `github.com/klauspost/oui` - MAC vendor lookups
- `github.com/koron/go-ssdp` - SSDP protocol implementation
- `github.com/miekg/dns` - DNS operations

All dependencies are production-quality and actively maintained.

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional protocol support (e.g., SNMP, ICMP)
- Performance optimizations
- Better error handling
- Additional test coverage
- Documentation improvements

## 📋 Use Cases

- **Network Inventory** - Build and maintain device inventory
- **Network Monitoring** - Detect new devices, hostname changes
- **Security Scanning** - Identify open ports, OS versions, services
- **Device Detection** - Locate smart TVs, IoT devices, printers
- **Network Management** - Automated device discovery and categorization
- **Incident Response** - Forensic analysis of network devices

## ⚠️ Important Notes

- **Permissions**: No administrative privileges required (pure Go implementation)
- **Network Impact**: Large CIDR scans generate significant traffic
- **Firewall**: Some protocols may be blocked or rate-limited by firewalls
- **Legal**: Only scan networks you own or have explicit permission to scan
- **Performance**: Adjust timeouts and workers based on network conditions
- **Reliability**: Some protocols may return stale or incorrect data

## 📄 License

MIT License - See LICENSE file for details

## 🔗 References

- [NetBIOS Specification (RFC 1001/1002)](https://tools.ietf.org/html/rfc1001)
- [mDNS (RFC 6762)](https://tools.ietf.org/html/rfc6762)
- [DNS (RFC 1035)](https://tools.ietf.org/html/rfc1035)
- [LLMNR (RFC 4795)](https://tools.ietf.org/html/rfc4795)
- [SSDP/UPnP Specification](https://upnp.org/specs/arch/)
- [DHCP (RFC 2131)](https://tools.ietf.org/html/rfc2131)
- [Finger Protocol (RFC 1288)](https://tools.ietf.org/html/rfc1288)
- [ARP (RFC 826)](https://tools.ietf.org/html/rfc826)
- [TCP/IP Fingerprinting](https://en.wikipedia.org/wiki/TCP/IP_fingerprinting)
