// Package hostdiscovery: Log prefix constants for consistent log tagging.
// These constants are exported so consumers can use them for consistent logging,
// but they are not required - consumers can use their own prefixes via SetDebugLogger.
package hostdiscovery

// Log prefix constants for discovery methods and components.
// Format follows [Component] or [Component:Subcomponent] pattern.
const (
	// Main discovery prefix
	LogPrefixDiscovery = "[Discovery]"

	// Protocol-specific prefixes
	LogPrefixDNS     = "[Discovery:DNS]"
	LogPrefixNetBIOS = "[Discovery:NetBIOS]"
	LogPrefixLLMNR   = "[Discovery:LLMNR]"
	LogPrefixMDNS    = "[Discovery:mDNS]"
	LogPrefixSSDP    = "[Discovery:SSDP]"
	LogPrefixDHCP    = "[Discovery:DHCP]"
	LogPrefixFinger  = "[Discovery:Finger]"
	LogPrefixARP     = "[Discovery:ARP]"
	LogPrefixOUI     = "[Discovery:OUI]"
	LogPrefixOSDetect = "[Discovery:OSDetect]"

	// Debug prefix - use as "[DEBUG][Discovery:*]" format
	LogPrefixDebug = "[DEBUG]"
)

// MethodToPrefix returns the log prefix for a given discovery method.
// This can be used by consumers who want consistent prefixes in their debug logger callback.
func MethodToPrefix(method DiscoveryMethod) string {
	switch method {
	case MethodDNS:
		return LogPrefixDNS
	case MethodNetBIOS:
		return LogPrefixNetBIOS
	case MethodLLMNR:
		return LogPrefixLLMNR
	case MethodMDNS:
		return LogPrefixMDNS
	case MethodSSDP:
		return LogPrefixSSDP
	case MethodDHCP:
		return LogPrefixDHCP
	case MethodFinger:
		return LogPrefixFinger
	case MethodARP:
		return LogPrefixARP
	default:
		return LogPrefixDiscovery
	}
}
