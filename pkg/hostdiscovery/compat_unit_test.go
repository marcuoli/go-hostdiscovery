package hostdiscovery

import (
	"testing"

	"github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery/arp"
	"github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery/mdns"
	"github.com/marcuoli/go-hostdiscovery/pkg/hostdiscovery/ssdp"
)

func TestCompat_ConstructorsNotNil(t *testing.T) {
	if NewDNSDiscovery() == nil {
		t.Fatal("NewDNSDiscovery() returned nil")
	}
	if NewNetBIOSDiscovery() == nil {
		t.Fatal("NewNetBIOSDiscovery() returned nil")
	}
	if NewMDNSDiscovery() == nil {
		t.Fatal("NewMDNSDiscovery() returned nil")
	}
	if NewLLMNRDiscovery() == nil {
		t.Fatal("NewLLMNRDiscovery() returned nil")
	}
	if NewSSDPDiscovery() == nil {
		t.Fatal("NewSSDPDiscovery() returned nil")
	}
	if NewDHCPDiscovery() == nil {
		t.Fatal("NewDHCPDiscovery() returned nil")
	}
	if NewFingerDiscovery() == nil {
		t.Fatal("NewFingerDiscovery() returned nil")
	}
	if NewARPDiscovery() == nil {
		t.Fatal("NewARPDiscovery() returned nil")
	}
}

func TestCompat_Reexports(t *testing.T) {
	if SSDPAll != ssdp.All {
		t.Fatalf("SSDPAll mismatch: got %q want %q", SSDPAll, ssdp.All)
	}
	if ErrARPNotSupported != arp.ErrNotSupported {
		t.Fatalf("ErrARPNotSupported mismatch: got %v want %v", ErrARPNotSupported, arp.ErrNotSupported)
	}
}

func TestCompat_SubpackageDebugLoggerWiring(t *testing.T) {
	oldLogger := debugLogger
	oldLevel := debugLevel
	defer func() {
		SetDebugLogger(oldLogger)
		SetDebugLevel(oldLevel)
	}()

	var gotMethod DiscoveryMethod
	var gotMsg string
	SetDebugLogger(func(method DiscoveryMethod, format string, args ...interface{}) {
		gotMethod = method
		gotMsg = format
	})
	SetDebugLevel(DebugBasic)

	// compat.go init() should have wired mdns.DebugLogger to hostdiscovery.debugLog.
	mdns.DebugLogger("hello %s", "world")

	if gotMethod != MethodMDNS {
		t.Fatalf("expected MethodMDNS, got %q", gotMethod)
	}
	if gotMsg != "hello %s" {
		t.Fatalf("expected format to pass through, got %q", gotMsg)
	}
}

func TestCompat_DiscoveryErrorString(t *testing.T) {
	err := &DiscoveryError{Method: MethodDNS, Message: "boom"}
	if got := err.Error(); got != "dns: boom" {
		t.Fatalf("expected error string %q, got %q", "dns: boom", got)
	}
}

func TestCompat_OUIWrappers_NoPanic(t *testing.T) {
	_ = GetOUIDatabase()
	_ = IsOUILoaded()
}
