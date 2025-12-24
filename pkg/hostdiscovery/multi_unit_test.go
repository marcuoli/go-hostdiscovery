package hostdiscovery

import (
	"context"
	"testing"
	"time"
)

func TestMultiDiscoveryResult_PrimaryHostnamePreferenceOrder(t *testing.T) {
	r := &MultiDiscoveryResult{Hostnames: map[DiscoveryMethod]string{}}
	if got := r.PrimaryHostname(); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}

	r.Hostnames[MethodLLMNR] = "llmnr"
	r.Hostnames[MethodMDNS] = "mdns"
	r.Hostnames[MethodNetBIOS] = "netbios"
	r.Hostnames[MethodDNS] = "dns"

	if got := r.PrimaryHostname(); got != "dns" {
		t.Fatalf("expected dns, got %q", got)
	}

	delete(r.Hostnames, MethodDNS)
	if got := r.PrimaryHostname(); got != "netbios" {
		t.Fatalf("expected netbios, got %q", got)
	}
}

func TestDefaultMultiDiscoveryOptions_HasExpectedDefaults(t *testing.T) {
	opts := DefaultMultiDiscoveryOptions()
	if opts.Timeout != 2*time.Second {
		t.Fatalf("expected Timeout=2s, got %v", opts.Timeout)
	}
	if opts.Workers != 256 {
		t.Fatalf("expected Workers=256, got %d", opts.Workers)
	}
	if !opts.EnableTCP || !opts.EnableDNS || !opts.EnableNetBIOS || !opts.EnableMDNS || !opts.EnableLLMNR || !opts.EnableSSDP || !opts.EnableARP {
		t.Fatalf("expected all main protocols enabled by default")
	}
	if opts.EnableTCPFP {
		t.Fatalf("expected EnableTCPFP=false by default")
	}
}

func TestMultiDiscovery_ResolveBatch_AllProtocolsDisabled_NoNetwork(t *testing.T) {
	m := &MultiDiscovery{Options: MultiDiscoveryOptions{Timeout: 10 * time.Millisecond}}
	m.Options.EnableTCP = false
	m.Options.EnableDNS = false
	m.Options.EnableNetBIOS = false
	m.Options.EnableMDNS = false
	m.Options.EnableLLMNR = false
	m.Options.EnableSSDP = false
	m.Options.EnableARP = false
	m.Options.EnableTCPFP = false

	results, err := m.ResolveBatch(context.Background(), []string{"192.0.2.1", "192.0.2.2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if r == nil {
			t.Fatalf("result %d is nil", i)
		}
		if r.IP == "" {
			t.Fatalf("result %d has empty IP", i)
		}
		if got := r.PrimaryHostname(); got != "" {
			t.Fatalf("expected empty PrimaryHostname, got %q", got)
		}
	}
}
