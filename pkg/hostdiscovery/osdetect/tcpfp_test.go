// Package osdetect: Tests for TCP/IP fingerprinting.
package osdetect

import (
	"context"
	"testing"
	"time"
)

// TestNewTCPFPDiscovery tests the constructor.
func TestNewTCPFPDiscovery(t *testing.T) {
	fp := NewTCPFPDiscovery()
	if fp == nil {
		t.Fatal("NewTCPFPDiscovery returned nil")
	}
	if fp.Timeout == 0 {
		t.Error("Timeout should have a default value")
	}
	if len(fp.Signatures) == 0 {
		t.Error("Signatures should have default values")
	}
}

// TestDefaultSignatures tests that default signatures are loaded.
func TestDefaultSignatures(t *testing.T) {
	sigs := defaultSignatures()
	if len(sigs) == 0 {
		t.Fatal("defaultSignatures returned empty list")
	}

	// Check for expected OS families
	families := make(map[string]bool)
	for _, sig := range sigs {
		families[sig.Family] = true
	}

	expectedFamilies := []string{"Windows", "Linux", "BSD", "Unix"}
	for _, family := range expectedFamilies {
		if !families[family] {
			t.Errorf("Expected signature family %q not found", family)
		}
	}

	t.Logf("Loaded %d signatures across %d families", len(sigs), len(families))
	for family := range families {
		t.Logf("  - %s", family)
	}
}

// TestEstimateOriginalTTL tests TTL estimation logic.
func TestEstimateOriginalTTL(t *testing.T) {
	tests := []struct {
		observed uint8
		expected uint8
	}{
		{128, 128}, // Windows, no hops
		{127, 128}, // Windows, 1 hop
		{120, 128}, // Windows, 8 hops
		{64, 64},   // Linux/BSD, no hops
		{63, 64},   // Linux/BSD, 1 hop
		{56, 64},   // Linux/BSD, 8 hops
		{255, 255}, // Cisco/Solaris
		{250, 255}, // Cisco/Solaris, 5 hops
		{32, 32},   // Old Windows
		{30, 32},   // Old Windows, 2 hops
		{1, 32},    // Very low TTL
	}

	for _, tt := range tests {
		result := estimateOriginalTTL(tt.observed)
		if result != tt.expected {
			t.Errorf("estimateOriginalTTL(%d) = %d, want %d", tt.observed, result, tt.expected)
		}
	}
}

// TestAnalyzeTTL tests TTL analysis function.
func TestAnalyzeTTL(t *testing.T) {
	tests := []struct {
		observedTTL    uint8
		expectedOriginal uint8
		expectedHint   string
	}{
		{128, 128, "Windows NT/2000/XP/Vista/7/8/10/11"},
		{64, 64, "Linux/Unix/BSD/macOS"},
		{255, 255, "Network device (Cisco/Solaris)"},
		{32, 32, "Windows 9x/NT (legacy)"},
	}

	for _, tt := range tests {
		original, hint, confidence := AnalyzeTTL(tt.observedTTL)
		if original != tt.expectedOriginal {
			t.Errorf("AnalyzeTTL(%d) original = %d, want %d", tt.observedTTL, original, tt.expectedOriginal)
		}
		if hint != tt.expectedHint {
			t.Errorf("AnalyzeTTL(%d) hint = %q, want %q", tt.observedTTL, hint, tt.expectedHint)
		}
		if confidence <= 0 {
			t.Errorf("AnalyzeTTL(%d) confidence should be > 0, got %d", tt.observedTTL, confidence)
		}
		t.Logf("TTL %d -> original=%d, hint=%q, confidence=%d%%", tt.observedTTL, original, hint, confidence)
	}
}

// TestTCPFPResultString tests the string representation.
func TestTCPFPResultString(t *testing.T) {
	result := &TCPFPResult{
		IP:         "192.168.1.100",
		Port:       80,
		OSGuess:    "Windows 10/11",
		OSFamily:   "Windows",
		DeviceType: "desktop",
		Confidence: 85,
	}

	str := result.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
	t.Logf("Result string: %s", str)

	// Test error case
	resultErr := &TCPFPResult{
		IP:    "192.168.1.100",
		Error: context.DeadlineExceeded,
	}
	strErr := resultErr.String()
	if strErr == "" {
		t.Error("String() with error returned empty string")
	}
	t.Logf("Error result string: %s", strErr)
}

// TestTCPFPResultMethod tests method identification.
func TestTCPFPResultMethod(t *testing.T) {
	result := &TCPFPResult{}
	method := result.Method()
	if method != "tcpfp" {
		t.Errorf("Method() = %q, want %q", method, "tcpfp")
	}
}

// TestTCPFPDiscoveryScoring tests signature scoring algorithm.
func TestTCPFPDiscoveryScoring(t *testing.T) {
	fp := NewTCPFPDiscovery()

	// Create a fingerprint that looks like Windows 10
	windowsFP := &TCPFingerprint{
		TTL:          128,
		EstimatedTTL: 128,
		WindowSize:   65535,
		MSS:          1460,
		WScale:       8,
		SACKPerm:     true,
		Timestamp:    false,
		DF:           true,
	}

	// Find Windows signature
	var windowsSig *TCPFPSignature
	for i := range fp.Signatures {
		if fp.Signatures[i].Family == "Windows" && fp.Signatures[i].Name == "Windows 10/11" {
			windowsSig = &fp.Signatures[i]
			break
		}
	}

	if windowsSig == nil {
		t.Skip("Windows 10/11 signature not found")
	}

	score := fp.scoreMatch(windowsFP, windowsSig)
	if score <= 0 {
		t.Errorf("Windows fingerprint should match Windows signature, got score=%d", score)
	}
	t.Logf("Windows 10 fingerprint vs Windows 10/11 signature: score=%d", score)

	// Create a fingerprint that looks like Linux
	linuxFP := &TCPFingerprint{
		TTL:          64,
		EstimatedTTL: 64,
		WindowSize:   29200,
		MSS:          1460,
		WScale:       7,
		SACKPerm:     true,
		Timestamp:    true,
		DF:           true,
	}

	// Find Linux signature
	var linuxSig *TCPFPSignature
	for i := range fp.Signatures {
		if fp.Signatures[i].Family == "Linux" {
			linuxSig = &fp.Signatures[i]
			break
		}
	}

	if linuxSig == nil {
		t.Skip("Linux signature not found")
	}

	linuxScore := fp.scoreMatch(linuxFP, linuxSig)
	if linuxScore <= 0 {
		t.Errorf("Linux fingerprint should match Linux signature, got score=%d", linuxScore)
	}
	t.Logf("Linux fingerprint vs Linux signature: score=%d", linuxScore)

	// Cross-test: Linux fingerprint should score lower against Windows signature
	crossScore := fp.scoreMatch(linuxFP, windowsSig)
	if crossScore >= linuxScore {
		t.Errorf("Linux fingerprint should score lower against Windows signature")
	}
	t.Logf("Linux fingerprint vs Windows signature: score=%d (should be lower)", crossScore)
}

// TestTCPFPDiscoveryGuessFromTTL tests OS guessing from TTL alone.
func TestTCPFPDiscoveryGuessFromTTL(t *testing.T) {
	fp := NewTCPFPDiscovery()

	tests := []struct {
		ttl            uint8
		expectedFamily string
	}{
		{128, "Windows"},
		{64, "Unix"},    // Linux/BSD/macOS all return "Unix" family
		{255, "Network"},
		{32, "Windows"},
	}

	for _, tt := range tests {
		osGuess, osFamily := fp.guessFromTTL(tt.ttl)
		if osFamily != tt.expectedFamily {
			t.Errorf("guessFromTTL(%d) family = %q, want %q", tt.ttl, osFamily, tt.expectedFamily)
		}
		t.Logf("TTL %d -> OS guess: %q, family: %q", tt.ttl, osGuess, osFamily)
	}
}

// TestRawTCPFPDiscovery tests the raw socket wrapper.
func TestRawTCPFPDiscovery(t *testing.T) {
	raw := NewRawTCPFPDiscovery()
	if raw == nil {
		t.Fatal("NewRawTCPFPDiscovery returned nil")
	}
	if raw.TCPFPDiscovery == nil {
		t.Error("Embedded TCPFPDiscovery should not be nil")
	}
}

// TestTCPFPDiscoveryFingerprint_Localhost tests fingerprinting localhost.
func TestTCPFPDiscoveryFingerprint_Localhost(t *testing.T) {
	fp := NewTCPFPDiscovery()
	fp.Timeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to fingerprint localhost on a likely open port
	// This may fail if no service is running, which is OK
	result, err := fp.Fingerprint(ctx, "127.0.0.1", 80)
	if err != nil {
		t.Logf("Localhost fingerprint (port 80) failed (expected if no service): %v", err)
		// Try alternative ports
		for _, port := range []int{443, 8080, 3000, 445} {
			result, err = fp.Fingerprint(ctx, "127.0.0.1", port)
			if err == nil {
				break
			}
		}
	}

	if result != nil && result.Error == nil {
		t.Logf("Localhost fingerprint result:")
		t.Logf("  OS Guess: %s", result.OSGuess)
		t.Logf("  OS Family: %s", result.OSFamily)
		t.Logf("  Device Type: %s", result.DeviceType)
		t.Logf("  Confidence: %d%%", result.Confidence)
		if result.Fingerprint != nil {
			t.Logf("  TTL: %d (estimated original: %d)", result.Fingerprint.TTL, result.Fingerprint.EstimatedTTL)
			t.Logf("  Window Size: %d", result.Fingerprint.WindowSize)
		}
	} else {
		t.Log("No localhost services available for fingerprinting (this is OK)")
	}
}

// TestTCPFPDiscoveryFingerprint_KnownHost tests fingerprinting a known host.
func TestTCPFPDiscoveryFingerprint_KnownHost(t *testing.T) {
	// Use the same test IP as other discovery tests
	testIP := "192.168.77.11"

	fp := NewTCPFPDiscovery()
	fp.Timeout = 3 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := fp.Fingerprint(ctx, testIP, 445) // SMB port - typically open on Windows
	if err != nil {
		// Try HTTP as fallback
		result, err = fp.Fingerprint(ctx, testIP, 80)
	}

	if err != nil {
		t.Logf("Fingerprint failed (host may be unavailable): %v", err)
		return
	}

	t.Logf("Fingerprint result for %s:", testIP)
	t.Logf("  OS Guess: %s", result.OSGuess)
	t.Logf("  OS Family: %s", result.OSFamily)
	t.Logf("  Device Type: %s", result.DeviceType)
	t.Logf("  Confidence: %d%%", result.Confidence)
	t.Logf("  Response Time: %dms", result.ResponseTimeMs)

	if result.Fingerprint != nil {
		t.Logf("  Raw fingerprint:")
		t.Logf("    TTL: %d (original estimate: %d)", result.Fingerprint.TTL, result.Fingerprint.EstimatedTTL)
		t.Logf("    Window Size: %d", result.Fingerprint.WindowSize)
		t.Logf("    MSS: %d", result.Fingerprint.MSS)
		t.Logf("    WScale: %d", result.Fingerprint.WScale)
		t.Logf("    SACK Permitted: %v", result.Fingerprint.SACKPerm)
		t.Logf("    Timestamp: %v", result.Fingerprint.Timestamp)
		t.Logf("    DF: %v", result.Fingerprint.DF)
	}
}

// TestTCPFPDiscoveryFingerprintBest tests the multi-port fingerprint method.
func TestTCPFPDiscoveryFingerprintBest(t *testing.T) {
	testIP := "192.168.77.11"

	fp := NewTCPFPDiscovery()
	fp.Timeout = 3 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := fp.FingerprintBest(ctx, testIP)
	if err != nil {
		t.Logf("FingerprintBest failed (host may be unavailable): %v", err)
		return
	}

	t.Logf("Best fingerprint for %s (port %d):", testIP, result.Port)
	t.Logf("  OS Guess: %s", result.OSGuess)
	t.Logf("  OS Family: %s", result.OSFamily)
	t.Logf("  Confidence: %d%%", result.Confidence)
}

// BenchmarkTCPFPDiscoveryScoring benchmarks the signature scoring algorithm.
func BenchmarkTCPFPDiscoveryScoring(b *testing.B) {
	fp := NewTCPFPDiscovery()
	testFP := &TCPFingerprint{
		TTL:          128,
		EstimatedTTL: 128,
		WindowSize:   65535,
		MSS:          1460,
		WScale:       8,
		SACKPerm:     true,
		Timestamp:    false,
		DF:           true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range fp.Signatures {
			fp.scoreMatch(testFP, &fp.Signatures[j])
		}
	}
}

// BenchmarkEstimateOriginalTTL benchmarks TTL estimation.
func BenchmarkEstimateOriginalTTL(b *testing.B) {
	ttls := []uint8{128, 64, 255, 127, 63, 250, 56, 120}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, ttl := range ttls {
			estimateOriginalTTL(ttl)
		}
	}
}
