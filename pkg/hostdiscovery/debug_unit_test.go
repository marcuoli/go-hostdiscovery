package hostdiscovery

import "testing"

func TestDebugLog_Gating(t *testing.T) {
	oldLogger := debugLogger
	oldLevel := debugLevel
	defer func() {
		SetDebugLogger(oldLogger)
		SetDebugLevel(oldLevel)
	}()

	var calls []struct {
		method DiscoveryMethod
		msg    string
	}

	SetDebugLogger(func(method DiscoveryMethod, format string, args ...interface{}) {
		calls = append(calls, struct {
			method DiscoveryMethod
			msg    string
		}{method: method, msg: format})
	})

	SetDebugLevel(DebugOff)
	debugLog(MethodDNS, "a")
	debugLogVerbose(MethodDNS, "b")
	if len(calls) != 0 {
		t.Fatalf("expected 0 calls with DebugOff, got %d", len(calls))
	}

	SetDebugLevel(DebugBasic)
	debugLog(MethodDNS, "c")
	debugLogVerbose(MethodDNS, "d")
	if len(calls) != 1 {
		t.Fatalf("expected 1 call with DebugBasic, got %d", len(calls))
	}
	if calls[0].method != MethodDNS || calls[0].msg != "c" {
		t.Fatalf("unexpected call: %#v", calls[0])
	}

	SetDebugLevel(DebugVerbose)
	debugLogVerbose(MethodMDNS, "e")
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls with DebugVerbose, got %d", len(calls))
	}
	if calls[1].method != MethodMDNS || calls[1].msg != "e" {
		t.Fatalf("unexpected call: %#v", calls[1])
	}
}

func TestFormatBytes(t *testing.T) {
	if got := FormatBytes(nil, 64); got != "(empty)" {
		t.Fatalf("expected (empty), got %q", got)
	}

	if got := FormatBytes([]byte{0x01, 0xab, 0x00}, 64); got != "01ab00" {
		t.Fatalf("expected hex string, got %q", got)
	}

	// Truncation path
	data := make([]byte, 100)
	for i := range data {
		data[i] = 0xff
	}
	got := FormatBytes(data, 8)
	if got == "" || got == "(empty)" {
		t.Fatalf("expected non-empty truncated string, got %q", got)
	}
}

func TestGetDebugLevelAndDebugLogf(t *testing.T) {
	oldLogger := debugLogger
	oldLevel := debugLevel
	defer func() {
		SetDebugLogger(oldLogger)
		SetDebugLevel(oldLevel)
	}()

	var called bool
	SetDebugLogger(func(method DiscoveryMethod, format string, args ...interface{}) {
		called = true
		if method != MethodDNS {
			t.Fatalf("expected MethodDNS, got %q", method)
		}
		if format != "msg" {
			t.Fatalf("expected format=msg, got %q", format)
		}
	})
	SetDebugLevel(DebugBasic)

	if got := GetDebugLevel(); got != DebugBasic {
		t.Fatalf("expected GetDebugLevel()=%v, got %v", DebugBasic, got)
	}

	debugLogf(MethodDNS, "msg")
	if !called {
		t.Fatalf("expected debugLogf to log at DebugBasic")
	}
}
