// Package dns tests for DNS discovery.
package dns

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewDiscovery(t *testing.T) {
	d := NewDiscovery()
	if d == nil {
		t.Fatal("NewDiscovery returned nil")
	}
	if d.Timeout != DefaultTimeout {
		t.Errorf("Expected timeout %v, got %v", DefaultTimeout, d.Timeout)
	}
	if d.Workers != DefaultWorkers {
		t.Errorf("Expected workers %d, got %d", DefaultWorkers, d.Workers)
	}
}

func TestResult_Structure(t *testing.T) {
	result := &Result{
		IP:       "192.168.1.1",
		Hostname: "router.local",
		All:      []string{"router.local", "gateway.local"},
		Error:    nil,
	}

	if result.IP != "192.168.1.1" {
		t.Errorf("Expected IP 192.168.1.1, got %s", result.IP)
	}
	if result.Hostname != "router.local" {
		t.Errorf("Expected Hostname router.local, got %s", result.Hostname)
	}
	if len(result.All) != 2 {
		t.Errorf("Expected 2 hostnames in All, got %d", len(result.All))
	}
}

func TestLookupMultiple_Empty(t *testing.T) {
	d := NewDiscovery()
	results := d.LookupMultiple(context.Background(), []string{})
	if results != nil {
		t.Errorf("Expected nil for empty input, got %v", results)
	}
}

func TestLookupMultiple_ContextCancellation(t *testing.T) {
	d := NewDiscovery()
	d.Timeout = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Should handle cancelled context gracefully
	results := d.LookupMultiple(ctx, []string{"192.168.1.1", "192.168.1.2"})
	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}
}

func TestLookupAddr_InvalidIP(t *testing.T) {
	d := NewDiscovery()
	d.Timeout = 100 * time.Millisecond

	ctx := context.Background()

	// This should fail with DNS lookup error, not panic
	result, err := d.LookupAddr(ctx, "invalid-ip")
	if err == nil {
		t.Logf("Lookup returned: %+v", result)
	}
	// Result should at least have the IP set
	if result != nil && result.IP != "invalid-ip" {
		t.Errorf("Expected IP to be set to input, got %s", result.IP)
	}
}

func TestLookupAddr_Localhost(t *testing.T) {
	d := NewDiscovery()
	d.Timeout = 2 * time.Second

	ctx := context.Background()

	// Lookup localhost - most systems should resolve this
	result, err := d.LookupAddr(ctx, "127.0.0.1")
	
	// Log result regardless of outcome
	t.Logf("Localhost lookup: hostname=%q, all=%v, err=%v", 
		result.Hostname, result.All, err)

	if result.IP != "127.0.0.1" {
		t.Errorf("Expected IP 127.0.0.1, got %s", result.IP)
	}

	// On most systems, localhost should resolve
	if err == nil && result.Hostname != "" {
		// Hostname should contain "localhost" 
		if !strings.Contains(strings.ToLower(result.Hostname), "localhost") {
			t.Logf("Unexpected hostname for 127.0.0.1: %s", result.Hostname)
		}
	}
}

func TestDebugLogger(t *testing.T) {
	var logMessages []string
	originalLogger := DebugLogger

	// Set test logger
	DebugLogger = func(format string, args ...interface{}) {
		logMessages = append(logMessages, format)
	}
	defer func() { DebugLogger = originalLogger }()

	// Trigger debug log
	debugLog("test message %s", "arg")

	if len(logMessages) != 1 {
		t.Errorf("Expected 1 log message, got %d", len(logMessages))
	}
}

func TestDebugLogger_Nil(t *testing.T) {
	originalLogger := DebugLogger
	DebugLogger = nil
	defer func() { DebugLogger = originalLogger }()

	// Should not panic when DebugLogger is nil
	debugLog("test message %s", "arg")
}

func TestDiscovery_WorkersDefault(t *testing.T) {
	d := &Discovery{Timeout: DefaultTimeout, Workers: 0}
	
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Should use DefaultWorkers when Workers is 0
	results := d.LookupMultiple(ctx, []string{"127.0.0.1"})
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}
}
