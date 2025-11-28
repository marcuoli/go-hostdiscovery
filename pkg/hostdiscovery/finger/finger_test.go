// Package finger tests for Finger protocol discovery.
package finger

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// getTestdataPath returns the path to testdata directory
func getTestdataPath() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("pkg", "hostdiscovery", "testdata")
	}
	// Navigate from finger/ -> hostdiscovery/ -> testdata/
	hostDiscoveryDir := filepath.Dir(filepath.Dir(filename))
	return filepath.Join(hostDiscoveryDir, "testdata")
}

// loadTestdata loads a testdata file
func loadTestdata(name string) (string, error) {
	path := filepath.Join(getTestdataPath(), name)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func TestNewDiscovery(t *testing.T) {
	d := NewDiscovery()
	if d == nil {
		t.Fatal("NewDiscovery returned nil")
	}
	if d.Timeout != DefaultTimeout {
		t.Errorf("Expected timeout %v, got %v", DefaultTimeout, d.Timeout)
	}
}

func TestConstants(t *testing.T) {
	if Port != 79 {
		t.Errorf("Expected Port 79, got %d", Port)
	}
	if DefaultTimeout != 2*time.Second {
		t.Errorf("Expected DefaultTimeout 2s, got %v", DefaultTimeout)
	}
}

func TestResult_Structure(t *testing.T) {
	result := &Result{
		IP:       "192.168.1.100",
		Hostname: "server.example.com",
		Users:    []string{"root", "admin", "user1"},
		Response: "Login Name TTY Idle When\nroot ...",
		Error:    nil,
	}

	if result.IP != "192.168.1.100" {
		t.Errorf("Expected IP 192.168.1.100, got %s", result.IP)
	}
	if result.Hostname != "server.example.com" {
		t.Errorf("Expected Hostname server.example.com, got %s", result.Hostname)
	}
	if len(result.Users) != 3 {
		t.Errorf("Expected 3 users, got %d", len(result.Users))
	}
}

func TestUser_Structure(t *testing.T) {
	user := User{
		Login:    "jdoe",
		Name:     "John Doe",
		Terminal: "pts/0",
		Idle:     "1:23",
		When:     "Dec 1 10:00",
		Office:   "Building A",
		Host:     "workstation.local",
	}

	if user.Login != "jdoe" {
		t.Errorf("Expected Login jdoe, got %s", user.Login)
	}
	if user.Name != "John Doe" {
		t.Errorf("Expected Name 'John Doe', got %s", user.Name)
	}
}

func TestParseUsers_Empty(t *testing.T) {
	d := NewDiscovery()
	users := d.parseUsers("")
	if len(users) != 0 {
		t.Errorf("Expected 0 users for empty response, got %d", len(users))
	}
}

func TestParseUsers_HeaderOnly(t *testing.T) {
	d := NewDiscovery()
	response := "Login     Name       TTY Idle  When    Office\n"
	users := d.parseUsers(response)
	if len(users) != 0 {
		t.Errorf("Expected 0 users for header-only response, got %d", len(users))
	}
}

func TestParseUsers_NoOneLoggedIn(t *testing.T) {
	d := NewDiscovery()
	response := "No one logged on."
	users := d.parseUsers(response)
	if len(users) != 0 {
		t.Errorf("Expected 0 users for 'no one' response, got %d", len(users))
	}
}

func TestParseUsers_ValidUsers(t *testing.T) {
	d := NewDiscovery()
	
	// Try to load from testdata
	response, err := loadTestdata("users_bsd.txt")
	if err != nil {
		// Fallback to inline data
		response = `Login     Name       TTY Idle  When    Office
root      System Admin pts/0  1:00  Dec 1 10:00
admin     Administrator pts/1      Dec 1 11:00
user1     Test User    pts/2  2:30  Dec 1 12:00`
	}

	users := d.parseUsers(response)
	if len(users) < 2 {
		t.Errorf("Expected at least 2 users, got %d: %v", len(users), users)
	}

	// Check that expected users are found
	foundRoot := false
	foundAdmin := false
	for _, u := range users {
		if u == "root" {
			foundRoot = true
		}
		if u == "admin" {
			foundAdmin = true
		}
	}
	if !foundRoot {
		t.Error("Expected user 'root' not found")
	}
	if !foundAdmin {
		t.Error("Expected user 'admin' not found")
	}
}

func TestParseUsers_DuplicatesRemoved(t *testing.T) {
	d := NewDiscovery()
	response := `root      Root1      pts/0
root      Root2      pts/1
admin     Admin      pts/2`

	users := d.parseUsers(response)
	// Should deduplicate root
	rootCount := 0
	for _, u := range users {
		if u == "root" {
			rootCount++
		}
	}
	if rootCount != 1 {
		t.Errorf("Expected 1 root user after dedup, got %d", rootCount)
	}
}

func TestExtractHostname_Empty(t *testing.T) {
	d := NewDiscovery()
	hostname := d.extractHostname("")
	if hostname != "" {
		t.Errorf("Expected empty hostname, got %s", hostname)
	}
}

func TestExtractHostname_WelcomeMessage(t *testing.T) {
	d := NewDiscovery()
	response := "Welcome to server.example.com\nLogin Name TTY"
	hostname := d.extractHostname(response)
	if hostname != "server.example.com" {
		t.Errorf("Expected server.example.com, got %s", hostname)
	}
}

func TestExtractHostname_FQDN(t *testing.T) {
	d := NewDiscovery()
	response := "This is host.domain.local\nSome other text"
	hostname := d.extractHostname(response)
	if hostname != "host.domain.local" {
		t.Errorf("Expected host.domain.local, got %s", hostname)
	}
}

func TestIsValidHostname(t *testing.T) {
	tests := []struct {
		hostname string
		valid    bool
	}{
		{"server.example.com", true},
		{"host.local", true},
		{"host-name.domain.org", true},
		{"a.b", true},            // Exactly 3 chars with dot - valid
		{"no-dots", false},       // No dots
		{"", false},              // Empty
		{"ab", false},            // Too short (less than 3)
		{"has space.com", false}, // Space
		{"has@at.com", false},    // @ symbol
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			got := isValidHostname(tt.hostname)
			if got != tt.valid {
				t.Errorf("isValidHostname(%q) = %v, want %v", tt.hostname, got, tt.valid)
			}
		})
	}
}

func TestLookupMultiple_Empty(t *testing.T) {
	d := NewDiscovery()
	results := d.LookupMultiple(context.Background(), []string{})
	if results != nil {
		t.Errorf("Expected nil for empty input, got %v", results)
	}
}

func TestDebugLogger(t *testing.T) {
	var logMessages []string
	originalLogger := DebugLogger

	DebugLogger = func(format string, args ...interface{}) {
		logMessages = append(logMessages, format)
	}
	defer func() { DebugLogger = originalLogger }()

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

func TestParseOutput_Empty(t *testing.T) {
	users := ParseOutput("")
	if len(users) != 0 {
		t.Errorf("Expected 0 users for empty response, got %d", len(users))
	}
}

func TestParseOutput_DetailedFormat(t *testing.T) {
	response := `Login: jdoe                     Name: John Doe
Directory: /home/jdoe            Shell: /bin/bash
Office: Room 123, 555-1234
On since Mon Dec  1 10:00 (EST) on pts/0

Login: admin                    Name: Administrator
Directory: /home/admin          Shell: /bin/bash
`

	users := ParseOutput(response)
	if len(users) != 2 {
		t.Errorf("Expected 2 users, got %d", len(users))
	}

	if len(users) >= 1 {
		if users[0].Login != "jdoe" {
			t.Errorf("Expected first user login 'jdoe', got %s", users[0].Login)
		}
		if users[0].Name != "John Doe" {
			t.Errorf("Expected first user name 'John Doe', got %s", users[0].Name)
		}
	}
}

// TestFingerProtocol documents Finger protocol details
func TestFingerProtocol_Documentation(t *testing.T) {
	t.Log("Finger Protocol (RFC 1288):")
	t.Log("  - Port: TCP/79")
	t.Log("  - Request: username<CRLF> or empty for all users")
	t.Log("  - Response: User information in text format")
	t.Log("  - Largely deprecated for security reasons")
	t.Log("  - Still found on some Unix/Linux systems")
}

// Benchmark tests
func BenchmarkParseUsers(b *testing.B) {
	d := NewDiscovery()
	response := `Login     Name       TTY Idle  When    Office
root      System Admin pts/0  1:00  Dec 1 10:00
admin     Administrator pts/1      Dec 1 11:00
user1     Test User    pts/2  2:30  Dec 1 12:00
user2     Another User pts/3       Dec 1 13:00`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.parseUsers(response)
	}
}

func BenchmarkExtractHostname(b *testing.B) {
	d := NewDiscovery()
	response := "Welcome to server.example.com\nLogin Name TTY Idle When"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.extractHostname(response)
	}
}

func BenchmarkIsValidHostname(b *testing.B) {
	hostname := "server.example.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = isValidHostname(hostname)
	}
}
