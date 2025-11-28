// Package finger provides Finger protocol (RFC 1288) for user/host information.
// Finger is a legacy protocol (TCP port 79) that can reveal:
//   - Logged-in users
//   - User information (real name, office, phone, etc.)
//   - Host information and uptime
//   - Idle time and login sessions
//
// While largely deprecated for security reasons, some Unix/Linux systems
// and network devices still run finger daemons. It's useful for:
//   - Legacy Unix systems
//   - Some network equipment
//   - Academic/research networks
//
// Security Note: Finger is considered insecure and is often disabled
// as it can leak sensitive user information.
package finger

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DebugLogger is the callback function for debug logging.
// Set this to enable debug output for Finger operations.
var DebugLogger func(format string, args ...interface{})

func debugLog(format string, args ...interface{}) {
	if DebugLogger != nil {
		DebugLogger(format, args...)
	}
}

const (
	// Port is the Finger protocol port
	Port = 79
	// DefaultTimeout is the default timeout for Finger lookups
	DefaultTimeout = 2 * time.Second
)

// Result contains information from a Finger query.
type Result struct {
	IP       string
	Hostname string   // Extracted from response if available
	Users    []string // List of logged-in users
	Response string   // Raw response
	Error    error
}

// User contains parsed user information from Finger.
type User struct {
	Login    string
	Name     string
	Terminal string
	Idle     string
	When     string
	Office   string
	Host     string
}

// Discovery performs Finger protocol queries.
type Discovery struct {
	Timeout time.Duration
}

// NewDiscovery creates a new Finger discovery helper with defaults.
func NewDiscovery() *Discovery {
	return &Discovery{Timeout: DefaultTimeout}
}

// Lookup performs a Finger query to get user/host information.
// If user is empty, it queries for all logged-in users.
// If user is specified, it queries for that specific user's info.
func (f *Discovery) Lookup(ctx context.Context, host, user string) (*Result, error) {
	result := &Result{IP: host}
	debugLog("Finger lookup host=%s user=%q", host, user)

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", Port))

	// Create dialer with timeout
	dialer := &net.Dialer{Timeout: f.Timeout}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		result.Error = fmt.Errorf("finger connection failed: %w", err)
		return result, result.Error
	}
	defer conn.Close()

	// Set read deadline
	deadline := time.Now().Add(f.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)

	// Send query
	if user == "" {
		fmt.Fprintf(conn, "\r\n")
	} else {
		fmt.Fprintf(conn, "%s\r\n", user)
	}

	// Read response
	reader := bufio.NewReader(conn)
	var response strings.Builder

	for {
		line, err := reader.ReadString('\n')
		response.WriteString(line)
		if err != nil {
			break
		}
	}

	result.Response = response.String()

	// Try to parse users from response
	result.Users = f.parseUsers(result.Response)

	// Try to extract hostname from response
	result.Hostname = f.extractHostname(result.Response)

	debugLog("Finger result host=%s hostname=%s users=%d", host, result.Hostname, len(result.Users))
	return result, nil
}

// LookupAddr queries a host for all logged-in users.
func (f *Discovery) LookupAddr(ctx context.Context, ip string) (*Result, error) {
	return f.Lookup(ctx, ip, "")
}

// LookupUser queries a specific user on a host.
func (f *Discovery) LookupUser(ctx context.Context, host, user string) (*Result, error) {
	return f.Lookup(ctx, host, user)
}

// LookupMultiple performs Finger lookups on multiple hosts concurrently.
func (f *Discovery) LookupMultiple(ctx context.Context, hosts []string) []*Result {
	if len(hosts) == 0 {
		return nil
	}

	results := make([]*Result, len(hosts))
	done := make(chan int, len(hosts))

	for i, host := range hosts {
		go func(idx int, h string) {
			results[idx], _ = f.LookupAddr(ctx, h)
			done <- idx
		}(i, host)
	}

	for range hosts {
		select {
		case <-done:
		case <-ctx.Done():
			return results
		}
	}

	return results
}

// IsAvailable checks if Finger service is available on a host.
func (f *Discovery) IsAvailable(ctx context.Context, host string) bool {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", Port))
	dialer := &net.Dialer{Timeout: f.Timeout}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// parseUsers attempts to extract usernames from Finger response.
// Finger output format varies by implementation, common formats:
//   - BSD: Login Name TTY Idle When Office
//   - GNU: Login Name Tstrstrstr
func (f *Discovery) parseUsers(response string) []string {
	var users []string
	seen := make(map[string]bool)

	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Skip header lines
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "login") ||
			strings.HasPrefix(lower, "user") ||
			strings.HasPrefix(lower, "no one") ||
			strings.Contains(lower, "finger:") {
			continue
		}

		// First field is typically the username
		fields := strings.Fields(line)
		if len(fields) > 0 {
			user := fields[0]
			// Skip if it looks like an error or system message
			if len(user) > 0 && len(user) <= 32 && !strings.Contains(user, ":") {
				if !seen[user] {
					seen[user] = true
					users = append(users, user)
				}
			}
		}
	}

	return users
}

// extractHostname attempts to extract hostname from Finger response.
func (f *Discovery) extractHostname(response string) string {
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		// Look for common patterns like "hostname.domain" or "[hostname]"
		if strings.Contains(line, "Welcome to") {
			// "Welcome to hostname" pattern
			parts := strings.Split(line, "Welcome to")
			if len(parts) > 1 {
				hostname := strings.TrimSpace(parts[1])
				hostname = strings.Trim(hostname, "[]()!.")
				if hostname != "" {
					return hostname
				}
			}
		}

		// Look for FQDN patterns in the response
		fields := strings.Fields(line)
		for _, field := range fields {
			if strings.Contains(field, ".") && !strings.Contains(field, "@") {
				// Could be a hostname
				field = strings.Trim(field, "[]():")
				if isValidHostname(field) {
					return field
				}
			}
		}
	}
	return ""
}

// isValidHostname checks if a string looks like a valid hostname.
func isValidHostname(s string) bool {
	if len(s) < 3 || len(s) > 255 {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	// Basic validation - alphanumeric, dots, hyphens
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// ParseOutput parses detailed user information from Finger response.
// This handles the common BSD/GNU finger output format.
func ParseOutput(response string) []User {
	var users []User

	lines := strings.Split(response, "\n")
	inUserBlock := false
	var currentUser *User

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			if currentUser != nil && currentUser.Login != "" {
				users = append(users, *currentUser)
				currentUser = nil
			}
			inUserBlock = false
			continue
		}

		// Check for "Login:" pattern (detailed user info)
		if strings.HasPrefix(line, "Login:") {
			if currentUser != nil && currentUser.Login != "" {
				users = append(users, *currentUser)
			}
			currentUser = &User{}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				// "Login: user   Name: Full Name"
				rest := strings.TrimSpace(parts[1])
				if nameIdx := strings.Index(rest, "Name:"); nameIdx > 0 {
					currentUser.Login = strings.TrimSpace(rest[:nameIdx])
					currentUser.Name = strings.TrimSpace(rest[nameIdx+5:])
				} else {
					currentUser.Login = strings.Fields(rest)[0]
				}
			}
			inUserBlock = true
			continue
		}

		if inUserBlock && currentUser != nil {
			if strings.HasPrefix(line, "Directory:") {
				// Skip
			} else if strings.HasPrefix(line, "Shell:") {
				// Skip
			} else if strings.HasPrefix(line, "Office:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) > 1 {
					currentUser.Office = strings.TrimSpace(parts[1])
				}
			} else if strings.HasPrefix(line, "On since") || strings.HasPrefix(line, "Last login") {
				currentUser.When = line
			}
		}
	}

	if currentUser != nil && currentUser.Login != "" {
		users = append(users, *currentUser)
	}

	return users
}
