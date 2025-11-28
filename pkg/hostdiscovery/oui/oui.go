// Package oui provides MAC address vendor lookup using the IEEE OUI database.
// This package resolves MAC addresses to vendor/manufacturer names.
package oui

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/klauspost/oui"
)

var (
	ouiDB     oui.OuiDB
	ouiDBOnce sync.Once
	ouiDBErr  error
	ouiDBMu   sync.RWMutex

	// customDBPath allows setting a custom path for the OUI database
	customDBPath string
)

// DebugLogger is a callback for debug logging.
// Set this to receive debug messages from OUI operations.
var DebugLogger func(format string, args ...interface{})

func debugLog(format string, args ...interface{}) {
	if DebugLogger != nil {
		DebugLogger(format, args...)
	}
}

// VendorInfo contains information about a MAC address vendor.
type VendorInfo struct {
	Manufacturer string
	Address      []string
	Country      string
	Prefix       string
}

// SetDatabase sets a custom path for the OUI database file.
// This should be called before any vendor lookups are performed.
// If not set, the library will use its embedded database.
func SetDatabase(path string) error {
	ouiDBMu.Lock()
	defer ouiDBMu.Unlock()

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("OUI database file not found: %s", path)
	}

	customDBPath = path

	// Reset the once so the database can be reloaded
	ouiDBOnce = sync.Once{}
	ouiDB = nil
	ouiDBErr = nil

	debugLog("Custom OUI database path set: %s", path)
	return nil
}

// GetDatabasePath returns the current OUI database path (empty if using embedded).
func GetDatabasePath() string {
	ouiDBMu.RLock()
	defer ouiDBMu.RUnlock()
	return customDBPath
}

// initDB initializes the OUI database (lazy initialization).
func initDB() error {
	ouiDBOnce.Do(func() {
		ouiDBMu.RLock()
		path := customDBPath
		ouiDBMu.RUnlock()

		if path != "" {
			// Load from custom file
			debugLog("Loading OUI database from: %s", path)
			db, err := oui.OpenFile(path)
			if err != nil {
				ouiDBErr = fmt.Errorf("failed to open OUI database: %w", err)
				return
			}
			ouiDB = db
			debugLog("OUI database loaded successfully from custom path")
		} else {
			// Use embedded static database
			debugLog("Loading embedded OUI database")
			db, err := oui.OpenStaticFile("")
			if err != nil {
				ouiDBErr = fmt.Errorf("failed to load embedded OUI database: %w", err)
				return
			}
			ouiDB = db
			debugLog("Embedded OUI database loaded successfully")
		}
	})
	return ouiDBErr
}

// Lookup looks up the vendor information for a MAC address.
// The MAC address can be in various formats: "00:11:22:33:44:55", "00-11-22-33-44-55", "001122334455"
func Lookup(mac string) (*VendorInfo, error) {
	if err := initDB(); err != nil {
		return nil, err
	}

	// Normalize MAC address
	mac = NormalizeMAC(mac)
	if mac == "" {
		return nil, fmt.Errorf("invalid MAC address format")
	}

	// Parse hardware address
	hwAddr, err := net.ParseMAC(mac)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MAC address: %w", err)
	}

	// Query the OUI database
	entry, err := ouiDB.Query(hwAddr.String())
	if err != nil {
		if err == oui.ErrNotFound {
			debugLog("%s: vendor not found in database", mac)
			return nil, nil // Not found is not an error, just unknown vendor
		}
		return nil, fmt.Errorf("OUI lookup failed: %w", err)
	}

	vendor := &VendorInfo{
		Manufacturer: entry.Manufacturer,
		Prefix:       entry.Prefix.String(),
	}

	if len(entry.Address) > 0 {
		vendor.Address = entry.Address
	}
	if entry.Country != "" {
		vendor.Country = entry.Country
	}

	debugLog("%s -> %s", mac, vendor.Manufacturer)
	return vendor, nil
}

// LookupName is a convenience function that returns just the manufacturer name.
// Returns empty string if not found or on error.
func LookupName(mac string) string {
	vendor, err := Lookup(mac)
	if err != nil || vendor == nil {
		return ""
	}
	return vendor.Manufacturer
}

// NormalizeMAC normalizes various MAC address formats to standard format.
// Returns empty string if invalid.
func NormalizeMAC(mac string) string {
	// Remove common separators and convert to lowercase
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, "-", "")
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, ".", "")

	// Must be 12 hex characters for a full MAC
	if len(mac) != 12 {
		return ""
	}

	// Validate hex characters
	for _, c := range mac {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}

	// Convert to standard format: 00:11:22:33:44:55
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		mac[0:2], mac[2:4], mac[4:6], mac[6:8], mac[8:10], mac[10:12])
}

// Reload forces a reload of the OUI database.
// Useful after updating the database file.
func Reload() error {
	ouiDBMu.Lock()
	ouiDBOnce = sync.Once{}
	ouiDB = nil
	ouiDBErr = nil
	ouiDBMu.Unlock()

	debugLog("OUI database reload triggered")
	return initDB()
}

// IsLoaded returns true if the OUI database has been loaded.
func IsLoaded() bool {
	ouiDBMu.RLock()
	defer ouiDBMu.RUnlock()
	return ouiDB != nil
}
