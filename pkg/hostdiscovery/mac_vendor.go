// Package hostdiscovery: MAC vendor lookup using IEEE OUI database.
// This file provides MAC address to vendor name resolution using the klauspost/oui library.
package hostdiscovery

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

	// customOUIPath allows setting a custom path for the OUI database
	customOUIPath string
)

// VendorInfo contains information about a MAC address vendor.
type VendorInfo struct {
	Manufacturer string
	Address      []string
	Country      string
	Prefix       string
}

// SetOUIDatabase sets a custom path for the OUI database file.
// This should be called before any vendor lookups are performed.
// If not set, the library will use its embedded database.
func SetOUIDatabase(path string) error {
	ouiDBMu.Lock()
	defer ouiDBMu.Unlock()

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("OUI database file not found: %s", path)
	}

	customOUIPath = path

	// Reset the once so the database can be reloaded
	ouiDBOnce = sync.Once{}
	ouiDB = nil
	ouiDBErr = nil

	debugLog("vendor", "Custom OUI database path set: %s", path)
	return nil
}

// GetOUIDatabase returns the current OUI database path (empty if using embedded).
func GetOUIDatabase() string {
	ouiDBMu.RLock()
	defer ouiDBMu.RUnlock()
	return customOUIPath
}

// initOUIDB initializes the OUI database (lazy initialization).
func initOUIDB() error {
	ouiDBOnce.Do(func() {
		ouiDBMu.RLock()
		path := customOUIPath
		ouiDBMu.RUnlock()

		if path != "" {
			// Load from custom file
			debugLog("vendor", "Loading OUI database from: %s", path)
			db, err := oui.OpenFile(path)
			if err != nil {
				ouiDBErr = fmt.Errorf("failed to open OUI database: %w", err)
				return
			}
			ouiDB = db
			debugLog("vendor", "OUI database loaded successfully from custom path")
		} else {
			// Use embedded static database
			debugLog("vendor", "Loading embedded OUI database")
			db, err := oui.OpenStaticFile("")
			if err != nil {
				ouiDBErr = fmt.Errorf("failed to load embedded OUI database: %w", err)
				return
			}
			ouiDB = db
			debugLog("vendor", "Embedded OUI database loaded successfully")
		}
	})
	return ouiDBErr
}

// LookupVendor looks up the vendor information for a MAC address.
// The MAC address can be in various formats: "00:11:22:33:44:55", "00-11-22-33-44-55", "001122334455"
func LookupVendor(mac string) (*VendorInfo, error) {
	if err := initOUIDB(); err != nil {
		return nil, err
	}

	// Normalize MAC address
	mac = normalizeMACForLookup(mac)
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
			debugLogVerbose("vendor", "%s: vendor not found in database", mac)
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

	debugLogVerbose("vendor", "%s -> %s", mac, vendor.Manufacturer)
	return vendor, nil
}

// LookupVendorName is a convenience function that returns just the manufacturer name.
// Returns empty string if not found or on error.
func LookupVendorName(mac string) string {
	vendor, err := LookupVendor(mac)
	if err != nil || vendor == nil {
		return ""
	}
	return vendor.Manufacturer
}

// normalizeMACForLookup normalizes various MAC address formats to standard format.
func normalizeMACForLookup(mac string) string {
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

// ReloadOUIDatabase forces a reload of the OUI database.
// Useful after updating the database file.
func ReloadOUIDatabase() error {
	ouiDBMu.Lock()
	ouiDBOnce = sync.Once{}
	ouiDB = nil
	ouiDBErr = nil
	ouiDBMu.Unlock()

	debugLog("vendor", "OUI database reload triggered")
	return initOUIDB()
}

// IsOUILoaded returns true if the OUI database has been loaded.
func IsOUILoaded() bool {
	ouiDBMu.RLock()
	defer ouiDBMu.RUnlock()
	return ouiDB != nil
}
