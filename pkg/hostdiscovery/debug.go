// Package hostdiscovery: Debug logging support.
package hostdiscovery

import (
	"fmt"
	"sync"
)

// DebugLevel represents the verbosity level for debug logging.
type DebugLevel int

const (
	// DebugOff disables all debug logging.
	DebugOff DebugLevel = iota
	// DebugBasic logs high-level operations (start/complete/errors).
	DebugBasic
	// DebugVerbose logs detailed protocol information.
	DebugVerbose
)

// DebugLogger is a callback function for debug logging.
// The method parameter indicates which discovery protocol generated the message.
type DebugLogger func(method DiscoveryMethod, format string, args ...interface{})

var (
	debugLogger DebugLogger
	debugLevel  DebugLevel
	debugMu     sync.RWMutex
)

// SetDebugLogger sets a custom debug logger callback.
// Pass nil to disable debug logging.
func SetDebugLogger(logger DebugLogger) {
	debugMu.Lock()
	defer debugMu.Unlock()
	debugLogger = logger
}

// SetDebugLevel sets the debug verbosity level.
func SetDebugLevel(level DebugLevel) {
	debugMu.Lock()
	defer debugMu.Unlock()
	debugLevel = level
}

// GetDebugLevel returns the current debug level.
func GetDebugLevel() DebugLevel {
	debugMu.RLock()
	defer debugMu.RUnlock()
	return debugLevel
}

// debugLog logs a message if debug logging is enabled.
func debugLog(method DiscoveryMethod, format string, args ...interface{}) {
	debugMu.RLock()
	logger := debugLogger
	level := debugLevel
	debugMu.RUnlock()

	if logger != nil && level >= DebugBasic {
		logger(method, format, args...)
	}
}

// debugLogVerbose logs a verbose message if verbose debug logging is enabled.
func debugLogVerbose(method DiscoveryMethod, format string, args ...interface{}) {
	debugMu.RLock()
	logger := debugLogger
	level := debugLevel
	debugMu.RUnlock()

	if logger != nil && level >= DebugVerbose {
		logger(method, format, args...)
	}
}

// debugLogf is a convenience function that formats and logs.
func debugLogf(method DiscoveryMethod, format string, args ...interface{}) {
	debugLog(method, format, args...)
}

// FormatBytes returns a hex dump preview of bytes for debugging.
func FormatBytes(data []byte, maxLen int) string {
	if len(data) == 0 {
		return "(empty)"
	}
	if maxLen <= 0 {
		maxLen = 64
	}
	if len(data) > maxLen {
		return fmt.Sprintf("%x... (%d bytes total)", data[:maxLen], len(data))
	}
	return fmt.Sprintf("%x", data)
}
