// Package osdetect: Internal debug logging for osdetect package.
package osdetect

import (
	"log"
	"os"
)

var (
	// debugEnabled controls whether debug logging is enabled for this package.
	debugEnabled = os.Getenv("OSDETECT_DEBUG") != ""
)

// debugLog logs a debug message if debug logging is enabled.
// This is an internal function used by the osdetect package.
func debugLog(prefix string, format string, args ...interface{}) {
	if debugEnabled {
		log.Printf("[osdetect:%s] "+format, append([]interface{}{prefix}, args...)...)
	}
}
