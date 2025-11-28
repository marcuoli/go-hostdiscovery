// Package hostdiscovery version information.
package hostdiscovery

// Version information for the hostdiscovery library.
const (
	// Version is the semantic version of the library.
	Version = "1.0.0"

	// VersionMajor is the major version number.
	VersionMajor = 1

	// VersionMinor is the minor version number.
	VersionMinor = 0

	// VersionPatch is the patch version number.
	VersionPatch = 0
)

// VersionInfo returns the full version string with library name.
func VersionInfo() string {
	return "go-hostdiscovery v" + Version
}
