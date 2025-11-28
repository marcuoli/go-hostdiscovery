// Package hostdiscovery version information.
package hostdiscovery

// Version information for the hostdiscovery library.
const (
	// Version is the semantic version of the library.
	Version = "1.3.1"

	// VersionMajor is the major version number.
	VersionMajor = 1

	// VersionMinor is the minor version number.
	VersionMinor = 3

	// VersionPatch is the patch version number.
	VersionPatch = 1
)

// VersionInfo returns the full version string with library name.
func VersionInfo() string {
	return "go-hostdiscovery v" + Version
}
