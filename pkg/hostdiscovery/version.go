// Package hostdiscovery version information.
package hostdiscovery

// Version information for the hostdiscovery library.
const (
	// Version is the semantic version of the library.
	Version = "0.9.9"

	// VersionMajor is the major version number.
	VersionMajor = 0

	// VersionMinor is the minor version number.
	VersionMinor = 9

	// VersionPatch is the patch version number.
	VersionPatch = 9
)

// VersionInfo returns the full version string with library name.
func VersionInfo() string {
	return "go-hostdiscovery v" + Version
}
