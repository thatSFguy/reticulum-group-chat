// Package version exposes the build-wide release marker so any package
// (cmd/fwdsvc for the CLI banner, internal/commands for the /about
// reply, future telemetry, etc.) can reference the same constant
// without an import cycle through main.
package version

// Version is bumped per release. cmd/fwdsvc/main.go's --version flag
// and the /about command both read it from here.
const Version = "1.2.4"

// RepoURL is the canonical source location. Surfaced in /about so users
// running an unfamiliar deployment can find the project, file issues,
// and confirm what code their forwarder is actually running.
const RepoURL = "https://github.com/thatSFguy/reticulum-forwarding-service"
