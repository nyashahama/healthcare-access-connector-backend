// Package version provides build-time metadata injected via ldflags.
package version

var (
	// Version is the semantic version of the application.
	// Override at build time with: -ldflags="-X github.com/nyashahama/healthcare-access-connector-backend/internal/version.Version=v1.2.3"
	Version = "dev"

	// Commit is the full git SHA of the build.
	// Override at build time with: -ldflags="-X github.com/nyashahama/healthcare-access-connector-backend/internal/version.Commit=abc123..."
	Commit = "unknown"

	// BuildDate is the ISO-8601 timestamp when the binary was built.
	// Override at build time with: -ldflags="-X github.com/nyashahama/healthcare-access-connector-backend/internal/version.BuildDate=2026-04-23T12:00:00Z"
	BuildDate = "unknown"
)
