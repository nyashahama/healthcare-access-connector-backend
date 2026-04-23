package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrackedEnvFilesContainNoLiveSecrets(t *testing.T) {
	root := filepath.Join("..", "..")
	files := []string{
		filepath.Join(root, ".env.example"),
		filepath.Join(root, ".env.development"),
		filepath.Join(root, ".env.production"),
	}

	// Patterns that indicate a live secret or a realistic placeholder that could be mistaken for one.
	bannedMarkers := []string{
		"postgresql://",
		"rediss://",
		"re_",
		"sk-",
		"hf_",
		"smtp_password",
		"smtp.gmail.com",
		"@gmail.com",
		"your-app-password",
		"your-key",
		"your-secret",
	}

	// Safe markers that indicate an obviously fake/example value.
	safeMarkers := []string{
		"<REPLACE_WITH_",
		"<YOUR_",
		"<DB_",
		"<SMTP_",
		"<REDIS_",
		"<NATS_",
		"EXAMPLE_PASSWORD",
		"replace_me",
		"dev-jwt-secret-replace-me-now",
		"example.local",
		"localhost",
		"127.0.0.1",
		"::1",
		"replace-in-secret-manager",
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		content := string(data)
		lower := strings.ToLower(content)

		for _, marker := range bannedMarkers {
			if strings.Contains(lower, strings.ToLower(marker)) {
				// If a banned marker is found, check whether the line also contains an obvious safe marker.
				lines := strings.Split(content, "\n")
				for _, line := range lines {
					lineLower := strings.ToLower(line)
					if strings.Contains(lineLower, strings.ToLower(marker)) {
						hasSafe := false
						for _, safe := range safeMarkers {
							if strings.Contains(lineLower, strings.ToLower(safe)) {
								hasSafe = true
								break
							}
						}
						assert.True(t, hasSafe, "file %s contains a line with banned marker %q that does not have an obvious safe placeholder: %s", file, marker, strings.TrimSpace(line))
					}
				}
			}
		}
	}
}
