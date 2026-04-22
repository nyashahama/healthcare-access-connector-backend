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
		filepath.Join(root, ".env.development"),
		filepath.Join(root, ".env.production"),
	}
	bannedMarkers := []string{
		"postgresql://",
		"rediss://",
		"re_",
		"sk-",
		"hf_",
		"smtp_password",
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		lower := strings.ToLower(string(data))
		for _, marker := range bannedMarkers {
			assert.NotContains(t, lower, strings.ToLower(marker), file)
		}
	}
}
