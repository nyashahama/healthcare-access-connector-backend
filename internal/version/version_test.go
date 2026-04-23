package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultValuesAreNotEmpty(t *testing.T) {
	// Defaults are set at package level; they should not panic or be empty
	// in a freshly loaded package. The real verification happens at build time
	// via ldflags, but this test ensures the variables exist and are strings.
	assert.Equal(t, "dev", Version)
	assert.Equal(t, "unknown", Commit)
	assert.Equal(t, "unknown", BuildDate)
}
