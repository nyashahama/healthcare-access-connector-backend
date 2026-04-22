package core

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"github.com/rs/zerolog"
)

func newAuthServiceForTest(t *testing.T, maxAttempts int, lockout time.Duration) *authService {
	t.Helper()
	logger := zerolog.New(io.Discard)
	return &authService{
		logger:           &logger,
		jwtSecret:        strings.Repeat("x", 32),
		jwtExpiry:        time.Hour,
		bcryptCost:       bcrypt.MinCost,
		loginAttempts:    make(map[string]loginAttempt),
		loginMaxAttempts: maxAttempts,
		loginLockout:     lockout,
	}
}

func TestRegisterRejectsPrivilegedSelfSelection(t *testing.T) {
	svc := newAuthServiceForTest(t, 5, 5*time.Minute)
	_, err := svc.Register(context.Background(), "admin@example.com", "", "StrongPass123!", "system_admin")
	require.Error(t, err)
}

func TestRecordFailedLoginUsesConfiguredThresholds(t *testing.T) {
	svc := newAuthServiceForTest(t, 3, 2*time.Minute)
	svc.recordFailedLogin("user@example.com")
	svc.recordFailedLogin("user@example.com")
	svc.recordFailedLogin("user@example.com")
	assert.True(t, svc.isLoginLocked("user@example.com"))
}
