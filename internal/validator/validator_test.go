package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	v := New()
	assert.NotNil(t, v)
	assert.True(t, v.Valid())
	assert.Empty(t, v.Errors())
}

func TestValidator_AddError(t *testing.T) {
	v := New()

	v.AddError("email", "is required")
	assert.False(t, v.Valid())
	assert.Len(t, v.Errors(), 1)
	assert.Equal(t, "email", v.Errors()[0].Field)
	assert.Equal(t, "is required", v.Errors()[0].Message)
}

func TestValidator_ValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"valid email", "test@example.com", false},
		{"valid email with subdomain", "user@mail.example.com", false},
		{"empty email", "", true},
		{"invalid format", "invalid", true},
		{"missing @", "testexample.com", true},
		{"missing domain", "test@", true},
		{"spaces", "test @example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New()
			v.ValidateEmail("email", tt.email)
			if tt.wantErr {
				assert.False(t, v.Valid())
			} else {
				assert.True(t, v.Valid())
			}
		})
	}
}

func TestValidator_ValidatePhone(t *testing.T) {
	tests := []struct {
		name    string
		phone   string
		wantErr bool
	}{
		{"valid international", "+14155551234", false},
		{"valid E164", "+442071234567", false},
		{"empty phone", "", false},
		{"too short", "+1", true},
		{"invalid characters", "+123-abc-4567", true},
		{"valid without plus", "14155551234", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New()
			v.ValidatePhone("phone", tt.phone)
			if tt.wantErr {
				assert.False(t, v.Valid())
			}
		})
	}
}

func TestValidator_ValidateUsername(t *testing.T) {
	tests := []struct {
		name    string
		username string
		wantErr bool
	}{
		{"valid username", "john_doe", false},
		{"valid alphanumeric", "user123", false},
		{"three chars minimum", "abc", false},
		{"fifty chars max", "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnop", false},
		{"empty username", "", true},
		{"too short", "ab", true},
		{"too long", "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopq", true},
		{"with space", "john doe", true},
		{"with special char", "john@doe", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New()
			v.ValidateUsername("username", tt.username)
			if tt.wantErr {
				assert.False(t, v.Valid())
			}
		})
	}
}

func TestValidator_ValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"valid password", "SecurePass123!", false},
		{"exactly 8 chars", "12345678", false},
		{"long password", "VeryLongSecurePassword123!", false},
		{"too short", "short", true},
		{"exactly 7 chars", "1234567", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New()
			v.ValidatePassword("password", tt.password)
			if tt.wantErr {
				assert.False(t, v.Valid())
			}
		})
	}
}

func TestValidator_ValidateRole(t *testing.T) {
	tests := []struct {
		name    string
		role    string
		wantErr bool
	}{
		{"patient", "patient", false},
		{"caregiver", "caregiver", false},
		{"provider_staff", "provider_staff", false},
		{"clinic_admin", "clinic_admin", false},
		{"system_admin", "system_admin", false},
		{"ngo_partner", "ngo_partner", false},
		{"empty role", "", false},
		{"invalid role", "superuser", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New()
			v.ValidateRole("role", tt.role)
			if tt.wantErr {
				assert.False(t, v.Valid())
			}
		})
	}
}

func TestValidator_ValidateRequired(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"non-empty", "value", false},
		{"empty string", "", true},
		{"whitespace only", "   ", true},
		{"tab and space", "\t ", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New()
			v.ValidateRequired("field", tt.value)
			if tt.wantErr {
				assert.False(t, v.Valid())
			}
		})
	}
}

func TestValidator_ValidateLength(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		min     int
		max     int
		wantErr bool
	}{
		{"within range", "hello", 3, 10, false},
		{"exact min", "abc", 3, 3, false},
		{"exact max", "abcdefghij", 3, 10, false},
		{"too short", "ab", 3, 10, true},
		{"too long", "this is too long", 3, 10, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New()
			v.ValidateLength("field", tt.value, tt.min, tt.max)
			if tt.wantErr {
				assert.False(t, v.Valid())
			} else {
				assert.True(t, v.Valid())
			}
		})
	}
}

func TestValidator_ValidateMinLength(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		min     int
		wantErr bool
	}{
		{"above min", "hello", 3, false},
		{"equal min", "abc", 3, false},
		{"below min", "ab", 3, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New()
			v.ValidateMinLength("field", tt.value, tt.min)
			if tt.wantErr {
				assert.False(t, v.Valid())
			}
		})
	}
}

func TestValidator_ValidateMaxLength(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		max     int
		wantErr bool
	}{
		{"below max", "hello", 10, false},
		{"equal max", "abcdefghij", 10, false},
		{"above max", "this is too long", 10, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New()
			v.ValidateMaxLength("field", tt.value, tt.max)
			if tt.wantErr {
				assert.False(t, v.Valid())
			}
		})
	}
}

func TestValidator_ValidateNumeric(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"all digits", "1234567890", false},
		{"single digit", "5", false},
		{"empty string", "", false},
		{"with letters", "123abc", true},
		{"with special chars", "123-456", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New()
			v.ValidateNumeric("field", tt.value)
			if tt.wantErr {
				assert.False(t, v.Valid())
			}
		})
	}
}

func TestValidator_ValidateOTP(t *testing.T) {
	tests := []struct {
		name    string
		otp     string
		wantErr bool
	}{
		{"valid 6 digit", "123456", false},
		{"all zeros", "000000", false},
		{"empty", "", true},
		{"too short", "12345", true},
		{"too long", "1234567", true},
		{"with letters", "12345a", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New()
			v.ValidateOTP("otp", tt.otp)
			if tt.wantErr {
				assert.False(t, v.Valid())
			}
		})
	}
}

func TestValidator_ValidateEnum(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		allowedValues []string
		wantErr       bool
	}{
		{"valid value", "active", []string{"active", "inactive", "pending"}, false},
		{"empty value", "", []string{"active", "inactive"}, true},
		{"invalid value", "unknown", []string{"active", "inactive"}, true},
		{"empty allowed", "value", []string{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New()
			v.ValidateEnum("field", tt.value, tt.allowedValues)
			if tt.wantErr {
				assert.False(t, v.Valid())
			}
		})
	}
}

func TestValidator_ValidateUUID(t *testing.T) {
	tests := []struct {
		name    string
		uuid    string
		wantErr bool
	}{
		{"valid lowercase", "550e8400-e29b-41d4-a716-446655440000", false},
		{"valid uppercase", "550E8400-E29B-41D4-A716-446655440000", false},
		{"empty uuid", "", true},
		{"invalid format", "550e8400e29b41d4a716446655440000", true},
		{"missing dashes", "550e8400-e29b-41d4-a716446655440000", true},
		{"too short", "550e8400-e29b-41d4-a716", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New()
			v.ValidateUUID("uuid", tt.uuid)
			if tt.wantErr {
				assert.False(t, v.Valid())
			}
		})
	}
}

func TestValidationError_Error(t *testing.T) {
	err := ValidationError{
		Field:   "email",
		Message: "is required",
	}

	assert.Equal(t, "email: is required", err.Error())
}

func TestValidator_MultipleErrors(t *testing.T) {
	v := New()

	v.ValidateEmail("email", "invalid")
	v.ValidatePassword("password", "short")
	v.ValidateRequired("name", "")

	assert.False(t, v.Valid())
	assert.Len(t, v.Errors(), 3)
}

func TestValidator_ChainedValidation(t *testing.T) {
	v := New()

	v.ValidateEmail("email", "test@example.com")
	v.ValidatePassword("password", "SecurePass123!")
	v.ValidateUsername("username", "john_doe")

	assert.True(t, v.Valid())
	assert.Empty(t, v.Errors())
}