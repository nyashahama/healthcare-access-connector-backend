// Package templates manages email templates
package templates

// Template data structures for rendering

// WelcomeData contains data for welcome emails
type WelcomeData struct {
	Username  string
	SignInURL string
}

// PasswordResetData contains data for password reset emails
type PasswordResetData struct {
	ResetURL string
}

// VerificationData contains data for verification emails
type VerificationData struct {
	VerifyURL string
}

// PasswordChangedData contains data for password changed emails
type PasswordChangedData struct {
	Username string
	Time     string
}

// LoginAlertData contains data for login alert emails
type LoginAlertData struct {
	Username  string
	Time      string
	IPAddress string
	Location  string
}

// OTPData contains data for OTP emails
type OTPData struct {
	Username string
	Email    string
	OTP      string
}
