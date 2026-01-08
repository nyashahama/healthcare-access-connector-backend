// Package templates manages email templates
package templates

import (
	"bytes"
	"fmt"
	"html/template"
	"time"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/email/types"
)

// Manager handles email template rendering
type Manager struct {
	config    *types.Config
	templates map[types.EmailTemplate]*template.Template
	base      *template.Template
	parser    *Parser
}

// NewManager creates a new template manager
func NewManager(cfg *types.Config) (*Manager, error) {
	parser, err := NewParser()
	if err != nil {
		return nil, fmt.Errorf("failed to create parser: %w", err)
	}

	manager := &Manager{
		config:    cfg,
		templates: make(map[types.EmailTemplate]*template.Template),
		parser:    parser,
	}

	// Load base template
	baseTmpl, err := template.New("base").Parse(baseTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base template: %w", err)
	}
	manager.base = baseTmpl

	// Load all templates
	if err := manager.loadTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load templates: %w", err)
	}

	return manager, nil
}

// loadTemplates loads all email templates
func (m *Manager) loadTemplates() error {
	templates := map[types.EmailTemplate]string{
		types.TemplateWelcome:         welcomeTemplate,
		types.TemplatePasswordReset:   passwordResetTemplate,
		types.TemplateVerification:    verificationTemplate,
		types.TemplatePasswordChanged: passwordChangedTemplate,
		types.TemplateLoginAlert:      loginAlertTemplate,
		types.TemplateOTP:             otpTemplate,
	}

	for tmplType, content := range templates {
		tmpl, err := template.New(string(tmplType)).Parse(content)
		if err != nil {
			return fmt.Errorf("failed to parse template %s: %w", tmplType, err)
		}
		m.templates[tmplType] = tmpl
	}

	return nil
}

// renderTemplate renders a template with base wrapper
func (m *Manager) renderTemplate(tmplType types.EmailTemplate, title string, data map[string]interface{}) (html string) {
	// Set default data
	if data == nil {
		data = make(map[string]interface{})
	}
	
	data["Title"] = title
	data["AppName"] = "Healthcare Access Connector"
	data["SupportEmail"] = "support@healthcare-access-connector.com"
	data["year"] = time.Now().Year()
	
	// Render content template
	tmpl, exists := m.templates[tmplType]
	if !exists {
		return m.defaultTemplate(title, "Template not found")
	}
	
	var contentBuf bytes.Buffer
	if err := tmpl.Execute(&contentBuf, data); err != nil {
		return m.defaultTemplate(title, "Failed to render template")
	}
	
	data["Content"] = template.HTML(contentBuf.String())
	
	// Render base template
	var baseBuf bytes.Buffer
	if err := m.base.Execute(&baseBuf, data); err != nil {
		return m.defaultTemplate(title, "Failed to render base template")
	}
	
	return baseBuf.String()
}

// RenderWelcome generates welcome email content
func (m *Manager) RenderWelcome(username string) (subject, text, html string) {
	subject = "Welcome to Healthcare Access Connector! 🏥"
	
	text = fmt.Sprintf(`Welcome %s!

We're thrilled to welcome you to Healthcare Access Connector – your new partner in health.

Your account has been successfully created. Here's what you can do now:
• Access personalized health information
• Connect with healthcare providers
• Manage your medical preferences
• Set up health reminders

To get started, sign in to your account:
https://healthcare-access-connector-web.vercel.app/auth/sign-in

Medical Emergency? Call 10177 or go to the nearest emergency room immediately.

Best regards,
The Healthcare Access Connector Team`, username)
	
	html = m.renderTemplate(types.TemplateWelcome, "Welcome to Healthcare Access Connector!", map[string]interface{}{
		"Username": username,
	})
	
	return subject, text, html
}

// RenderPasswordReset generates password reset email
func (m *Manager) RenderPasswordReset(resetToken string) (subject, text, html string) {
	resetURL := fmt.Sprintf("https://healthcare-access-connector-web.vercel.app/auth/reset-password?token=%s", resetToken)
	
	subject = "Reset Your Healthcare Access Connector Password 🔐"
	
	text = fmt.Sprintf(`Password Reset Request

We received a request to reset your password for your Healthcare Access Connector account.

Click the link below to reset your password:
%s

This link will expire in 1 hour.

If you didn't request this password reset, please ignore this email.

Medical Emergency? Call 10177 or go to the nearest emergency room immediately.

Stay safe,
The Healthcare Access Connector Team`, resetURL)
	
	html = m.renderTemplate(types.TemplatePasswordReset, "Reset Your Password", map[string]interface{}{
		"URL":       resetURL,
		"ExpiresIn": "1 hour",
	})
	
	return subject, text, html
}

// RenderVerification generates email verification email
func (m *Manager) RenderVerification(verificationToken string) (subject, text, html string) {
	verifyURL := fmt.Sprintf("https://healthcare-access-connector-web.vercel.app/verify-email?token=%s", verificationToken)
	
	subject = "Verify Your Healthcare Access Connector Email ✉️"
	
	text = fmt.Sprintf(`Verify Your Email Address

Welcome to Healthcare Access Connector! Please verify your email address to complete your registration.

Click the link below to verify your email:
%s

This link will expire in 24 hours.

Medical Emergency? Call 10177 or go to the nearest emergency room immediately.

Thank you,
The Healthcare Access Connector Team`, verifyURL)
	
	html = m.renderTemplate(types.TemplateVerification, "Verify Your Email", map[string]interface{}{
		"URL":       verifyURL,
		"ExpiresIn": "24 hours",
	})
	
	return subject, text, html
}

// RenderPasswordChanged generates password changed notification
func (m *Manager) RenderPasswordChanged(username string) (subject, text, html string) {
	currentTime := time.Now().Format("January 2, 2006 at 3:04 PM")
	
	subject = "Your Healthcare Access Connector Password Was Changed 🔒"
	
	text = fmt.Sprintf(`Password Changed Successfully

Hi %s,

Your Healthcare Access Connector password was successfully changed on %s.

If you made this change, no further action is needed.

If you DID NOT make this change, please reset your password immediately.

Medical Emergency? Call 10177 or go to the nearest emergency room immediately.

Stay secure,
The Healthcare Access Connector Team`, username, currentTime)
	
	html = m.renderTemplate(types.TemplatePasswordChanged, "Password Changed", map[string]interface{}{
		"Username": username,
		"Time":     currentTime,
	})
	
	return subject, text, html
}

// RenderLoginAlert generates suspicious login alert
func (m *Manager) RenderLoginAlert(username, ipAddress, location string) (subject, text, html string) {
	currentTime := time.Now().Format("January 2, 2006 at 3:04 PM")
	
	subject = "New Login Detected on Your Healthcare Account 🔔"
	
	text = fmt.Sprintf(`New Login Alert

Hi %s,

We detected a new login to your Healthcare Access Connector account:

Time: %s
IP Address: %s
Location: %s

If this was you, no action is needed.

Medical Emergency? Call 10177 or go to the nearest emergency room immediately.

Stay safe,
Healthcare Access Connector Security Team`, username, currentTime, ipAddress, location)
	
	html = m.renderTemplate(types.TemplateLoginAlert, "New Login Alert", map[string]interface{}{
		"Username":  username,
		"Timestamp": currentTime,
		"IPAddress": ipAddress,
		"Location":  location,
	})
	
	return subject, text, html
}

// RenderOTP generates OTP email template
func (m *Manager) RenderOTP(email, otp, username string) (subject, text, html string) {
	subject = "Your Password Reset Code - Healthcare Access Connector 🔢"
	
	greeting := "Hello,"
	if username != "" {
		greeting = fmt.Sprintf("Hello %s,", username)
	}
	
	text = fmt.Sprintf(`Password Reset Code

%s

Your password reset verification code is:

%s

This code will expire in 10 minutes.

Medical Emergency? Call 10177 or go to the nearest emergency room immediately.

Stay secure,
Healthcare Access Connector Team`, greeting, otp)
	
	html = m.renderTemplate(types.TemplateOTP, "Your Verification Code", map[string]interface{}{
		"Username":  username,
		"OTP":       otp,
		"Action":    "password reset",
		"ExpiresIn": "10 minutes",
	})
	
	return subject, text, html
}

// defaultTemplate creates a simple fallback template
func (m *Manager) defaultTemplate(title, message string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s</title>
</head>
<body>
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2>%s</h2>
        <p>%s</p>
    </div>
</body>
</html>`, title, title, message)
}

// Template strings (these would be in separate template files in production)
const (
	baseTemplate = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{{.Title}} - {{.AppName}}</title>
    <style>
      /* CSS from base.html */
      body {
        margin: 0;
        padding: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Roboto",
          "Oxygen", "Ubuntu", "Cantarell", "Fira Sans", "Droid Sans",
          "Helvetica Neue", sans-serif;
        line-height: 1.6;
        color: #1e293b;
        background-color: #f8fafc;
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
      }
      /* ... rest of the CSS from base.html ... */
    </style>
  </head>
  <body>
    <div class="email-wrapper">
      <div class="email-container">
        <div class="header">
          <div class="logo-container">
            <div class="logo">
              <span class="logo-icon">🏥</span>{{.AppName}}
            </div>
          </div>
          <h1>{{.Title}}</h1>
        </div>
        <div class="content">{{.Content}}</div>
        {{if .EmergencyInfo}}
        <div class="emergency-notice">
          <strong>⚠️ Medical Emergency?</strong>
          <p>{{.EmergencyInfo}}</p>
        </div>
        {{end}}
        <div class="footer">
          <div class="footer-links">
            <a href="https://healthcare-access-connector-web.vercel.app/">Home</a>
            <a href="https://healthcare-access-connector-web.vercel.app/auth/sign-in">Sign In</a>
            <a href="https://healthcare-access-connector-web.vercel.app/help">Help Center</a>
            <a href="https://healthcare-access-connector-web.vercel.app/privacy">Privacy Policy</a>
            <a href="https://healthcare-access-connector-web.vercel.app/terms">Terms of Service</a>
          </div>
          <p class="copyright">
            © {{.year}} {{.AppName}}. All rights reserved.<br />
            This email was sent to you as part of our healthcare services.<br />
            If you have any questions, contact us at {{.SupportEmail}}
          </p>
        </div>
      </div>
    </div>
  </body>
</html>`

	welcomeTemplate = `{{define "welcome"}}
<h2>Welcome aboard, {{.Username}}! 👋</h2>

<p>
  We're thrilled to welcome you to {{.AppName}} – your new partner in health and
  wellness.
</p>

<p>Your account has been successfully created and you're now ready to:</p>

<ul>
  <li>Access personalized health information</li>
  <li>Connect with healthcare providers</li>
  <li>Manage your medical preferences</li>
  <li>Set up health reminders and alerts</li>
  <li>Track your health journey securely</li>
</ul>

<a
  href="https://healthcare-access-connector-web.vercel.app/auth/sign-in"
  class="button button-success"
>
  Sign In to Your Account
</a>

<div class="info-box">
  <h3>🔐 Security First</h3>
  <p>
    We use industry-standard encryption to protect your health data. Always keep
    your login credentials secure and never share them with anyone.
  </p>
  <p>
    <strong>Recommended:</strong> Enable two-factor authentication in your
    account settings for added security.
  </p>
</div>

<div class="success-box">
  <h3>🎉 Getting Started</h3>
  <p>Complete your profile to get personalized recommendations:</p>
  <ol>
    <li>Add your medical history (optional)</li>
    <li>Set up emergency contacts</li>
    <li>Configure notification preferences</li>
    <li>Connect with healthcare providers</li>
  </ol>
</div>

<p style="color: #64748b; font-size: 14px; margin-top: 30px">
  If you have any questions or need assistance, our support team is here to
  help.<br />
  Email us at:
  <a href="mailto:{{.SupportEmail}}" style="color: #3b82f6"
    >{{.SupportEmail}}</a
  >
</p>
{{end}}`

	passwordResetTemplate = `{{define "password_reset"}}
<h2>Password Reset Request 🔐</h2>

<p>
  We received a request to reset your password for your {{.AppName}} account.
</p>

<p>Click the button below to securely reset your password:</p>

<a href="{{.URL}}" class="button"> Reset Your Password </a>

<div class="warning-box">
  <h3>⏰ Link Expires Soon</h3>
  <p>
    This password reset link will expire in <strong>{{.ExpiresIn}}</strong> for
    your security.
  </p>
  <p>If the link expires, you can request a new one from the login page.</p>
</div>

<div class="info-box">
  <h3>🔒 Didn't Request This?</h3>
  <p>
    If you <strong>DID NOT</strong> request a password reset, please ignore this
    email. Your account remains secure.
  </p>
  <p>For added security, we recommend:</p>
  <ul>
    <li>Review your recent account activity</li>
    <li>Update your security settings</li>
    <li>Contact support if you notice anything suspicious</li>
  </ul>
</div>

<p
  style="
    color: #64748b;
    font-size: 13px;
    border-top: 1px solid #e2e8f0;
    padding-top: 20px;
    margin-top: 30px;
  "
>
  <strong>Note:</strong> For your security, this link can only be used once.<br />
  If you need another reset link, request a new one at:
  <a
    href="https://healthcare-access-connector-web.vercel.app/auth/forgot-password"
    style="color: #3b82f6"
    >Forgot Password</a
  >
</p>

<p style="color: #64748b; font-size: 12px; margin-top: 10px">
  Or copy and paste this URL into your browser:<br />
  <code
    style="
      background: #f1f5f9;
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 11px;
      word-break: break-all;
      display: inline-block;
      margin-top: 5px;
    "
    >{{.URL}}</code
  >
</p>
{{end}}`

	loginAlertTemplate = `{{define "login_alert"}}
<h2>New Login Detected 🔔</h2>

<p>Hi {{.Username}},</p>

<p>We detected a new login to your {{.AppName}} account:</p>

<div class="info-box">
  <h3>📋 Login Details</h3>
  <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
    <tr>
      <td style="padding: 8px 0; border-bottom: 1px solid #e2e8f0;"><strong>Time:</strong></td>
      <td style="padding: 8px 0; border-bottom: 1px solid #e2e8f0; text-align: right;">{{.Timestamp}}</td>
    </tr>
    <tr>
      <td style="padding: 8px 0; border-bottom: 1px solid #e2e8f0;"><strong>IP Address:</strong></td>
      <td style="padding: 8px 0; border-bottom: 1px solid #e2e8f0; text-align: right;"><code>{{.IPAddress}}</code></td>
    </tr>
    <tr>
      <td style="padding: 8px 0;"><strong>Location:</strong></td>
      <td style="padding: 8px 0; text-align: right;">{{.Location}}</td>
    </tr>
  </table>
</div>

<div class="info-box">
  <h3> This Was You?</h3>
  <p>If you recognize this login activity, no further action is needed. Your account remains secure.</p>
</div>

<div class="warning-box">
  <h3>⚠️ Don't Recognize This Login?</h3>
  <p>If you <strong>DON'T</strong> recognize this activity, please take immediate action:</p>
  <ol>
    <li>Change your password immediately</li>
    <li>Review your recent account activity</li>
    <li>Enable two-factor authentication</li>
    <li>Contact our security team at {{.SupportEmail}}</li>
  </ol>
  <a
    href="https://healthcare-access-connector-web.vercel.app/auth/forgot-password"
    class="button button-danger"
  >
    Reset Password Now
  </a>
</div>

<h3>🔒 Security Tips</h3>
<ul>
  <li>Use strong, unique passwords for all your accounts</li>
  <li>Enable login notifications in your account settings</li>
  <li>Regularly review your account activity</li>
  <li>Never share your login credentials with anyone</li>
</ul>

<p style="color: #64748b; font-size: 13px; margin-top: 30px;">
  <strong>Note:</strong> This is an automated security alert. If you have any concerns,
  please contact our security team immediately.
</p>
{{end}}`

	otpTemplate = `{{define "otp"}}
<h2>Your Verification Code 🔢</h2>

<p>Hello {{.Username}},</p>

<p>Your verification code for {{.AppName}} is:</p>

<div class="otp-container">
  <div class="otp-code">{{.OTP}}</div>
  <p style="color: #64748b; font-size: 14px; margin-top: 10px;">
    Use this code to complete your {{.Action}}
  </p>
</div>

<div class="warning-box">
  <h3>⏰ Code Expires Soon</h3>
  <p>This verification code will expire in <strong>{{.ExpiresIn}}</strong> for your security.</p>
  <p>If the code expires, you can request a new one.</p>
</div>

<div class="info-box">
  <h3>🔒 Security Notice</h3>
  <p><strong>Never share this code with anyone.</strong> Our team will never ask for this code.</p>
  <p>If you didn't request this code, please:</p>
  <ul>
    <li>Ignore this email</li>
    <li>Review your account security</li>
    <li>Contact support if you notice suspicious activity</li>
  </ul>
</div>

<p style="color: #64748b; font-size: 14px; margin-top: 30px;">
  <strong>Need help?</strong> Contact our support team at {{.SupportEmail}}
</p>
{{end}}`

	verificationTemplate = `{{define "verification"}}
<h2>Verify Your Email Address ✉️</h2>

<p>Welcome to {{.AppName}}! Please verify your email address to complete your registration.</p>

<p>Click the button below to verify your email address:</p>

<a href="{{.URL}}" class="button button-success">
  Verify Email Address
</a>

<div class="info-box">
  <h3>🎉 What's Next?</h3>
  <p>After verification, you'll have access to:</p>
  <ul>
    <li><strong>Health Dashboard:</strong> Personalized health insights</li>
    <li><strong>Appointments:</strong> Schedule with healthcare providers</li>
    <li><strong>Medical Records:</strong> Secure access to your health data</li>
    <li><strong>Messaging:</strong> Secure communication with providers</li>
    <li><strong>Reminders:</strong> Medication and appointment alerts</li>
  </ul>
</div>

<div class="warning-box">
  <h3>⏰ Link Expires</h3>
  <p>This verification link will expire in <strong>{{.ExpiresIn}}</strong>.</p>
</div>

<p style="color: #64748b; font-size: 14px; margin-top: 30px;">
  If you didn't create an account, please ignore this email.<br />
  If you're having trouble with the link, copy and paste this URL into your browser:<br />
  <code style="
    background: #f1f5f9;
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 12px;
    word-break: break-all;
    display: inline-block;
    margin-top: 5px;
  ">{{.URL}}</code>
</p>
{{end}}`

	passwordChangedTemplate = `{{define "password_changed"}}
<h2>Password Changed Successfully 🔒</h2>

<p>Hi {{.Username}},</p>

<p>Your {{.AppName}} password was successfully changed on <strong>{{.Time}}</strong>.</p>

<div class="info-box">
  <h3> You're All Set</h3>
  <p>If you made this change, no further action is needed. Your account is now secured with your new password.</p>
</div>

<div class="warning-box">
  <h3>⚠️ Didn't Make This Change?</h3>
  <p>If you <strong>DID NOT</strong> make this change, please take immediate action:</p>
  <ol>
    <li>
      <strong>Reset your password immediately:</strong><br />
      <a href="https://healthcare-access-connector-web.vercel.app/auth/forgot-password" style="color: #3b82f6">Reset Password Now</a>
    </li>
    <li><strong>Review your recent account activity</strong></li>
    <li>
      <strong>Contact our security team if you notice anything suspicious</strong><br />
      Email: security@healthcare-access-connector.com
    </li>
  </ol>
</div>

<h3>🔐 Security Recommendations</h3>
<p>For optimal account security, we recommend:</p>
<ul>
  <li>Use a strong, unique password (8+ characters with letters, numbers, and symbols)</li>
  <li>Enable two-factor authentication for added security</li>
  <li>Regularly update your password every 3-6 months</li>
  <li>Never share your login credentials with anyone</li>
</ul>

<p style="color: #64748b; font-size: 13px; border-top: 1px solid #e2e8f0; padding-top: 20px;">
  <strong>Need Help?</strong> Contact our security team at security@healthcare-access-connector.com
</p>
{{end}}`
)