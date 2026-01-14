// Package templates manages email templates
package templates

import (
	"fmt"
	"html/template"
	"time"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/email/types"
)

// Manager handles email template rendering
type Manager struct {
	config      *types.Config
	templates   map[types.EmailTemplate]*template.Template
	parser      *Parser
	frontendURL string
}

// NewManager creates a new template manager
func NewManager(cfg *types.Config, frontendURL string) (*Manager, error) {
	parser, err := NewParser()
	if err != nil {
		return nil, fmt.Errorf("failed to create parser: %w", err)
	}

	manager := &Manager{
		config:      cfg,
		templates:   make(map[types.EmailTemplate]*template.Template),
		parser:      parser,
		frontendURL: frontendURL,
	}

	// Load all templates
	if err := manager.loadTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load templates: %w", err)
	}

	return manager, nil
}

// loadTemplates loads all email templates
func (m *Manager) loadTemplates() error {
	// For now, we'll use inline templates
	// Later, these can be loaded from files
	return nil
}

// RenderWelcome generates welcome email content
func (m *Manager) RenderWelcome(username string) (subject, text, html string) {
	subject = "Welcome to Healthcare Access Connector"
	signInURL := fmt.Sprintf("%s/auth/sign-in", m.frontendURL)
	supportEmail := m.config.GetSupportAddress()

	text = fmt.Sprintf(`Welcome %s!

We're thrilled to welcome you to Healthcare Access Connector — your new partner in health.

Your account has been successfully created. Here's what you can do now:
• Access personalized health information
• Connect with healthcare providers
• Manage your medical preferences
• Set up health reminders
• Track your health journey

To get started, sign in to your account:
%s

If you have any questions or need assistance, our support team is here to help: %s

Medical Emergency? Call 10177 or go to the nearest emergency room immediately.

Best regards,
The Healthcare Access Connector Team`, username, signInURL, supportEmail)

	content := fmt.Sprintf(`
		<h2>Welcome aboard, %s!</h2>
		
		<p>We're thrilled to welcome you to Healthcare Access Connector — your new partner in health and wellness.</p>
		
		<p>Your account has been successfully created and you're now ready to:</p>
		
		<ul>
			<li>Access personalized health information</li>
			<li>Connect with healthcare providers</li>
			<li>Manage your medical preferences</li>
			<li>Set up health reminders and alerts</li>
			<li>Track your health journey securely</li>
		</ul>
		
		<a href="%s" class="button">
			Sign In to Your Account
		</a>
		
		<div class="info-box">
			<h3>🔒 Security First</h3>
			<p>We use industry-standard encryption to protect your health data. Always keep your login credentials secure and never share them with anyone.</p>
			<p><strong>Recommended:</strong> Enable two-factor authentication in your account settings for added security.</p>
		</div>
		
		<div class="success-box">
			<h3>Getting Started</h3>
			<p>Complete your profile to get personalized recommendations:</p>
			<ol>
				<li>Add your medical history (optional)</li>
				<li>Set up emergency contacts</li>
				<li>Configure notification preferences</li>
				<li>Connect with healthcare providers</li>
			</ol>
		</div>
		
		<p style="color: #6b7280; font-size: 14px; margin-top: 32px;">
			If you have any questions or need assistance, our support team is here to help.<br>
			Email us at: <a href="mailto:%s" style="color: #10b981;">%s</a>
		</p>`, username, signInURL, supportEmail, supportEmail)

	html = m.baseTemplate("Welcome to Healthcare Access Connector", content, supportEmail, true)
	return subject, text, html
}

// RenderPasswordReset generates password reset email
func (m *Manager) RenderPasswordReset(resetToken string) (subject, text, html string) {
	resetURL := fmt.Sprintf("%s/auth/reset-password?token=%s", m.frontendURL, resetToken)
	forgotPasswordURL := fmt.Sprintf("%s/auth/forgot-password", m.frontendURL)
	supportEmail := m.config.GetSupportAddress()

	subject = "Reset Your Healthcare Access Connector Password"

	text = fmt.Sprintf(`Password Reset Request

We received a request to reset your password for your Healthcare Access Connector account.

Click the link below to reset your password:
%s

This link will expire in 1 hour.

If you didn't request this password reset, please ignore this email. Your account remains secure.

Medical Emergency? Call 10177 or go to the nearest emergency room immediately.

Stay safe,
The Healthcare Access Connector Team`, resetURL)

	content := fmt.Sprintf(`
		<h2>Password Reset Request</h2>
		
		<p>We received a request to reset your password for your Healthcare Access Connector account.</p>
		
		<p>Click the button below to securely reset your password:</p>
		
		<a href="%s" class="button">Reset Your Password</a>
		
		<div class="warning-box">
			<h3>⏰ Link Expires Soon</h3>
			<p>This password reset link will expire in <strong>1 hour</strong> for your security.</p>
			<p>If the link expires, you can request a new one from the login page.</p>
		</div>
		
		<div class="info-box">
			<h3>🔐 Didn't Request This?</h3>
			<p>If you <strong>DID NOT</strong> request a password reset, please ignore this email. Your account remains secure.</p>
			<p>For added security, we recommend:</p>
			<ul>
				<li>Review your recent account activity</li>
				<li>Update your security settings</li>
				<li>Contact support if you notice anything suspicious</li>
			</ul>
		</div>
		
		<hr class="divider">
		
		<p style="color: #6b7280; font-size: 13px;">
			<strong>Note:</strong> For your security, this link can only be used once.<br>
			If you need another reset link, request a new one at: 
			<a href="%s" style="color: #10b981;">Forgot Password</a>
		</p>
		
		<p style="color: #9ca3af; font-size: 12px; margin-top: 12px;">
			Or copy and paste this URL into your browser:<br>
			<code style="background: #f3f4f6; padding: 6px 10px; border-radius: 4px; font-size: 11px; word-break: break-all; display: inline-block; margin-top: 4px; color: #1f2937;">%s</code>
		</p>`, resetURL, forgotPasswordURL, resetURL)

	html = m.baseTemplate("Reset Your Password", content, supportEmail, true)
	return subject, text, html
}

// RenderVerification generates email verification email
func (m *Manager) RenderVerification(verificationToken string) (subject, text, html string) {
	verifyURL := fmt.Sprintf("%s/auth/verify-email?token=%s", m.frontendURL, verificationToken)
	supportEmail := m.config.GetSupportAddress()

	subject = "Verify Your Healthcare Access Connector Email"

	text = fmt.Sprintf(`Verify Your Email Address

Welcome to Healthcare Access Connector! Please verify your email address to complete your registration.

Click the link below to verify your email:
%s

This link will expire in 24 hours.

Medical Emergency? Call 10177 or go to the nearest emergency room immediately.

Thank you,
The Healthcare Access Connector Team`, verifyURL)

	content := fmt.Sprintf(`
		<h2>Verify Your Email Address</h2>
		
		<p>Welcome to Healthcare Access Connector! Please verify your email address to complete your registration.</p>
		
		<a href="%s" class="button">Verify Email Address</a>
		
		<div class="success-box">
			<h3>What's Next?</h3>
			<p>After verification, you'll have access to:</p>
			<ul>
				<li><strong>Health Dashboard:</strong> Personalized health insights</li>
				<li><strong>Appointments:</strong> Schedule with healthcare providers</li>
				<li><strong>Medical Records:</strong> Secure access to your health data</li>
				<li><strong>Messaging:</strong> Secure communication with providers</li>
				<li><strong>Reminders:</strong> Medication and appointment alerts</li>
			</ul>
		</div>
		
		<div class="neutral-box">
			<h3>⏰ Link Expires</h3>
			<p>This verification link will expire in <strong>24 hours</strong>.</p>
		</div>
		
		<p style="color: #6b7280; font-size: 14px; margin-top: 28px;">
			If you didn't create an account, please ignore this email.<br>
			If you're having trouble with the link, copy and paste this URL into your browser:
		</p>
		
		<p style="color: #9ca3af; font-size: 12px; margin-top: 8px;">
			<code style="background: #f3f4f6; padding: 6px 10px; border-radius: 4px; font-size: 11px; word-break: break-all; display: inline-block; color: #1f2937;">%s</code>
		</p>`, verifyURL, verifyURL)

	html = m.baseTemplate("Verify Your Email", content, supportEmail, true)
	return subject, text, html
}

// RenderPasswordChanged generates password changed notification
func (m *Manager) RenderPasswordChanged(username string) (subject, text, html string) {
	currentTime := time.Now().Format("January 2, 2006 at 3:04 PM")
	forgotPasswordURL := fmt.Sprintf("%s/auth/forgot-password", m.frontendURL)
	supportEmail := m.config.GetSupportAddress()

	subject = "Your Healthcare Access Connector Password Was Changed"

	text = fmt.Sprintf(`Password Changed Successfully

Hi %s,

Your Healthcare Access Connector password was successfully changed on %s.

If you made this change, no further action is needed.

If you DID NOT make this change, please reset your password immediately.

Stay secure,
The Healthcare Access Connector Team`, username, currentTime)

	content := fmt.Sprintf(`
		<h2>Password Changed Successfully</h2>
		
		<p>Hi %s,</p>
		
		<p>Your Healthcare Access Connector password was successfully changed on <strong>%s</strong>.</p>
		
		<div class="success-box">
			<h3>✓ You're All Set</h3>
			<p>If you made this change, no further action is needed. Your account is secure.</p>
		</div>
		
		<div class="warning-box">
			<h3>⚠️ Didn't Make This Change?</h3>
			<p>If you <strong>DID NOT</strong> make this change, please take immediate action:</p>
			<ol>
				<li>Reset your password immediately</li>
				<li>Review your recent account activity</li>
				<li>Contact our security team: %s</li>
			</ol>
			<a href="%s" class="button">Reset Password Now</a>
		</div>`, username, currentTime, supportEmail, forgotPasswordURL)

	html = m.baseTemplate("Password Changed", content, supportEmail, true)
	return subject, text, html
}

// RenderLoginAlert generates suspicious login alert
func (m *Manager) RenderLoginAlert(username, ipAddress, location string) (subject, text, html string) {
	currentTime := time.Now().Format("January 2, 2006 at 3:04 PM")
	forgotPasswordURL := fmt.Sprintf("%s/auth/forgot-password", m.frontendURL)
	supportEmail := m.config.GetSupportAddress()

	subject = "New Login Detected on Your Healthcare Account"

	text = fmt.Sprintf(`New Login Alert

Hi %s,

We detected a new login to your Healthcare Access Connector account:

Time: %s
IP Address: %s
Location: %s

If this was you, no action is needed.

If you don't recognize this activity, contact our security team: %s

Stay safe,
Healthcare Access Connector Security Team`, username, currentTime, ipAddress, location, supportEmail)

	content := fmt.Sprintf(`
		<h2>New Login Detected</h2>
		
		<p>Hi %s,</p>
		
		<p>We detected a new login to your Healthcare Access Connector account:</p>
		
		<div class="neutral-box">
			<h3>📋 Login Details</h3>
			<table class="data-table">
				<tr>
					<td><strong>Time:</strong></td>
					<td>%s</td>
				</tr>
				<tr>
					<td><strong>IP Address:</strong></td>
					<td><code>%s</code></td>
				</tr>
				<tr>
					<td><strong>Location:</strong></td>
					<td>%s</td>
				</tr>
			</table>
		</div>
		
		<div class="info-box">
			<h3>This Was You?</h3>
			<p>If you recognize this login activity, no further action is needed. Your account remains secure.</p>
		</div>
		
		<div class="warning-box">
			<h3>⚠️ Don't Recognize This Login?</h3>
			<p>If you <strong>DON'T</strong> recognize this activity, please take immediate action:</p>
			<ol>
				<li>Change your password immediately</li>
				<li>Review your recent account activity</li>
				<li>Enable two-factor authentication</li>
				<li>Contact our security team at %s</li>
			</ol>
			<a href="%s" class="button">Reset Password Now</a>
		</div>
		
		<hr class="divider">
		
		<h3>🔐 Security Tips</h3>
		<ul>
			<li>Use strong, unique passwords for all your accounts</li>
			<li>Enable login notifications in your account settings</li>
			<li>Regularly review your account activity</li>
			<li>Never share your login credentials with anyone</li>
		</ul>
		
		<p style="color: #6b7280; font-size: 13px; margin-top: 28px;">
			<strong>Note:</strong> This is an automated security alert. If you have any concerns, please contact our security team immediately.
		</p>`, username, currentTime, template.HTMLEscapeString(ipAddress), template.HTMLEscapeString(location), supportEmail, forgotPasswordURL)

	html = m.baseTemplate("New Login Alert", content, supportEmail, false)
	return subject, text, html
}

// RenderOTP generates OTP email template
func (m *Manager) RenderOTP(email, otp, username string) (subject, text, html string) {
	subject = "Your Verification Code - Healthcare Access Connector"
	supportEmail := m.config.GetSupportAddress()

	greeting := "Hello,"
	if username != "" {
		greeting = fmt.Sprintf("Hello %s,", username)
	}

	text = fmt.Sprintf(`Your Verification Code

%s

Your verification code is:

%s

This code will expire in 10 minutes.

Medical Emergency? Call 10177 or go to the nearest emergency room immediately.

Stay secure,
Healthcare Access Connector Team`, greeting, otp)

	content := fmt.Sprintf(`
		<h2>Your Verification Code</h2>
		
		<p>%s</p>
		
		<p>Your verification code for Healthcare Access Connector is:</p>
		
		<div class="otp-container">
			<div class="otp-code">%s</div>
			<p style="color: #6b7280; font-size: 14px; margin-top: 10px;">
				Use this code to complete your password reset
			</p>
		</div>
		
		<div class="warning-box">
			<h3>⏰ Code Expires Soon</h3>
			<p>This verification code will expire in <strong>10 minutes</strong> for your security.</p>
			<p>If the code expires, you can request a new one.</p>
		</div>
		
		<div class="info-box">
			<h3>🔒 Security Notice</h3>
			<p><strong>Never share this code with anyone.</strong> Our team will never ask for this code.</p>
			<p>If you didn't request this code, please:</p>
			<ul>
				<li>Ignore this email</li>
				<li>Review your account security</li>
				<li>Contact support if you notice suspicious activity: %s</li>
			</ul>
		</div>
		
		<p style="color: #6b7280; font-size: 14px; margin-top: 28px;">
			<strong>Need help?</strong> Contact our support team at %s
		</p>`, greeting, otp, supportEmail, supportEmail)

	html = m.baseTemplate("Your Verification Code", content, supportEmail, true)
	return subject, text, html
}

// baseTemplate provides the common structure for all emails
func (m *Manager) baseTemplate(title, content string, supportEmail string, showEmergency bool) string {
	year := time.Now().Year()

	emergencySection := ""
	if showEmergency {
		emergencySection = `
		<div class="emergency-notice">
			<strong>⚠️ Medical Emergency?</strong>
			<p>Call 10177 or go to the nearest emergency room immediately.</p>
		</div>`
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background-color: #f9fafb;
        }
        
        .email-wrapper {
            max-width: 100%%;
            width: 100%%;
            margin: 0 auto;
            background-color: #f9fafb;
            padding: 40px 20px;
        }
        
        .email-container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
            border: 1px solid #e5e7eb;
        }
        
        .header {
            background-color: #ffffff;
            border-bottom: 3px solid #10b981;
            color: #1f2937;
            padding: 40px 40px 32px;
            text-align: left;
        }
        
        .logo-container {
            margin-bottom: 24px;
        }
        
        .logo {
            font-weight: 600;
            font-size: 18px;
            letter-spacing: -0.3px;
            color: #1f2937;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .header h1 {
            margin: 0;
            font-size: 26px;
            font-weight: 600;
            letter-spacing: -0.5px;
            line-height: 1.3;
            color: #111827;
        }
        
        .content {
            padding: 40px;
            color: #4b5563;
            font-size: 15px;
            line-height: 1.7;
        }
        
        .content h2 {
            color: #111827;
            font-size: 20px;
            font-weight: 600;
            margin-top: 0;
            margin-bottom: 16px;
        }
        
        .content h3 {
            color: #1f2937;
            font-size: 17px;
            font-weight: 600;
            margin-top: 28px;
            margin-bottom: 12px;
        }
        
        .content p {
            margin-bottom: 16px;
        }
        
        .content ul, .content ol {
            margin: 16px 0;
            padding-left: 24px;
        }
        
        .content li {
            margin-bottom: 8px;
        }
        
        .button {
            display: inline-block;
            background-color: #10b981;
            color: white;
            text-decoration: none;
            padding: 14px 28px;
            border-radius: 6px;
            font-weight: 500;
            font-size: 15px;
            margin: 20px 0;
        }
        
        .info-box {
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-left: 3px solid #10b981;
            padding: 20px;
            margin: 24px 0;
            border-radius: 6px;
        }
        
        .info-box h3 {
            color: #059669;
            margin-top: 0;
            margin-bottom: 8px;
            font-size: 15px;
            font-weight: 600;
        }
        
        .info-box p {
            margin-bottom: 12px;
            font-size: 14px;
        }
        
        .info-box p:last-child {
            margin-bottom: 0;
        }
        
        .warning-box {
            background: #fef9f9;
            border: 1px solid #fee2e2;
            border-left: 3px solid #dc2626;
            padding: 20px;
            margin: 24px 0;
            border-radius: 6px;
        }
        
        .warning-box h3 {
            color: #dc2626;
            margin-top: 0;
            margin-bottom: 8px;
            font-size: 15px;
            font-weight: 600;
        }
        
        .success-box {
            background: #f6fef9;
            border: 1px solid #d1fae5;
            border-left: 3px solid #10b981;
            padding: 20px;
            margin: 24px 0;
            border-radius: 6px;
        }
        
        .success-box h3 {
            color: #059669;
            margin-top: 0;
            margin-bottom: 8px;
            font-size: 15px;
            font-weight: 600;
        }
        
        .neutral-box {
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-left: 3px solid #6b7280;
            padding: 20px;
            margin: 24px 0;
            border-radius: 6px;
        }
        
        .neutral-box h3 {
            color: #374151;
            margin-top: 0;
            margin-bottom: 8px;
            font-size: 15px;
            font-weight: 600;
        }
        
        .otp-container {
            margin: 28px 0;
            text-align: center;
        }
        
        .otp-code {
            display: inline-block;
            background: #ffffff;
            padding: 16px 32px;
            border-radius: 8px;
            font-size: 32px;
            font-weight: 600;
            letter-spacing: 12px;
            color: #111827;
            border: 2px solid #e5e7eb;
            font-family: monospace;
            margin: 10px 0;
        }
        
        .footer {
            background: #f9fafb;
            padding: 32px 40px;
            border-top: 1px solid #e5e7eb;
        }
        
        .footer-links {
            margin: 0 0 20px 0;
            display: flex;
            justify-content: flex-start;
            gap: 20px;
            flex-wrap: wrap;
        }
        
        .footer-links a {
            color: #6b7280;
            text-decoration: none;
            font-size: 13px;
        }
        
        .copyright {
            color: #9ca3af;
            font-size: 12px;
            line-height: 1.6;
        }
        
        .emergency-notice {
            background: #fef2f2;
            border: 1px solid #fecaca;
            color: #991b1b;
            padding: 16px 20px;
            margin: 24px 40px;
            border-radius: 6px;
            text-align: center;
        }
        
        .emergency-notice strong {
            font-size: 14px;
            font-weight: 600;
            display: block;
            margin-bottom: 4px;
        }
        
        .emergency-notice p {
            margin: 0;
            font-size: 13px;
        }
        
        .divider {
            height: 1px;
            background-color: #e5e7eb;
            margin: 32px 0;
            border: none;
        }
        
        .data-table {
            width: 100%%;
            border-collapse: collapse;
            font-size: 14px;
            margin: 16px 0;
        }
        
        .data-table tr {
            border-bottom: 1px solid #e5e7eb;
        }
        
        .data-table tr:last-child {
            border-bottom: none;
        }
        
        .data-table td {
            padding: 12px 0;
            color: #4b5563;
        }
        
        .data-table td:first-child {
            font-weight: 500;
            color: #1f2937;
        }
        
        .data-table td:last-child {
            text-align: right;
        }
        
        .data-table code {
            background: #f3f4f6;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 13px;
            color: #1f2937;
        }
        
        @media (max-width: 600px) {
            .email-wrapper {
                padding: 20px 10px;
            }
            
            .header, .content, .footer {
                padding: 32px 24px;
            }
            
            .emergency-notice {
                margin: 24px 24px;
            }
            
            .header h1 {
                font-size: 22px;
            }
            
            .otp-code {
                font-size: 26px;
                letter-spacing: 8px;
            }
        }
    </style>
</head>
<body>
    <div class="email-wrapper">
        <div class="email-container">
            <div class="header">
                <div class="logo-container">
                    <div class="logo">
                        <span>🏥</span>
                        <span>Healthcare Access Connector</span>
                    </div>
                </div>
                <h1>%s</h1>
            </div>
            
            <div class="content">
                %s
            </div>
            
            %s
            
            <div class="footer">
                <div class="footer-links">
                    <a href="%s/">Home</a>
                    <a href="%s/auth/sign-in">Sign In</a>
                    <a href="%s/help">Help</a>
                    <a href="%s/privacy">Privacy</a>
                    <a href="%s/terms">Terms</a>
                </div>
                <p class="copyright">
                    © %d Healthcare Access Connector. All rights reserved.<br>
                    Questions? Contact %s
                </p>
            </div>
        </div>
    </div>
</body>
</html>`, title, content, emergencySection, m.frontendURL, m.frontendURL, m.frontendURL, m.frontendURL, m.frontendURL, year, supportEmail)
}
