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
	config    *types.Config
	templates map[types.EmailTemplate]*template.Template
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

If you have any questions or need assistance, our support team is here to help.

Medical Emergency? Call 10177 or go to the nearest emergency room immediately.

Best regards,
The Healthcare Access Connector Team`, username)

	content := fmt.Sprintf(`
		<h2>Welcome aboard, %s! 👋</h2>
		
		<p>We're thrilled to welcome you to Healthcare Access Connector – your new partner in health and wellness.</p>
		
		<p>Your account has been successfully created and you're now ready to:</p>
		
		<ul style="margin: 20px 0; padding-left: 20px;">
			<li style="margin-bottom: 8px;">Access personalized health information</li>
			<li style="margin-bottom: 8px;">Connect with healthcare providers</li>
			<li style="margin-bottom: 8px;">Manage your medical preferences</li>
			<li style="margin-bottom: 8px;">Set up health reminders and alerts</li>
			<li>Track your health journey</li>
		</ul>
		
		<p>To get started, sign in to your account:</p>
		
		<table class="btn btn-primary" cellpadding="0" cellspacing="0" border="0">
			<tr>
				<td align="center">
					<table cellpadding="0" cellspacing="0" border="0">
						<tr>
							<td style="background-color: #3b82f6; border-radius: 8px;">
								<a href="https://healthcare-access-connector-web.vercel.app/auth/sign-in" target="_blank" style="color: #ffffff; font-family: 'Inter', Arial, sans-serif; font-size: 14px; font-weight: 600; text-decoration: none; padding: 12px 24px; display: inline-block;">
									Sign In to Your Account
								</a>
							</td>
						</tr>
					</table>
				</td>
			</tr>
		</table>
		
		<div class="info-box">
			<h3>🔐 Security First</h3>
			<p>We use industry-standard encryption to protect your health data. Always keep your login credentials secure and never share them with anyone.</p>
		</div>
		
		<p style="color: #64748b; font-size: 14px;">
			If you have any questions or need assistance, our support team is here to help.<br>
			Email us at: support@healthcare-access-connector.com
		</p>`, username)

	html = m.baseTemplate("Welcome to Healthcare Access Connector!", content)
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

If you didn't request this password reset, please ignore this email. Your account remains secure.

Medical Emergency? Call 10177 or go to the nearest emergency room immediately.

Stay safe,
The Healthcare Access Connector Team`, resetURL)

	content := fmt.Sprintf(`
		<h2>Password Reset Request 🔐</h2>
		
		<p>We received a request to reset your password for your Healthcare Access Connector account.</p>
		
		<p>Click the button below to securely reset your password:</p>
		
		<table class="btn btn-primary" cellpadding="0" cellspacing="0" border="0">
			<tr>
				<td align="center">
					<table cellpadding="0" cellspacing="0" border="0">
						<tr>
							<td style="background-color: #3b82f6; border-radius: 8px;">
								<a href="%s" target="_blank" style="color: #ffffff; font-family: 'Inter', Arial, sans-serif; font-size: 14px; font-weight: 600; text-decoration: none; padding: 12px 24px; display: inline-block;">
									Reset Your Password
								</a>
							</td>
						</tr>
					</table>
				</td>
			</tr>
		</table>
		
		<div class="warning-box">
			<h3>⏰ Link Expires Soon</h3>
			<p>This password reset link will expire in <strong>1 hour</strong> for your security.</p>
		</div>
		
		<div class="info-box">
			<h3>🔒 Didn't Request This?</h3>
			<p>If you didn't request a password reset, please ignore this email. Your account remains secure.</p>
		</div>`, resetURL)

	html = m.baseTemplate("Reset Your Password", content)
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

	content := fmt.Sprintf(`
		<h2>Verify Your Email Address ✉️</h2>
		
		<p>Welcome to Healthcare Access Connector! Please verify your email address to complete your registration.</p>
		
		<table class="btn btn-primary" cellpadding="0" cellspacing="0" border="0">
			<tr>
				<td align="center">
					<table cellpadding="0" cellspacing="0" border="0">
						<tr>
							<td style="background-color: #10b981; border-radius: 8px;">
								<a href="%s" target="_blank" style="color: #ffffff; font-family: 'Inter', Arial, sans-serif; font-size: 14px; font-weight: 600; text-decoration: none; padding: 12px 24px; display: inline-block;">
									Verify Email Address
								</a>
							</td>
						</tr>
					</table>
				</td>
			</tr>
		</table>
		
		<div class="warning-box">
			<h3>⏰ Link Expires</h3>
			<p>This verification link will expire in <strong>24 hours</strong>.</p>
		</div>`, verifyURL)

	html = m.baseTemplate("Verify Your Email", content)
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

Stay secure,
The Healthcare Access Connector Team`, username, currentTime)

	content := fmt.Sprintf(`
		<h2>Password Changed Successfully 🔒</h2>
		
		<p>Hi %s,</p>
		
		<p>Your Healthcare Access Connector password was successfully changed on <strong>%s</strong>.</p>
		
		<div class="info-box">
			<h3>✅ You're All Set</h3>
			<p>If you made this change, no further action is needed.</p>
		</div>
		
		<div class="warning-box">
			<h3>⚠️ Didn't Make This Change?</h3>
			<p>If you <strong>DID NOT</strong> make this change, please reset your password immediately.</p>
		</div>`, username, currentTime)

	html = m.baseTemplate("Password Changed", content)
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

Stay safe,
Healthcare Access Connector Security Team`, username, currentTime, ipAddress, location)

	content := fmt.Sprintf(`
		<h2>New Login Detected 🔔</h2>
		
		<p>Hi %s,</p>
		
		<p>We detected a new login to your Healthcare Access Connector account:</p>
		
		<div class="info-box">
			<h3>📋 Login Details</h3>
			<table style="width: 100%%; border-collapse: collapse; font-size: 14px;">
				<tr>
					<td style="padding: 8px 0;"><strong>Time:</strong></td>
					<td style="padding: 8px 0; text-align: right;">%s</td>
				</tr>
				<tr>
					<td style="padding: 8px 0;"><strong>IP Address:</strong></td>
					<td style="padding: 8px 0; text-align: right;"><code>%s</code></td>
				</tr>
				<tr>
					<td style="padding: 8px 0;"><strong>Location:</strong></td>
					<td style="padding: 8px 0; text-align: right;">%s</td>
				</tr>
			</table>
		</div>`, username, currentTime, template.HTMLEscapeString(ipAddress), template.HTMLEscapeString(location))

	html = m.baseTemplate("New Login Alert", content)
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

	content := fmt.Sprintf(`
		<h2>Password Reset Code 🔢</h2>
		
		<p>%s</p>
		
		<p>Your password reset verification code is:</p>
		
		<div class="otp-container">
			<div class="otp-code">%s</div>
		</div>
		
		<div class="warning-box">
			<h3>⏰ Code Expires Soon</h3>
			<p>This verification code will expire in <strong>10 minutes</strong> for your security.</p>
		</div>
		
		<div class="info-box">
			<h3>🔒 Security Notice</h3>
			<p><strong>Never share this code with anyone.</strong> Our team will never ask for this code.</p>
		</div>`, greeting, otp)

	html = m.baseTemplate("Your Verification Code", content)
	return subject, text, html
}

// baseTemplate provides the common structure for all emails
func (m *Manager) baseTemplate(title, content string) string {
	year := time.Now().Year()

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #1e293b;
            background-color: #f8fafc;
        }
        
        .email-container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
        }
        
        .header {
            background: linear-gradient(135deg, #3b82f6 0%%, #1d4ed8 100%%);
            color: white;
            padding: 40px 30px;
            text-align: center;
        }
        
        .logo {
            font-weight: 700;
            font-size: 24px;
            margin-bottom: 20px;
        }
        
        .header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 700;
        }
        
        .content {
            padding: 40px 30px;
            color: #334155;
        }
        
        .content h2 {
            color: #1e293b;
            font-size: 20px;
            font-weight: 600;
            margin-top: 0;
        }
        
        .otp-container {
            margin: 30px 0;
            text-align: center;
        }
        
        .otp-code {
            display: inline-block;
            background: #f1f5f9;
            padding: 16px 24px;
            border-radius: 12px;
            font-size: 32px;
            font-weight: 700;
            letter-spacing: 8px;
            color: #3b82f6;
            border: 2px dashed #cbd5e1;
            font-family: monospace;
        }
        
        .info-box {
            background: #f0f9ff;
            border-left: 4px solid #3b82f6;
            padding: 20px;
            margin: 30px 0;
            border-radius: 8px;
        }
        
        .info-box h3 {
            color: #1d4ed8;
            margin-top: 0;
            font-size: 16px;
        }
        
        .warning-box {
            background: #fef2f2;
            border-left: 4px solid #dc2626;
            padding: 20px;
            margin: 30px 0;
            border-radius: 8px;
        }
        
        .warning-box h3 {
            color: #dc2626;
            margin-top: 0;
            font-size: 16px;
        }
        
        .footer {
            background: #f8fafc;
            padding: 30px;
            text-align: center;
            border-top: 1px solid #e2e8f0;
        }
        
        .copyright {
            color: #94a3b8;
            font-size: 13px;
        }
        
        .emergency-notice {
            background: linear-gradient(135deg, #dc2626 0%%, #b91c1c 100%%);
            color: white;
            padding: 20px;
            text-align: center;
            margin-top: 20px;
            border-radius: 12px;
        }
    </style>
</head>
<body>
    <div class="email-container">
        <div class="header">
            <div class="logo">🏥 Healthcare Access Connector</div>
            <h1>%s</h1>
        </div>
        
        <div class="content">
            %s
        </div>
        
        <div class="emergency-notice">
            <strong>⚠️ Medical Emergency?</strong>
            <p style="margin: 0; font-size: 14px;">
                Call <strong>10177</strong> or go to the nearest emergency room immediately.
            </p>
        </div>
        
        <div class="footer">
            <p class="copyright">
                © %d Healthcare Access Connector. All rights reserved.
            </p>
        </div>
    </div>
</body>
</html>`, title, content, year)
}