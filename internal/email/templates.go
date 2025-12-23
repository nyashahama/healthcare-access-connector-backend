// Package email provides email templates
package email

import (
	"fmt"
	"html/template"
	"strings"
	"time"
)

type TemplateManager struct {
	config *Config
}

func NewTemplateManager(cfg *Config) *TemplateManager {
	return &TemplateManager{config: cfg}
}

// baseTemplate provides the common structure for all emails
func (tm *TemplateManager) baseTemplate(title, content, actionButtonText, actionButtonURL string) (html string) {
	year := time.Now().Year()

	// Build action button if provided
	actionSection := ""
	fmt.Println(actionSection)
	if actionButtonText != "" && actionButtonURL != "" {
		actionSection = fmt.Sprintf(`
			<table class="btn btn-primary" cellpadding="0" cellspacing="0" border="0">
				<tr>
					<td align="center">
						<table cellpadding="0" cellspacing="0" border="0">
							<tr>
								<td style="background-color: #3b82f6; border-radius: 8px;">
									<a href="%s" target="_blank" style="color: #ffffff; font-family: 'Inter', Arial, sans-serif; font-size: 14px; font-weight: 600; text-decoration: none; padding: 12px 24px; display: inline-block;">
										%s
									</a>
								</td>
							</tr>
						</table>
					</td>
				</tr>
			</table>`, actionButtonURL, actionButtonText)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        /* Base Styles */
        body {
            margin: 0;
            padding: 0;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
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
            position: relative;
        }
        
        .logo-container {
            margin-bottom: 20px;
        }
        
        .logo {
            font-weight: 700;
            font-size: 24px;
            letter-spacing: -0.5px;
        }
        
        .logo-icon {
            color: #60a5fa;
            margin-right: 8px;
        }
        
        .header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }
        
        .header p {
            margin: 10px 0 0;
            opacity: 0.9;
            font-size: 16px;
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
            margin-bottom: 16px;
        }
        
        .content p {
            margin-bottom: 20px;
            font-size: 15px;
            line-height: 1.7;
        }
        
        /* OTP Display */
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
            font-family: 'SF Mono', 'Roboto Mono', monospace;
        }
        
        /* Info Box */
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
            font-weight: 600;
        }
        
        /* Warning Box */
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
            font-weight: 600;
        }
        
        /* Footer */
        .footer {
            background: #f8fafc;
            padding: 30px;
            text-align: center;
            border-top: 1px solid #e2e8f0;
        }
        
        .footer-links {
            margin: 20px 0;
        }
        
        .footer-links a {
            color: #64748b;
            text-decoration: none;
            margin: 0 12px;
            font-size: 14px;
        }
        
        .footer-links a:hover {
            color: #3b82f6;
        }
        
        .copyright {
            color: #94a3b8;
            font-size: 13px;
            margin-top: 20px;
        }
        
        /* Emergency Notice */
        .emergency-notice {
            background: linear-gradient(135deg, #dc2626 0%%, #b91c1c 100%%);
            color: white;
            padding: 20px;
            text-align: center;
            margin-top: 20px;
            border-radius: 12px;
        }
        
        .emergency-notice strong {
            font-size: 18px;
            display: block;
            margin-bottom: 8px;
        }
        
        /* Responsive */
        @media (max-width: 600px) {
            .email-container {
                border-radius: 0;
            }
            
            .header, .content, .footer {
                padding: 30px 20px;
            }
            
            .header h1 {
                font-size: 24px;
            }
            
            .otp-code {
                font-size: 24px;
                letter-spacing: 6px;
                padding: 12px 20px;
            }
        }
    </style>
</head>
<body>
    <div class="email-container">
        <!-- Header -->
        <div class="header">
            <div class="logo-container">
                <div class="logo">
                    <span class="logo-icon">🏥</span>Healthcare Access Connector
                </div>
            </div>
            <h1>%s</h1>
        </div>
        
        <!-- Content -->
        <div class="content">
            %s
        </div>
        
        <!-- Emergency Notice (only for medical-related emails) -->
        <div class="emergency-notice">
            <strong>⚠️ Medical Emergency?</strong>
            <p style="margin: 0; font-size: 14px; opacity: 0.9;">
                Call <strong>10177</strong> or go to the nearest emergency room immediately.
            </p>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <div class="footer-links">
                <a href="https://healthcare-access-connector-web.vercel.app/">Home</a>
                <a href="https://healthcare-access-connector-web.vercel.app/auth/sign-in">Sign In</a>
                <a href="https://healthcare-access-connector-web.vercel.app/help">Help Center</a>
            </div>
            <p class="copyright">
                © %d Healthcare Access Connector. All rights reserved.<br>
                This email was sent to you as part of our healthcare services.
            </p>
        </div>
    </div>
</body>
</html>`, title, content, year)
}

// RenderWelcome generates welcome email content
func (tm *TemplateManager) RenderWelcome(username string) (subject, text, html string) {
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

	html = tm.baseTemplate("Welcome to Healthcare Access Connector!", content, "", "")
	return subject, text, html
}

// RenderPasswordReset generates password reset email
func (tm *TemplateManager) RenderPasswordReset(resetToken string) (subject, text, html string) {
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
			<p>If you didn't request a password reset, please ignore this email. Your account remains secure. For added security, you might want to:</p>
			<ul style="margin: 10px 0 0 20px; font-size: 14px;">
				<li style="margin-bottom: 5px;">Review your recent account activity</li>
				<li style="margin-bottom: 5px;">Update your security settings</li>
				<li>Contact support if you notice anything suspicious</li>
			</ul>
		</div>
		
		<p style="color: #64748b; font-size: 13px; border-top: 1px solid #e2e8f0; padding-top: 20px; margin-top: 30px;">
			<strong>Note:</strong> For your security, this link can only be used once. If you need another reset link, 
			you can request a new one at: <a href="https://healthcare-access-connector-web.vercel.app/auth/forgot-password" style="color: #3b82f6;">Forgot Password</a>
		</p>`, resetURL)

	html = tm.baseTemplate("Reset Your Password", content, "", "")
	return subject, text, html
}

// RenderVerification generates email verification email
func (tm *TemplateManager) RenderVerification(verificationToken string) (subject, text, html string) {
	verifyURL := fmt.Sprintf("https://healthcare-access-connector-web.vercel.app/verify-email?token=%s", verificationToken)

	subject = "Verify Your Healthcare Access Connector Email ✅"

	text = fmt.Sprintf(`Verify Your Email Address

Welcome to Healthcare Access Connector! Please verify your email address to complete your registration.

Click the link below to verify your email:
%s

This link will expire in 24 hours.

By verifying your email, you'll gain full access to:
• Your health dashboard
• Appointment scheduling
• Medical record access
• Secure messaging

If you didn't create an account, please ignore this email.

Medical Emergency? Call 10177 or go to the nearest emergency room immediately.

Thank you,
The Healthcare Access Connector Team`, verifyURL)

	content := fmt.Sprintf(`
		<h2>Verify Your Email Address ✅</h2>
		
		<p>Welcome to Healthcare Access Connector! Please verify your email address to complete your registration and access all features.</p>
		
		<p>Click the button below to verify your email:</p>
		
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
		
		<div class="info-box">
			<h3>🎉 What's Next?</h3>
			<p>After verification, you'll have access to:</p>
			<ul style="margin: 10px 0 0 20px; font-size: 14px;">
				<li style="margin-bottom: 5px;"><strong>Health Dashboard:</strong> Personalized health insights</li>
				<li style="margin-bottom: 5px;"><strong>Appointments:</strong> Schedule with healthcare providers</li>
				<li style="margin-bottom: 5px;"><strong>Medical Records:</strong> Secure access to your health data</li>
				<li style="margin-bottom: 5px;"><strong>Messaging:</strong> Secure communication with providers</li>
				<li><strong>Reminders:</strong> Medication and appointment alerts</li>
			</ul>
		</div>
		
		<div class="warning-box">
			<h3>⏰ Link Expires</h3>
			<p>This verification link will expire in <strong>24 hours</strong>.</p>
		</div>
		
		<p style="color: #64748b; font-size: 14px;">
			If you didn't create an account, please ignore this email.<br>
			If you're having trouble with the link, copy and paste this URL into your browser:<br>
			<code style="background: #f1f5f9; padding: 8px 12px; border-radius: 6px; font-size: 12px; word-break: break-all;">%s</code>
		</p>`, verifyURL, verifyURL)

	html = tm.baseTemplate("Verify Your Email", content, "", "")
	return subject, text, html
}

// RenderPasswordChanged generates password changed notification
func (tm *TemplateManager) RenderPasswordChanged(username string) (subject, text, html string) {
	currentTime := time.Now().Format("January 2, 2006 at 3:04 PM")

	subject = "Your Healthcare Access Connector Password Was Changed 🔒"

	text = fmt.Sprintf(`Password Changed Successfully

Hi %s,

Your Healthcare Access Connector password was successfully changed on %s.

If you made this change, no further action is needed.

If you DID NOT make this change, please take immediate action:

1. Reset your password immediately
2. Review your account activity
3. Contact our support team if you notice anything suspicious

For security reasons, we recommend:
• Using a strong, unique password
• Enabling two-factor authentication
• Regularly updating your password

Medical Emergency? Call 10177 or go to the nearest emergency room immediately.

Stay secure,
The Healthcare Access Connector Team`, username, currentTime)

	content := fmt.Sprintf(`
		<h2>Password Changed Successfully 🔒</h2>
		
		<p>Hi %s,</p>
		
		<p>Your Healthcare Access Connector password was successfully changed on <strong>%s</strong>.</p>
		
		<div class="info-box">
			<h3>✅ You're All Set</h3>
			<p>If you made this change, no further action is needed. Your account is now secured with your new password.</p>
		</div>
		
		<div class="warning-box">
			<h3>⚠️ Didn't Make This Change?</h3>
			<p>If you <strong>DID NOT</strong> make this change, please take immediate action:</p>
			<ol style="margin: 10px 0 0 20px; font-size: 14px;">
				<li style="margin-bottom: 8px;">
					<strong>Reset your password immediately:</strong><br>
					<a href="https://healthcare-access-connector-web.vercel.app/auth/forgot-password" style="color: #3b82f6;">Reset Password Now</a>
				</li>
				<li style="margin-bottom: 8px;">
					<strong>Review your recent account activity</strong>
				</li>
				<li>
					<strong>Contact our support team if you notice anything suspicious</strong><br>
					Email: security@healthcare-access-connector.com
				</li>
			</ol>
		</div>
		
		<h3 style="margin-top: 30px;">🔐 Security Recommendations</h3>
		<p>For optimal account security, we recommend:</p>
		<ul style="margin: 10px 0 20px 20px; font-size: 14px;">
			<li style="margin-bottom: 8px;">Use a strong, unique password (8+ characters with letters, numbers, and symbols)</li>
			<li style="margin-bottom: 8px;">Enable two-factor authentication for added security</li>
			<li style="margin-bottom: 8px;">Regularly update your password every 3-6 months</li>
			<li>Never share your login credentials with anyone</li>
		</ul>
		
		<p style="color: #64748b; font-size: 13px; border-top: 1px solid #e2e8f0; padding-top: 20px;">
			<strong>Need Help?</strong> Contact our security team at security@healthcare-access-connector.com
		</p>`, username, currentTime)

	html = tm.baseTemplate("Password Changed", content, "", "")
	return subject, text, html
}

// RenderLoginAlert generates suspicious login alert
func (tm *TemplateManager) RenderLoginAlert(username, ipAddress, location string) (subject, text, html string) {
	currentTime := time.Now().Format("January 2, 2006 at 3:04 PM")

	subject = "New Login Detected on Your Healthcare Account 🔔"

	text = fmt.Sprintf(`New Login Alert

Hi %s,

We detected a new login to your Healthcare Access Connector account:

Time: %s
IP Address: %s
Location: %s

If this was you, no action is needed.

If you don't recognize this activity, please:
1. Change your password immediately
2. Review your account activity
3. Enable two-factor authentication
4. Contact our security team

For your security, consider:
• Using strong, unique passwords
• Enabling login notifications
• Regularly reviewing account activity

Medical Emergency? Call 10177 or go to the nearest emergency room immediately.

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
					<td style="padding: 8px 0; border-bottom: 1px solid #e2e8f0;"><strong>Time:</strong></td>
					<td style="padding: 8px 0; border-bottom: 1px solid #e2e8f0; text-align: right;">%s</td>
				</tr>
				<tr>
					<td style="padding: 8px 0; border-bottom: 1px solid #e2e8f0;"><strong>IP Address:</strong></td>
					<td style="padding: 8px 0; border-bottom: 1px solid #e2e8f0; text-align: right;"><code>%s</code></td>
				</tr>
				<tr>
					<td style="padding: 8px 0;"><strong>Location:</strong></td>
					<td style="padding: 8px 0; text-align: right;">%s</td>
				</tr>
			</table>
		</div>
		
		<div class="info-box">
			<h3>✅ This Was You?</h3>
			<p>If you recognize this login activity, no further action is needed. Your account remains secure.</p>
		</div>
		
		<div class="warning-box">
			<h3>⚠️ Don't Recognize This Login?</h3>
			<p>If you <strong>DON'T</strong> recognize this activity, please take immediate action:</p>
			<ol style="margin: 10px 0 0 20px; font-size: 14px;">
				<li style="margin-bottom: 8px;">
					<strong>Change your password immediately:</strong><br>
					<a href="https://healthcare-access-connector-web.vercel.app/auth/forgot-password" style="color: #3b82f6;">Reset Password Now</a>
				</li>
				<li style="margin-bottom: 8px;">
					<strong>Review your recent account activity</strong>
				</li>
				<li style="margin-bottom: 8px;">
					<strong>Enable two-factor authentication for added security</strong>
				</li>
				<li>
					<strong>Contact our security team</strong><br>
					Email: security@healthcare-access-connector.com
				</li>
			</ol>
		</div>
		
		<h3 style="margin-top: 30px;">🔒 Security Tips</h3>
		<ul style="margin: 10px 0 20px 20px; font-size: 14px;">
			<li style="margin-bottom: 8px;">Use strong, unique passwords for all your accounts</li>
			<li style="margin-bottom: 8px;">Enable login notifications in your account settings</li>
			<li style="margin-bottom: 8px;">Regularly review your account activity</li>
			<li>Never share your login credentials with anyone</li>
		</ul>
		
		<p style="color: #64748b; font-size: 13px;">
			<strong>Note:</strong> This is an automated security alert. If you have any concerns, please contact our security team immediately.
		</p>`, username, currentTime, template.HTMLEscapeString(ipAddress), template.HTMLEscapeString(location))

	html = tm.baseTemplate("New Login Alert", content, "", "")
	return subject, text, html
}

// RenderOTP generates OTP email template
func (tm *TemplateManager) RenderOTP(email, otp, username string) (subject, text, html string) {
	subject = "Your Password Reset Code - Healthcare Access Connector 🔢"

	text = fmt.Sprintf(`Password Reset Code

Hello%s,

Your password reset verification code is:

%s

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email or contact our support team immediately.

For security reasons, never share this code with anyone.

Medical Emergency? Call 10177 or go to the nearest emergency room immediately.

Stay secure,
Healthcare Access Connector Team`, func() string {
		if username != "" {
			return fmt.Sprintf(" %s,", username)
		}
		return ","
	}(), otp)

	// Build greeting with optional username
	greeting := "Hello,"
	if username != "" {
		greeting = fmt.Sprintf("Hello %s,", username)
	}

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
			<p>If you didn't request this code, please:</p>
			<ul style="margin: 10px 0 0 20px; font-size: 14px;">
				<li style="margin-bottom: 5px;">Ignore this email</li>
				<li style="margin-bottom: 5px;">Review your account security</li>
				<li>Contact support if you notice suspicious activity</li>
			</ul>
		</div>
		
		<p style="color: #64748b; font-size: 14px;">
			<strong>Need help?</strong> Contact our support team at support@healthcare-access-connector.com
		</p>`, greeting, otp)

	html = tm.baseTemplate("Your Verification Code", content, "", "")
	return subject, text, html
}

// EscapeHTML safely escapes HTML content
func EscapeHTML(s string) string {
	return strings.ReplaceAll(
		strings.ReplaceAll(
			strings.ReplaceAll(s, "&", "&amp;"),
			"<", "&lt;"),
		">", "&gt;")
}
