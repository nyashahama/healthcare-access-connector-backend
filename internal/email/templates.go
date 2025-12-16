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

// RenderWelcome generates welcome email content
func (tm *TemplateManager) RenderWelcome(username string) (subject, text, html string) {
	subject = "Welcome to Our Platform!"

	text = fmt.Sprintf(`Hi %s,

Welcome to our platform! We're excited to have you on board.

Your account has been successfully created. You can now log in and start using all of our features.

If you have any questions, feel free to reach out to our support team.

Best regards,
The Team`, username)

	html = fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .button { display: inline-block; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 Welcome Aboard!</h1>
        </div>
        <div class="content">
            <h2>Hi %s,</h2>
            <p>We're thrilled to have you join our platform! Your account has been successfully created.</p>
            <p>You can now:</p>
            <ul>
                <li>Access all platform features</li>
                <li>Customize your profile</li>
                <li>Start exploring</li>
            </ul>
            <p>If you have any questions, our support team is here to help.</p>
            <p>Best regards,<br>The Team</p>
        </div>
        <div class="footer">
            <p>© %d Our Platform. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`, username, time.Now().Year())

	return subject, text, html
}

// RenderPasswordReset generates password reset email
func (tm *TemplateManager) RenderPasswordReset(resetToken string) (subject, text, html string) {
	resetURL := fmt.Sprintf("https://yourdomain.com/reset-password?token=%s", resetToken)

	subject = "Password Reset Request"

	text = fmt.Sprintf(`Password Reset Request

You've requested to reset your password. Click the link below to create a new password:

%s

This link will expire in 1 hour.

If you didn't request this, please ignore this email and your password will remain unchanged.

Best regards,
The Team`, resetURL)

	html = fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #ff6b6b; color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .button { display: inline-block; padding: 12px 30px; background: #ff6b6b; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Password Reset</h1>
        </div>
        <div class="content">
            <p>You've requested to reset your password.</p>
            <p>Click the button below to create a new password:</p>
            <center>
                <a href="%s" class="button">Reset Password</a>
            </center>
            <div class="warning">
                <strong>⚠️ Important:</strong> This link will expire in 1 hour.
            </div>
            <p>If you didn't request this, please ignore this email and your password will remain unchanged.</p>
            <p style="font-size: 12px; color: #666;">If the button doesn't work, copy and paste this link: %s</p>
        </div>
        <div class="footer">
            <p>© %d Our Platform. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`, resetURL, resetURL, time.Now().Year())

	return subject, text, html
}

// RenderVerification generates email verification email
func (tm *TemplateManager) RenderVerification(verificationToken string) (subject, text, html string) {
	verifyURL := fmt.Sprintf("https://yourdomain.com/verify-email?token=%s", verificationToken)

	subject = "Please Verify Your Email Address"

	text = fmt.Sprintf(`Email Verification Required

Please verify your email address by clicking the link below:

%s

This link will expire in 24 hours.

If you didn't create an account, please ignore this email.

Best regards,
The Team`, verifyURL)

	html = fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #4CAF50; color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .button { display: inline-block; padding: 12px 30px; background: #4CAF50; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>✅ Verify Your Email</h1>
        </div>
        <div class="content">
            <p>Thanks for signing up! Please verify your email address to get started.</p>
            <center>
                <a href="%s" class="button">Verify Email Address</a>
            </center>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't create an account, you can safely ignore this email.</p>
            <p style="font-size: 12px; color: #666;">If the button doesn't work, copy and paste this link: %s</p>
        </div>
        <div class="footer">
            <p>© %d Our Platform. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`, verifyURL, verifyURL, time.Now().Year())

	return subject, text, html
}

// RenderPasswordChanged generates password changed notification
func (tm *TemplateManager) RenderPasswordChanged(username string) (subject, text, html string) {
	subject = "Your Password Has Been Changed"

	text = fmt.Sprintf(`Hi %s,

Your password has been successfully changed.

If you made this change, you can safely ignore this email.

If you didn't make this change, please contact our support team immediately.

Best regards,
The Team`, username)

	html = fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #2196F3; color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .alert { background: #e3f2fd; border-left: 4px solid #2196F3; padding: 15px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Password Changed</h1>
        </div>
        <div class="content">
            <h2>Hi %s,</h2>
            <p>Your password has been successfully changed at %s.</p>
            <div class="alert">
                <strong>ℹ️ Note:</strong> If you made this change, you can safely ignore this email.
            </div>
            <p><strong>If you didn't make this change:</strong> Please contact our support team immediately to secure your account.</p>
        </div>
        <div class="footer">
            <p>© %d Our Platform. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`, username, time.Now().Format("January 2, 2006 at 3:04 PM"), time.Now().Year())

	return subject, text, html
}

// RenderLoginAlert generates suspicious login alert
func (tm *TemplateManager) RenderLoginAlert(username, ipAddress, location string) (subject, text, html string) {
	subject = "New Login to Your Account"

	text = fmt.Sprintf(`Hi %s,

We detected a new login to your account:

Time: %s
IP Address: %s
Location: %s

If this was you, you can safely ignore this email.

If you don't recognize this activity, please secure your account immediately by changing your password.

Best regards,
The Team`, username, time.Now().Format("January 2, 2006 at 3:04 PM"), ipAddress, location)

	html = fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #FF9800; color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .info-box { background: white; border: 1px solid #ddd; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔔 New Login Alert</h1>
        </div>
        <div class="content">
            <h2>Hi %s,</h2>
            <p>We detected a new login to your account:</p>
            <div class="info-box">
                <strong>Login Details:</strong><br>
                <strong>Time:</strong> %s<br>
                <strong>IP Address:</strong> %s<br>
                <strong>Location:</strong> %s
            </div>
            <div class="warning">
                <strong>⚠️ Was this you?</strong><br>
                If you don't recognize this activity, please secure your account immediately by changing your password.
            </div>
        </div>
        <div class="footer">
            <p>© %d Our Platform. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`, username, time.Now().Format("January 2, 2006 at 3:04 PM"),
		template.HTMLEscapeString(ipAddress),
		template.HTMLEscapeString(location),
		time.Now().Year())

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
