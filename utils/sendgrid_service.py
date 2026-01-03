"""
SendGrid Email Service
Handles all email sending through SendGrid API
"""
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content
from django.conf import settings
from django.template.loader import render_to_string
from typing import List, Optional


class SendGridService:
    """SendGrid email sending service"""
    
    def __init__(self):
        self.api_key = getattr(settings, 'SENDGRID_API_KEY', None)
        self.from_email = getattr(settings, 'SENDGRID_FROM_EMAIL', 'noreply@bugbounty-arsenal.com')
        self.from_name = getattr(settings, 'SENDGRID_FROM_NAME', 'BugBounty Arsenal')
        
        if self.api_key:
            self.client = SendGridAPIClient(self.api_key)
        else:
            self.client = None
            print('⚠️  SendGrid API key not configured. Emails will be printed to console.')
    
    def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
        to_name: Optional[str] = None
    ) -> bool:
        """
        Send email via SendGrid
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML email body
            text_content: Plain text fallback (optional)
            to_name: Recipient name (optional)
        
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.client:
            # Fallback to console output for development
            print('\n' + '='*70)
            print('📧 EMAIL (Console Output - SendGrid not configured)')
            print('='*70)
            print(f'From: {self.from_name} <{self.from_email}>')
            print(f'To: {to_name or ""} <{to_email}>')
            print(f'Subject: {subject}')
            print('-'*70)
            print(html_content)
            print('='*70 + '\n')
            return True
        
        try:
            message = Mail(
                from_email=Email(self.from_email, self.from_name),
                to_emails=To(to_email, to_name),
                subject=subject,
                html_content=Content("text/html", html_content)
            )
            
            if text_content:
                message.add_content(Content("text/plain", text_content))
            
            response = self.client.send(message)
            
            if response.status_code in [200, 201, 202]:
                print(f'✅ Email sent successfully to {to_email}')
                return True
            else:
                print(f'❌ SendGrid error: {response.status_code} - {response.body}')
                return False
                
        except Exception as e:
            print(f'❌ Failed to send email: {str(e)}')
            return False
    
    def send_verification_email(self, user_email: str, user_name: str, verification_url: str) -> bool:
        """Send email verification link"""
        subject = 'Verify Your BugBounty Arsenal Account'
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; }}
                .button {{ display: inline-block; padding: 15px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }}
                .footer {{ text-align: center; margin-top: 30px; color: #6b7280; font-size: 14px; }}
                .code {{ background: #e5e7eb; padding: 10px 15px; border-radius: 5px; font-family: monospace; font-size: 16px; letter-spacing: 2px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎯 BugBounty Arsenal</h1>
                    <p>Advanced Security Scanning Platform</p>
                </div>
                <div class="content">
                    <h2>Welcome, {user_name}! 👋</h2>
                    <p>Thanks for signing up for BugBounty Arsenal. To get started, please verify your email address by clicking the button below:</p>
                    
                    <div style="text-align: center;">
                        <a href="{verification_url}" class="button">Verify Email Address</a>
                    </div>
                    
                    <p>Or copy and paste this link into your browser:</p>
                    <p style="word-break: break-all; color: #667eea;">{verification_url}</p>
                    
                    <p><strong>This link will expire in 24 hours.</strong></p>
                    
                    <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">
                    
                    <p><strong>What's Next?</strong></p>
                    <ul>
                        <li>✅ Complete email verification</li>
                        <li>🔍 Run your first security scan</li>
                        <li>📊 View detailed vulnerability reports</li>
                        <li>🚀 Upgrade to Pro for unlimited scans</li>
                    </ul>
                </div>
                <div class="footer">
                    <p>If you didn't create an account, please ignore this email.</p>
                    <p>&copy; 2026 BugBounty Arsenal. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_content = f"""
        Welcome to BugBounty Arsenal, {user_name}!
        
        Please verify your email address by visiting:
        {verification_url}
        
        This link will expire in 24 hours.
        
        If you didn't create an account, please ignore this email.
        
        © 2026 BugBounty Arsenal
        """
        
        return self.send_email(user_email, subject, html_content, text_content, user_name)
    
    def send_password_reset_email(self, user_email: str, user_name: str, reset_url: str) -> bool:
        """Send password reset link"""
        subject = 'Reset Your BugBounty Arsenal Password'
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; }}
                .button {{ display: inline-block; padding: 15px 30px; background: #ef4444; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }}
                .footer {{ text-align: center; margin-top: 30px; color: #6b7280; font-size: 14px; }}
                .warning {{ background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Password Reset</h1>
                </div>
                <div class="content">
                    <h2>Hello, {user_name}</h2>
                    <p>We received a request to reset your password for your BugBounty Arsenal account.</p>
                    
                    <div style="text-align: center;">
                        <a href="{reset_url}" class="button">Reset Password</a>
                    </div>
                    
                    <p>Or copy and paste this link into your browser:</p>
                    <p style="word-break: break-all; color: #667eea;">{reset_url}</p>
                    
                    <div class="warning">
                        <strong>⚠️ Security Notice:</strong>
                        <ul style="margin: 10px 0;">
                            <li>This link will expire in 1 hour</li>
                            <li>If you didn't request this, please ignore this email</li>
                            <li>Your password will not be changed unless you click the link above</li>
                        </ul>
                    </div>
                </div>
                <div class="footer">
                    <p>If you didn't request a password reset, you can safely ignore this email.</p>
                    <p>&copy; 2026 BugBounty Arsenal. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_content = f"""
        Password Reset Request - BugBounty Arsenal
        
        Hello {user_name},
        
        We received a request to reset your password. Click the link below to reset it:
        {reset_url}
        
        This link will expire in 1 hour.
        
        If you didn't request this, please ignore this email.
        
        © 2026 BugBounty Arsenal
        """
        
        return self.send_email(user_email, subject, html_content, text_content, user_name)
    
    def send_scan_complete_email(self, user_email: str, user_name: str, scan_data: dict) -> bool:
        """Send scan completion notification"""
        subject = f'Scan Complete: {scan_data.get("target", "Target")}'
        
        vulnerabilities = scan_data.get('vulnerabilities_found', 0)
        severity_color = '#ef4444' if vulnerabilities > 0 else '#10b981'
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; }}
                .stats {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin: 20px 0; }}
                .stat-card {{ background: white; padding: 20px; border-radius: 8px; text-align: center; border: 2px solid #e5e7eb; }}
                .stat-value {{ font-size: 32px; font-weight: bold; color: {severity_color}; }}
                .stat-label {{ font-size: 14px; color: #6b7280; margin-top: 5px; }}
                .button {{ display: inline-block; padding: 15px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }}
                .footer {{ text-align: center; margin-top: 30px; color: #6b7280; font-size: 14px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✅ Scan Complete</h1>
                </div>
                <div class="content">
                    <h2>Hello, {user_name}</h2>
                    <p>Your security scan has finished running.</p>
                    
                    <div style="background: #e0e7ff; padding: 15px; border-radius: 8px; margin: 20px 0;">
                        <strong>Target:</strong> {scan_data.get('target', 'N/A')}<br>
                        <strong>Scan Type:</strong> {scan_data.get('scan_type', 'N/A')}<br>
                        <strong>Duration:</strong> {scan_data.get('duration', 'N/A')}
                    </div>
                    
                    <div class="stats">
                        <div class="stat-card">
                            <div class="stat-value">{vulnerabilities}</div>
                            <div class="stat-label">Vulnerabilities Found</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">{scan_data.get('detectors_run', 0)}</div>
                            <div class="stat-label">Detectors Run</div>
                        </div>
                    </div>
                    
                    <div style="text-align: center;">
                        <a href="{scan_data.get('results_url', '#')}" class="button">View Detailed Results</a>
                    </div>
                    
                    {"<p style='color: #ef4444; font-weight: bold;'>⚠️ Critical vulnerabilities detected! Review immediately.</p>" if vulnerabilities > 0 else "<p style='color: #10b981; font-weight: bold;'>✅ No critical vulnerabilities found.</p>"}
                </div>
                <div class="footer">
                    <p>&copy; 2026 BugBounty Arsenal. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return self.send_email(user_email, subject, html_content, None, user_name)
    
    def send_welcome_email(self, user_email: str, user_name: str) -> bool:
        """Send welcome email after successful verification"""
        subject = 'Welcome to BugBounty Arsenal! 🎯'
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; }}
                .feature {{ background: white; padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #667eea; }}
                .button {{ display: inline-block; padding: 15px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }}
                .footer {{ text-align: center; margin-top: 30px; color: #6b7280; font-size: 14px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎉 Welcome to BugBounty Arsenal!</h1>
                </div>
                <div class="content">
                    <h2>You're all set, {user_name}!</h2>
                    <p>Your account is now verified and ready to use. Here's what you can do:</p>
                    
                    <div class="feature">
                        <h3>🔍 Run Security Scans</h3>
                        <p>Scan websites for 40+ vulnerability types including XSS, SQLi, SSRF, and more.</p>
                    </div>
                    
                    <div class="feature">
                        <h3>🔥 0-Day Hunting</h3>
                        <p>Use advanced techniques to discover zero-day vulnerabilities before they're known.</p>
                    </div>
                    
                    <div class="feature">
                        <h3>📊 Detailed Reports</h3>
                        <p>Get comprehensive reports with proof-of-concept and remediation steps.</p>
                    </div>
                    
                    <div class="feature">
                        <h3>🚀 Pro Features</h3>
                        <p>Upgrade to Pro for unlimited scans and advanced detectors.</p>
                    </div>
                    
                    <div style="text-align: center;">
                        <a href="http://localhost:3000/dashboard" class="button">Go to Dashboard</a>
                    </div>
                    
                    <p style="margin-top: 30px;"><strong>Need Help?</strong></p>
                    <ul>
                        <li>📖 Read the <a href="http://localhost:3000/docs">Documentation</a></li>
                        <li>💬 Join our Discord community (coming soon)</li>
                        <li>📧 Email us at foxvr81@gmail.com</li>
                    </ul>
                </div>
                <div class="footer">
                    <p>Happy hunting! 🎯</p>
                    <p>&copy; 2026 BugBounty Arsenal. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return self.send_email(user_email, subject, html_content, None, user_name)


# Global instance
sendgrid_service = SendGridService()
