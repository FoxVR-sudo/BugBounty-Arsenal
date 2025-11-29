"""
Email Service for BugBounty Arsenal
Handles email verification and notifications
"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from typing import Optional
import secrets

class EmailService:
    def __init__(self):
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.sender_email = os.getenv("SENDER_EMAIL", "")
        self.sender_password = os.getenv("SENDER_PASSWORD", "")
        self.frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8000")
        
    def generate_verification_token(self) -> str:
        """Generate a secure random token for email verification"""
        return secrets.token_urlsafe(32)
    
    def send_verification_email(self, recipient_email: str, verification_token: str) -> bool:
        """Send email verification link to user"""
        try:
            verification_link = f"{self.frontend_url}/verify-email?token={verification_token}"
            
            message = MIMEMultipart("alternative")
            message["Subject"] = "Verify Your BugBounty Arsenal Account"
            message["From"] = self.sender_email
            message["To"] = recipient_email
            
            html = f"""
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2 style="color: #2563eb;">Welcome to BugBounty Arsenal!</h2>
                        <p>Thank you for registering. Please verify your email address to activate your account.</p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{verification_link}" 
                               style="background-color: #2563eb; color: white; padding: 12px 30px; 
                                      text-decoration: none; border-radius: 5px; display: inline-block;">
                                Verify Email Address
                            </a>
                        </div>
                        <p style="color: #666; font-size: 14px;">
                            Or copy and paste this link into your browser:<br>
                            <a href="{verification_link}">{verification_link}</a>
                        </p>
                        <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                        <p style="color: #999; font-size: 12px;">
                            If you didn't create this account, please ignore this email.
                        </p>
                    </div>
                </body>
            </html>
            """
            
            part = MIMEText(html, "html")
            message.attach(part)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(message)
            
            return True
        except Exception as e:
            print(f"Email send error: {e}")
            return False
    
    def send_password_reset_email(self, recipient_email: str, reset_token: str) -> bool:
        """Send password reset link to user"""
        try:
            reset_link = f"{self.frontend_url}/reset-password?token={reset_token}"
            
            message = MIMEMultipart("alternative")
            message["Subject"] = "Reset Your BugBounty Arsenal Password"
            message["From"] = self.sender_email
            message["To"] = recipient_email
            
            html = f"""
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2 style="color: #2563eb;">Password Reset Request</h2>
                        <p>We received a request to reset your password. Click the button below to reset it.</p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{reset_link}" 
                               style="background-color: #2563eb; color: white; padding: 12px 30px; 
                                      text-decoration: none; border-radius: 5px; display: inline-block;">
                                Reset Password
                            </a>
                        </div>
                        <p style="color: #666; font-size: 14px;">
                            This link will expire in 24 hours for security reasons.
                        </p>
                        <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                        <p style="color: #999; font-size: 12px;">
                            If you didn't request this, please ignore this email. Your password will remain unchanged.
                        </p>
                    </div>
                </body>
            </html>
            """
            
            part = MIMEText(html, "html")
            message.attach(part)
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(message)
            
            return True
        except Exception as e:
            print(f"Email send error: {e}")
            return False

# Global instance
email_service = EmailService()
