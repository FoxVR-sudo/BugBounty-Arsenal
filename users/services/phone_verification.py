"""
Phone verification service using Twilio
Cost: ~$0.01 per SMS
"""
import random
import string
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache


class PhoneVerificationService:
    """
    Phone number verification using SMS codes
    Supports Twilio and fallback to console/email for development
    """
    
    def __init__(self):
        self.use_twilio = getattr(settings, 'TWILIO_ENABLED', False)
        if self.use_twilio:
            try:
                from twilio.rest import Client
                self.client = Client(
                    settings.TWILIO_ACCOUNT_SID,
                    settings.TWILIO_AUTH_TOKEN
                )
                self.from_number = settings.TWILIO_PHONE_NUMBER
            except ImportError:
                print("⚠️ Twilio SDK not installed. Run: pip install twilio")
                self.use_twilio = False
            except AttributeError:
                print("⚠️ Twilio credentials not configured in settings")
                self.use_twilio = False
    
    def generate_code(self, length=6):
        """Generate random numeric verification code"""
        return ''.join(random.choices(string.digits, k=length))
    
    def send_verification_code(self, user, phone_number):
        """
        Send SMS verification code to phone number
        Returns: (success: bool, code: str, message: str)
        """
        # Rate limiting: max 3 SMS per phone per hour
        cache_key = f'sms_rate_limit_{phone_number}'
        attempts = cache.get(cache_key, 0)
        
        if attempts >= 3:
            return False, None, 'Rate limit exceeded. Try again in 1 hour.'
        
        # Generate code
        code = self.generate_code()
        
        # Save to user model
        user.phone = phone_number
        user.phone_verification_code = code
        user.phone_verification_expires = timezone.now() + timedelta(minutes=10)
        user.phone_verified = False
        user.save()
        
        # Send SMS
        success, message = self._send_sms(phone_number, code)
        
        if success:
            # Increment rate limit counter
            cache.set(cache_key, attempts + 1, 3600)  # 1 hour
            return True, code, 'Verification code sent successfully'
        else:
            return False, None, message
    
    def _send_sms(self, phone_number, code):
        """
        Internal method to send SMS
        Returns: (success: bool, message: str)
        """
        message_text = f"Your BugBounty Arsenal verification code is: {code}\n\nValid for 10 minutes.\n\nDo not share this code with anyone."
        
        if self.use_twilio:
            try:
                message = self.client.messages.create(
                    body=message_text,
                    from_=self.from_number,
                    to=phone_number
                )
                
                if message.sid:
                    print(f"✅ SMS sent to {phone_number} (SID: {message.sid})")
                    return True, f'SMS sent (SID: {message.sid})'
                else:
                    return False, 'Failed to send SMS'
                    
            except Exception as e:
                print(f"❌ Twilio error: {str(e)}")
                return False, f'Twilio error: {str(e)}'
        
        else:
            # Development mode: print to console
            print("=" * 60)
            print("📱 SMS VERIFICATION (Development Mode)")
            print("=" * 60)
            print(f"To: {phone_number}")
            print(f"Code: {code}")
            print(f"Message: {message_text}")
            print("=" * 60)
            
            # Also send email notification if configured
            try:
                from django.core.mail import send_mail
                from django.contrib.auth import get_user_model
                User = get_user_model()
                
                user = User.objects.filter(phone=phone_number).first()
                if user and user.email:
                    send_mail(
                        subject='Phone Verification Code',
                        message=message_text,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[user.email],
                        fail_silently=True,
                    )
                    print(f"📧 Email sent to {user.email}")
            except:
                pass
            
            return True, 'Verification code sent (development mode)'
    
    def verify_code(self, user, code):
        """
        Verify SMS code
        Returns: (success: bool, message: str)
        """
        # Check if code exists
        if not user.phone_verification_code:
            return False, 'No verification code found. Request a new code.'
        
        # Check if code matches
        if user.phone_verification_code != code:
            return False, 'Invalid verification code'
        
        # Check if code expired
        if user.phone_verification_expires and timezone.now() > user.phone_verification_expires:
            return False, 'Verification code expired. Request a new code.'
        
        # Mark phone as verified
        user.phone_verified = True
        user.phone_verification_code = None
        user.phone_verification_expires = None
        user.save()
        
        # Clear rate limit
        cache_key = f'sms_rate_limit_{user.phone}'
        cache.delete(cache_key)
        
        return True, 'Phone number verified successfully'
    
    def resend_code(self, user):
        """
        Resend verification code to existing phone number
        Returns: (success: bool, code: str, message: str)
        """
        if not user.phone:
            return False, None, 'No phone number found'
        
        return self.send_verification_code(user, user.phone)
    
    @staticmethod
    def format_phone_number(phone, country_code='359'):
        """
        Format phone number to international format
        Examples:
            0888123456 -> +359888123456
            888123456 -> +359888123456
            +359888123456 -> +359888123456
        """
        # Remove spaces and dashes
        phone = phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
        
        # If starts with +, assume already formatted
        if phone.startswith('+'):
            return phone
        
        # If starts with 0, remove it
        if phone.startswith('0'):
            phone = phone[1:]
        
        # Add country code
        return f'+{country_code}{phone}'
    
    @staticmethod
    def validate_phone_format(phone):
        """
        Validate phone number format
        Returns: (valid: bool, message: str)
        """
        import re
        
        # Must start with + and contain only digits
        if not re.match(r'^\+\d{10,15}$', phone):
            return False, 'Phone number must be in international format (+XXXXXXXXXXX)'
        
        return True, 'Valid phone number format'
    
    def send_test_sms(self, phone_number):
        """
        Send test SMS (admin only)
        Returns: (success: bool, message: str)
        """
        code = self.generate_code()
        return self._send_sms(phone_number, code)
