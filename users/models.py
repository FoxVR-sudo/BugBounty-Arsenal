from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models


class UserManager(BaseUserManager):
    """Custom user manager"""
    
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_admin', True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """Custom User model with email as username"""
    
    username = None  # Remove username field
    email = models.EmailField(unique=True)
    
    # Personal information (required for all plans)
    first_name = models.CharField(max_length=100, blank=True)
    middle_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    full_name = models.CharField(max_length=255, blank=True)  # Auto-generated from first+middle+last
    address = models.TextField(blank=True, help_text='Full address')
    
    # Phone verification
    phone = models.CharField(max_length=20, blank=True, help_text='International format: +359XXXXXXXXX')
    phone_verified = models.BooleanField(default=False)
    phone_verification_code = models.CharField(max_length=6, blank=True, null=True)
    phone_verification_expires = models.DateTimeField(null=True, blank=True)
    
    # Company information (Enterprise plan)
    company_name = models.CharField(max_length=255, blank=True, help_text='Company/Organization name')
    company_registration_number = models.CharField(max_length=100, blank=True, help_text='Registration/VAT number')
    company_address = models.TextField(blank=True, help_text='Company address')
    company_country = models.CharField(max_length=2, blank=True, help_text='ISO country code')
    company_verified = models.BooleanField(default=False)
    company_verification_date = models.DateTimeField(null=True, blank=True)
    
    # Account status
    is_admin = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=100, blank=True, null=True)
    
    # Stripe integration
    stripe_customer_id = models.CharField(max_length=100, blank=True, null=True, help_text='Stripe customer ID')
    
    # Timestamps
    last_login = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    class Meta:
        db_table = 'users'
        ordering = ['-created_at']
    
    def __str__(self):
        return self.email
    
    def save(self, *args, **kwargs):
        """Auto-generate full_name from first, middle, last names"""
        if self.first_name or self.middle_name or self.last_name:
            parts = [self.first_name, self.middle_name, self.last_name]
            self.full_name = ' '.join(filter(None, parts))
        super().save(*args, **kwargs)
