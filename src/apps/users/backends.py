import time
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone


class EmailBackend(ModelBackend):
    """
    Custom authentication backend that uses email instead of username.
    Includes timing attack protection.
    """
    
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        
        try:
            # Normalize email
            username = username.lower().strip()
            
            # Get user with consistent timing
            user = UserModel._default_manager.get(email=username)
        except UserModel.DoesNotExist:
            # Run hash anyway for timing attack protection
            UserModel().set_password(password)
            return None
        
        # Check if account is locked
        if user.is_locked:
            return None
        
        # Use Django's check_password with timing attack protection
        if user.check_password(password):
            return user
        
        return None
    
    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            return UserModel._default_manager.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None


class RateLimitedBackend(EmailBackend):
    """
    Authentication backend with built-in rate limiting.
    """
    
    def authenticate(self, request, username=None, password=None, **kwargs):
        ip_address = request.META.get('REMOTE_ADDR')
        
        # Check IP-based rate limiting
        cache_key = f"login_rate:{ip_address}"
        attempts = cache.get(cache_key, 0)
        
        if attempts >= 10:  # 10 attempts per IP
            return None
        
        # Authenticate
        user = super().authenticate(request, username, password, **kwargs)
        
        if user is None:
            # Increment rate limit counter (expires in 15 minutes)
            cache.set(cache_key, attempts + 1, timeout=900)
        
        return user