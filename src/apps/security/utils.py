import jwt
import hashlib
import json
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status


def generate_jwt_token(user, expiration_minutes=15):
    """Generate JWT token with RS256 algorithm."""
    private_key = settings.SIMPLE_JWT['SIGNING_KEY']
    
    payload = {
        'user_id': str(user.id),
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(minutes=expiration_minutes),
        'iat': datetime.utcnow(),
        'token_type': 'access',
        'jti': hashlib.sha256(
            f"{user.id}{datetime.utcnow().timestamp()}".encode()
        ).hexdigest()
    }
    
    token = jwt.encode(payload, private_key, algorithm='RS256')
    return token


def verify_jwt_token(token):
    """Verify JWT token with RS256 algorithm."""
    public_key = settings.SIMPLE_JWT['VERIFYING_KEY']
    
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=['RS256'],
            options={'verify_exp': True}
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def blacklist_token(token, expiration_hours=24):
    """Blacklist a token in Redis."""
    cache_key = f"blacklisted_token:{token}"
    cache.set(cache_key, True, timeout=expiration_hours * 3600)


def is_token_blacklisted(token):
    """Check if token is blacklisted in Redis."""
    cache_key = f"blacklisted_token:{token}"
    return cache.get(cache_key) is not None


def generate_device_fingerprint(request):
    """Generate device fingerprint for security tracking."""
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    accept_language = request.META.get('HTTP_ACCEPT_LANGUAGE', '')
    accept_encoding = request.META.get('HTTP_ACCEPT_ENCODING', '')
    
    fingerprint_data = f"{user_agent}{accept_language}{accept_encoding}"
    fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    return fingerprint


def custom_exception_handler(exc, context):
    """Custom exception handler for security."""
    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)
    
    if response is not None:
        # Remove sensitive information from errors
        if 'detail' in response.data and isinstance(response.data['detail'], str):
            # Generic error message for security
            if 'password' in response.data['detail'].lower():
                response.data['detail'] = 'Authentication failed'
            elif 'token' in response.data['detail'].lower():
                response.data['detail'] = 'Invalid token'
        
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
    
    return response


def check_rate_limit(key, limit, period):
    """Check and increment rate limit counter."""
    cache_key = f"rate_limit:{key}"
    current = cache.get(cache_key, 0)
    
    if current >= limit:
        return False
    
    cache.set(cache_key, current + 1, timeout=period)
    return True


def get_client_ip(request):
    """Get client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


class SecurityLogger:
    """Custom logger for security events."""
    
    @staticmethod
    def log_login_attempt(email, ip_address, success, user_agent=''):
        """Log login attempt."""
        import logging
        logger = logging.getLogger('security')
        
        log_data = {
            'event': 'login_attempt',
            'email': email,
            'ip_address': ip_address,
            'success': success,
            'user_agent': user_agent[:200],
            'timestamp': timezone.now().isoformat()
        }
        
        if success:
            logger.info(json.dumps(log_data))
        else:
            logger.warning(json.dumps(log_data))
    
    @staticmethod
    def log_password_change(user, ip_address):
        """Log password change."""
        import logging
        logger = logging.getLogger('security')
        
        log_data = {
            'event': 'password_change',
            'user_id': str(user.id),
            'email': user.email,
            'ip_address': ip_address,
            'timestamp': timezone.now().isoformat()
        }
        
        logger.info(json.dumps(log_data))
    
    @staticmethod
    def log_account_lock(user, ip_address, reason):
        """Log account lock."""
        import logging
        logger = logging.getLogger('security')
        
        log_data = {
            'event': 'account_lock',
            'user_id': str(user.id),
            'email': user.email,
            'ip_address': ip_address,
            'reason': reason,
            'timestamp': timezone.now().isoformat()
        }
        
        logger.warning(json.dumps(log_data))