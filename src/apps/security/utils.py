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
import logging

logger = logging.getLogger('security')


def generate_jwt_token(user, expiration_minutes=15):
    """Generate JWT token with RS256 algorithm."""
    try:
        private_key = settings.SIMPLE_JWT.get('SIGNING_KEY', settings.SECRET_KEY)
        
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
        
        algorithm = settings.SIMPLE_JWT.get('ALGORITHM', 'HS256')
        token = jwt.encode(payload, private_key, algorithm=algorithm)
        return token
    except Exception as e:
        logger.error(f"Error generating JWT token: {str(e)}")
        return None


def verify_jwt_token(token):
    """Verify JWT token."""
    try:
        public_key = settings.SIMPLE_JWT.get('VERIFYING_KEY', settings.SECRET_KEY)
        algorithm = settings.SIMPLE_JWT.get('ALGORITHM', 'HS256')
        
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[algorithm],
            options={'verify_exp': True}
        )
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Error verifying JWT token: {str(e)}")
        return None


def blacklist_token(token, expiration_hours=24):
    """Blacklist a token in Redis."""
    try:
        cache_key = f"blacklisted_token:{token}"
        cache.set(cache_key, True, timeout=expiration_hours * 3600)
        return True
    except Exception as e:
        logger.error(f"Error blacklisting token: {str(e)}")
        return False


def is_token_blacklisted(token):
    """Check if token is blacklisted in Redis."""
    try:
        cache_key = f"blacklisted_token:{token}"
        return cache.get(cache_key) is not None
    except Exception as e:
        logger.error(f"Error checking token blacklist: {str(e)}")
        return False


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
            error_detail = response.data['detail'].lower()
            if 'password' in error_detail or 'credentials' in error_detail:
                response.data['detail'] = 'Authentication failed'
            elif 'token' in error_detail or 'jwt' in error_detail:
                response.data['detail'] = 'Invalid token'
            elif 'permission' in error_detail or 'forbidden' in error_detail:
                response.data['detail'] = 'Access denied'
        
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
    
    return response


def check_rate_limit(key, limit, period):
    """Check and increment rate limit counter."""
    try:
        cache_key = f"rate_limit:{key}"
        current = cache.get(cache_key, 0)
        
        if current >= limit:
            return False
        
        cache.set(cache_key, current + 1, timeout=period)
        return True
    except Exception as e:
        logger.error(f"Error checking rate limit: {str(e)}")
        return True  # Permitir en caso de error


def get_client_ip(request):
    """Get client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
    return ip


class SecurityLogger:
    """Custom logger for security events."""
    
    @staticmethod
    def log_login_attempt(email, ip_address, success, user_agent=''):
        """Log login attempt."""
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
        log_data = {
            'event': 'account_lock',
            'user_id': str(user.id),
            'email': user.email,
            'ip_address': ip_address,
            'reason': reason,
            'timestamp': timezone.now().isoformat()
        }
        
        logger.warning(json.dumps(log_data))