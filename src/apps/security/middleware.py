import uuid
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from apps.users.models import UserSession


class SecurityHeadersMiddleware(MiddlewareMixin):
    """Middleware to add security headers to all responses."""
    
    def process_response(self, request, response):
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Content Security Policy
        response['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self';"
        )
        
        return response


class SessionSecurityMiddleware(MiddlewareMixin):
    """Middleware for enhanced session security."""
    
    def process_request(self, request):
        if hasattr(request, 'user') and request.user.is_authenticated:
            # Check session expiration
            session_key = request.session.session_key
            
            if session_key:
                # Check if session exists in our tracking
                try:
                    user_session = UserSession.objects.get(
                        user=request.user,
                        session_key=session_key
                    )
                    
                    if user_session.is_expired:
                        # Logout user if session expired
                        from django.contrib.auth import logout
                        logout(request)
                        return
                    
                    # Update last activity
                    user_session.last_activity = timezone.now()
                    user_session.save(update_fields=['last_activity'])
                    
                except UserSession.DoesNotExist:
                    # Create new session tracking
                    ip_address = request.META.get('REMOTE_ADDR')
                    user_agent = request.META.get('HTTP_USER_AGENT', '')
                    
                    UserSession.objects.create(
                        user=request.user,
                        session_key=session_key,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        expires_at=request.session.get_expiry_date()
                    )
    
    def process_response(self, request, response):
        if (hasattr(request, 'user') and 
            request.user.is_authenticated and 
            'sessionid' in response.cookies):
            
            # Secure session cookie
            response.cookies['sessionid']['httponly'] = True
            response.cookies['sessionid']['secure'] = not settings.DEBUG
            response.cookies['sessionid']['samesite'] = 'Strict'
        
        return response


class RequestLoggingMiddleware(MiddlewareMixin):
    """Middleware for logging security-related requests."""
    
    def process_request(self, request):
        # Generate request ID for tracing
        request.request_id = str(uuid.uuid4())
        
        # Log sensitive operations
        if request.method in ['POST', 'PUT', 'DELETE']:
            path = request.path
            
            # Check if it's a security-related endpoint
            security_paths = ['/login', '/register', '/password', '/logout']
            if any(path.startswith(p) for p in security_paths):
                ip_address = request.META.get('REMOTE_ADDR')
                user_agent = request.META.get('HTTP_USER_AGENT', '')
                
                # Log to security log
                import logging
                logger = logging.getLogger('security')
                logger.info(
                    f"Security request: {request.method} {path} "
                    f"from IP: {ip_address} "
                    f"User-Agent: {user_agent[:100]} "
                    f"Request-ID: {request.request_id}"
                )
        
        return None