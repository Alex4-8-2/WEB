import logging
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth import login as auth_login
from django.core.cache import cache
from rest_framework import status, generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import User, LoginAudit, PasswordResetToken
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserSerializer,
    PasswordChangeSerializer,
    LoginAuditSerializer
)
from .backends import EmailBackend

logger = logging.getLogger('security')


class UserRegistrationView(APIView):
    """View for user registration."""
    
    permission_classes = [AllowAny]
    
    @method_decorator(ratelimit(key='ip', rate='3/h', method='POST'))
    @swagger_auto_schema(
        request_body=UserRegistrationSerializer,
        responses={
            201: UserSerializer,
            400: "Bad Request"
        }
    )
    def post(self, request):
        serializer = UserRegistrationSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if serializer.is_valid():
            user = serializer.save()
            
            # Log registration
            logger.info(f"User registered: {user.email} from IP: {request.META.get('REMOTE_ADDR')}")
            
            # Return user data (without sensitive info)
            user_serializer = UserSerializer(user)
            return Response(user_serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    """View for user login with security features."""
    
    permission_classes = [AllowAny]
    
    @method_decorator(ratelimit(key='ip', rate='5/15m', method='POST'))
    @method_decorator(ratelimit(key='post:email', rate='5/15m', method='POST'))
    @swagger_auto_schema(
        request_body=UserLoginSerializer,
        responses={
            200: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'access': openapi.Schema(type=openapi.TYPE_STRING),
                    'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                    'user': UserSerializer(),
                    'requires_2fa': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                }
            ),
            400: "Bad Request",
            401: "Unauthorized",
            423: "Account Locked"
        }
    )
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        remember_me = serializer.validated_data.get('remember_me', False)
        
        # Get client info
        ip_address = request.META.get('REMOTE_ADDR')
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Log failed attempt for non-existent user
            LoginAudit.objects.create(
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                attempt_number=1
            )
            logger.warning(f"Failed login attempt for non-existent user: {email} from IP: {ip_address}")
            return Response(
                {"detail": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Check if account is locked
        if user.is_locked:
            LoginAudit.objects.create(
                user=user,
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                attempt_number=user.login_attempts,
                lockout_triggered=True
            )
            
            time_remaining = user.locked_until - timezone.now()
            minutes = int(time_remaining.total_seconds() // 60)
            
            return Response({
                "detail": "Account temporarily locked",
                "locked_until": user.locked_until,
                "minutes_remaining": minutes
            }, status=status.HTTP_423_LOCKED)
        
        # Authenticate user
        backend = EmailBackend()
        user = backend.authenticate(
            request,
            username=email,
            password=password
        )
        
        if user is not None:
            # Reset login attempts on successful login
            user.reset_login_attempts()
            
            # Update last login info
            user.last_login = timezone.now()
            user.last_login_ip = ip_address
            user.last_login_user_agent = user_agent
            user.save(update_fields=[
                'last_login', 'last_login_ip', 'last_login_user_agent'
            ])
            
            # Create login audit record
            LoginAudit.objects.create(
                user=user,
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=True,
                attempt_number=1
            )
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            # Set token expiration based on remember_me
            if not remember_me:
                # Shorter expiration for regular sessions
                refresh.access_token.set_exp(lifetime=timedelta(minutes=15))
            else:
                # Longer expiration for "remember me"
                refresh.access_token.set_exp(lifetime=timedelta(hours=24))
            
            # Log successful login
            logger.info(f"Successful login: {user.email} from IP: {ip_address}")
            
            response_data = {
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': UserSerializer(user).data,
                'requires_2fa': user.two_factor_enabled,
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
        else:
            # Increment failed login attempts
            user.increment_login_attempts()
            
            # Create failed login audit
            LoginAudit.objects.create(
                user=user,
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                attempt_number=user.login_attempts,
                lockout_triggered=user.is_locked
            )
            
            logger.warning(f"Failed login attempt: {email} from IP: {ip_address}. Attempts: {user.login_attempts}")
            
            if user.is_locked:
                return Response({
                    "detail": "Account temporarily locked due to multiple failed attempts",
                    "locked_until": user.locked_until
                }, status=status.HTTP_423_LOCKED)
            
            return Response(
                {"detail": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED
            )


class UserLogoutView(APIView):
    """View for user logout with token blacklisting."""
    
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        responses={
            200: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )
        }
    )
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            
            # Clear any session data
            request.session.flush()
            
            logger.info(f"User logged out: {request.user.email}")
            
            return Response(
                {"detail": "Successfully logged out"},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return Response(
                {"detail": "Error during logout"},
                status=status.HTTP_400_BAD_REQUEST
            )


class UserProfileView(generics.RetrieveUpdateAPIView):
    """View for user profile management."""
    
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    
    def get_object(self):
        return self.request.user


class PasswordChangeView(APIView):
    """View for changing user password."""
    
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        request_body=PasswordChangeSerializer,
        responses={
            200: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            ),
            400: "Bad Request"
        }
    )
    def post(self, request):
        serializer = PasswordChangeSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if serializer.is_valid():
            user = request.user
            
            # Verify current password
            if not user.check_password(serializer.validated_data['current_password']):
                return Response(
                    {"current_password": "Current password is incorrect"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Set new password
            new_password = serializer.validated_data['new_password']
            user.set_password(new_password)
            
            # Save password to history
            user.save_password_to_history(new_password)
            
            user.save()
            
            # Blacklist all existing tokens
            RefreshToken.for_user(user).blacklist()
            
            # Log password change
            logger.info(f"Password changed for user: {user.email}")
            
            return Response(
                {"detail": "Password changed successfully. Please login again."},
                status=status.HTTP_200_OK
            )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginHistoryView(generics.ListAPIView):
    """View for user login history."""
    
    serializer_class = LoginAuditSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return LoginAudit.objects.filter(user=self.request.user).order_by('-timestamp')[:50]


class CustomTokenRefreshView(TokenRefreshView):
    """Custom token refresh view with Redis-based blacklist check."""
    
    @method_decorator(ratelimit(key='ip', rate='10/min', method='POST'))
    def post(self, request, *args, **kwargs):
        # Check if token is blacklisted in Redis
        refresh_token = request.data.get('refresh')
        if refresh_token:
            cache_key = f"blacklisted_token:{refresh_token}"
            if cache.get(cache_key):
                return Response(
                    {"detail": "Token is blacklisted"},
                    status=status.HTTP_401_UNAUTHORIZED
                )
        
        response = super().post(request, *args, **kwargs)
        
        # Blacklist the old refresh token
        if refresh_token and 'refresh' in response.data:
            # Store blacklisted token in Redis for 7 days
            cache.set(f"blacklisted_token:{refresh_token}", True, timeout=7*24*60*60)
        
        return response