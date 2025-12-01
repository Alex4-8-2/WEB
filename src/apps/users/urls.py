from django.urls import path, include
from rest_framework_simplejwt.views import TokenVerifyView
from .views import (
    UserRegistrationView,
    UserLoginView,
    UserLogoutView,
    UserProfileView,
    PasswordChangeView,
    LoginHistoryView,
    CustomTokenRefreshView
)

urlpatterns = [
    # Registration
    path('register/', UserRegistrationView.as_view(), name='register'),
    
    # Login/Logout
    path('login/', UserLoginView.as_view(), name='login'),
    path('logout/', UserLogoutView.as_view(), name='logout'),
    
    # Token management
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    
    # User profile
    path('profile/', UserProfileView.as_view(), name='profile'),
    
    # Password management
    path('password/change/', PasswordChangeView.as_view(), name='password_change'),
    
    # Security features
    path('login-history/', LoginHistoryView.as_view(), name='login_history'),
]