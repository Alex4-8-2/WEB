from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from .models import User, LoginAudit
from .validators import ComplexPasswordValidator


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""
    
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        min_length=12
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    
    class Meta:
        model = User
        fields = [
            'email', 'first_name', 'last_name',
            'password', 'password_confirm'
        ]
    
    def validate(self, attrs):
        # Check password match
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({
                "password": "Passwords do not match."
            })
        
        # Validate password complexity
        password = attrs['password']
        
        # Use Django's built-in validators
        try:
            validate_password(password)
        except ValidationError as e:
            raise serializers.ValidationError({
                "password": list(e.messages)
            })
        
        # Use custom validator
        custom_validator = ComplexPasswordValidator()
        try:
            custom_validator.validate(password)
        except ValidationError as e:
            raise serializers.ValidationError({
                "password": list(e.messages)
            })
        
        return attrs
    
    def create(self, validated_data):
        # Remove password_confirm from validated data
        validated_data.pop('password_confirm')
        
        # Get IP address from request context
        request = self.context.get('request')
        ip_address = request.META.get('REMOTE_ADDR') if request else None
        
        # Create user
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            created_by_ip=ip_address,
            is_active=True  # For development, set to False in production
        )
        
        # Save password to history
        user.save_password_to_history(validated_data['password'])
        
        return user


class UserLoginSerializer(serializers.Serializer):
    """Serializer for user login."""
    
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    remember_me = serializers.BooleanField(default=False)
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        if not email or not password:
            raise serializers.ValidationError(
                "Both email and password are required."
            )
        
        return attrs


class UserSerializer(serializers.ModelSerializer):
    """Serializer for user data (safe fields only)."""
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'email_verified', 'two_factor_enabled',
            'created_at', 'last_login'
        ]
        read_only_fields = fields


class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for password change."""
    
    current_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    new_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        min_length=12
    )
    confirm_password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    
    def validate(self, attrs):
        # Check new passwords match
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({
                "new_password": "New passwords do not match."
            })
        
        # Validate new password complexity
        password = attrs['new_password']
        
        try:
            validate_password(password)
        except ValidationError as e:
            raise serializers.ValidationError({
                "new_password": list(e.messages)
            })
        
        # Use custom validator
        custom_validator = ComplexPasswordValidator()
        try:
            custom_validator.validate(password)
        except ValidationError as e:
            raise serializers.ValidationError({
                "new_password": list(e.messages)
            })
        
        # Check against password history
        user = self.context['request'].user
        if user.check_password(password):
            raise serializers.ValidationError({
                "new_password": "New password cannot be the same as current password."
            })
        
        # Check against password history
        from django.contrib.auth.hashers import make_password
        hashed_password = make_password(password)
        if hashed_password in user.password_history:
            raise serializers.ValidationError({
                "new_password": "You cannot reuse a previous password."
            })
        
        return attrs


class LoginAuditSerializer(serializers.ModelSerializer):
    """Serializer for login audit logs."""
    
    class Meta:
        model = LoginAudit
        fields = [
            'id', 'email', 'ip_address', 'user_agent',
            'success', 'attempt_number', 'lockout_triggered',
            'two_factor_used', 'country', 'city', 'timestamp'
        ]
        read_only_fields = fields