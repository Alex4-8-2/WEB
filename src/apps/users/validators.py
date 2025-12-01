import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class ComplexPasswordValidator:
    """
    Validate whether the password meets complexity requirements.
    """
    
    def validate(self, password, user=None):
        errors = []
        
        # Minimum length
        if len(password) < 12:
            errors.append(_("Password must be at least 12 characters long."))
        
        # Check for uppercase
        if not re.search(r'[A-Z]', password):
            errors.append(_("Password must contain at least one uppercase letter."))
        
        # Check for lowercase
        if not re.search(r'[a-z]', password):
            errors.append(_("Password must contain at least one lowercase letter."))
        
        # Check for numbers
        if not re.search(r'[0-9]', password):
            errors.append(_("Password must contain at least one number."))
        
        # Check for special characters
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append(_("Password must contain at least one special character."))
        
        # Check for common passwords (simplified check)
        common_passwords = [
            'password', '123456', 'qwerty', 'admin', 'welcome',
            'password123', 'letmein', 'monkey', 'football', 'iloveyou'
        ]
        if password.lower() in common_passwords:
            errors.append(_("Password is too common. Please choose a stronger password."))
        
        # Check for sequential characters
        if re.search(r'(.)\1{2,}', password):
            errors.append(_("Password contains repeating characters."))
        
        # Check for sequential numbers
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
            errors.append(_("Password contains sequential numbers."))
        
        if errors:
            raise ValidationError(errors)
    
    def get_help_text(self):
        return _(
            "Your password must contain at least 12 characters, "
            "including uppercase, lowercase, numbers, and special characters. "
            "Avoid common passwords and sequential patterns."
        )