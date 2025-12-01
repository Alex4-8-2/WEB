# fix_apps.ps1 - Script para corregir todos los problemas
Write-Host "=========================================" -ForegroundColor Green
Write-Host "  CORRIGIENDO ESTRUCTURA DE APPS" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green

# Definir ruta base
$basePath = "D:\WEB_T\LOGIN\src\apps"
if (-not (Test-Path $basePath)) {
    Write-Host "Error: No se encuentra la ruta $basePath" -ForegroundColor Red
    exit 1
}

Write-Host "`n[1/7] Verificando estructura actual..." -ForegroundColor Yellow
Get-ChildItem -Path $basePath -Recurse -Directory | Select-Object FullName

# 1. Crear __init__.py en apps/
Write-Host "`n[2/7] Creando __init__.py en apps/..." -ForegroundColor Yellow
$initFile = Join-Path $basePath "__init__.py"
if (-not (Test-Path $initFile)) {
    "" | Out-File -FilePath $initFile -Encoding UTF8
    Write-Host "  ✓ Creado: $initFile" -ForegroundColor Green
} else {
    Write-Host "  ✓ Ya existe: $initFile" -ForegroundColor Green
}

# 2. Verificar users/__init__.py
Write-Host "`n[3/7] Verificando users/__init__.py..." -ForegroundColor Yellow
$usersInit = Join-Path $basePath "users\__init__.py"
if (-not (Test-Path $usersInit)) {
    "" | Out-File -FilePath $usersInit -Encoding UTF8
    Write-Host "  ✓ Creado: $usersInit" -ForegroundColor Green
} else {
    Write-Host "  ✓ Ya existe: $usersInit" -ForegroundColor Green
}

# 3. Verificar security/__init__.py
Write-Host "`n[4/7] Verificando security/__init__.py..." -ForegroundColor Yellow
$securityInit = Join-Path $basePath "security\__init__.py"
if (-not (Test-Path $securityInit)) {
    "" | Out-File -FilePath $securityInit -Encoding UTF8
    Write-Host "  ✓ Creado: $securityInit" -ForegroundColor Green
} else {
    Write-Host "  ✓ Ya existe: $securityInit" -ForegroundColor Green
}

# 4. Crear users/apps.py CORREGIDO
Write-Host "`n[5/7] Creando users/apps.py..." -ForegroundColor Yellow
$usersApps = Join-Path $basePath "users\apps.py"
@'
from django.apps import AppConfig


class UsersConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.users"
    verbose_name = "Users Management"
    
    def ready(self):
        # Importar señales cuando la app esté lista
        try:
            import apps.users.signals  # noqa: F401
        except ImportError:
            pass
'@ | Out-File -FilePath $usersApps -Encoding UTF8 -Force
Write-Host "  ✓ Creado/Actualizado: $usersApps" -ForegroundColor Green

# 5. Crear security/apps.py en ubicación CORRECTA
Write-Host "`n[6/7] Creando security/apps.py en ubicación correcta..." -ForegroundColor Yellow
$securityApps = Join-Path $basePath "security\apps.py"

# Eliminar carpeta anidada incorrecta si existe
$wrongPath = Join-Path $basePath "security\security"
if (Test-Path $wrongPath) {
    Remove-Item -Path $wrongPath -Recurse -Force
    Write-Host "  ✗ Eliminada carpeta incorrecta: $wrongPath" -ForegroundColor Red
}

@'
from django.apps import AppConfig


class SecurityConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.security"
    verbose_name = "Security System"
'@ | Out-File -FilePath $securityApps -Encoding UTF8 -Force
Write-Host "  ✓ Creado/Actualizado: $securityApps" -ForegroundColor Green

# 6. Corregir security/middleware.py
Write-Host "`n[7/7] Corrigiendo security/middleware.py..." -ForegroundColor Yellow
$middlewareFile = Join-Path $basePath "security\middleware.py"
if (Test-Path $middlewareFile) {
    $content = Get-Content $middlewareFile -Raw
    # Verificar si tiene errores comunes
    if ($content -match "from django\.conf import settings as django_settings") {
        # Reemplazar con versión corregida
        @'
import uuid
import json
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from apps.users.models import UserSession
import logging

logger = logging.getLogger("security")


class SecurityHeadersMiddleware(MiddlewareMixin):
    """Middleware to add security headers to all responses."""
    
    def process_response(self, request, response):
        # Add security headers
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Content Security Policy (simplificado para desarrollo)
        if not settings.DEBUG:
            response["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' https:; "
                "connect-src 'self'; "
                "frame-ancestors 'none';"
            )
        
        return response


class SessionSecurityMiddleware(MiddlewareMixin):
    """Middleware for enhanced session security."""
    
    def process_request(self, request):
        if hasattr(request, "user") and request.user.is_authenticated:
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
                    user_session.save(update_fields=["last_activity"])
                    
                except UserSession.DoesNotExist:
                    # Create new session tracking
                    ip_address = request.META.get("REMOTE_ADDR", "0.0.0.0")
                    user_agent = request.META.get("HTTP_USER_AGENT", "")
                    
                    UserSession.objects.create(
                        user=request.user,
                        session_key=session_key,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        expires_at=request.session.get_expiry_date()
                    )
    
    def process_response(self, request, response):
        if (hasattr(request, "user") and 
            request.user.is_authenticated and 
            "sessionid" in response.cookies):
            
            # Secure session cookie
            response.cookies["sessionid"]["httponly"] = True
            response.cookies["sessionid"]["secure"] = not settings.DEBUG
            response.cookies["sessionid"]["samesite"] = "Strict"
        
        return response


class RequestLoggingMiddleware(MiddlewareMixin):
    """Middleware for logging security-related requests."""
    
    def process_request(self, request):
        # Generate request ID for tracing
        request.request_id = str(uuid.uuid4())
        
        # Log sensitive operations
        if request.method in ["POST", "PUT", "DELETE"]:
            path = request.path
            
            # Check if it"s a security-related endpoint
            security_paths = ["/login", "/register", "/password", "/logout", "/auth"]
            if any(p in path for p in security_paths):
                ip_address = request.META.get("REMOTE_ADDR", "0.0.0.0")
                user_agent = request.META.get("HTTP_USER_AGENT", "")[:100]
                
                # Log to security log
                logger.info(
                    f"Security request: {request.method} {path} "
                    f"from IP: {ip_address} "
                    f"User-Agent: {user_agent} "
                    f"Request-ID: {request.request_id}"
                )
        
        return None
'@ | Out-File -FilePath $middlewareFile -Encoding UTF8 -Force
        Write-Host "  ✓ Middleware corregido" -ForegroundColor Green
    } else {
        Write-Host "  ℹ️ Middleware ya está correcto" -ForegroundColor Cyan
    }
} else {
    Write-Host "  ✗ Archivo middleware.py no encontrado" -ForegroundColor Red
}

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host "  VERIFICACIÓN FINAL" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green

# Verificar estructura final
Write-Host "`nEstructura final de apps:" -ForegroundColor Cyan
Get-ChildItem -Path $basePath -Recurse -File | 
    Where-Object { $_.Extension -eq ".py" } | 
    Select-Object @{Name="Archivo";Expression={$_.FullName.Replace($basePath, "")}} |
    Format-Table -AutoSize

Write-Host "`n✅ Correcciones completadas" -ForegroundColor Green
Write-Host "`n📋 Archivos creados/corregidos:" -ForegroundColor Yellow
Write-Host "  1. src/apps/__init__.py" -ForegroundColor White
Write-Host "  2. src/apps/users/__init__.py" -ForegroundColor White
Write-Host "  3. src/apps/security/__init__.py" -ForegroundColor White
Write-Host "  4. src/apps/users/apps.py" -ForegroundColor White
Write-Host "  5. src/apps/security/apps.py" -ForegroundColor White
Write-Host "  6. src/apps/security/middleware.py" -ForegroundColor White

Write-Host "`n🚀 Ahora ejecuta: docker-compose build" -ForegroundColor Green