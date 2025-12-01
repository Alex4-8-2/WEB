#  Sistema de Login con Django

Sistema de autenticación empresarial con seguridad avanzada, construido con Django, Docker y PostgreSQL.

## Características

### Seguridad
-  Autenticación JWT con RS256
-  Rate limiting por IP y usuario
-  Protección contra fuerza bruta
-  Contraseñas Argon2
-  2FA (Google Authenticator)
-  Headers de seguridad avanzados
-  Auditoría completa de logins
-  Blacklist de tokens en Redis

### Tecnologías
- Django 4.2 + Django REST Framework
- PostgreSQL 15
- Redis 7
- Docker + Docker Compose
- Nginx como reverse proxy

##  Estructura del Proyecto
LOGIN/
├── docker-compose.yml # Orquestación de contenedores
├── Dockerfile # Imagen Django
├── requirements.txt # Dependencias Python
├── .env.example # Variables de entorno
├── src/ # Código fuente Django
├── nginx/ # Configuración Nginx
├── postgres/ # Scripts PostgreSQL
## Inicio Rápido

### 1. Prerrequisitos
- Docker Desktop para Windows
- Git (opcional)

### 2. Configuración
```powershell
# Copiar variables de entorno
Copy-Item .env.example .env

# Editar .env con tus valores
notepad .env
└── redis/ # Configuración Redis

