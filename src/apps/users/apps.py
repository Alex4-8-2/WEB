from django.apps import AppConfig


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.users'
    verbose_name = 'Users Management'
    
    def ready(self):
        # Importar señales cuando la app esté lista
        try:
            import apps.users.signals  # noqa: F401
        except ImportError:
            pass