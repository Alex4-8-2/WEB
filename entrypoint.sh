#!/bin/sh

# Esperar a que PostgreSQL esté listo
echo "Waiting for PostgreSQL..."
while ! nc -z postgres 5432; do
  sleep 0.1
done
echo "PostgreSQL started"

# Esperar a que Redis esté listo
echo "Waiting for Redis..."
while ! nc -z redis 6379; do
  sleep 0.1
done
echo "Redis started"

# Aplicar migraciones
python manage.py migrate --noinput

# Recoger archivos estáticos
python manage.py collectstatic --noinput

# Crear superusuario si no existe (solo en desarrollo)
if [ "$DEBUG" = "True" ]; then
  echo "Creating superuser..."
  python manage.py createsuperuser --noinput --username admin --email admin@example.com || true
fi

# Ejecutar comando principal
exec "$@"