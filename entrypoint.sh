#!/bin/sh

# Esperar a que PostgreSQL esté listo usando psycopg2
echo "Waiting for PostgreSQL..."
while ! python -c "import psycopg2; psycopg2.connect(dbname='${DB_NAME}', user='${DB_USER}', password='${DB_PASSWORD}', host='postgres')" 2>/dev/null; do
  sleep 2
done
echo "PostgreSQL started"

# Esperar a que Redis esté listo
echo "Waiting for Redis..."
while ! python -c "import redis; r = redis.Redis(host='redis', port=6379, password='${REDIS_PASSWORD}'); r.ping()" 2>/dev/null; do
  sleep 2
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