-- Extensiones
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Configuración de seguridad
ALTER DATABASE login_db SET "default_transaction_isolation" TO 'read committed';
ALTER DATABASE login_db SET "jit" TO 'off';

-- Roles de solo lectura (para reportes)
CREATE ROLE login_readonly WITH LOGIN PASSWORD 'readonly_password' NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE login_db TO login_readonly;