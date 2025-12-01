FROM nginx:1.23-alpine

# Copiar configuración
COPY nginx.conf /etc/nginx/nginx.conf

# Crear directorios de certificados
RUN mkdir -p /etc/nginx/ssl

EXPOSE 80 443