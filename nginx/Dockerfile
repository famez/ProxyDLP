FROM nginx:1.28.0

# Create directory for certs
RUN mkdir -p /etc/nginx/certs

# Generate self-signed cert
RUN openssl req -x509 -nodes -days 365 \
  -subj "/C=US/ST=State/L=City/O=Org/CN=test.com" \
  -newkey rsa:4096 \
  -keyout /etc/nginx/certs/server.key \
  -out /etc/nginx/certs/server.crt

# Copy your Nginx config
COPY default.conf /etc/nginx/conf.d/default.conf
