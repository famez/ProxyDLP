FROM nginx:1.28.0

# Create directory for certs
RUN mkdir -p /etc/nginx/certs

COPY server.crt /etc/nginx/certs/server.crt
COPY server.key /etc/nginx/certs/server.key

# Copy your Nginx config
COPY default.conf /etc/nginx/conf.d/default.conf
