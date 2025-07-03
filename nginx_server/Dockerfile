FROM nginx:1.28.0

# Create directory for certs
RUN mkdir -p /etc/nginx/certs

COPY server.crt /etc/nginx/certs/server.crt
COPY server.key /etc/nginx/certs/server.key


RUN mkdir -p /var/www/images/

COPY proxydlp-dark.png /var/www/images/
COPY proxydlp-light.png /var/www/images/
COPY proxydlp.png /var/www/images/
COPY favicon.ico /var/www/images/


# Copy your Nginx config
COPY default.conf /etc/nginx/conf.d/default.conf
