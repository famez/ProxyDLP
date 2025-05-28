#!/bin/bash

set -e

# Output directories
NGINX_DIR="./nginx"
MITM_DIR="./proxy"
ENV_FILE=".env"

# File names
NGINX_CERT="$NGINX_DIR/server.crt"
NGINX_KEY="$NGINX_DIR/server.key"
MITM_CERT="$MITM_DIR/mitmCA.pem"
MITM_KEY="$MITM_DIR/mitmCA.key"

# Function to generate random string
generate_secret() {
  local length=$1
  openssl rand -base64 $length | tr -dc 'A-Za-z0-9' | head -c $length
}

# Create .env file
echo "Generating .env file..."
MONGO_PASSWORD=$(generate_secret 32)
JWT_SECRET=$(generate_secret 64)

cat <<EOF > "$ENV_FILE"
MONGO_INITDB_ROOT_PASSWORD=$MONGO_PASSWORD
JWT_SECRET=$JWT_SECRET
EOF
echo ".env file created."

# Generate app certificate and key if not provided
if [[ ! -f "$NGINX_CERT" || ! -f "$NGINX_KEY" ]]; then
  echo "Generating self-signed app certificate..."
  openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
    -keyout "$NGINX_KEY" \
    -out "$NGINX_CERT" \
    -subj "/CN=localhost"
  echo "App certificate and key generated."
else
  echo "App certificate and key already exist. Skipping generation."
fi

# Generate mitmproxy CA cert and key if not provided
if [[ ! -f "$MITM_CERT" || ! -f "$MITM_KEY" ]]; then
  echo "Generating mitmproxy CA certificate..."
  openssl req -x509 -nodes -new -newkey rsa:4096 -days 365 \
    -keyout "$MITM_KEY" \
    -out "$MITM_CERT" \
    -subj "/CN=mitmproxy-ca"
  echo "mitmproxy CA cert and key generated."
else
  echo "mitmproxy CA cert and key already exist. Skipping generation."
fi

echo "All files ready."
