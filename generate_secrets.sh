#!/bin/bash

set -e

# Usage check
if [[ -z "$1" ]]; then
  echo "Usage: $0 <nginx_san>"
  echo "Example: $0 proxy.contoso.com"
  exit 1
fi

NGINX_SAN="$1"

# Output directories
NGINX_DIR="./nginx_server"
MITM_DIR="./proxy"
ENV_FILE=".env"
HOST_FILE="web/hostname"

# File names
NGINX_CERT="$NGINX_DIR/server.crt"
NGINX_KEY="$NGINX_DIR/server.key"
NGINX_CSR="$NGINX_DIR/server.csr"
MITM_CERT="$MITM_DIR/mitmCA.pem"
MITM_KEY="$MITM_DIR/mitmCA.key"

# Function to generate random string
generate_secret() {
  local length=$1
  openssl rand -base64 $length | tr -dc 'A-Za-z0-9' | head -c $length
}

# Create directories
mkdir -p "$NGINX_DIR" "$MITM_DIR"

# Create .env file
echo "Generating .env file..."
MONGO_PASSWORD=$(generate_secret 32)
JWT_SECRET=$(generate_secret 64)
PROXY_HOSTNAME=${NGINX_SAN}

cat <<EOF > "$ENV_FILE"
MONGO_INITDB_ROOT_PASSWORD=$MONGO_PASSWORD
JWT_SECRET=$JWT_SECRET
EOF
echo ".env file created."

cat <<EOF > "$HOST_FILE"
PROXY_HOSTNAME=$PROXY_HOSTNAME
EOF

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


# Generate nginx key
if [[ ! -f "$NGINX_KEY" ]]; then
  echo "Generating nginx private key..."
  openssl genrsa -out "$NGINX_KEY" 4096
fi

# Generate nginx CSR with SAN
echo "Generating nginx CSR with SAN $NGINX_SAN..."
cat > "$NGINX_DIR/san.cnf" <<EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = $NGINX_SAN

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = $NGINX_SAN
EOF

openssl req -new -key "$NGINX_KEY" -out "$NGINX_CSR" -config "$NGINX_DIR/san.cnf"

# Sign nginx CSR with mitmproxy CA
echo "Signing nginx certificate with mitmproxy CA..."
openssl x509 -req -in "$NGINX_CSR" -CA "$MITM_CERT" -CAkey "$MITM_KEY" -CAcreateserial \
  -out "$NGINX_CERT" -days 365 -extensions v3_req -extfile "$NGINX_DIR/san.cnf"

rm $NGINX_CSR

echo "NGINX certificate signed by mitmproxy CA."
echo "All files ready."
