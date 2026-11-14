#!/usr/bin/env bash
# Genera un certificado autofirmado de DESARROLLO (EC P-256, SAN=IP:127.0.0.1,DNS:localhost).
# Salida: $VIGIA_CERTS_DIR (default certs/) -> cert.pem y key.pem (la llave queda 0600).
set -euo pipefail

DIR="${VIGIA_CERTS_DIR:-certs}"
mkdir -p "$DIR"

if [[ -e "$DIR/cert.pem" || -e "$DIR/key.pem" ]]; then
  echo "Ya existen certificados en $DIR; bórralos para regenerarlos." >&2
  exit 1
fi

umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$DIR/key.pem" -out "$DIR/cert.pem" -days 365 \
  -subj "/CN=localhost/O=VIGIA dev" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth"
chmod 600 "$DIR/key.pem"
chmod 644 "$DIR/cert.pem"
echo "Certificado generado en $DIR/ (cert.pem, key.pem)."
