#!/usr/bin/env bash
# Comprueba que el servidor VIGÍA acepta TLS 1.3 (con certificado verificable) y rechaza TLS 1.2.
# Requiere el servidor corriendo. Uso: scripts/verificar_tls.sh [host:puerto] [cafile]
#   por defecto: 127.0.0.1:8443 y $VIGIA_CERTS_DIR/cert.pem (certs/cert.pem)
set -uo pipefail

DESTINO="${1:-127.0.0.1:8443}"
CAFILE="${2:-${VIGIA_CERTS_DIR:-certs}/cert.pem}"

if [[ ! -f "$CAFILE" ]]; then
  echo "Error: no existe $CAFILE (ver scripts/generar_cert.sh)" >&2
  exit 2
fi

echo "== TLS 1.3 (se espera: ACEPTADO) =="
# </dev/null cierra la sesión tras el handshake; timeout evita bloqueos.
SALIDA13="$(timeout 10 openssl s_client -connect "$DESTINO" -tls1_3 -CAfile "$CAFILE" \
  -verify_hostname localhost </dev/null 2>&1)"
echo "$SALIDA13" | grep -E "^(New, |Protocol:|Verification|Verified peername|Server public key|Peer signature type)|Verify return code" || true

# Línea "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384" (estable entre versiones de OpenSSL).
PROTO="$(echo "$SALIDA13" | sed -n 's/^New, \([^,]*\), Cipher is .*/\1/p' | head -n1)"
CIFRADO="$(echo "$SALIDA13" | sed -n 's/^New, [^,]*, Cipher is \(.*\)$/\1/p' | head -n1)"
VERIFY="$(echo "$SALIDA13" | sed -n 's/^ *Verify return code: *\([0-9]*\).*/\1/p' | head -n1)"

echo
echo "== TLS 1.2 (se espera: RECHAZADO) =="
SALIDA12="$(timeout 10 openssl s_client -connect "$DESTINO" -tls1_2 -CAfile "$CAFILE" </dev/null 2>&1)"
echo "$SALIDA12" | grep -Ei "alert|error|no peer certificate|^New, " | head -n3 || true
# Aceptado solo si se negoció un cifrado real (si no, openssl imprime "New, (NONE), Cipher is (NONE)").
PROTO12="$(echo "$SALIDA12" | sed -n 's/^New, \(TLSv1\.2\), Cipher is [A-Za-z0-9].*/\1/p' | head -n1)"

OK=0
if [[ "$PROTO" == "TLSv1.3" && "$VERIFY" == "0" ]]; then
  R13="ACEPTADO (cipher: ${CIFRADO:-?}, Verify return code: 0 (ok))"
else
  R13="FALLO (Protocol='${PROTO:-ninguno}', Verify return code='${VERIFY:-?}')"; OK=1
fi
if [[ "$PROTO12" == "TLSv1.2" ]]; then
  R12="ACEPTADO (¡INSEGURO: el servidor debería rechazarlo!)"; OK=1
else
  R12="RECHAZADO"
fi

echo
echo "=============== RESUMEN ==============="
echo "TLS 1.3: $R13"
echo "TLS 1.2: $R12"
echo "======================================="
exit "$OK"
