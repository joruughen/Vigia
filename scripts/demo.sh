#!/usr/bin/env bash
# Entorno de DEMO aislado de VIGÍA (todo vive en demo-run/, ignorado por git).
#
#   scripts/demo.sh up        crea demo-run/ (si falta), levanta servidor TLS y simulador de sensor-01
#   scripts/demo.sh status    estado de procesos y resumen de sensores
#   scripts/demo.sh down      detiene servidor y simulador
#   scripts/demo.sh reset     down + borra demo-run/ (contraseña, BD, llaves y certificado)
# Atajos para la demo en vivo (usan la configuración de demo-run/):
#   scripts/demo.sh ataque <subcomando>   = scripts/ataques.py <subcomando>   (p.ej. "ataque todos")
#   scripts/demo.sh bd                    = scripts/mostrar_bd.py (llaves ilegibles)
#   scripts/demo.sh tls                   = scripts/verificar_tls.sh (TLS 1.3 sí, TLS 1.2 no)
#   scripts/demo.sh estatico              resumen del último reporte de análisis estático (solo lectura)
#   scripts/demo.sh logs                  sigue el log del servidor (Ctrl-C para salir)
# Puerto distinto: VIGIA_PORT=9443 scripts/demo.sh up (queda fijado en demo-run/.env).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PY="$ROOT/.venv/bin/python"
RUN="$ROOT/demo-run"
ENVF="$RUN/.env"
SRV_PID="$RUN/server.pid"
SIM_PID="$RUN/sensor-01.pid"
SRV_LOG="$RUN/server.log"
SIM_LOG="$RUN/sensor-01.log"
SENSORES=(sensor-01 sensor-02)

die()  { echo "Error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

[[ -x "$PY" ]] || die "no existe $PY (crea el venv: python -m venv .venv && .venv/bin/pip install -r requirements.txt)"

cargar_env() {
  [[ -f "$ENVF" ]] || die "no existe $ENVF; ejecuta primero: scripts/demo.sh up"
  set -a
  # shellcheck disable=SC1090
  . "$ENVF"
  set +a
  URL="https://${VIGIA_HOST}:${VIGIA_PORT}"
  CACERT="${VIGIA_CERTS_DIR}/cert.pem"
}

# ¿El PID del archivo sigue vivo y es el proceso esperado? (evita matar un PID reciclado)
pid_vivo() {
  local f="$1" patron="$2" pid
  [[ -f "$f" ]] || return 1
  pid="$(<"$f")"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  ps -p "$pid" -o args= 2>/dev/null | grep -q -- "$patron"
}

puerto_ocupado() {  # 0 si algo escucha en host:puerto
  "$PY" - "$1" "$2" <<'EOF'
import socket, sys
s = socket.socket()
s.settimeout(1)
ocupado = s.connect_ex((sys.argv[1], int(sys.argv[2]))) == 0
s.close()
sys.exit(0 if ocupado else 1)
EOF
}

responde() {  # 0 si el servidor contesta /api/config por HTTPS validando el certificado
  "$PY" - "$URL" "$CACERT" <<'EOF' 2>/dev/null
import ssl, sys, httpx
ctx = ssl.create_default_context(cafile=sys.argv[2])
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
sys.exit(0 if httpx.get(sys.argv[1] + "/api/config", verify=ctx, timeout=2).status_code == 200 else 1)
EOF
}

crear_env() {
  mkdir -p "$RUN"
  chmod 700 "$RUN"
  local pass
  pass="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(32))')"
  ( umask 077
    cat > "$ENVF" <<EOF
# Generado por scripts/demo.sh: SOLO para la demo. No subir al repo (demo-run/ está en .gitignore).
VIGIA_MASTER_PASSWORD=$pass
VIGIA_DB_PATH=$RUN/data/vigia.db
VIGIA_VENTANA_MS=30000
VIGIA_SENSORES_DIR=$RUN/sensores
VIGIA_CERTS_DIR=$RUN/certs
VIGIA_HOST=127.0.0.1
VIGIA_PORT=${VIGIA_PORT:-8443}
EOF
  )
  info "Creado $ENVF (contraseña maestra aleatoria; no se muestra)."
}

arrancar_servidor() {
  if pid_vivo "$SRV_PID" run_server.py; then
    info "Servidor ya en ejecución (PID $(<"$SRV_PID"))."
    return
  fi
  if puerto_ocupado "$VIGIA_HOST" "$VIGIA_PORT"; then
    die "el puerto $VIGIA_HOST:$VIGIA_PORT ya está en uso por otro proceso. Libéralo o usa otro: VIGIA_PORT=9443 scripts/demo.sh reset && VIGIA_PORT=9443 scripts/demo.sh up"
  fi
  info "Arrancando servidor TLS 1.3 en $URL ..."
  setsid "$PY" -u scripts/run_server.py > "$SRV_LOG" 2>&1 < /dev/null &
  echo $! > "$SRV_PID"
  local i
  for i in $(seq 1 60); do  # hasta ~30 s (incluye la derivación Argon2id)
    if ! pid_vivo "$SRV_PID" run_server.py; then
      echo "--- últimas líneas de $SRV_LOG ---" >&2
      tail -n 15 "$SRV_LOG" >&2 || true
      rm -f "$SRV_PID"
      die "el servidor terminó al arrancar."
    fi
    if responde; then
      info "Servidor listo (PID $(<"$SRV_PID")), log: $SRV_LOG"
      return
    fi
    sleep 0.5
  done
  die "el servidor no respondió en 30 s; revisa $SRV_LOG"
}

arrancar_simulador() {
  if pid_vivo "$SIM_PID" vigia.sensor; then
    info "Simulador sensor-01 ya en ejecución (PID $(<"$SIM_PID"))."
    return
  fi
  info "Arrancando simulador de sensor-01 (1 medición cada 2 s) ..."
  setsid "$PY" -u -m vigia.sensor --sensor sensor-01 --url "$URL" --intervalo 2 \
    --cacert "$CACERT" --sensores-dir "$VIGIA_SENSORES_DIR" > "$SIM_LOG" 2>&1 < /dev/null &
  echo $! > "$SIM_PID"
  sleep 1
  if ! pid_vivo "$SIM_PID" vigia.sensor; then
    tail -n 10 "$SIM_LOG" >&2 || true
    rm -f "$SIM_PID"
    die "el simulador terminó al arrancar."
  fi
  info "Simulador listo (PID $(<"$SIM_PID")), log: $SIM_LOG"
}

cmd_up() {
  [[ -f "$ENVF" ]] || crear_env
  cargar_env
  if [[ ! -f "$VIGIA_CERTS_DIR/cert.pem" ]]; then
    info "Generando certificado autofirmado de desarrollo ..."
    scripts/generar_cert.sh
  fi
  info "Inicializando BD (si hace falta) ..."
  "$PY" -m vigia.cli init
  local s
  for s in "${SENSORES[@]}"; do
    if "$PY" -m vigia.cli listar-sensores | grep -q "^$s "; then
      info "$s ya está registrado."
    else
      "$PY" -m vigia.cli registrar-sensor "$s"
    fi
  done
  arrancar_servidor
  arrancar_simulador
  cat <<EOF

================ DEMO LISTA ================
Dashboard : $URL
Certificado autofirmado: el navegador mostrará una advertencia.
  - Aceptarla: "Avanzado" -> "Continuar a 127.0.0.1" / "Aceptar el riesgo y continuar".
  - O confiar en él: importar $CACERT como autoridad
    (Firefox: Ajustes > Privacidad > Certificados > Ver certificados > Autoridades > Importar;
     Chrome: Ajustes > Privacidad y seguridad > Seguridad > Administrar certificados > Autoridades).
  - Con curl: curl --cacert $CACERT $URL/api/sensores
Comandos de la demo:
  scripts/demo.sh ataque todos     # todos los ataques y tabla resumen
  scripts/demo.sh ataque --help    # ataques individuales
  scripts/demo.sh bd               # BD robada: llaves cifradas
  scripts/demo.sh tls              # TLS 1.3 activo
  scripts/demo.sh status | down | reset
============================================
EOF
}

parar() {  # parar <archivo-pid> <patrón> <nombre>
  local f="$1" patron="$2" nombre="$3" pid i
  if pid_vivo "$f" "$patron"; then
    pid="$(<"$f")"
    kill "$pid" 2>/dev/null || true
    for i in $(seq 1 20); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.25
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
      info "$nombre no respondió a SIGTERM: SIGKILL (PID $pid)."
    else
      info "$nombre detenido (PID $pid)."
    fi
  else
    info "$nombre no estaba en ejecución."
  fi
  rm -f "$f"
}

cmd_down() {
  parar "$SIM_PID" vigia.sensor "Simulador sensor-01"
  parar "$SRV_PID" run_server.py "Servidor"
}

cmd_reset() {
  cmd_down
  if [[ -L "$RUN" ]]; then die "$RUN es un enlace simbólico; no se borra."; fi
  if [[ -d "$RUN" ]]; then
    rm -rf -- "$RUN"
    info "Borrado $RUN."
  else
    info "No existe $RUN."
  fi
}

cmd_status() {
  if [[ ! -f "$ENVF" ]]; then
    echo "demo-run/ no existe: la demo no está creada. Ejecuta: scripts/demo.sh up"
    return 0
  fi
  cargar_env
  local etiqueta
  for par in "Servidor:$SRV_PID:run_server.py" "Simulador sensor-01:$SIM_PID:vigia.sensor"; do
    IFS=: read -r etiqueta f patron <<<"$par"
    if pid_vivo "$f" "$patron"; then echo "$etiqueta: EN EJECUCIÓN (PID $(<"$f"))"
    else echo "$etiqueta: detenido"; fi
  done
  if responde; then
    echo "API: responde en $URL (TLS 1.3, certificado validado)"
    "$PY" - "$URL" "$CACERT" <<'EOF'
import ssl, sys, httpx
ctx = ssl.create_default_context(cafile=sys.argv[2])
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ss = httpx.get(sys.argv[1] + "/api/sensores", verify=ctx, timeout=5).json()
print(f"{'SENSOR':<12}{'ACTIVO':<8}{'VERIFICADAS':<13}{'INTENTOS':<10}{'ÚLT.SEQ':<9}ÚLTIMO ESTADO")
for s in ss:
    print(f"{s['id']:<12}{str(s['activo']):<8}{s['verificadas']:<13}{s['intentos']:<10}"
          f"{str(s['ultima_seq']):<9}{s['ultimo_estado']}")
EOF
  else
    echo "API: no responde en $URL"
  fi
}

cmd_estatico() {
  local d="$ROOT/docs/analisis-estatico"
  if [[ ! -f "$d/bandit.txt" ]]; then
    echo "No hay reporte en $d. Genéralo con: scripts/analisis_estatico.sh"
    return 1
  fi
  echo "== Reporte de análisis estático (último generado; solo lectura) =="
  sed -n '1,4p' "$d/VERSIONES.txt" 2>/dev/null || true
  echo "-- bandit (vigia/ y scripts/) --"
  grep -E "No issues identified|Total lines of code|Low:|Medium:|High:|>> Issue" "$d/bandit.txt" || true
  if [[ -f "$d/pip-audit.txt" ]]; then
    echo "-- pip-audit (dependencias) --"
    head -n 5 "$d/pip-audit.txt"
  fi
  echo "Regenerar: scripts/analisis_estatico.sh"
}

case "${1:-}" in
  up)       cmd_up ;;
  down)     cmd_down ;;
  reset)    cmd_reset ;;
  status)   cmd_status ;;
  ataque)   shift; cargar_env; exec "$PY" scripts/ataques.py "$@" ;;
  bd)       shift; cargar_env; exec "$PY" scripts/mostrar_bd.py --db "$VIGIA_DB_PATH" \
              --sensores-dir "$VIGIA_SENSORES_DIR" "$@" ;;
  tls)      cargar_env; exec scripts/verificar_tls.sh "${VIGIA_HOST}:${VIGIA_PORT}" "$CACERT" ;;
  estatico) cmd_estatico ;;
  logs)     [[ -f "$SRV_LOG" ]] || die "no hay $SRV_LOG"; exec tail -n 30 -f "$SRV_LOG" ;;
  *)        sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; [[ -z "${1:-}" ]] || exit 2 ;;
esac
