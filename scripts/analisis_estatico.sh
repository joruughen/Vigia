#!/usr/bin/env bash
# Análisis estático de VIGÍA (Python): bandit (código y tests) y pip-audit (dependencias).
# Ejecutar desde la raíz del repo: scripts/analisis_estatico.sh
# Salidas en docs/analisis-estatico/ (texto y JSON). Los hallazgos NO abortan el script.
set -euo pipefail

cd "$(dirname "$0")/.."

PY=".venv/bin/python"
BANDIT=".venv/bin/bandit"
PIP_AUDIT=".venv/bin/pip-audit"
OUT="${ANALISIS_OUT:-docs/analisis-estatico}"  # ANALISIS_OUT: otra carpeta de salida

mkdir -p "$OUT"

{
  echo "Fecha: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "Python: $($PY --version 2>&1)"
  echo "bandit: $($BANDIT --version 2>&1 | head -n 1)"
  echo "pip-audit: $($PIP_AUDIT --version 2>&1)"
} > "$OUT/VERSIONES.txt"

# bandit sobre código de la aplicación (exit != 0 significa hallazgos; no abortar)
$BANDIT -r vigia scripts -f txt -o "$OUT/bandit.txt" || true
$BANDIT -r vigia scripts -f json -o "$OUT/bandit.json" || true

# bandit sobre tests (los assert B101 son esperables en pytest)
$BANDIT -r tests -f txt -o "$OUT/bandit-tests.txt" || true

# pip-audit sobre dependencias de runtime y de desarrollo (requiere red; el error queda en el archivo)
$PIP_AUDIT -r requirements.txt --format columns > "$OUT/pip-audit.txt" 2>&1 || true
$PIP_AUDIT -r requirements.txt --format json > "$OUT/pip-audit.json" 2>"$OUT/pip-audit.json.err" || true
$PIP_AUDIT -r requirements-dev.txt --format columns > "$OUT/pip-audit-dev.txt" 2>&1 || true

echo "Análisis estático terminado. Salidas en $OUT/"
