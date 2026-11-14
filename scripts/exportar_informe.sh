#!/usr/bin/env bash
# Exporta docs/informe.md a PDF (y DOCX) con los diagramas PNG ya dibujados.
# Requisitos: pandoc (p.ej. `pip install pypandoc_binary`) y un Chrome/Chromium headless
# (p.ej. el que instala `npx @mermaid-js/mermaid-cli` en ~/.cache/puppeteer).
# Uso: scripts/exportar_informe.sh            (salida en docs/informe.pdf y docs/informe.docx)
#      PANDOC=/ruta/pandoc CHROME=/ruta/chrome scripts/exportar_informe.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PANDOC="${PANDOC:-$(command -v pandoc || true)}"
CHROME="${CHROME:-$(command -v chromium || command -v google-chrome || command -v google-chrome-stable || \
  find "$HOME/.cache/puppeteer" -type f -name chrome-headless-shell -perm -u+x 2>/dev/null | head -1 || true)}"
[ -x "$PANDOC" ] || { echo "No se encontró pandoc (define PANDOC=...)"; exit 1; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# 1) Markdown -> HTML autocontenido (imágenes embebidas), con estilo de impresión.
(cd docs && "$PANDOC" informe.md --standalone --embed-resources --toc --toc-depth=2 \
  --css ../scripts/informe.css \
  --metadata toc-title="Contenido" -o "$TMP/informe.html")

# 2) HTML -> PDF con Chrome headless.
if [ -x "${CHROME:-}" ]; then
  "$CHROME" --headless --disable-gpu --no-sandbox --no-pdf-header-footer \
    --print-to-pdf="docs/informe.pdf" "file://$TMP/informe.html" 2>/dev/null
  echo "PDF:  docs/informe.pdf"
else
  echo "Sin Chrome headless: no se generó PDF"
fi

# 3) DOCX (alternativa editable).
(cd docs && "$PANDOC" informe.md --toc -o informe.docx)
echo "DOCX: docs/informe.docx"
