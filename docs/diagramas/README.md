# Diagramas de VIGÍA

Los diagramas están en Mermaid (un archivo `.mmd` por diagrama) y reflejan lo que hace el código
en `vigia/crypto/`, `vigia/server/`, `vigia/sensor.py`, `vigia/cli.py` y `scripts/run_server.py`.

| Archivo | Tipo | Qué muestra |
|---|---|---|
| `arquitectura-resumen.mmd` | flowchart TD | Arquitectura simplificada para el informe principal (Figura 1): sensor, TLS 1.3, API y verificador, KEK en memoria, las cuatro tablas de SQLite, dashboard y host de administración (CLI, `.env`, `sensores/<id>.key`), marcando qué va cifrado (K en `sensores`, KEK) y qué va en claro (K en el `.key`, `mediciones`, `eventos`). |
| `arquitectura.mmd` | flowchart | Arquitectura detallada (se usa en el Anexo A): componentes (simulador, canal TLS 1.3, API FastAPI, SQLite, dashboard, CLI, `.env`) y qué está cifrado o protegido en cada punto: la llave K en `sensores/<id>.key` va en claro (0600), las llaves en la BD van cifradas con AES-256-GCM, la tabla `mediciones` queda protegida contra alteración por HMAC y cadena de hashes, y `eventos` no lleva cadena (guarda el tag solo si fue VERIFICADA y la huella SHA-256 del tag si fue rechazada). |
| `flujo-sensor.mmd` | flowchart | Del valor medido al mensaje canónico `VIGIA-v1\|id\|seq\|ts\|valor`, el HMAC-SHA256 con K, el JSON y el envío por TLS 1.3. Incluye cuándo se persiste la `seq` en `sensores/<id>.seq` (solo tras VERIFICADA o un replay de la misma seq) y cuándo no avanza. |
| `flujo-verificacion.mmd` | flowchart TD | Solo la ingesta (Figura 3): formato y HTTP 422, `BEGIN IMMEDIATE`, descifrado de K, lectura del último registro, los 5 pasos en orden con cada estado de fallo al lado (FALSA, MANIPULADA, REPLAY O HUECO, FUERA DE VENTANA, CADENA ROTA), el cálculo `h_i = SHA256(h_prev ‖ mensaje ‖ tag)`, VERIFICADA, y qué se guarda en `mediciones` y en `eventos` (tag si VERIFICADA, huella si rechazada). El detalle de cada paso va en el texto del informe. |
| `flujo-historial.mmd` | flowchart TD | "Verificar historial completo" (Figura 4): recorrido de todos los registros, MANIPULADA (formato, id o HMAC), CADENA ROTA (hueco, enlace o hash) y VERIFICADA, y el reporte que se devuelve al dashboard sin escribir en la BD. |
| `flujo-almacenamiento.mmd` | sequenceDiagram | `init` (salt de 16 B, Argon2id t=3 m=64 MiB p=4, canario), `registrar-sensor` (K de 32 B cifrada con AES-256-GCM, nonce nuevo de 12 B, AAD ligada al id), arranque del servidor (KEK, canario, fallo con contraseña incorrecta) e ingesta (K descifrada bajo demanda). |
| `modelo-amenazas.mmd` | flowchart | Siete atacantes (red/MITM, sensor falso, replay, insider con acceso a la BD, ladrón de la BD o backup, operador con la contraseña maestra o servidor comprometido, sensor físicamente comprometido) → la defensa implementada que los mitiga (TLS 1.3, HMAC, seq y ventana, cadena con re-verificación de HMAC e historial, AES-256-GCM con Argon2id, huella del tag en `eventos`) → riesgo residual. Marca lo fuera de alcance. |

## Cómo exportar a PNG

Los siete PNG están generados en esta carpeta (uno por `.mmd`, con fondo blanco y escala 2) con Mermaid CLI 11.4.2 (requiere Node; el comando descarga el paquete la primera vez):

```bash
cd docs/diagramas
for d in arquitectura arquitectura-resumen flujo-sensor flujo-verificacion flujo-historial flujo-almacenamiento modelo-amenazas; do
  npx @mermaid-js/mermaid-cli@11.4.2 -i "$d.mmd" -o "$d.png" -b white -s 2
done
```

Alternativas: pegar el contenido del `.mmd` en <https://mermaid.live> y descargar PNG o SVG.
GitHub renderiza los diagramas directamente si se pegan en un bloque de código con la etiqueta `mermaid`.

Forma de los diagramas para impresión: `flujo-verificacion`, `flujo-historial` y `arquitectura-resumen` son estrechos y altos (proporción cercana a A4 vertical, pocas palabras por nodo) para que el texto sea legible en el PDF del informe; `arquitectura.mmd` (detallada) se usa en el Anexo A.
