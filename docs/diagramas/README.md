# Diagramas de VIGÍA

Los diagramas están en Mermaid (un archivo `.mmd` por diagrama) y reflejan lo que hace el código
en `vigia/crypto/`, `vigia/server/`, `vigia/sensor.py`, `vigia/cli.py` y `scripts/run_server.py`.

| Archivo | Tipo | Qué muestra |
|---|---|---|
| `arquitectura.mmd` | flowchart | Componentes (simulador, canal TLS 1.3, API FastAPI, SQLite, dashboard, CLI, `.env`) y qué está cifrado o protegido en cada punto: la llave K en `sensores/<id>.key` va en claro (0600), las llaves en la BD van cifradas con AES-256-GCM, la tabla `mediciones` queda protegida contra alteración por HMAC y cadena de hashes, y `eventos` no lleva cadena (guarda el tag solo si fue VERIFICADA y la huella SHA-256 del tag si fue rechazada). |
| `flujo-sensor.mmd` | flowchart | Del valor medido al mensaje canónico `VIGIA-v1\|id\|seq\|ts\|valor`, el HMAC-SHA256 con K, el JSON y el envío por TLS 1.3. Incluye cuándo se persiste la `seq` en `sensores/<id>.seq` (solo tras VERIFICADA o un replay de la misma seq) y cuándo no avanza. |
| `flujo-verificacion.mmd` | flowchart | Los 5 pasos en orden con cada estado de salida (FALSA, MANIPULADA, REPLAY O HUECO, FUERA DE VENTANA, CADENA ROTA, VERIFICADA), el cálculo `h_i = SHA256(h_prev ‖ mensaje ‖ tag)`, el paso 5 (re-verifica hash y HMAC del último registro), qué se guarda en `eventos` (tag si VERIFICADA, huella si rechazada) y en `mediciones`, y el subgrafo "Verificar historial completo". |
| `flujo-almacenamiento.mmd` | sequenceDiagram | `init` (salt de 16 B, Argon2id t=3 m=64 MiB p=4, canario), `registrar-sensor` (K de 32 B cifrada con AES-256-GCM, nonce nuevo de 12 B, AAD ligada al id), arranque del servidor (KEK, canario, fallo con contraseña incorrecta) e ingesta (K descifrada bajo demanda). |
| `modelo-amenazas.mmd` | flowchart | Siete atacantes (red/MITM, sensor falso, replay, insider con acceso a la BD, ladrón de la BD o backup, operador con la contraseña maestra o servidor comprometido, sensor físicamente comprometido) → la defensa implementada que los mitiga (TLS 1.3, HMAC, seq y ventana, cadena con re-verificación de HMAC e historial, AES-256-GCM con Argon2id, huella del tag en `eventos`) → riesgo residual. Marca lo fuera de alcance. |

## Cómo exportar a PNG

Con Mermaid CLI (requiere Node; el comando descarga el paquete la primera vez):

```bash
cd docs/diagramas
npx @mermaid-js/mermaid-cli -i arquitectura.mmd -o arquitectura.png
npx @mermaid-js/mermaid-cli -i flujo-sensor.mmd -o flujo-sensor.png
npx @mermaid-js/mermaid-cli -i flujo-verificacion.mmd -o flujo-verificacion.png
npx @mermaid-js/mermaid-cli -i flujo-almacenamiento.mmd -o flujo-almacenamiento.png
npx @mermaid-js/mermaid-cli -i modelo-amenazas.mmd -o modelo-amenazas.png
```

Opciones útiles: `-s 2` (escala, más resolución para el informe) y `-b white` (fondo blanco).

Alternativas: pegar el contenido del `.mmd` en <https://mermaid.live> y descargar PNG o SVG.
GitHub renderiza los diagramas directamente si se pegan en un bloque de código con la etiqueta `mermaid`.

Estado: los PNG todavía no se generaron (`mmdc` no está instalado en esta máquina). Los cuatro primeros `.mmd` se
comprobaron con el parser de Mermaid (la versión incluida en una extensión de VS Code local), sin errores de
sintaxis. `modelo-amenazas.mmd` solo pasó una revisión estructural (nodos y aristas definidos, comillas y
`subgraph`/`end` balanceados); conviene abrirlo en <https://mermaid.live> o exportarlo con el comando anterior.
