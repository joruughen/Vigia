# VIGÍA: telemetría de sensores criptográficamente verificable

VIGÍA es un sistema de telemetría en el que un servidor **verifica criptográficamente** cada medición de un sensor (simulado) y el historial completo de cada sensor, y muestra el resultado en un dashboard. Lo que garantiza, **además de TLS 1.3**:

- **Autenticidad e integridad** de cada medición: HMAC-SHA256 con una llave K por sensor (comparación en tiempo constante).
- **Frescura y orden**: número de secuencia estricto, ventana de timestamp y cadena de hashes SHA-256 que incluye el tag; cada intento recibe uno de seis estados (`VERIFICADA`, `FALSA`, `MANIPULADA`, `REPLAY O HUECO`, `FUERA DE VENTANA`, `CADENA ROTA`).
- **Llaves en reposo cifradas**: AES-256-GCM con llave derivada por Argon2id (salt y nonce únicos).

VIGÍA **no** cifra las mediciones almacenadas (las hace verificables, no confidenciales) ni da no-repudio (llave compartida).

## Requisitos

- Linux o macOS, Python: probado con Python 3.14 (no se probó en otras versiones) y OpenSSL (para `scripts/generar_cert.sh` y `scripts/verificar_tls.sh`).
- Opcional: Node (`npx`) para regenerar los diagramas; `pandoc` y un Chrome/Chromium headless para exportar el informe a PDF.

## Instalación

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Demo en un comando

`scripts/demo.sh` crea un entorno aislado en `demo-run/` (contraseña aleatoria, BD, llaves y certificado propios), levanta el servidor con TLS 1.3 y un simulador de `sensor-01`:

```bash
scripts/demo.sh up              # crea demo-run/, levanta servidor y sensor
# abrir https://127.0.0.1:8443 y aceptar el certificado autofirmado
scripts/demo.sh ataque todos    # todos los ataques, con su estado y una tabla resumen
scripts/demo.sh bd              # la BD "robada": llaves ilegibles, mediciones en claro
scripts/demo.sh tls             # TLS 1.3 aceptado, TLS 1.2 rechazado
scripts/demo.sh estatico        # resumen del último análisis estático
scripts/demo.sh down            # detiene servidor y sensor
scripts/demo.sh reset           # down y borra demo-run/
```

Otros subcomandos: `status`, `logs` y `ataque <nombre>` (`manipulada`, `falsa`, `replay`, `hueco`, `fuera-ventana`, `bd-alterar-valor`, `bd-borrar`, `cadena-rota`). Guion de 5 minutos en [`docs/demo.md`](docs/demo.md).

## Uso manual, paso a paso

Desde la raíz del repo:

```bash
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(32))"   # pega el resultado como VIGIA_MASTER_PASSWORD en .env

scripts/generar_cert.sh                                   # certificado de desarrollo en certs/
.venv/bin/python -m vigia.cli init                        # salt Argon2id y canario en la BD
.venv/bin/python -m vigia.cli registrar-sensor sensor-01  # K cifrada en la BD y en claro en sensores/sensor-01.key
.venv/bin/python scripts/run_server.py                    # https://127.0.0.1:8443, TLS 1.3 mínimo

# en otra terminal
.venv/bin/python -m vigia.sensor --sensor sensor-01 --cacert certs/cert.pem --n 3 --intervalo 1
```

La CLI también ofrece `revocar-sensor <id>` y `listar-sensores`. La contraseña debe tener 16 o más caracteres y no puede ser el valor de ejemplo.

## Tests y análisis estático

```bash
.venv/bin/python -m pytest -q                  # 266 tests
.venv/bin/pip install -r requirements-dev.txt
scripts/analisis_estatico.sh                   # bandit y pip-audit; resultados en docs/analisis-estatico/
```

## Exportar el informe

```bash
scripts/exportar_informe.sh                    # docs/informe.pdf y docs/informe.docx
PANDOC=/ruta/pandoc CHROME=/ruta/chrome scripts/exportar_informe.sh   # si no están en el PATH
```

## Estructura del repositorio

| Ruta | Contenido |
|---|---|
| `vigia/crypto/` | Núcleo criptográfico: formato canónico, HMAC, cadena, keystore (AES-256-GCM, Argon2id), verificador |
| `vigia/server/` | API FastAPI, persistencia SQLite y dashboard |
| `vigia/sensor.py`, `vigia/cli.py`, `vigia/config.py` | Simulador de sensor, CLI de administración y configuración |
| `scripts/` | Arranque con TLS, certificado, demo, ataques, vista de la BD, verificación de TLS, análisis estático y exportación del informe |
| `tests/` | 266 tests (estados, ataques, regresiones de la revisión) |
| `docs/` | Informe, anexos, diagramas, evidencias y guías |

## Documentación

- Informe técnico: [`docs/informe.md`](docs/informe.md) ([PDF](docs/informe.pdf)).
- Anexos (protocolo, amenazas, revisión de seguridad, reproducción): [`docs/anexos/`](docs/anexos/README.md).
- Diagramas (Mermaid y PNG): [`docs/diagramas/`](docs/diagramas/README.md).
- Seguridad práctica: [`docs/seguridad-practica.md`](docs/seguridad-practica.md).
- Demo y presentación: [`docs/demo.md`](docs/demo.md) y [`docs/presentacion.md`](docs/presentacion.md).
- Contrato entre módulos y diseño de la Entrega 1: [`docs/contrato-modulos.md`](docs/contrato-modulos.md) y [`docs/diseno-entrega1.md`](docs/diseno-entrega1.md).

## Seguridad

- **Nunca subas** `.env`, `sensores/`, `certs/`, `data/` ni `demo-run/` (están en `.gitignore`); solo `.env.example`, sin secretos, es público.
- El certificado de `scripts/generar_cert.sh` es autofirmado y **solo de desarrollo**.

## Limitaciones principales

Lista completa en la [sección 8 del informe](docs/informe.md#8-limitaciones).

- El HMAC usa llave compartida: un servidor comprometido o quien tenga la contraseña maestra puede forjar tags (sin no-repudio).
- K también queda en claro en `sensores/<id>.key`; la revocación es solo un flag en la BD, sin rotación de llaves.
- El truncado de las últimas mediciones no se ve en el historial; operativamente aparece como `REPLAY O HUECO`.
- La API y el dashboard no tienen autenticación (escuchan en 127.0.0.1 por defecto); la denegación de servicio está fuera de alcance.
- Las mediciones se guardan en claro, `eventos` no está encadenada y el sensor es simulado (sin hardware real).

## Autores

Jorge Eduardo Melgarejo Castillo y Sergio Felipe Delgado Amado. Proyecto final del curso de Criptografía (UTEC).
