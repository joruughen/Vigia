# Anexo D: cómo reproducir

Comandos para levantar el sistema, ejecutar los tests y repetir el análisis estático, y detalles de los scripts de apoyo. La guía con salidas esperadas está en `docs/seguridad-practica.md`.

## D.1 Puesta en marcha

La guía completa y los comandos con salidas esperadas están en `docs/seguridad-practica.md`. Resumen, desde la raíz del repositorio (`Vigia/`):

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env     # editar VIGIA_MASTER_PASSWORD (16+ caracteres, no el valor de ejemplo)
python3 -c "import secrets; print(secrets.token_urlsafe(32))"   # genera una buena

scripts/generar_cert.sh                                   # certificado de desarrollo -> certs/
.venv/bin/python -m vigia.cli init                        # salt Argon2id + canario
.venv/bin/python -m vigia.cli registrar-sensor sensor-01  # llave -> sensores/sensor-01.key
.venv/bin/python scripts/run_server.py                    # https://127.0.0.1:8443 (TLS 1.3 mínimo)

# en otra terminal
.venv/bin/python -m vigia.sensor --sensor sensor-01 --cacert certs/cert.pem --n 3 --intervalo 1
scripts/verificar_tls.sh                                  # TLS 1.3 aceptado, TLS 1.2 rechazado
.venv/bin/python scripts/mostrar_bd.py                    # la BD robada: llaves cifradas, datos en claro
```

Dashboard: `https://127.0.0.1:8443/` (el navegador avisará del certificado autofirmado).

## D.2 Tests y análisis estático

Tests y análisis estático:

```bash
.venv/bin/python -m pytest -q                 # 266 passed
.venv/bin/pip install -r requirements-dev.txt
scripts/analisis_estatico.sh                  # resultados en docs/analisis-estatico/
```

Evidencias en el repositorio: `docs/evidencia/tls-y-simulador.txt` y `docs/analisis-estatico/`. Diagramas (Mermaid, en `docs/diagramas/`): `arquitectura.mmd`, `flujo-sensor.mmd`, `flujo-verificacion.mmd`, `flujo-almacenamiento.mmd` y `modelo-amenazas.mmd`.

Conversión de este informe: `pandoc docs/informe.md -o informe.pdf` (o `.docx`).

## D.3 Scripts de TLS y de la BD robada

- `scripts/generar_cert.sh` crea un certificado autofirmado **solo de desarrollo**: EC P-256, SAN `IP:127.0.0.1, DNS:localhost`, `CA:FALSE`, uso `digitalSignature` y `serverAuth`, 365 días. `certs/` está en `.gitignore`.
- `scripts/run_server.py` fija `ssl.TLSVersion.TLSv1_3` como versión mínima del contexto que usa Uvicorn.
- El simulador exige `--cacert`, verifica cadena y hostname, y exige TLS 1.3.

La vista de la BD robada se obtiene con `scripts/mostrar_bd.py`, que abre la BD en solo lectura, no usa la contraseña, imprime nonce y blob de la tabla `sensores` y comprueba que la llave en claro del archivo no aparece en el blob (48 B: 32 B cifrados y 16 B de tag GCM), y luego muestra las mediciones en claro.

Archivos y secretos: `.env`, `*.key`, `*.pem`, `certs/`, `sensores/`, `data/` y `*.db` están en `.gitignore`; solo `.env.example`, sin secretos, es público. La BD se crea con permiso 0600 y su directorio con 0700.

