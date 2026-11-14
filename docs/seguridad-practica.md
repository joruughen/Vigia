# VIGÍA — Seguridad práctica (en tránsito, en reposo, análisis estático)

Guía para reproducir desde cero y para explicar al profesor qué protege cada capa. Todos los
comandos se ejecutan desde la raíz del repo (`Vigia/`).

## 0. Instalación desde cero

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env          # y editar VIGIA_MASTER_PASSWORD (>= 16 caracteres; no el valor de ejemplo)
python3 -c "import secrets; print(secrets.token_urlsafe(32))"   # genera una buena
```

`.env` está en `.gitignore`: **nunca** se sube al repo. Solo `.env.example` (sin secretos) es público.
La contraseña maestra también puede pasarse como variable de entorno (tiene prioridad sobre `.env`).

Arranque completo (resumen; los detalles están en las secciones siguientes):

```bash
scripts/generar_cert.sh                                  # certificado TLS de desarrollo -> certs/
.venv/bin/python -m vigia.cli init                       # salt Argon2id + canario en la BD
.venv/bin/python -m vigia.cli registrar-sensor sensor-01 # llave K -> sensores/sensor-01.key (0600)
.venv/bin/python scripts/run_server.py                   # https://127.0.0.1:8443 (TLS 1.3 mínimo)
# en otra terminal:
.venv/bin/python -m vigia.sensor --sensor sensor-01 --cacert certs/cert.pem --n 3 --intervalo 1
```

## 1. En tránsito: TLS 1.3

### 1.1 Certificado autofirmado de desarrollo

```bash
scripts/generar_cert.sh
```

Crea en `certs/` (o en `$VIGIA_CERTS_DIR`):

| Archivo | Contenido | Permisos |
|---|---|---|
| `certs/key.pem` | llave privada EC P-256 (sin passphrase, solo para desarrollo) | `0600` |
| `certs/cert.pem` | certificado X.509 autofirmado, válido 365 días | `0644` |

Características del certificado (comprobables con `openssl x509 -in certs/cert.pem -noout -text`):

- **EC P-256 (`prime256v1`)**, firma `ecdsa-with-SHA256`: ~128 bits de seguridad con llaves y
  handshake pequeños; es la curva estándar (NIST) soportada en todas partes.
- **SAN = `IP:127.0.0.1, DNS:localhost`**: los clientes modernos validan el *Subject Alternative Name*,
  no el CN. Sin SAN, la verificación de hostname falla aunque se confíe en el certificado.
- `basicConstraints CA:FALSE`, `keyUsage digitalSignature`, `extendedKeyUsage serverAuth`:
  el certificado solo sirve para autenticar un servidor TLS, no para firmar otros certificados.
- Validez de 1 año: razonable para desarrollo; limita el daño si la llave se filtra.

`certs/` está en `.gitignore` (también `*.pem` y `*.key`): ni el certificado ni la llave privada se suben.
El script no sobrescribe certificados existentes (hay que borrarlos para regenerar).

**En producción** se usaría un certificado emitido por una CA real (p. ej. Let's Encrypt o una CA
interna) con el nombre DNS real del servidor, y la llave privada se guardaría en un gestor de secretos.
El autofirmado solo existe para poder demostrar TLS sin depender de una CA.

### 1.2 Arrancar el servidor con TLS 1.3 como mínimo

```bash
.venv/bin/python scripts/run_server.py
# INFO: Uvicorn running on https://127.0.0.1:8443
```

Cómo se fuerza TLS 1.3 (`scripts/run_server.py`): uvicorn construye el `ssl.SSLContext` al llamar
`config.load()`; justo después se fija `config.ssl.minimum_version = ssl.TLSVersion.TLSv1_3`. Uvicorn
reutiliza ese contexto ya cargado (`config.loaded`), así que cualquier ClientHello que no ofrezca
TLS 1.3 es rechazado. Host/puerto se cambian con `VIGIA_HOST` / `VIGIA_PORT`.

### 1.3 El simulador valida el certificado

```bash
.venv/bin/python -m vigia.sensor --sensor sensor-01 --cacert certs/cert.pem --url https://127.0.0.1:8443
```

`--cacert` es **obligatorio**: el cliente crea su contexto con `ssl.create_default_context(cafile=...)`
(verifica cadena y hostname), exige `minimum_version = TLSv1_3` y nunca usa `verify=False`. Como el
certificado es autofirmado, se le dice al cliente que ese mismo certificado es su "CA". Con otro
certificado (o un servidor suplantado) la conexión falla antes de enviar ningún dato.

### 1.4 Comprobarlo

**Automático (recomendado para la demo)**, con el servidor corriendo:

```bash
scripts/verificar_tls.sh                 # 127.0.0.1:8443 y certs/cert.pem
scripts/verificar_tls.sh host:puerto ruta/cert.pem   # otros destinos
```

Salida esperada (resumida; el exit code es 0 si todo es correcto):

```
== TLS 1.3 (se espera: ACEPTADO) ==
Verification: OK
Verified peername: localhost
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
Verify return code: 0 (ok)

== TLS 1.2 (se espera: RECHAZADO) ==
...error:0A000126:SSL routines::unexpected eof while reading...
New, (NONE), Cipher is (NONE)

=============== RESUMEN ===============
TLS 1.3: ACEPTADO (cipher: TLS_AES_256_GCM_SHA384, Verify return code: 0 (ok))
TLS 1.2: RECHAZADO
=======================================
```

(El texto exacto varía según la versión de OpenSSL; el cipher puede ser también
`TLS_CHACHA20_POLY1305_SHA256` o `TLS_AES_128_GCM_SHA256`.)

**Manual**:

```bash
# TLS 1.3: debe mostrar "Protocol: TLSv1.3", un cipher TLS_* y "Verify return code: 0 (ok)"
openssl s_client -connect 127.0.0.1:8443 -tls1_3 -CAfile certs/cert.pem -verify_hostname localhost </dev/null

# TLS 1.2: debe FALLAR (sin cipher negociado, "New, (NONE), Cipher is (NONE)")
openssl s_client -connect 127.0.0.1:8443 -tls1_2 -CAfile certs/cert.pem </dev/null

# curl: con TLS 1.3 responde HTTP 200; con --tls-max 1.2 falla (exit 35); sin --cacert falla (exit 60)
curl --cacert certs/cert.pem --tlsv1.3 https://127.0.0.1:8443/api/sensores
curl --cacert certs/cert.pem --tls-max 1.2 https://127.0.0.1:8443/api/sensores
curl https://127.0.0.1:8443/api/sensores
```

## 2. Qué protege TLS y qué NO (por qué existe el HMAC)

TLS 1.3 protege el canal sensor ↔ servidor contra espionaje y modificación **en la red**. No cubre:

| Riesgo | Por qué TLS no basta | Qué lo cubre en VIGÍA |
|---|---|---|
| Autenticidad del sensor extremo a extremo | TLS autentica al **servidor**; el sensor no tiene certificado de cliente. Cualquiera que llegue al puerto puede abrir una sesión TLS válida y enviar datos. | HMAC-SHA256 con la llave K propia de cada sensor (paso 2: `MANIPULADA`; id inexistente: `FALSA`). |
| Replay a nivel de aplicación | Un mensaje repetido dentro de **otra** sesión TLS es válido para TLS. | Número de secuencia estricto (+1) y ventana de timestamp (`REPLAY O HUECO`, `FUERA DE VENTANA`). |
| Huecos y orden | TLS entrega bytes, no sabe qué mediciones faltan. | Secuencia consecutiva y cadena de hashes que incluye el tag (`CADENA ROTA`). |
| Manipulación de lo almacenado | TLS termina en el servidor; lo guardado en la BD ya no está protegido por el canal. | Re-verificación de HMAC y cadena con "Verificar historial completo". |

## 3. En reposo

### 3.1 Qué se cifra (decisión de diseño aprobada)

**Solo las llaves K de los sensores**, en la tabla `sensores` (`nonce`, `llave_cifrada`):

- Cifrado: **AES-256-GCM** (librería `cryptography`). Cada cifrado usa un **nonce de 12 bytes
  aleatorio** (`os.urandom`), nuevo siempre; repetir (llave, nonce) en GCM rompería el cifrado.
- **AAD** = `b"vigia-sensor-key|" + id del sensor`: ata cada blob a su sensor; copiar el blob de un
  sensor a la fila de otro hace fallar el descifrado.
- La llave de cifrado (KEK, 32 B) se deriva de la contraseña maestra con **Argon2id**
  (`argon2-cffi`; RFC 9106): `time_cost=3`, `memory_cost=64 MiB`, `parallelism=4`, salida 32 B.
- **Salt de 16 B único y aleatorio**, generado en `init` y guardado en la tabla `meta`
  (`kdf_salt`, junto a `kdf_params`). El salt no es secreto; evita tablas precalculadas.
- **Canario**: en `init` se cifra un texto fijo (`canario_nonce`, `canario_ct`, en `meta`). Al arrancar,
  si la contraseña es incorrecta el canario no descifra y el servidor aborta con un mensaje claro,
  sin tocar ninguna llave de sensor.
- La KEK vive solo en memoria del proceso; las llaves se descifran bajo demanda y nunca se escriben.

La **contraseña maestra** va en `VIGIA_MASTER_PASSWORD` (archivo `.env` local o variable de entorno;
plantilla en `.env.example` con un valor de ejemplo que hay que cambiar). Nunca está en el repo ni en la BD.

### 3.2 Mostrar que la BD robada es ilegible

```bash
.venv/bin/python scripts/mostrar_bd.py            # últimas 5 mediciones
.venv/bin/python scripts/mostrar_bd.py -n 10 --db data/vigia.db --sensores-dir sensores
```

Abre la BD en solo lectura (`mode=ro`), nunca lee la contraseña maestra ni descifra nada. Salida esperada:

```
=== Tabla sensores: lo que ve un atacante con la BD robada ===
sensor        : sensor-01  (activo, ...)
nonce         : a1c7588a33c6cd77d8dbbdbc  (12 B)
llave_cifrada : 92c24cff...b2aaecebcba3844f...  (48 B = 32 B cifrados + 16 B tag GCM)
¿llave en claro en el BLOB?: NO  (el contenido de sensores/sensor-01.key no aparece en llave_cifrada)
=== Últimas 3 mediciones (EN CLARO: protegidas por integridad, no por confidencialidad) ===
sensor-01 seq=1 ... valor=21.543
  tag / hash_prev / hash ...
```

Alternativa con la herramienta estándar:

```bash
sqlite3 -readonly data/vigia.db "select id, hex(nonce), hex(llave_cifrada) from sensores"
cat sensores/sensor-01.key        # la llave en claro (entregada "fuera de banda"): NO coincide con el blob
```

### 3.3 Lo que NO se cifra y por qué

Las **mediciones, tags y hashes quedan en claro**. Es deliberado: VIGÍA garantiza
**autenticidad, integridad, frescura e historial**, no confidencialidad de los datos de temperatura
(ver diseño: "VIGÍA no oculta las mediciones"). Un atacante con la BD puede *leerlas*. Lo que sí es
secreto —las llaves K— está cifrado, porque con ellas se podrían forjar tags válidos.
Qué se detecta y qué no si alguien edita la BD está en la sección 3.4 (hay limitaciones aceptadas).
Si en el futuro hiciera falta confidencialidad de las mediciones, se añadiría cifrado de columnas con la
misma KEK, a costa de perder consultas directas en SQL.

`sensores/<id>.key` queda en disco en claro como simulación de la entrega fuera de banda
(permiso `0600`, directorio `0700`, gitignored); el simulador avisa si el permiso es más amplio y
rechaza llaves que no sean hex de 32 bytes. La BD se crea con `0600` y su directorio con `0700`.

### 3.4 Qué detecta la verificación y qué no

Sobre la cadena SHA-256: **no lleva llave**, así que por sí sola no impide que alguien con acceso a la
BD recalcule una cadena entera. La detección de inserciones, ediciones y borrados la dan (a) el HMAC
(con K, que el atacante no tiene) que cubre `sensor_id`, `seq`, `timestamp` y `valor` de cada registro
y (b) la re-verificación de ese HMAC al verificar el historial y en el paso 5 contra el último
registro; la cadena aporta el **orden y el enlace** entre registros (el hash de cada registro incluye
el tag y el hash anterior).

Con el historial en la BD y la acción de un atacante sobre él:

| Acción sobre la BD | Resultado de "Verificar historial completo" |
|---|---|
| Alterar el **valor** de una medición intermedia | **MANIPULADA** en ese registro (su HMAC ya no coincide) |
| Borrar una medición intermedia | **CADENA ROTA** (hueco de secuencia y enlace de hash roto) |
| Insertar un registro con tag inventado | **MANIPULADA** (HMAC inválido) |

Nota: la tabla de demostración del diseño original (`docs/diseno-entrega1.md`) decía CADENA ROTA
para "eliminar o alterar" una intermedia. La implementación es más precisa: alterar el valor da
MANIPULADA en ese registro (el HMAC se comprueba antes que la cadena); borrar da CADENA ROTA.

### 3.5 Limitaciones (aceptadas)

- **Re-sync manual tras mensaje perdido (fail-closed).** Si se pierde una respuesta, el simulador
  reconoce el caso "el servidor ya tiene esta seq" y avanza solo. Ante un `hueco` (el servidor está
  atrasado respecto del sensor) no hay corrección automática: se rechaza todo hasta una
  re-sincronización manual. Es preferible a aceptar datos con huecos.
- **La tabla `eventos` no está encadenada.** Un insider con acceso a la BD puede editar el registro de
  intentos (VERIFICADA/FALSA/...) que muestra el dashboard. La tabla protegida es `mediciones`.
- **Alteración intermedia detectada solo con "Verificar historial completo".** La ingesta normal solo
  re-verifica el último registro guardado; una edición en medio no se ve hasta verificar todo el
  historial.
- **El truncado de las últimas mediciones no es detectable.** Si se borran los registros finales,
  lo que queda es una cadena válida más corta (no hay un ancla externa del último hash/seq).
- **HMAC con llave compartida.** El servidor conoce K y podría forjar tags válidos; no hay no-repudio.
  Mitigación futura: firmas Ed25519 por sensor (fuera de alcance).
- **API y dashboard sin autenticación.** Escuchan en `127.0.0.1` por defecto (`VIGIA_HOST`). La
  denegación de servicio queda fuera de alcance.

## 4. Análisis estático desde cero

```bash
.venv/bin/pip install -r requirements-dev.txt
scripts/analisis_estatico.sh
```

Deja en `docs/analisis-estatico/`: `bandit.txt`, `bandit.json`, `bandit-tests.txt`, `pip-audit.txt`,
`pip-audit.json`, `pip-audit-dev.txt` y `VERSIONES.txt` (versiones de las herramientas usadas).

<!-- RESULTADOS-ANALISIS -->
### Resultados (2026-11-14; bandit 1.9.4, pip-audit 2.10.1, Python 3.14.10)

| Alcance | Herramienta | Resultado |
|---|---|---|
| Código de la aplicación (`vigia/`, `scripts/`) | bandit | **0 hallazgos** (ninguna severidad); el comentario `# nosec B311` de `vigia/sensor.py` es preventivo (`random.gauss` no está en la lista de B311; bandit reporta `nosec: 0`) |
| Dependencias (`requirements.txt`, 28 paquetes con transitivas) | pip-audit | **0 vulnerabilidades conocidas** |
| Dependencias de desarrollo (`requirements-dev.txt`) | pip-audit | **0 vulnerabilidades conocidas** |
| Tests (`tests/`) | bandit | 159 hallazgos: 158 × B101, 1 × B105 (falsos positivos, ver abajo) |

### Falsos positivos justificados (solo en `tests/`)

- **B101 `assert_used` (158).** Bandit advierte que `assert` se elimina al ejecutar Python con `-O`, lo que es un riesgo si un `assert` hace un control de seguridad en código de producción. En VIGÍA **ningún `assert` está en código de producción** (bandit sobre `vigia/` y `scripts/` da 0 hallazgos). En `tests/` el `assert` es el mecanismo estándar de pytest para expresar la condición esperada; nunca se ejecuta en el servidor.
- **B105 `hardcoded_password_string` en `tests/conftest.py:28`.** Es la contraseña maestra de prueba (`"contrasena-de-prueba-NO-usar-en-produccion"`) con la que los tests crean bases de datos temporales en `tmp_path` que se destruyen al terminar. No protege ningún dato real ni coincide con ninguna contraseña de despliegue. La contraseña real solo se lee de `VIGIA_MASTER_PASSWORD` (`.env`, excluido del repositorio; plantilla en `.env.example`).

Por qué el código de la aplicación sale limpio: las consultas SQL están todas parametrizadas, no se usa `subprocess`/`eval`/`pickle`, la aleatoriedad criptográfica viene de `secrets`/`os.urandom` (el único uso de `random` es `random.gauss` en `vigia/sensor.py`, que solo genera el ruido de la temperatura simulada y no tiene ningún papel criptográfico; el `# nosec B311` ahí es preventivo, no suprime ningún hallazgo), y no hay hashes rotos (MD5/SHA-1) ni modos inseguros. Limitación: bandit es análisis de patrones, no prueba la ausencia de errores lógicos; por eso se complementa con los 228 tests de estados y ataques y con la revisión independiente.
