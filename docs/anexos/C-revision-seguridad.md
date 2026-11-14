# Anexo C: revisión de seguridad, pruebas y análisis estático

Detalle de los resultados que el informe principal (`docs/informe.md`, secciones 6.3 y 7) resume: las dos rondas de revisión independiente con todos los hallazgos, la lista de tests por archivo y el análisis estático con sus falsos positivos justificados.

## C.1 Pruebas por archivo

`.venv/bin/python -m pytest -q` ejecuta 266 tests, todos pasan (1 advertencia de deprecación de `starlette.testclient` con `httpx`, sin relación con la seguridad).

| Archivo | Tests | Qué cubre |
|---|---|---|
| `tests/test_crypto.py` | 90 | Formato canónico (válidos e inválidos), HMAC contra la implementación estándar, robustez ante hex inválido, cadena, Argon2id, unicidad de salts y nonces, AAD, AES-GCM, canario |
| `tests/test_estados.py` | 18 | **Un test por estado**: VERIFICADA, FALSA (inexistente y revocado), MANIPULADA, REPLAY O HUECO (con su detalle interno), FUERA DE VENTANA (pasado y futuro) y CADENA ROTA; independencia entre sensores; registro de eventos |
| `tests/test_ataques.py` | 46 | **Un test por ataque** (numerados 1 a 8): alterar un valor en la BD, fabricar con id válido sin llave y con id inexistente, replay, borrar una intermedia, mensaje perdido, timestamp fuera de ventana, romper la cadena (hash, `hash_prev`, tags reordenados), contraseña incorrecta o BD sin inicializar, blob copiado a otro sensor, formato inválido (422) y no filtración de llaves en las respuestas |
| `tests/test_fase2.py` | 74 | Regresiones de la primera revisión independiente (sección 7.3) |
| `tests/test_fase3.py` | 38 | Regresiones de la re-verificación: huella del tag en `eventos` (N1), cotas máximas de `kdf_params` (N2) y casos asociados |

## C.2 Hallazgos de la revisión de seguridad independiente

Hubo dos rondas de revisión independiente (un revisor distinto de quien implementó): una al cierre de la Fase 2 y una re-verificación acotada al inicio de la Fase 3. Cada corrección de código tiene tests de regresión (`tests/test_fase2.py` y `tests/test_fase3.py`); las correcciones que son solo de documentación se revisaron leyendo el texto.

### Primera revisión independiente (cierre de la Fase 2)

| Id | Severidad | Hallazgo | Corrección |
|---|---|---|---|
| M1 | Media | El paso 5 no re-verificaba el HMAC del último registro: SHA-256 no lleva llave, así que una fila final falsa con hash recalculado servía de base de la cadena | El paso 5 **re-verifica el HMAC del último registro** además de su hash; un último registro con formato corrupto da `CADENA ROTA` sin excepción. Corregido |
| M2 | Media | Limitaciones no documentadas y una afirmación falsa en `seguridad-practica.md` ("no pueden modificar/borrar/insertar sin que se detecte") | Se documentaron las limitaciones (sección 8) y se corrigió la afirmación (también en la sección 6.2 de este informe). Corregido |
| B1 | Baja | El sensor quedaba en un bucle de `REPLAY O HUECO` tras perder la respuesta | Avance automático solo en el caso estricto "el servidor ya tiene esta `seq`"; el resto exige re-sincronización manual (fail-closed). Corregido |
| B2 | Baja | API y dashboard sin autenticación | Documentado como limitación (sección 8) |
| B3 | Baja | Afirmaciones de documentación desactualizadas (`nosec`, comentario de un test) | Texto corregido |
| B4 | Baja | Contraseña maestra sin política mínima | Mínimo de 16 caracteres y rechazo del valor de `.env.example`. Corregido |
| B5 | Baja | Los parámetros Argon2 guardados en la BD no se usaban para derivar | Se leen y se usan, validados con mínimos (después, también con máximos: N2). Corregido |
| I1 | Info | Una llave de sensor corrupta producía un error 500 | Manejador que responde HTTP 500 genérico, sin traceback ni detalles, y registra el error en el log; el resto de sensores no se ve afectado. Corregido |
| I2 | Info | Sin validación de la llave en el simulador | `leer_llave` valida hex y longitud y sale con un mensaje claro. Corregido |
| I3 | Info | Permisos de la BD según el umask | BD 0600 y directorio 0700; llaves 0600 en directorio 0700. Corregido |
| I4 | Info | Diseño frente a código: `MANIPULADA` frente a `CADENA ROTA` al alterar una intermedia | Documentado (secciones 4.4 y 9) |
| I5 | Info | Handshake TLS real sin evidencia | Se agregó `docs/evidencia/` con `scripts/verificar_tls.sh` (sección 6.1) |
| I6 | Info | Integridad de subrecursos (SRI) de Chart.js | Verificado: el hash coincide; sin cambios |

### Re-verificación acotada (inicio de la Fase 3)

El revisor comprobó las correcciones anteriores: todas quedaron **cerradas**, salvo documentación parcial, que se completó al cerrar el informe. Encontró tres hallazgos nuevos:

| Id | Severidad | Hallazgo | Corrección |
|---|---|---|---|
| N1 | Baja | **Promoción de un mensaje auténtico rechazado.** `eventos` guardaba el tag de todo intento; alguien con escritura en la BD podía copiar el tag de un mensaje auténtico rechazado (por ejemplo `FUERA DE VENTANA`) a `mediciones` y hacerlo pasar por válido | `eventos` guarda el tag solo si es `VERIFICADA` y, en las rechazadas, solo la huella `sha256:` + SHA-256 de `"vigia-huella-tag\|" + tag`. El dashboard rotula "HMAC" o "huella". Corregido |
| N2 | Baja | **Sin cotas superiores en Argon2.** Unos `kdf_params` manipulados podían causar denegación de servicio o una excepción no controlada al arrancar | Máximos (t <= 10, m <= 1 GiB, p <= 64) además de los mínimos; las excepciones de la derivación se convierten en un error de arranque claro. Corregido |
| N3 | Info | **Precisión sobre el truncado.** El borrado de las últimas mediciones no se detecta en el historial; sí se detecta operativamente como hueco | Precisión documentada (sección 8) |

Además, la API añade cabeceras de seguridad (CSP, `nosniff`, `Referrer-Policy`, HSTS, `no-store`) y el dashboard usa `textContent` en lugar de `innerHTML`.

Dos observaciones de la propia implementación, hechas durante la documentación:

- Si se altera el **valor del último registro guardado**, la ingesta siguiente da `CADENA ROTA` (el hash recalculado no coincide), no `MANIPULADA`.
- Si se altera el **`seq` del último registro**, la ingesta siguiente da `REPLAY O HUECO` en vez de `CADENA ROTA` (sección 8).

## C.3 Análisis estático (bandit y pip-audit)

Herramientas: **bandit** 1.9.4 (patrones de código inseguro en Python) y **pip-audit** 2.10.1 (vulnerabilidades conocidas en dependencias). Python 3.14.10. Se ejecutan con:

```bash
.venv/bin/pip install -r requirements-dev.txt
scripts/analisis_estatico.sh
```

El script deja los resultados en `docs/analisis-estatico/` (`bandit.txt`, `bandit.json`, `bandit-tests.txt`, `pip-audit*.txt`, `VERSIONES.txt`).

| Alcance | Herramienta | Resultado |
|---|---|---|
| Código de la aplicación (`vigia/` y `scripts/`, 1589 líneas) | bandit | **0 hallazgos** (ninguna severidad) |
| Dependencias de ejecución (`requirements.txt`) | pip-audit | **0 vulnerabilidades conocidas** |
| Dependencias de desarrollo (`requirements-dev.txt`) | pip-audit | **0 vulnerabilidades conocidas** |
| Tests (`tests/`, 1053 líneas) | bandit | 202 hallazgos: 201 × B101 y 1 × B105, **falsos positivos** |

**Falsos positivos justificados (solo en `tests/`).**

- **B101 `assert_used` (201).** Bandit advierte que `assert` desaparece con `python -O`, lo que importa si protege un control de seguridad en producción. En VIGÍA no hay ningún `assert` en el código de producción (0 hallazgos en `vigia/` y `scripts/`). En los tests, `assert` es el mecanismo de pytest.
- **B105 `hardcoded_password_string` (1, `tests/conftest.py:28`).** Es la contraseña maestra de prueba, con la que los tests crean BD temporales en `tmp_path` que se destruyen. No protege datos reales. La contraseña real solo se lee de `VIGIA_MASTER_PASSWORD`.

Por qué el código sale limpio: las consultas SQL son parametrizadas; no se usa `subprocess`, `eval` ni `pickle`; la aleatoriedad criptográfica viene de `secrets` y `os.urandom`; no hay hashes rotos ni modos inseguros. El único uso de `random` es `random.gauss` en el simulador, que solo genera ruido de temperatura sin papel criptográfico (el comentario `# nosec B311` es preventivo: bandit reporta 0 líneas omitidas).

**Limitación.** Bandit es análisis de patrones: **no prueba la ausencia de errores lógicos** (por ejemplo, un orden incorrecto de pasos de verificación no lo ve). Por eso se complementa con los tests de estados y ataques y con una revisión de seguridad independiente (sección 7).

## C.4 Qué se logró frente al diseño (tabla completa)

| Elemento del diseño | Estado |
|---|---|
| HMAC-SHA256 por sensor, tag en hex, comparación en tiempo constante | Implementado |
| Formato canónico `VIGIA-v1` con validación estricta | Implementado |
| Verificación de 5 pasos con los 6 estados | Implementado |
| Cadena SHA-256 que incluye el tag | Implementado |
| Verificación de historial completo | Implementado (API y dashboard) |
| AES-256-GCM para llaves, nonce único, AAD | Implementado |
| Argon2id con salt único y parámetros RFC 9106 | Implementado, con parámetros guardados y validados con mínimos y máximos |
| Huella del tag en `eventos` para mensajes rechazados (hallazgo N1) | Implementado |
| TLS 1.3 en tránsito | Implementado y comprobado con `openssl` y `curl` |
| Simulador, API, dashboard y CLI | Implementados |
| Análisis estático | bandit y pip-audit ejecutados; resultados en el repo |
| Ed25519, ESP32 real | **No implementados** (extensión) |

