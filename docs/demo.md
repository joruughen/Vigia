# VIGÍA — Guion de demo (5 minutos)

Todos los comandos se ejecutan desde la raíz del repo (`.`), con la demo levantada.
Las salidas son de ejecuciones reales, recortadas. Horas, PID y números de seq cambian en cada corrida.
Los comandos de ataque usan `scripts/demo.sh ataque <subcomando>`, que llama a `scripts/ataques.py`.

## Cronograma

| Bloque | Tiempo | Qué se muestra |
|---|---|---|
| 0. Preparación | antes de presentar | `up`, certificado aceptado |
| 1. Sensor enviando | 0:00 – 0:40 | dashboard: VERIFICADA en tabla y gráfico |
| 2. Ataques | 0:40 – 3:00 | 5 ataques por la API y 3 sobre la BD, cada uno con su estado |
| 3. BD robada | 3:00 – 3:40 | `demo.sh bd`: llaves ilegibles, mediciones en claro |
| 4. TLS 1.3 | 3:40 – 4:10 | `demo.sh tls`: 1.3 acepta, 1.2 rechaza |
| 5. Análisis estático | 4:10 – 4:35 | `demo.sh estatico`: 0 hallazgos |
| Cierre | 4:35 – 5:00 | resumen y preguntas |

---

## 0. Preparación (antes de presentar; no cuenta en los 5 minutos)

1. Levantar la demo. Si ya está arriba, `up` solo lo confirma:

   ```bash
   scripts/demo.sh up
   ```

   Esperar unos 10 s para que sensor-01 tenga mediciones, y comprobar:

   ```bash
   scripts/demo.sh status
   ```

   Salida esperada:

   ```
   Servidor: EN EJECUCIÓN (PID 208674)
   Simulador sensor-01: EN EJECUCIÓN (PID 208737)
   API: responde en https://127.0.0.1:8443 (TLS 1.3, certificado validado)
   SENSOR      ACTIVO  VERIFICADAS  INTENTOS  ÚLT.SEQ  ÚLTIMO ESTADO
   sensor-01   True    6            6         6        VERIFICADA
   sensor-02   True    0            0         None     None
   ```

2. Abrir **https://127.0.0.1:8443** en el navegador y aceptar el certificado autofirmado
   ("Avanzado" → "Continuar a 127.0.0.1"; en Firefox, "Aceptar el riesgo y continuar").
   Sin esto el dashboard no carga. Dejar el dashboard en una pestaña y la terminal en la raíz del repo.

3. Si la BD tiene daño de ensayos anteriores, deshacerlo:

   ```bash
   scripts/demo.sh ataque restaurar
   ```

   Salida: `BD restaurada (1 operación(es) deshecha(s)).` (o `No hay daños en BD pendientes de restaurar.`)

4. Solo si todo está inconsistente: `scripts/demo.sh reset && scripts/demo.sh up`.
   **Ojo:** `reset` borra el certificado, así que hay que volver a aceptarlo en el navegador.

---

## 1. Sensor enviando → VERIFICADA (0:00 – 0:40)

**Dashboard:** mostrar la tabla de mediciones de sensor-01 (estado VERIFICADA, HMAC, detalle `ok`)
y el gráfico de serie de tiempo.

**Comando:**

```bash
scripts/demo.sh status
```

**Salida esperada:** la del paso 0 (sensor-01 con `ÚLTIMO ESTADO` = `VERIFICADA`).

**Qué decir:** "El simulador de sensor-01 envía una medición cada 2 segundos, firmada con su llave K
(HMAC-SHA256). Viaja por TLS 1.3 y el servidor la verifica en cinco pasos. Las aceptadas quedan
como VERIFICADA en la tabla y en el gráfico."

**Qué demuestra:** el flujo normal de extremo a extremo, con autenticidad e integridad correctas.

---

## 2. Ataques (0:40 – 3:00)

**Qué decir al empezar:** "Ahora ataco el sistema. Los primeros cinco son ataques por la API. Cada uno
debe producir exactamente el estado que indica la tabla. Después ataco la base de datos directamente."

### 2.1 Manipulada → MANIPULADA

```bash
scripts/demo.sh ataque manipulada
```

Salida esperada (recortada):

```
=== ATAQUE: manipulada (valor alterado en tránsito) ===
  Firmado   : valor=22.500
  Enviado   : sensor-02 seq=1 t=21:03:11Z valor=99.900 tag=5c129ff53c66c465…
  Respuesta : MANIPULADA (HMAC inválido)
  El atacante no conoce la llave K: no puede recalcular el HMAC del valor nuevo.

  Esperado: MANIPULADA | Obtenido: MANIPULADA -> OK
```

**Qué decir:** "Firmé una medición con valor 22.5 y el dato se cambió a 99.9 después de firmarlo. El
atacante no tiene la llave, así que no puede recalcular el tag. El HMAC lo delata sin importar el canal."

**Qué demuestra:** integridad y autenticidad (paso 2 del flujo).

### 2.2 Falsa → FALSA

```bash
scripts/demo.sh ataque falsa
```

Salida esperada (recortada):

```
=== ATAQUE: falsa (sensor inexistente) ===
  Enviado   : sensor-99 seq=1 t=21:03:11Z valor=21.000 tag=dd69585a9ecb62f8…
  Respuesta : FALSA (sensor no registrado o revocado)
  Esperado: FALSA | Obtenido: FALSA -> OK
```

**Qué decir:** "Un dispositivo que no está registrado. No hay llave con qué verificarlo y se rechaza en el paso 1."

**Qué demuestra:** solo los sensores registrados pueden escribir datos.

*Variante opcional si sobra tiempo:* `scripts/demo.sh ataque falsa --id-valido` usa el id de sensor-01 sin su
llave y da `MANIPULADA (HMAC inválido)`. Se dice: "El id no basta: hace falta la llave."

### 2.3 Replay → REPLAY O HUECO

```bash
scripts/demo.sh ataque replay
```

Salida esperada (recortada):

```
=== ATAQUE: replay (reenvío exacto de una medición ya aceptada) ===
  Enviado   : sensor-01 seq=8 t=21:03:10Z valor=22.619 tag=1832d794242e7b8f…
  Respuesta : REPLAY O HUECO (replay: seq 8 <= última 8)
  Esperado: REPLAY O HUECO | Obtenido: REPLAY O HUECO -> OK
```

**Qué decir:** "Reenvío exacto de una medición legítima. El tag es válido, así que el HMAC no puede detectarlo.
Lo para la secuencia: exige que la seq sea la última más uno."

**Qué demuestra:** la frescura no depende del HMAC; lo cubre el número de secuencia.

### 2.4 Fuera-ventana → FUERA DE VENTANA

```bash
scripts/demo.sh ataque fuera-ventana
```

Salida esperada (recortada):

```
=== ATAQUE: fuera-ventana (mensaje retenido y entregado tarde) ===
  Enviado   : sensor-02 seq=2 t=21:01:11Z valor=21.986 tag=03c22f48451d214d…
  Respuesta : FUERA DE VENTANA (desfase 120000 ms > ventana 30000 ms)
  Esperado: FUERA DE VENTANA | Obtenido: FUERA DE VENTANA -> OK
```

**Qué decir:** "Un mensaje válido que un atacante retuvo dos minutos. La firma y la secuencia son correctas;
solo el paso 4, la ventana de tiempo de 30 segundos, lo detiene."

**Qué demuestra:** frescura por timestamp, además de la secuencia.

### 2.5 Hueco → REPLAY O HUECO (y no bloquea)

```bash
scripts/demo.sh ataque hueco
```

Salida esperada (recortada):

```
=== ATAQUE: hueco (mensaje perdido o suprimido) ===
  Enviado   : sensor-02 seq=3 t=21:03:11Z valor=22.196 tag=caefb075149bfffe…
  Respuesta : REPLAY O HUECO (hueco: esperaba 2, llegó 3)
  El rechazado NO se guarda en mediciones, así que no bloquea al sensor: su siguiente seq correcta (2) sigue siendo aceptada.
  Recupera  : seq 2 -> VERIFICADA (ok)
  Esperado: REPLAY O HUECO | Obtenido: REPLAY O HUECO -> OK
```

**Qué decir:** "Salté la seq 2. El servidor lo rechaza como hueco, pero no guarda el rechazo, así que el
sensor no queda bloqueado: la seq 2 entra después como VERIFICADA."

**Qué demuestra:** el orden de la secuencia y la recuperación sin bloqueo.

### 2.6 BD: alterar valor → MANIPULADA (dashboard)

```bash
scripts/demo.sh ataque bd-alterar-valor
```

Salida esperada (recortada):

```
=== ATAQUE: bd-alterar-valor (atacante con escritura en la BD edita un valor) ===
  Qué hace  : UPDATE directo en SQLite: valor de sensor-02 seq 3 21.900 -> 31.900 (el tag y los hashes quedan como estaban)
  Acción    : POST /api/sensores/sensor-02/verificar-historial
  Historial : integro=false (4 registros)
    seq 3   : MANIPULADA (HMAC inválido (contenido alterado))
  Daño dejado en la BD (visible con 'Verificar historial' en el dashboard). Deshacer: scripts/ataques.py restaurar

  Esperado: MANIPULADA | Obtenido: MANIPULADA -> OK
```

**Dashboard:** seleccionar sensor-02 y pulsar **"Verificar historial completo del sensor"**. Debe aparecer
el registro seq 3 como MANIPULADA.

**Qué decir:** "Ahora el atacante tiene escritura en la base de datos y cambia un valor. El HMAC de ese
registro ya no cuadra. El resto de la cadena sigue íntegro, así que el sistema lo localiza."

Deshacer antes del siguiente ataque:

```bash
scripts/demo.sh ataque restaurar
```

**Qué demuestra:** que la alteración directa en la BD se detecta con la re-verificación del historial.

### 2.7 BD: borrar → CADENA ROTA (dashboard)

```bash
scripts/demo.sh ataque bd-borrar
```

Salida esperada (recortada):

```
=== ATAQUE: bd-borrar (atacante con escritura en la BD borra una medición) ===
  Qué hace  : DELETE directo en SQLite del registro de sensor-02 seq 3 (intermedio)
  Acción    : POST /api/sensores/sensor-02/verificar-historial
  Historial : integro=false (3 registros)
    seq 4   : CADENA ROTA (hueco de secuencia: esperaba 3, hay 4; enlace roto: hash_prev no coincide con el hash del anterior)
  Esperado: CADENA ROTA | Obtenido: CADENA ROTA -> OK
```

**Dashboard:** con sensor-02 seleccionado, "Verificar historial completo del sensor" muestra seq 4 como CADENA ROTA.

**Qué decir:** "Borré un registro intermedio. El siguiente apunta por hash a un eslabón que ya no existe."

Deshacer:

```bash
scripts/demo.sh ataque restaurar
```

**Qué demuestra:** que el borrado también se detecta, por la cadena de hashes.

### 2.8 BD: cadena rota → CADENA ROTA en la ingesta (cierre del bloque)

```bash
scripts/demo.sh ataque cadena-rota
```

Salida esperada (recortada):

```
=== ATAQUE: cadena-rota (se corrompe el último eslabón y llega la siguiente medición) ===
  Qué hace  : UPDATE del hash guardado del último registro de sensor-02 (seq 4) c5de04fd9712afd3… -> 05de04fd9712afd3… y luego envía la siguiente medición válida
  Enviado   : sensor-02 seq=5 t=21:03:22Z valor=22.509 tag=8ce6b4e215c74b10…
  Respuesta : CADENA ROTA (hash del registro guardado seq 4 no coincide)
  HMAC, seq y timestamp son correctos, pero el servidor no encadena sobre una base corrupta: sensor-02 queda bloqueado hasta restaurar (scripts/ataques.py restaurar).
  Esperado: CADENA ROTA | Obtenido: CADENA ROTA -> OK
```

**Qué decir:** "Corrompí el último eslabón de la base de datos y llegó una medición perfectamente firmada.
El servidor se niega a encadenar sobre una base corrupta. Por eso sensor-02 queda bloqueado hasta restaurar."

Restaurar:

```bash
scripts/demo.sh ataque restaurar
```

**Nota para el presentador:** tras `cadena-rota`, el "último estado" de sensor-02 en el dashboard queda como
CADENA ROTA (es el último evento registrado). Vuelve a VERIFICADA con la siguiente medición válida de sensor-02.

**Qué demuestra:** la cadena protege el historial incluso ante una medición auténtica.

---

## 3. BD robada (3:00 – 3:40)

```bash
scripts/demo.sh bd
```

Salida esperada (recortada; la ruta del .key aparece relativa a la raíz del repo):

```
=== Tabla sensores: lo que ve un atacante con la BD robada ===
sensor        : sensor-02  (activo, creado 2026-11-14 21:02:55 UTC)
nonce         : ad1ccfe8139ac662fc788797  (12 B)
llave_cifrada : 643513f584126cd3f82d80173d5820edac8e24b4ee553dbd0cc9e1362c6208bdee42e62d49f31642e3ddffdf2b26a255  (48 B = 32 B cifrados + 16 B tag GCM)
¿llave en claro en el BLOB?: NO  (el contenido de sensores/sensor-02.key no aparece en llave_cifrada)

=== Tabla meta (parámetros públicos del KDF; la contraseña NO está aquí) ===
canario_ct    : 424b9b44580346fe9c053b62a462c31d9dd7691b3a12781335c9374dfcdaa1d0
canario_nonce : 003d9f918339683ed526f25b
kdf_params    : {"hash_len": 32, "memory_cost": 65536, "parallelism": 4, "time_cost": 3}
kdf_salt      : e512549a479b4297a886dca07fe4cd51

=== Últimas 5 mediciones (EN CLARO: protegidas por integridad, no por confidencialidad) ===
sensor-02 seq=4 t=2026-11-14 21:03:18 UTC valor=22.063
  tag       : dab7e89014e723090e9fd81fb4116d7251810438d0a2e3354389f94bd261e3d3
  hash_prev : c30b03aa90c152db75b496690a52d4b20dd14887d9cbb20aab7d2ef872b93c6c
  hash      : c5de04fd9712afd3109a37327e4de146e7b0779821d49fd74127883e8f92d951
```

**Qué decir:** "Si roban la base, ven los nonces, las llaves cifradas con AES-256-GCM (48 bytes, sin la
llave en claro) y los parámetros de Argon2id, que son públicos. La clave de cifrado sale de la contraseña
maestra, que no está en la base. Las mediciones sí se leen: VIGÍA garantiza integridad, no confidencialidad."

**Contraste con la app:** "Lo que no pueden hacer es modificar sin que se note. Eso es lo que vimos en 2.6 y 2.7:
la app que sí verifica da MANIPULADA o CADENA ROTA."

**Qué demuestra:** confidencialidad de las llaves en reposo, e integridad aparte de la confidencialidad.

---

## 4. TLS 1.3 activo (3:40 – 4:10)

```bash
scripts/demo.sh tls
```

Salida esperada (recortada):

```
== TLS 1.3 (se espera: ACEPTADO) ==
Verification: OK
Verified peername: localhost
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
Verify return code: 0 (ok)

== TLS 1.2 (se espera: RECHAZADO) ==
...unexpected eof while reading...
New, (NONE), Cipher is (NONE)

=============== RESUMEN ===============
TLS 1.3: ACEPTADO (cipher: TLS_AES_256_GCM_SHA384, Verify return code: 0 (ok))
TLS 1.2: RECHAZADO
=======================================
```

**Qué decir:** "El canal va por TLS 1.3 con certificado verificado. TLS 1.2 se rechaza, porque la versión
mínima está forzada. TLS protege la red, pero no prueba quién es el sensor ni protege el historial. Para eso está el HMAC."

**Qué demuestra:** transporte cifrado y autenticado, con versión mínima forzada.

---

## 5. Análisis estático (4:10 – 4:35)

```bash
scripts/demo.sh estatico
```

Salida esperada (recortada; las líneas de severidad se repiten en la salida real):

```
== Reporte de análisis estático (último generado; solo lectura) ==
Fecha: 2026-11-14 19:50:08 UTC
Python: Python 3.14.10
bandit: bandit 1.9.4
pip-audit: pip-audit 2.10.1
-- bandit (vigia/ y scripts/) --
	No issues identified.
	Total lines of code: 1589
-- pip-audit (dependencias) --
No known vulnerabilities found
Regenerar: scripts/analisis_estatico.sh
```

**Qué decir:** "Bandit sobre 1589 líneas de la aplicación: cero hallazgos. pip-audit sobre las dependencias:
cero vulnerabilidades conocidas. Es un reporte generado antes de la demo; se regenera con `scripts/analisis_estatico.sh`."

**Qué demuestra:** revisión estática y de dependencias, además de las pruebas.

---

## Cierre (4:35 – 5:00)

Resumen de una frase: "Cinco capas: TLS 1.3 en tránsito, HMAC por sensor, secuencia y ventana contra replay,
cadena de hashes sobre el historial, y llaves cifradas en reposo. Cada ataque tuvo su estado esperado."

Al terminar (opcional):

```bash
scripts/demo.sh down
```

---

## Plan B (si algo falla)

| Síntoma | Qué hacer |
|---|---|
| El dashboard no carga o pide certificado | Aceptar el certificado (paso 0.2). Como alternativa: `curl --cacert ./demo-run/certs/cert.pem https://127.0.0.1:8443/api/sensores` (devuelve JSON). |
| El servidor no responde | `scripts/demo.sh status`; ver el log con `scripts/demo.sh logs` (Ctrl-C para salir); reiniciar con `scripts/demo.sh down && scripts/demo.sh up`. |
| Un ataque da ERROR o un estado distinto | `scripts/demo.sh ataque restaurar` y repetirlo. |
| sensor-02 queda bloqueado (CADENA ROTA en la ingesta) | `scripts/demo.sh ataque restaurar`. |
| Puerto 8443 ocupado | `VIGIA_PORT=9443 scripts/demo.sh reset && VIGIA_PORT=9443 scripts/demo.sh up`; la URL pasa a https://127.0.0.1:9443 (aceptar el certificado de nuevo). |
| Sin tiempo o sin navegador: resumen completo | `scripts/demo.sh ataque todos`. Ejecuta los 9 ataques en orden (restaura la BD entre ellos) y muestra una tabla RESUMEN con `Todos los estados coinciden con lo esperado.` |
| El gráfico no aparece | Chart.js viene de un CDN; sin red el dashboard funciona sin gráfico. Usar la tabla y la salida de terminal. |
| Todo falla | Usar las capturas de pantalla preparadas antes (guardadas fuera del repo) y la salida del paso 2 de este guion. Reiniciar después con `scripts/demo.sh reset && scripts/demo.sh up`. |
