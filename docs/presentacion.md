# VIGÍA — Esquema de la presentación final (10–15 min)

Duración objetivo: 12–13 min sin contar preguntas. El guion detallado de la demo está en `docs/demo.md`.
Diagramas en `docs/diagramas/*.png` (fuentes `.mmd` en la misma carpeta).

## Estructura temporal

| Bloque | Tiempo | Contenido |
|---|---|---|
| 1. Repaso de diseño | 3,5 min | problema, garantías, arquitectura, verificación en 5 pasos |
| 2. Qué cambió e implementación | 2 min | diferencias con la Entrega 1 y decisiones de implementación |
| 3. Demo | 5 min | `docs/demo.md` (sensor, ataques, BD, TLS, análisis estático) |
| 4. Limitaciones y cierre | 2 min | qué no garantiza el sistema y trabajo futuro |

---

## 1. Repaso de diseño (3,5 min)

**Qué decir:**

- (0:00–0:45) "Los sistemas IoT toman decisiones con mediciones. Un atacante puede modificar una lectura,
  inventar datos, repetir mensajes antiguos o alterar la base de datos. VIGÍA no oculta las mediciones:
  permite que el servidor verifique cada una y el historial completo."
- (0:45–1:30) "Garantizamos cuatro propiedades: autenticidad (la llave K de cada sensor), integridad (HMAC),
  frescura (secuencia estricta y ventana de tiempo) e historial (cadena de hashes que incluye el tag).
  No garantizamos confidencialidad de las mediciones: se guardan en claro."
- (1:30–2:30) "Arquitectura: el simulador firma, TLS 1.3 transporta, la API verifica en cinco pasos,
  SQLite guarda, y el dashboard muestra el estado criptográfico de cada medición."
- (2:30–3:30) "Verificación en orden: FALSA (sensor no registrado), MANIPULADA (HMAC inválido),
  REPLAY O HUECO (secuencia), FUERA DE VENTANA (timestamp), CADENA ROTA (cadena). Si todo pasa, VERIFICADA."

**Diapositivas:** 1, 2, 3, 5 (ver sección de diapositivas).

---

## 2. Qué cambió e implementación (2 min)

**Qué decir:**

- "La Entrega 1 proponía las mismas garantías; la implementación ajustó cinco puntos:"
  - **FALSA** significa solo sensor no registrado o revocado. Fabricar con un id válido sin la llave da MANIPULADA.
  - **REPLAY O HUECO** es un solo estado visible; el detalle indica el motivo.
  - **La cadena de hashes incluye el tag**: `h_i = SHA256(h_{i-1} ∥ mensaje ∥ tag_i)`.
  - **El paso 5 re-verifica el HMAC del último registro**. Una revisión independiente detectó que la cadena
    sola, sin llave, no bastaba.
  - **Alterar el valor de una medición da MANIPULADA; borrarla da CADENA ROTA.**
- "Implementación: solo librerías probadas (`cryptography`, `argon2-cffi`, `hmac`, `hashlib`). La comparación de
  tags es en tiempo constante (`hmac.compare_digest`). Las llaves en reposo van con AES-256-GCM, con nonce nuevo
  y AAD ligada al id del sensor. La KEK sale de Argon2id con salt único. TLS 1.3 es la versión mínima forzada."
- "Ed25519 y el ESP32 quedan como extensión; no se implementaron."

**Diapositiva:** 4 y 6.

---

## 3. Demo (5 min)

Seguir `docs/demo.md`. Orden:

1. Sensor enviando, VERIFICADA en dashboard (0:40).
2. Cinco ataques por la API (manipulada, falsa, replay, fuera-ventana, hueco) y tres sobre la BD (alterar, borrar, cadena rota) (2:20).
3. `scripts/demo.sh bd`: llaves ilegibles, mediciones en claro (40 s).
4. `scripts/demo.sh tls`: 1.3 acepta, 1.2 rechaza (30 s).
5. `scripts/demo.sh estatico`: 0 hallazgos de bandit, 0 vulnerabilidades en dependencias (25 s).

**Qué decir al terminar la demo:** "Lo que acaban de ver es lo que hace el sistema. Cada ataque tuvo el
estado que anunciamos, y el atacante con acceso a la base de datos no pudo modificar nada sin que se notara."

---

## 4. Limitaciones y cierre (2 min)

**Qué decir:**

- (0:00–0:50) "Lo que no hace VIGÍA: no oculta las mediciones. Un insider con la BD las lee. El HMAC usa
  llave compartida: el servidor podría forjar tags, y no hay no-repudio. El truncado de las últimas mediciones
  no se detecta en el historial, solo operativamente. La tabla `eventos` no está encadenada. La API y el dashboard
  no tienen autenticación y escuchan en 127.0.0.1. La denegación de servicio y un sensor físicamente comprometido
  quedan fuera de alcance."
- (0:50–1:30) "Trabajo futuro: firmas Ed25519 por sensor para eliminar la llave compartida, un ancla externa para
  el truncado, encadenar `eventos`, rotación de llaves y sensor real."
- (1:30–2:00) "Conclusión: el HMAC, la secuencia y la cadena de hashes dan autenticidad, integridad, frescura e
  historial además de TLS, en lo que TLS no cubre. Gracias."

**Diapositiva:** 7 y 8.

---

## Diapositivas sugeridas (8)

| # | Título | Línea | Diagrama |
|---|---|---|---|
| 1 | VIGÍA: telemetría de sensores verificable | Autenticidad, integridad, frescura e historial de las mediciones | ninguno |
| 2 | El problema y lo que garantizamos | Qué garantiza VIGÍA y qué no (las mediciones van en claro) | ninguno (tabla) |
| 3 | Arquitectura | Sensor, TLS 1.3, API de verificación, SQLite y dashboard | `docs/diagramas/arquitectura-resumen.png` |
| 4 | Sensor: HMAC y canal | Cada medición lleva un tag HMAC-SHA256 con la llave K del sensor | `docs/diagramas/flujo-sensor.png` |
| 5 | Verificación en 5 pasos | Cada paso produce un estado de rechazo; si todo pasa, VERIFICADA | `docs/diagramas/flujo-verificacion.png` |
| 6 | En reposo: llaves cifradas | AES-256-GCM por sensor, KEK con Argon2id y salt único, contraseña fuera de la BD | `docs/diagramas/flujo-almacenamiento.png` |
| 7 | Modelo de amenazas | Qué atacante mitiga cada capa y qué queda fuera de alcance | `docs/diagramas/modelo-amenazas.png` |
| 8 | Demo y limitaciones | Demo en vivo (guion en `docs/demo.md`) y trabajo futuro | ninguno (capturas de respaldo) |

Notas de diseño de las diapositivas:

- Los diagramas PNG son grandes: usar la imagen completa, sin texto adicional. Si se proyecta en pantalla
  pequeña, usar el `.mmd` solo como referencia.
- En la diapositiva 8, dejar una captura del dashboard y de la salida de `demo.sh ataque todos` por si falla la demo.

---

## Preguntas probables del profesor

**¿Por qué HMAC si ya hay TLS?**
TLS termina en el servidor y no autentica al sensor (no tiene certificado de cliente). Tampoco detecta un replay
dentro de otra sesión TLS, ni huecos en la secuencia, ni cambios en lo que ya está guardado en la BD. El HMAC cubre
esas cuatro cosas. TLS protege el canal; el HMAC protege el dato.

**¿Por qué no firmas Ed25519?**
Con HMAC la llave es compartida: el servidor podría forjar tags, y no hay no-repudio. Ed25519 (firmas con PyNaCl)
lo resolvería, pero lo dejamos como extensión porque el alcance acordado es HMAC con llave por sensor. Se
implementaría si se pidiera o con un sensor real (ESP32).

**¿Qué pasa si roban la BD?**
Ven las mediciones en claro, porque VIGÍA no ofrece confidencialidad de los datos. No obtienen las llaves K: están
cifradas con AES-256-GCM. La clave de cifrado sale de la contraseña maestra con Argon2id, que no está en la BD.
Si modifican algo, el historial lo detecta (MANIPULADA o CADENA ROTA). Límite honesto: `sensores/<id>.key` queda en
claro en disco, como simulación de la entrega fuera de banda; quien lo tenga puede forjar tags de ese sensor.

**¿Por qué Argon2id?**
Es una función de derivación de claves resistente a fuerza bruta con GPU y ASIC, porque exige memoria además de
tiempo (RFC 9106). Lo usamos para derivar la KEK desde la contraseña maestra, con salt único de 16 bytes. Los
parámetros van en `meta` con cotas mínimas y máximas.

**¿Por qué AES-256-GCM y qué pasa con el nonce?**
GCM cifra y autentica a la vez (AEAD). El nonce de 12 bytes es aleatorio y nuevo en cada cifrado; reutilizar un
nonce con la misma llave rompe GCM, por eso cada cifrado genera uno. El AAD liga cada blob a su sensor.

**¿Por qué la cadena de hashes incluye el tag?**
Porque así cada eslabón depende del contenido autenticado. Un hash sin el tag encadenaría solo los datos, no la
prueba de autenticidad.

**¿Por qué no se usa `==` para comparar tags?**
Porque `==` puede filtrar información por tiempo de respuesta. Usamos `hmac.compare_digest`, que es en tiempo constante.

**¿Qué pasa con un replay dentro de la ventana de tiempo?**
La defensa principal es el número de secuencia estricto (última + 1), no el reloj. La ventana de 30 s es una capa
adicional, y depende de relojes sincronizados.

**¿Qué NO detecta el sistema?**
- El truncado de las últimas mediciones en el historial. Solo se ve de forma operativa: la siguiente medición
  llega con hueco y se responde REPLAY O HUECO.
- Un insider con la llave K puede forjar tags (el servidor la conoce; no hay no-repudio).
- Ediciones en la tabla `eventos`, que no está encadenada.
- Revocación efectiva: `activo` es un flag sin protección criptográfica; la revocación real requeriría rotar K.
- Sensor físicamente comprometido, denegación de servicio y el acceso no autenticado a la API.
- Alteraciones intermedias en la ingesta normal: solo se ven con "Verificar historial completo".

**¿Por qué REPLAY O HUECO y no dos estados?**
Porque para el usuario el resultado es el mismo (el servidor rechaza la medición y la secuencia está desalineada);
el motivo exacto queda en el campo de detalle.

**¿Por qué el certificado es autofirmado?**
Es solo para desarrollo, para demostrar TLS sin depender de una CA. En producción se usaría un certificado de una
CA real con el nombre DNS del servidor.

**¿Cómo sé que la criptografía no es casera?**
Solo usamos librerías probadas: `cryptography`, `argon2-cffi`, `hmac` y `hashlib`. Bandit no encontró hallazgos en
la aplicación y pip-audit no encontró vulnerabilidades en las dependencias (ver `scripts/demo.sh estatico`).

**¿Qué pasa si se pierde un mensaje?**
El servidor rechaza todo lo que llega con hueco (fail-closed) hasta una re-sincronización manual. Preferimos no
aceptar datos con huecos. Si se pierde solo la respuesta, el simulador se recupera solo.

**¿Por qué TLS 1.3 forzado?**
Para que ninguna conexión pueda negociar 1.2 o inferior. La demo lo muestra: `scripts/demo.sh tls` acepta 1.3
y rechaza 1.2.
