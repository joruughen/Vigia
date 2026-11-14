# Anexo B: amenazas y limitaciones (detalle)

Modelo de atacante, supuestos, tabla completa de amenazas con su riesgo residual y tabla completa de limitaciones. El informe principal (`docs/informe.md`, secciones 5 y 8) presenta la versión condensada; las referencias "sección N" remiten a él.

## B.1 Modelo de atacante y supuestos

Se consideran siete atacantes:

| Atacante | Qué puede hacer |
|---|---|
| Red / MITM | Leer, modificar, retener, descartar o reenviar el tráfico entre sensor y servidor |
| Sensor falso | Enviar mensajes con un `sensor_id` inexistente, o con uno válido pero sin conocer su llave K |
| Replay | Reenviar mensajes auténticos que capturó antes |
| Insider con acceso a la BD | Leer y **escribir** el archivo SQLite. No conoce K ni la contraseña maestra, no tiene acceso al directorio `sensores/` y no controla el proceso del servidor |
| Ladrón de la BD o de un backup | Obtiene una copia del archivo, sin la contraseña maestra |
| Operador con la contraseña maestra, o servidor comprometido | Conoce la KEK, puede descifrar todas las K y ejecutar código en el servidor |
| Sensor físicamente comprometido | Extrae K del dispositivo |

**Supuestos.**

- K se genera con CSPRNG (256 bits); la conocen el sensor y el servidor (cifrada en la BD), y además queda en claro en `sensores/<id>.key` (0600) en el host donde se registró (sección 8). Se supone que el insider con acceso a la BD no tiene acceso a ese directorio.
- La contraseña maestra es secreta y tiene entropía suficiente. VIGÍA solo exige 16 caracteres y no mide la entropía (sección 8).
- Las primitivas (HMAC-SHA256, SHA-256, AES-256-GCM, Argon2id, TLS 1.3) y sus implementaciones en las librerías usadas son seguras.
- Mientras el servidor no esté comprometido, ejecuta el código sin modificar. El insider modifica el archivo de la BD, no la memoria del proceso.
- Los relojes del sensor y del servidor están razonablemente sincronizados (la ventana es de 30 s).
- El sensor verifica el certificado del servidor con `--cacert`. El certificado de desarrollo es autofirmado.
- Fuera de alcance: el hardware del sensor, la denegación de servicio, el no-repudio y la confidencialidad de las mediciones almacenadas (sección 1.3).

## B.2 Qué cubre TLS y qué no (detalle)

TLS 1.3 cubre el **tramo de red**: confidencialidad e integridad del tráfico entre el sensor y el servidor y autenticación del servidor mediante su certificado. Eso mitiga el espionaje y la modificación en tránsito.

TLS **no** cubre lo siguiente, y por eso VIGÍA añade HMAC, secuencia y cadena (detalle en la sección 3.7):

- **Autenticidad del sensor extremo a extremo.** TLS autentica al servidor, no al sensor: aquí no hay certificado de cliente, y cualquiera que alcance el puerto abre una sesión TLS válida. Además TLS termina en el servidor (o en un proxy), por lo que no dice nada sobre quién generó el dato. El HMAC con la K de cada sensor sí lo dice.
- **Replay a nivel de aplicación.** Un mensaje legítimo reenviado en otra sesión TLS es válido para TLS. La secuencia estricta y la ventana de timestamp lo rechazan.
- **Huecos y orden.** TLS entrega bytes, no sabe qué mediciones faltan. La secuencia consecutiva y la cadena de hashes sí.
- **Manipulación de lo almacenado por un insider o una BD alterada.** Cuando el dato llega al servidor, TLS ya no lo protege. La re-verificación del HMAC y de la cadena sí.

## B.3 Amenazas, mitigaciones y riesgo residual (tabla completa)

| Amenaza | Mitigación (estado observable) | Riesgo residual |
|---|---|---|
| **Modificación en tránsito** (MITM cambia el valor) | TLS 1.3 lo detecta (AEAD) y corta la conexión; no impide que el MITM descarte el tráfico. Si el mensaje viajara por un tramo sin TLS o por un proxy, el HMAC cubre versión, `sensor_id`, `seq`, `timestamp_ms` y `valor`: cualquier cambio da `MANIPULADA` | Un proxy que termine TLS ve los datos en claro: el HMAC da integridad, no confidencialidad |
| **Espionaje en tránsito** | TLS 1.3 forzado como versión mínima (comprobado: `TLS_AES_256_GCM_SHA384`; TLS 1.2 rechazado). El HMAC **no** cifra | Metadatos visibles (direcciones, tamaños, tiempos). Un certificado autofirmado mal distribuido permitiría un MITM; el cliente solo confía en el certificado que se le da con `--cacert` |
| **Sensor falso / id inexistente** | Paso 1: sin llave registrada o activa, `FALSA`; no se guarda medición | Un id válido sin llave da `MANIPULADA` y uno inexistente da `FALSA`: la respuesta permite enumerar ids registrados, y `GET /api/sensores` lista todos los ids sin autenticación. Cada intento con formato válido deja una fila en `eventos` |
| **Falsificación con id válido sin la llave** | Paso 2: el HMAC no valida (`hmac.compare_digest`, tiempo constante): `MANIPULADA`. Adivinar un tag de 256 bits es inviable | Ninguno práctico sin K. Con K, véase "servidor comprometido" y "sensor físico" |
| **Replay** de un mensaje aceptado | Paso 3: la secuencia debe ser exactamente última + 1; si no, `REPLAY O HUECO` (`replay: seq N <= última M`), aunque llegue por otra sesión TLS | Ninguno para mensajes ya aceptados |
| **Eliminación de un mensaje en tránsito** | TLS no impide que alguien corte la conexión. El sensor no avanza su `seq` sin `VERIFICADA` y reintenta; si se perdió la respuesta de un mensaje ya guardado, el simulador lo reconoce (replay de la misma `seq`) y avanza. Cualquier otra desincronización se rechaza como `REPLAY O HUECO` (fail-closed) | Es una pérdida de disponibilidad: el dato no llega. No hay alerta cuando un sensor guarda silencio |
| **Retraso / mensaje viejo** | El `timestamp_ms` está dentro del tag: no se puede ajustar. Paso 4: fuera de ±30 s (`VIGIA_VENTANA_MS`) da `FUERA DE VENTANA`, sin guardar ni consumir la `seq`. La secuencia estricta impide además reutilizar un mensaje ya aceptado | Un mensaje retenido y entregado dentro de la ventana se acepta si su `seq` es la esperada. Depende de relojes sincronizados |
| **Alteración de un valor guardado** (insider o BD alterada, sin K) | El HMAC ya no coincide: "Verificar historial completo" da `MANIPULADA` en ese registro. Si es el último, la siguiente ingesta da `CADENA ROTA` (el hash recalculado no coincide) | Una alteración intermedia solo se ve al verificar el historial, que es una acción manual; no hay verificación automática |
| **Borrado intermedio** | Se rompen la continuidad de `seq` y el enlace `hash_prev`: `CADENA ROTA` en el registro siguiente | Igual que arriba: detección bajo demanda |
| **Inserción de una fila final falsa** (con hash recalculado) | SHA-256 no lleva llave y por sí solo no lo impediría. El paso 5 **re-verifica el HMAC del último registro**: `CADENA ROTA`; el historial la marca `MANIPULADA`. Si el `seq` de la fila no es el esperado, `REPLAY O HUECO`. En todos los casos la medición legítima siguiente se rechaza y no se encadena sobre la fila falsa | La recuperación automática del sensor confía en la respuesta del servidor: una fila final falsa con la `seq` esperada hace que el sensor descarte una medición antes de que aparezca `CADENA ROTA` (sigue fallando cerrado). Sin K el insider no puede fabricar un tag válido. Con K, véase "servidor comprometido" |
| **Promoción de un mensaje auténtico rechazado** (copiar su tag desde `eventos` a `mediciones`) | `eventos` guarda el tag completo solo si fue `VERIFICADA` (ya está en `mediciones`). Si fue rechazada (p. ej. `FUERA DE VENTANA`) guarda solo la huella `sha256:` + SHA-256 de `"vigia-huella-tag\|" + tag`, que no es un tag válido ni se puede invertir (N1) | Ninguno por esta vía. La huella solo permite correlacionar intentos repetidos |
| **Truncado de las últimas mediciones** | El historial no lo detecta: queda una cadena válida más corta. Operativamente la siguiente medición del sensor, que ya avanzó su `seq`, llega con un hueco y recibe `REPLAY O HUECO` (N3) | No hay ancla externa del último hash o `seq`. La señal depende de que el sensor siga enviando y no distingue truncado de desincronización |
| **Edición de la tabla `eventos`** | Ninguna criptográfica: no está encadenada. No afecta a `mediciones`, y desde N1 ya no contiene tags de mensajes rechazados | El registro de intentos que muestra el dashboard no es confiable ante un insider. La fuente de verdad es `mediciones` con su verificación |
| **Robo de la BD o de un backup** | Las llaves K están cifradas con AES-256-GCM (nonce único, AAD = id) bajo una KEK derivada con Argon2id (salt único de 16 B, t=3, m=64 MiB, p=4). Sin la contraseña no se descifran y un blob copiado a otro sensor falla | Mediciones, tags, hashes y eventos están **en claro**: no hay confidencialidad. Se puede atacar la contraseña sin conexión (el canario sirve de verificador), frenado por Argon2id |
| **Contraseña maestra débil** | Política: al menos 16 caracteres y se rechaza el valor de `.env.example`. Argon2id encarece cada intento | El largo no garantiza entropía: una contraseña larga y predecible la cumple. Si es débil, el robo de la BD compromete todas las K |
| **Degradación o DoS por `kdf_params`** | Se validan antes de derivar: mínimos (t >= 2, m >= 19456 KiB, p >= 1) contra la degradación y máximos (t <= 10, m <= 1 GiB, p <= 64) contra el DoS y las excepciones no controladas (N2). Es defensa en profundidad: editar `kdf_params` o el salt cambia la KEK, el canario no descifra y el servidor no arranca, así que no se puede abaratar la KEK real. Con valores fuera de las cotas el error es de parámetros | Quien edite `kdf_params` o el salt puede impedir el arranque (falla cerrado). Si los valores editados quedan dentro de las cotas, el mensaje es "contraseña incorrecta", engañoso. Dentro de las cotas el costo puede llegar a 1 GiB y t = 10 |
| **Servidor comprometido o insider con la KEK** | Ninguna. La llave es compartida: quien tiene la KEK descifra cada K, puede forjar tags válidos, insertar mediciones con cadena consistente y suplantar sensores. No hay no-repudio | **Alto, aceptado.** Mitigación futura: firmas Ed25519 por sensor, de modo que el servidor no tenga una llave capaz de firmar |
| **API sin autenticación / DoS** | Escucha en 127.0.0.1 por defecto. Sin K nada se acepta, y un mensaje sin HMAC válido no consume la `seq` (el paso 2 va antes que el 3), así que no se puede desincronizar a un sensor. El modelo de entrada limita tipos y largos | Cualquiera que alcance el puerto lee datos y envía intentos (se llena `eventos`). No hay autenticación ni límite de tasa. DoS **fuera de alcance** |
| **Sensor físicamente comprometido** | **Fuera de alcance.** Quien extraiga K se hace pasar por el sensor. Revocarlo (`revocar-sensor`) hace que lo posterior dé `FALSA`; lo ya guardado sigue verificable | Sin defensa: no hay almacén seguro de llaves ni rotación. Además `sensores/<id>.key` queda en disco en claro (0600) tras la "entrega". La revocación es un flag `activo` sin protección criptográfica: un insider con escritura en la BD puede reactivar un sensor revocado y quien tenga la K robada vuelve a obtener `VERIFICADA` |

## B.4 Lectura de conjunto

- **Cubierto por diseño:** modificación y espionaje en tránsito (TLS), falsificación sin K, replay, mensajes viejos, y alteración, borrado intermedio e inserción en lo almacenado por quien no tiene K.
- **Detectado solo bajo demanda u operativamente:** las alteraciones intermedias (hay que pulsar "Verificar historial completo") y el truncado (se ve como hueco).
- **Aceptado como limitación:** el servidor o el operador con la KEK puede forjar (llave compartida), la API no tiene autenticación, `eventos` no es confiable ante un insider y las mediciones no son confidenciales.
- **Fuera de alcance:** el sensor físicamente comprometido y la denegación de servicio.

## B.5 Fallas y limitaciones (tabla completa)

Todas son decisiones o límites aceptados; ninguna está oculta.

| Limitación | Detalle y consecuencia |
|---|---|
| Re-sincronización manual tras un mensaje perdido (fail-closed) | El sensor se recupera solo si el servidor ya tiene exactamente esa `seq`. Ante un hueco (el servidor está atrasado) se rechaza todo hasta una re-sincronización manual. Se prefiere esto a aceptar datos con huecos. Si `sensores/<id>.seq` se pierde o se corrompe, `leer_seq` devuelve 0 y el sensor queda en `REPLAY O HUECO` permanente (el servidor está adelantado); también requiere re-sincronización manual |
| La tabla `eventos` no está encadenada | Un insider con acceso a la BD puede editar el registro de intentos que muestra el dashboard (estados, detalles, valores). La tabla protegida es `mediciones`. Desde N1 ya no puede obtener tags auténticos de ahí, porque en las rechazadas solo hay huella |
| Alteración intermedia solo detectada con "Verificar historial completo" | La ingesta normal solo re-verifica el último registro guardado. Una edición en medio no se ve hasta verificar todo el historial |
| Truncado de las últimas mediciones | **No se detecta en el historial**: si se borran los registros finales, queda una cadena válida más corta, y no hay ancla externa del último hash o `seq`. **Sí se detecta operativamente** (precisión N3): el sensor ya avanzó su `seq`, su siguiente medición llega con un hueco y el servidor responde `REPLAY O HUECO` (también si se restaura un respaldo antiguo); el sensor queda detenido hasta una re-sincronización manual. Esa señal depende de que el sensor siga enviando y no distingue un truncado de una desincronización |
| HMAC de llave compartida | El servidor conoce K y podría forjar tags válidos; no hay no-repudio. Mitigación futura: firmas Ed25519 por sensor |
| API y dashboard sin autenticación | Escuchan en 127.0.0.1 por defecto. Cualquiera que alcance el puerto puede consultar datos y enviar intentos (que quedan en `eventos`, incluso con ids inexistentes). DoS fuera de alcance |
| Alterar el `seq` del último registro se etiqueta `REPLAY O HUECO` en vez de `CADENA ROTA` | El orden de 5 pasos del diseño pone la secuencia (paso 3) antes de la cadena (paso 5). **En ambos casos se rechaza** la medición; solo cambia la etiqueta |
| El dashboard depende de `cdnjs.cloudflare.com` | Chart.js se carga de un CDN con Subresource Integrity (SRI) y la CSP lo permite. Sin red, el dashboard funciona sin gráfico. Una alternativa sería servir Chart.js localmente |
| Certificado autofirmado solo para desarrollo | En producción se usaría una CA real. El cliente se configura con ese certificado como su "CA" |
| Sensor simulado, no hardware | No se prueba un dispositivo real ni protecciones de hardware (almacén seguro de llaves) |
| El archivo `sensores/<id>.key` queda en disco | `registrar-sensor` escribe K en claro (0600) para simular la entrega y no se borra después; no hay rotación de llaves. Quien lea ese archivo (o el respaldo del directorio `sensores/`) puede forjar tags de ese sensor |
| Gestión de llaves básica | La revocación no borra el blob cifrado; la KEK y la contraseña maestra residen en memoria y entorno del proceso |
| La política de contraseña es de largo, no de entropía | Se exigen 16 caracteres y se rechaza el valor de ejemplo, pero una contraseña larga y predecible la cumple. Si se roba la BD, el canario permite probar candidatos sin conexión (frenados por Argon2id) |
| `kdf_params` editable | Las cotas son defensa en profundidad: editar `kdf_params` o el salt cambia la KEK y el canario falla, así que no se puede abaratar la KEK real, y los máximos evitan el DoS o la excepción no controlada al arrancar. Quien los edite puede impedir el arranque (falla cerrado; es una denegación de servicio, no un compromiso de llaves). Si los valores editados quedan dentro de las cotas, el mensaje es "contraseña incorrecta", engañoso |
| La revocación es un flag sin protección criptográfica | `sensores.activo` no está autenticado: un insider con escritura en la BD puede reactivar un sensor revocado, y quien tenga la K robada vuelve a obtener `VERIFICADA`. La revocación efectiva exigiría rotar K |
| La recuperación automática del sensor confía en el servidor | Una fila final falsa con la `seq` esperada hace que el sensor descarte una medición antes de que aparezca `CADENA ROTA`. Sigue fallando cerrado: nunca se encadena sobre la fila falsa |
| Reloj | La frescura por timestamp depende de relojes sincronizados (ventana de 30 s). La defensa principal contra el replay es la secuencia, no el reloj |

