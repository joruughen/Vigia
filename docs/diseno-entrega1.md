# VIGÍA — Diseño (Entrega 1, con ajustes acordados)

Sistema de telemetría criptográficamente verificable. Curso de Criptografía.
Integrantes: Jorge Eduardo Melgarejo Castillo, Sergio Felipe Delgado Amado.

## Problema y objetivo
Los sistemas IoT deciden a partir de mediciones. Un atacante puede modificar una medición, inventar datos, repetir mensajes antiguos o alterar/borrar el historial en la base de datos.
VIGÍA **no oculta** las mediciones: garantiza que el servidor pueda verificar
1. **Autenticidad**: la medición vino del dispositivo autorizado.
2. **Integridad**: no fue modificada tras el envío.
3. **Frescura**: una medición antigua no se reutiliza.
4. **Historial**: la secuencia de mediciones se mantiene intacta.

## Modelo de amenazas
| Atacante | Defensa |
|---|---|
| Red: modifica mensajes en tránsito | TLS 1.3 (y HMAC-SHA256 extremo a extremo) |
| Repite mensajes antiguos | Número de secuencia + ventana de timestamp |
| Sensor falso que fabrica mediciones | No tiene la llave secreta; el HMAC no valida |
| Acceso a la base de datos | Cadena de hashes (+ re-verificación del HMAC) |
| **Fuera de alcance** | Sensor físicamente comprometido; denegación de servicio |

Feedback del profesor: TLS ya protege en tránsito contra espionaje y modificación. El HMAC se justifica por lo que TLS **no** cubre: autenticidad del sensor extremo a extremo (TLS termina en el servidor), replay a nivel de aplicación, huecos/orden y manipulación de lo ya almacenado.

## Arquitectura
Sensor (simulador: genera mediciones y calcula el HMAC) → Canal protegido (TLS 1.3) → API de verificación (valida HMAC, secuencia, timestamp y cadena) → Base de datos (mediciones, tags, hashes, llaves de sensores cifradas) → Dashboard (estado criptográfico de cada medición).
- En tránsito: TLS 1.3.
- En reposo: llaves de sensores cifradas + cadena de hashes.

## Algoritmos y librerías
| Función | Elección |
|---|---|
| Autenticación de mensajes | HMAC-SHA256 (librería estándar de Python), comparación en tiempo constante |
| Cadena del historial | SHA-256 (hashlib) |
| Transporte | TLS 1.3 |
| Llaves de sensor | 256 bits, generador aleatorio criptográfico del SO |
| Llaves en reposo en el servidor | AES-256-GCM (librería `cryptography`), nonce aleatorio único por cifrado |
| Derivación de la llave de cifrado | Argon2id con salt único |
| Extensión opcional (no implementar salvo pedido) | Firmas Ed25519 con PyNaCl; ESP32 real |

Nunca se implementa criptografía desde cero.

## Protocolo
Mensaje = `ID | SECUENCIA | TIMESTAMP | MEDICIÓN | TAG`, con `TAG = HMAC-SHA256(K, mensaje)`.
- Cada sensor tiene su propia llave K de 256 bits.
- Serialización canónica (mismos bytes en ambos lados).
- La secuencia aumenta de uno en uno (previene replay y detecta huecos).
- Cadena de hashes (ajuste acordado): `h_i = SHA256(h_{i-1} || mensaje_canónico_i || tag_i)`; **el hash incluye el tag**.

## Flujo de verificación (5 pasos, en orden)
| # | Pregunta | Si falla |
|---|---|---|
| 1 | ¿El id del sensor está registrado? | **FALSA** |
| 2 | ¿El HMAC es válido? | **MANIPULADA** |
| 3 | ¿La secuencia es igual a la última + 1? | **REPLAY O HUECO** |
| 4 | ¿El timestamp está dentro de la ventana? | **FUERA DE VENTANA** |
| 5 | ¿La cadena de hashes es consistente? | **CADENA ROTA** |
| — | Todo correcto | **VERIFICADA** (se guarda) |

Aclaración a fijar en la implementación: "FALSA" = sensor no registrado. Un mensaje fabricado con un id válido pero sin la llave falla el paso 2 (MANIPULADA). Si en la demo se quiere mostrar FALSA, usar un id de sensor inexistente.
"REPLAY O HUECO" es un solo estado visible; internamente guardar el motivo (replay vs. hueco) en un campo de detalle.

## Manejo de llaves
- Generación: K de 256 bits por sensor con RNG criptográfico.
- Entrega: una sola vez, por canal fuera de banda; se asocia al id.
- Servidor: llaves de sensores cifradas con AES-256-GCM (nonce único); llave de cifrado derivada con Argon2id y salt único. La contraseña maestra va en variable de entorno, nunca en el repo.
- En tránsito: TLS 1.3. En reposo: llaves cifradas + cadena de hashes.
- Revocación: una llave comprometida se desactiva en el servidor.

## Funcionalidades e interfaz
- **Simulador de sensor**: genera mediciones y calcula su HMAC.
- **API de verificación**: valida y almacena cada medición recibida.
- **Dashboard**: menú (resumen, mediciones, historial, configuración); sensor activo; tabla (fecha y hora, valor, HMAC, estado con etiqueta de color); gráfico de serie de tiempo; botón **"Verificar historial completo del sensor"**.
- **Verificación completa**: recorre y verifica toda la cadena de un sensor (re-verifica HMAC y hashes; así se detecta la alteración directa en la base de datos).

## Demo: ataques que VIGÍA detecta
Primero mediciones normales, luego:
| Ataque | Qué se hace | Cómo se detecta | Estado |
|---|---|---|---|
| Modificar una lectura en la BD | Cambiar el valor de una medición guardada | HMAC y hash no coinciden | MANIPULADA |
| Reenviar una medición antigua | Reenviar una ya registrada | La secuencia ya fue usada | REPLAY |
| Fabricar una medición falsa | Crear una medición sin la llave | HMAC inválido (o sensor no registrado) | MANIPULADA / FALSA |
| Eliminar o alterar una medición intermedia | Borrar o editar una intermedia | Hueco en la secuencia y cadena rota | CADENA ROTA |

## Limitaciones (para el informe)
- HMAC usa llave compartida: el servidor también podría generar tags válidos (mitigación posible: Ed25519).
- No oculta las mediciones (no hay confidencialidad más allá de TLS).
- Truncar las últimas mediciones es difícil de detectar.
- Fuera de alcance: sensor físicamente comprometido, DoS.

## Plan de trabajo
1. Protocolo, llaves, modelo de amenazas. 2. Simulador de sensor. 3. Servidor de verificación. 4. Interfaz sencilla. 5. Ataques, demo final, análisis estático (Bandit) e informe técnico.
