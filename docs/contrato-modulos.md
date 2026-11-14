# Contrato entre módulos (Fase 1)

Fuente del diseño: `docs/diseno-entrega1.md`. Este archivo fija las interfaces para que
`vigia/crypto/` (núcleo criptográfico) y `vigia/server/` + `vigia/sensor.py` (aplicación)
se puedan desarrollar en paralelo.

## 1. Formato canónico del mensaje (lo que se autentica con HMAC)

```
VIGIA-v1|<sensor_id>|<seq>|<timestamp_ms>|<valor>
```
codificado en UTF-8 (en la práctica, ASCII). Ejemplo: `VIGIA-v1|sensor-01|42|1763140000123|23.475`

Reglas estrictas (se validan ANTES de calcular o verificar el HMAC; si no cumplen → error de formato, HTTP 422):
| Campo | Regex | Nota |
|---|---|---|
| `sensor_id` | `^[A-Za-z0-9_-]{1,64}$` | No puede contener `\|`, así los campos no son ambiguos |
| `seq` | entero, 1 ≤ seq ≤ 2^63−1 | Representación decimal sin ceros a la izquierda |
| `timestamp_ms` | entero ≥ 0 | Milisegundos Unix UTC, decimal |
| `valor` | `^-?(0\|[1-9][0-9]{0,11})(\.[0-9]{1,6})?$` | Se autentica **el string tal cual se recibió**; nunca se reformatea un float |

- El prefijo `VIGIA-v1` separa dominios y versiona el formato.
- Tag: `HMAC-SHA256(K_sensor, mensaje_canónico)`, transmitido en hex minúscula (64 caracteres).

## 2. Cadena de hashes (por sensor)

```
h_0 = 32 bytes en cero (génesis)
h_i = SHA-256( h_{i-1} || mensaje_canónico_i || tag_i )   # h y tag como bytes crudos de 32 bytes
```
Se guarda en hex. Solo las mediciones VERIFICADAS entran a la cadena.

## 3. Payload HTTP del sensor

`POST /api/mediciones` (JSON):
```json
{"sensor_id": "sensor-01", "seq": 42, "timestamp_ms": 1763140000123, "valor": "23.475", "tag": "<64 hex>"}
```
Respuesta: `{"estado": "VERIFICADA" | "FALSA" | ..., "detalle": "..."}`. Las rechazadas también responden 200 con su estado (es un resultado de verificación, no un error de transporte); el formato inválido responde 422.

## 4. API de `vigia/crypto/` (la implementa cripto-core)

```python
# vigia/crypto/canonical.py
class FormatoInvalido(ValueError): ...
def mensaje_canonico(sensor_id: str, seq: int, timestamp_ms: int, valor: str) -> bytes  # valida y serializa

# vigia/crypto/mac.py
def generar_llave_sensor() -> bytes                              # 32 bytes, secrets/os.urandom
def calcular_tag(llave: bytes, mensaje: bytes) -> str            # hex
def verificar_tag(llave: bytes, mensaje: bytes, tag_hex: str) -> bool   # tiempo constante, False si hex inválido

# vigia/crypto/chain.py
GENESIS: str                                                     # "00"*32
def siguiente_hash(hash_prev_hex: str, mensaje: bytes, tag_hex: str) -> str

# vigia/crypto/keystore.py   (cifrado en reposo de las llaves de sensores)
class ContrasenaIncorrecta(Exception): ...
PARAMS_ARGON2: dict                                              # time_cost, memory_cost (KiB), parallelism, hash_len=32
def nuevo_salt() -> bytes                                        # 16 bytes aleatorios
def derivar_kek(contrasena: str, salt: bytes) -> bytes           # Argon2id -> 32 bytes
def cifrar_llave_sensor(kek: bytes, sensor_id: str, llave: bytes) -> tuple[bytes, bytes]  # (nonce 12B nuevo, ciphertext+tag); AAD = sensor_id
def descifrar_llave_sensor(kek: bytes, sensor_id: str, nonce: bytes, ct: bytes) -> bytes   # InvalidTag -> ContrasenaIncorrecta
def crear_canario(kek: bytes) -> tuple[bytes, bytes]             # para validar la contraseña al arrancar
def comprobar_canario(kek: bytes, nonce: bytes, ct: bytes) -> None   # lanza ContrasenaIncorrecta

# vigia/crypto/verifier.py
class Estado(str, Enum):
    VERIFICADA = "VERIFICADA"; FALSA = "FALSA"; MANIPULADA = "MANIPULADA"
    REPLAY_O_HUECO = "REPLAY O HUECO"; FUERA_DE_VENTANA = "FUERA DE VENTANA"; CADENA_ROTA = "CADENA ROTA"

@dataclass(frozen=True)
class Medicion:            # lo que llega del sensor
    sensor_id: str; seq: int; timestamp_ms: int; valor: str; tag: str

@dataclass(frozen=True)
class RegistroGuardado:    # fila de la cadena en la BD
    sensor_id: str; seq: int; timestamp_ms: int; valor: str; tag: str; hash_prev: str; hash: str

@dataclass(frozen=True)
class Resultado:
    estado: Estado
    detalle: str                 # motivo interno: p.ej. "replay: seq 5 <= última 7", "hueco: esperaba 8, llegó 10"
    hash_nuevo: str | None       # solo si VERIFICADA

def verificar_medicion(m: Medicion, llave: bytes | None, ultimo: RegistroGuardado | None,
                       ahora_ms: int, ventana_ms: int) -> Resultado
    # 1 llave None (no registrado o revocado) -> FALSA
    # 2 HMAC inválido -> MANIPULADA
    # 3 seq != ultimo.seq+1 (o 1 si no hay último) -> REPLAY O HUECO (detalle "replay"/"hueco")
    # 4 |ahora_ms - timestamp_ms| > ventana_ms -> FUERA DE VENTANA
    # 5 recalcular hash del último registro guardado (hash_prev + canónico + tag) != ultimo.hash -> CADENA ROTA
    # todo ok -> VERIFICADA con hash_nuevo = siguiente_hash(ultimo.hash o GENESIS, ...)

@dataclass(frozen=True)
class ResultadoRegistro:
    seq: int; estado: Estado; detalle: str

@dataclass(frozen=True)
class ReporteHistorial:
    sensor_id: str; integro: bool; total: int; registros: list[ResultadoRegistro]

def verificar_historial(sensor_id: str, registros: list[RegistroGuardado], llave: bytes) -> ReporteHistorial
    # registros ordenados por seq. Para cada uno: re-verifica HMAC (-> MANIPULADA),
    # continuidad de seq y enlace hash_prev == hash del anterior y hash recalculado (-> CADENA ROTA, detalle con el motivo).
```

## 5. Responsabilidades de la aplicación (app-dev)

- SQLite (`vigia/server/db.py`): tablas `meta` (salt Argon2, parámetros, canario), `sensores` (id, nonce, llave cifrada, activo, creado), `mediciones` (cadena verificada, `UNIQUE(sensor_id, seq)`), `eventos` (todo intento recibido con estado y detalle).
- La ingesta es atómica por sensor (transacción `BEGIN IMMEDIATE`): leer último → verificar → insertar.
- CLI `python -m vigia.cli init | registrar-sensor <id> | revocar-sensor <id> | listar-sensores`.
  `registrar-sensor` guarda la llave cifrada en la BD y escribe la llave en claro **solo** en `sensores/<id>.key` (permiso 0600, gitignored) para simular la entrega fuera de banda.
- La contraseña maestra se lee de `VIGIA_MASTER_PASSWORD` (`.env`, ver `.env.example`); si es incorrecta, el servidor no arranca.
