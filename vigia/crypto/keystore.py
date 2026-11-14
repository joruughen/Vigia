"""Cifrado en reposo de las llaves de sensores.

KEK = Argon2id(contraseña maestra, salt)  ->  AES-256-GCM(KEK, nonce, llave_sensor, AAD)

Por qué:
- Argon2id (ganador de la PHC, RFC 9106) es memory-hard: encarece el ataque de
  diccionario con GPU/ASIC si se roba la BD. Salt aleatorio único evita tablas precomputadas.
- AES-256-GCM es cifrado autenticado: detecta contraseña incorrecta y cualquier
  alteración del ciphertext. El nonce de 12 B es aleatorio y NUEVO en cada cifrado;
  repetir (llave, nonce) en GCM rompe confidencialidad e integridad.
- AAD = b"vigia-sensor-key|" + sensor_id liga cada llave cifrada a su sensor: copiar
  el blob de un sensor a la fila de otro hace fallar el descifrado.
"""
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .canonical import FormatoInvalido, validar_sensor_id

# RFC 9106 §4, segunda opción recomendada (entornos con poca memoria): t=3, m=64 MiB, p=4.
PARAMS_ARGON2: dict = {
    "time_cost": 3,
    "memory_cost": 65536,  # KiB = 64 MiB
    "parallelism": 4,
    "hash_len": 32,        # 256 bits -> llave AES-256
}
LARGO_SALT = 16   # 128 bits, recomendado por RFC 9106
LARGO_NONCE = 12  # 96 bits, tamaño estándar de nonce para GCM
LARGO_KEK = 32
LARGO_LLAVE_SENSOR = 32

_AAD_LLAVE = b"vigia-sensor-key|"
_AAD_CANARIO = b"vigia-canario"  # dominio distinto: el canario no se confunde con una llave
_TEXTO_CANARIO = b"VIGIA canario v1"


class ContrasenaIncorrecta(Exception):
    """La KEK no descifra: contraseña maestra incorrecta o datos alterados."""


def nuevo_salt() -> bytes:
    """Salt aleatorio de 16 bytes (os.urandom = CSPRNG del SO)."""
    return os.urandom(LARGO_SALT)


# Mínimos OWASP para Argon2id (m=19 MiB, t=2, p=1). Impiden que quien edite
# kdf_params en la BD degrade la derivación (p.ej. t=1, m=8 KiB) para acelerar
# un ataque de diccionario sobre la contraseña maestra.
MIN_ARGON2: dict = {"time_cost": 2, "memory_cost": 19456, "parallelism": 1}
# Cotas superiores: unos kdf_params manipulados en la BD no deben poder forzar una
# derivación desproporcionada (DoS por CPU/RAM al abrir el almacén).
MAX_ARGON2: dict = {"time_cost": 10, "memory_cost": 1048576, "parallelism": 64}  # 1 GiB
_CLAVES_ARGON2 = frozenset(PARAMS_ARGON2)


def validar_params_argon2(params: dict) -> dict:
    """Valida parámetros Argon2id leídos de la BD; devuelve una copia limpia o ValueError."""
    if not isinstance(params, dict):
        raise ValueError("kdf_params debe ser un objeto/dict")
    claves = set(params)
    if claves != _CLAVES_ARGON2:
        faltan = sorted(_CLAVES_ARGON2 - claves)
        sobran = sorted(claves - _CLAVES_ARGON2)
        raise ValueError(f"kdf_params con claves inválidas (faltan {faltan}, sobran {sobran})")
    for k, v in params.items():
        # bool es subclase de int: se rechaza explícitamente.
        if not isinstance(v, int) or isinstance(v, bool):
            raise ValueError(f"kdf_params.{k} debe ser entero")
    if params["hash_len"] != LARGO_KEK:
        raise ValueError(f"kdf_params.hash_len debe ser {LARGO_KEK} (AES-256)")
    for k, minimo in MIN_ARGON2.items():
        if params[k] < minimo:
            raise ValueError(f"kdf_params.{k}={params[k]} por debajo del mínimo {minimo} "
                             "(posible degradación de Argon2id)")
    for k, maximo in MAX_ARGON2.items():
        if params[k] > maximo:
            raise ValueError(f"kdf_params.{k}={params[k]} por encima del máximo {maximo} "
                             "(posible DoS por parámetros Argon2id manipulados)")
    return {k: int(params[k]) for k in PARAMS_ARGON2}


def derivar_kek(contrasena: str, salt: bytes, params: dict | None = None) -> bytes:
    """Deriva la KEK de 32 bytes con Argon2id (Type.ID: resiste canal lateral y GPU).

    params: los kdf_params guardados en la BD (None = PARAMS_ARGON2). Se validan
    con validar_params_argon2 para rechazar valores degradados.
    """
    if not isinstance(contrasena, str) or not contrasena:
        raise ValueError("contraseña maestra vacía")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < LARGO_SALT:
        raise ValueError("salt debe tener al menos 16 bytes")
    efectivos = dict(PARAMS_ARGON2) if params is None else validar_params_argon2(params)
    return hash_secret_raw(
        secret=contrasena.encode("utf-8"),
        salt=bytes(salt),
        type=Type.ID,
        **efectivos,
    )


def _aes(kek: bytes) -> AESGCM:
    if not isinstance(kek, (bytes, bytearray)) or len(kek) != LARGO_KEK:
        raise ValueError("la KEK debe tener 32 bytes (AES-256)")
    return AESGCM(bytes(kek))


def _aad_llave(sensor_id: str) -> bytes:
    try:
        validar_sensor_id(sensor_id)
    except FormatoInvalido as e:
        raise ValueError(str(e)) from None
    return _AAD_LLAVE + sensor_id.encode("utf-8")


def cifrar_llave_sensor(kek: bytes, sensor_id: str, llave: bytes) -> tuple[bytes, bytes]:
    """Devuelve (nonce de 12 B nuevo, ciphertext||tag GCM)."""
    if not isinstance(llave, (bytes, bytearray)) or len(llave) != LARGO_LLAVE_SENSOR:
        raise ValueError("la llave de sensor debe tener 32 bytes")
    aes = _aes(kek)
    nonce = os.urandom(LARGO_NONCE)
    return nonce, aes.encrypt(nonce, bytes(llave), _aad_llave(sensor_id))


def descifrar_llave_sensor(kek: bytes, sensor_id: str, nonce: bytes, ct: bytes) -> bytes:
    """Descifra y autentica; InvalidTag (contraseña o datos alterados) -> ContrasenaIncorrecta."""
    aes = _aes(kek)
    try:
        llave = aes.decrypt(bytes(nonce), bytes(ct), _aad_llave(sensor_id))
    except (InvalidTag, ValueError) as e:
        raise ContrasenaIncorrecta("no se pudo descifrar la llave del sensor") from e
    if len(llave) != LARGO_LLAVE_SENSOR:
        raise ContrasenaIncorrecta("llave descifrada con largo inesperado")
    return llave


def crear_canario(kek: bytes) -> tuple[bytes, bytes]:
    """Cifra un texto fijo para poder validar la contraseña al arrancar sin tocar llaves."""
    aes = _aes(kek)
    nonce = os.urandom(LARGO_NONCE)
    return nonce, aes.encrypt(nonce, _TEXTO_CANARIO, _AAD_CANARIO)


def comprobar_canario(kek: bytes, nonce: bytes, ct: bytes) -> None:
    """Lanza ContrasenaIncorrecta si la KEK no descifra el canario."""
    aes = _aes(kek)
    try:
        texto = aes.decrypt(bytes(nonce), bytes(ct), _AAD_CANARIO)
    except (InvalidTag, ValueError) as e:
        raise ContrasenaIncorrecta("contraseña maestra incorrecta") from e
    if texto != _TEXTO_CANARIO:
        raise ContrasenaIncorrecta("canario inesperado")
