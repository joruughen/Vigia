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


def derivar_kek(contrasena: str, salt: bytes) -> bytes:
    """Deriva la KEK de 32 bytes con Argon2id (Type.ID: resiste canal lateral y GPU)."""
    if not isinstance(contrasena, str) or not contrasena:
        raise ValueError("contraseña maestra vacía")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < LARGO_SALT:
        raise ValueError("salt debe tener al menos 16 bytes")
    return hash_secret_raw(
        secret=contrasena.encode("utf-8"),
        salt=bytes(salt),
        type=Type.ID,
        **PARAMS_ARGON2,
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
