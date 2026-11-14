"""Núcleo criptográfico de VIGÍA (HMAC-SHA256, cadena de hashes, AES-256-GCM + Argon2id)."""
from .canonical import FormatoInvalido, mensaje_canonico
from .chain import GENESIS, siguiente_hash
from .keystore import (
    MAX_ARGON2,
    MIN_ARGON2,
    PARAMS_ARGON2,
    ContrasenaIncorrecta,
    comprobar_canario,
    crear_canario,
    cifrar_llave_sensor,
    derivar_kek,
    descifrar_llave_sensor,
    nuevo_salt,
    validar_params_argon2,
)
from .mac import calcular_tag, generar_llave_sensor, huella_tag, verificar_tag
from .verifier import (
    Estado,
    Medicion,
    RegistroGuardado,
    ReporteHistorial,
    Resultado,
    ResultadoRegistro,
    verificar_historial,
    verificar_medicion,
)

__all__ = [
    "FormatoInvalido", "mensaje_canonico", "GENESIS", "siguiente_hash",
    "PARAMS_ARGON2", "MIN_ARGON2", "MAX_ARGON2", "validar_params_argon2", "ContrasenaIncorrecta", "nuevo_salt", "derivar_kek",
    "cifrar_llave_sensor", "descifrar_llave_sensor", "crear_canario", "comprobar_canario",
    "generar_llave_sensor", "calcular_tag", "verificar_tag", "huella_tag",
    "Estado", "Medicion", "RegistroGuardado", "Resultado", "ResultadoRegistro",
    "ReporteHistorial", "verificar_medicion", "verificar_historial",
]
