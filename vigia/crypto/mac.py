"""HMAC-SHA256 por sensor (autenticidad e integridad extremo a extremo).

Por qué HMAC y no SHA-256(llave||mensaje): HMAC es una construcción probada, resistente
a extensión de longitud. Se usa la implementación de la biblioteca estándar (hmac + hashlib).
"""
import hashlib
import hmac
import re
import secrets

LARGO_LLAVE = 32  # 256 bits = tamaño del bloque de salida de SHA-256; más no aporta seguridad
_RE_HEX64 = re.compile(r"[0-9a-f]{64}")


def generar_llave_sensor() -> bytes:
    """Llave de 32 bytes del CSPRNG del sistema (secrets), nunca de random."""
    return secrets.token_bytes(LARGO_LLAVE)


def _validar_llave(llave: bytes) -> None:
    if not isinstance(llave, (bytes, bytearray)) or len(llave) != LARGO_LLAVE:
        raise ValueError("la llave de sensor debe tener 32 bytes")


def calcular_tag(llave: bytes, mensaje: bytes) -> str:
    """Tag HMAC-SHA256 en hex minúscula (64 caracteres)."""
    _validar_llave(llave)
    return hmac.new(bytes(llave), mensaje, hashlib.sha256).hexdigest()


def tag_a_bytes(tag_hex: str) -> bytes | None:
    """Decodifica un tag hex estricto (64 hex minúscula) o devuelve None.

    Se exige minúscula para que cada tag tenga una única representación textual
    (sin maleabilidad del string almacenado).
    """
    if not isinstance(tag_hex, str) or not _RE_HEX64.fullmatch(tag_hex):
        return None
    try:
        crudo = bytes.fromhex(tag_hex)
    except ValueError:
        return None
    return crudo if len(crudo) == 32 else None


def verificar_tag(llave: bytes, mensaje: bytes, tag_hex: str) -> bool:
    """Compara en tiempo constante (hmac.compare_digest) para no filtrar, por tiempos,
    cuántos bytes del tag acierta un atacante. Hex inválido o de largo != 64 -> False."""
    recibido = tag_a_bytes(tag_hex)
    if recibido is None:
        return False
    _validar_llave(llave)
    esperado = hmac.new(bytes(llave), mensaje, hashlib.sha256).digest()
    return hmac.compare_digest(esperado, recibido)


_DOMINIO_HUELLA = b"vigia-huella-tag|"


def huella_tag(tag_hex: str) -> str:
    """Huella no reversible de un tag para la tabla eventos (mensajes RECHAZADOS).

    La tabla eventos guarda solo esta huella, nunca el tag, para que un insider con
    escritura en la BD no pueda copiar un tag HMAC auténtico de un mensaje rechazado
    (p.ej. FUERA DE VENTANA) a la tabla mediciones y hacerlo pasar por válido.
    La huella permite correlacionar intentos repetidos sin conservar el tag.
    No es un MAC: no requiere llave (SHA-256 con separación de dominio).
    Acepta cualquier string, incluso un tag inválido, sin lanzar.
    """
    if not isinstance(tag_hex, str):
        tag_hex = str(tag_hex)
    datos = _DOMINIO_HUELLA + tag_hex.encode("ascii", "replace")
    return "sha256:" + hashlib.sha256(datos).hexdigest()
