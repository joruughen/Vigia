"""Cadena de hashes por sensor.

    h_0 = 32 bytes en cero
    h_i = SHA-256( h_{i-1} || mensaje_canónico_i || tag_i )

Por qué incluir el tag: así la cadena compromete también la autenticación de cada
medición; borrar, reordenar o editar un registro intermedio rompe todos los enlaces
posteriores. h y tag tienen largo fijo (32 B), por lo que la concatenación no es ambigua.
"""
import hashlib
import re

GENESIS: str = "00" * 32
_RE_HEX64 = re.compile(r"[0-9a-f]{64}")


def _hex32(valor: str, nombre: str) -> bytes:
    if not isinstance(valor, str) or not _RE_HEX64.fullmatch(valor):
        raise ValueError(f"{nombre} debe ser 64 caracteres hex minúscula")
    return bytes.fromhex(valor)


def siguiente_hash(hash_prev_hex: str, mensaje: bytes, tag_hex: str) -> str:
    """Calcula h_i en hex minúscula. Lanza ValueError si hash_prev o tag no son hex de 32 B."""
    h_prev = _hex32(hash_prev_hex, "hash_prev")
    tag = _hex32(tag_hex, "tag")
    return hashlib.sha256(h_prev + mensaje + tag).hexdigest()
