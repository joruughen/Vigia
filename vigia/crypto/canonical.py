"""Formato canónico del mensaje que se autentica con HMAC.

    VIGIA-v1|<sensor_id>|<seq>|<timestamp_ms>|<valor>

Por qué: el HMAC autentica bytes, no objetos. Si emisor y receptor no serializan
exactamente igual, o si la serialización es ambigua (p. ej. un sensor_id con "|"),
dos mediciones distintas podrían producir el mismo mensaje. Por eso se validan
todos los campos con reglas estrictas ANTES de calcular o verificar el tag.
"""
import re

PREFIJO = "VIGIA-v1"  # separación de dominio + versión del formato
SEQ_MAX = 2**63 - 1

_RE_SENSOR = re.compile(r"[A-Za-z0-9_-]{1,64}")
_RE_VALOR = re.compile(r"-?(0|[1-9][0-9]{0,11})(\.[0-9]{1,6})?")


class FormatoInvalido(ValueError):
    """La medición no cumple el formato canónico (la app responde HTTP 422)."""


def _es_entero(x) -> bool:
    # bool es subclase de int: True no debe aceptarse como seq=1.
    return isinstance(x, int) and not isinstance(x, bool)


def validar_sensor_id(sensor_id: str) -> None:
    """Valida el id de sensor (sin '|', así los campos nunca son ambiguos)."""
    if not isinstance(sensor_id, str) or not _RE_SENSOR.fullmatch(sensor_id):
        raise FormatoInvalido("sensor_id inválido")


def mensaje_canonico(sensor_id: str, seq: int, timestamp_ms: int, valor: str) -> bytes:
    """Valida los campos y devuelve el mensaje canónico en UTF-8.

    Se usa fullmatch (no '$', que acepta un '\\n' final). El valor se autentica
    como el string recibido: reformatear un float cambiaría los bytes y rompería
    la verificación (o permitiría representaciones alternativas del mismo dato).
    """
    validar_sensor_id(sensor_id)
    if not _es_entero(seq) or not (1 <= seq <= SEQ_MAX):
        raise FormatoInvalido("seq inválido")
    if not _es_entero(timestamp_ms) or timestamp_ms < 0:
        raise FormatoInvalido("timestamp_ms inválido")
    if not isinstance(valor, str) or not _RE_VALOR.fullmatch(valor):
        raise FormatoInvalido("valor inválido")
    return f"{PREFIJO}|{sensor_id}|{seq}|{timestamp_ms}|{valor}".encode("utf-8")
