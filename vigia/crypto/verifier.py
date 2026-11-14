"""Verificación de mediciones en 5 pasos y auditoría del historial.

Orden fijo (se detiene en el primer fallo):
  1 llave existe            -> FALSA
  2 HMAC válido             -> MANIPULADA
  3 seq == última + 1       -> REPLAY O HUECO
  4 timestamp en ventana    -> FUERA DE VENTANA
  5 cadena consistente      -> CADENA ROTA
Por qué este orden: primero se autentica (sin HMAC válido, ningún otro campo es
confiable para decidir), luego la frescura (seq y tiempo) y al final la integridad
del almacenamiento. Funciones puras: sin I/O ni BD.
"""
import hmac
from dataclasses import dataclass
from enum import Enum

from .canonical import FormatoInvalido, mensaje_canonico
from .chain import GENESIS, siguiente_hash
from .mac import verificar_tag


class Estado(str, Enum):
    VERIFICADA = "VERIFICADA"
    FALSA = "FALSA"
    MANIPULADA = "MANIPULADA"
    REPLAY_O_HUECO = "REPLAY O HUECO"
    FUERA_DE_VENTANA = "FUERA DE VENTANA"
    CADENA_ROTA = "CADENA ROTA"


@dataclass(frozen=True)
class Medicion:
    sensor_id: str
    seq: int
    timestamp_ms: int
    valor: str
    tag: str


@dataclass(frozen=True)
class RegistroGuardado:
    sensor_id: str
    seq: int
    timestamp_ms: int
    valor: str
    tag: str
    hash_prev: str
    hash: str


@dataclass(frozen=True)
class Resultado:
    estado: Estado
    detalle: str
    hash_nuevo: str | None


@dataclass(frozen=True)
class ResultadoRegistro:
    seq: int
    estado: Estado
    detalle: str


@dataclass(frozen=True)
class ReporteHistorial:
    sensor_id: str
    integro: bool
    total: int
    registros: list[ResultadoRegistro]


def _hash_iguales(a: str, b: str) -> bool:
    # Los hashes no son secretos, pero compare_digest no cuesta nada y evita dudas.
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a.encode("ascii", "replace"), b.encode("ascii", "replace"))


def _recalcular_hash(r: RegistroGuardado) -> str | None:
    """Recalcula h_i de un registro guardado; None si sus campos están corruptos."""
    try:
        canon = mensaje_canonico(r.sensor_id, r.seq, r.timestamp_ms, r.valor)
        return siguiente_hash(r.hash_prev, canon, r.tag)
    except (FormatoInvalido, ValueError):
        return None


def verificar_medicion(m: Medicion, llave: bytes | None, ultimo: RegistroGuardado | None,
                       ahora_ms: int, ventana_ms: int) -> Resultado:
    """Aplica los 5 pasos. FormatoInvalido de mensaje_canonico se propaga (HTTP 422)."""
    # 1. Sensor registrado y activo.
    if llave is None:
        return Resultado(Estado.FALSA, "sensor no registrado o revocado", None)

    # 2. Autenticidad e integridad del mensaje (tiempo constante).
    canon = mensaje_canonico(m.sensor_id, m.seq, m.timestamp_ms, m.valor)
    if not verificar_tag(llave, canon, m.tag):
        return Resultado(Estado.MANIPULADA, "HMAC inválido", None)

    # 3. Secuencia estrictamente consecutiva.
    esperado = 1 if ultimo is None else ultimo.seq + 1
    if m.seq < esperado:
        return Resultado(Estado.REPLAY_O_HUECO,
                         f"replay: seq {m.seq} <= última {esperado - 1}", None)
    if m.seq > esperado:
        return Resultado(Estado.REPLAY_O_HUECO,
                         f"hueco: esperaba {esperado}, llegó {m.seq}", None)

    # 4. Frescura temporal.
    desfase = abs(ahora_ms - m.timestamp_ms)
    if desfase > ventana_ms:
        return Resultado(Estado.FUERA_DE_VENTANA,
                         f"desfase {desfase} ms > ventana {ventana_ms} ms", None)

    # 5. Consistencia del último eslabón guardado.
    if ultimo is None:
        hash_base = GENESIS
    else:
        recalculado = _recalcular_hash(ultimo)
        if recalculado is None or not _hash_iguales(recalculado, ultimo.hash):
            return Resultado(Estado.CADENA_ROTA,
                             f"hash del registro guardado seq {ultimo.seq} no coincide", None)
        hash_base = ultimo.hash

    return Resultado(Estado.VERIFICADA, "ok", siguiente_hash(hash_base, canon, m.tag))


def verificar_historial(sensor_id: str, registros: list[RegistroGuardado],
                        llave: bytes) -> ReporteHistorial:
    """Audita la cadena completa de un sensor (registros ordenados por seq).

    Cada registro se evalúa contra el anterior TAL COMO ESTÁ GUARDADO, de modo que
    el daño se localiza en el punto exacto (un borrado marca solo el registro
    siguiente; una edición de valor marca solo el editado).
    """
    resultados: list[ResultadoRegistro] = []
    hash_anterior = GENESIS
    seq_esperado = 1

    for r in registros:
        estado, detalle = Estado.VERIFICADA, "ok"

        try:
            canon = mensaje_canonico(r.sensor_id, r.seq, r.timestamp_ms, r.valor)
        except FormatoInvalido as e:
            canon = None
            estado, detalle = Estado.MANIPULADA, f"formato inválido en BD: {e}"

        if canon is not None:
            if r.sensor_id != sensor_id:
                estado, detalle = Estado.MANIPULADA, f"registro pertenece a {r.sensor_id}"
            elif not verificar_tag(llave, canon, r.tag):
                estado, detalle = Estado.MANIPULADA, "HMAC inválido (contenido alterado)"
            else:
                motivos = []
                if r.seq != seq_esperado:
                    motivos.append(f"hueco de secuencia: esperaba {seq_esperado}, hay {r.seq}")
                if not _hash_iguales(r.hash_prev, hash_anterior):
                    motivos.append("enlace roto: hash_prev no coincide con el hash del anterior")
                recalculado = _recalcular_hash(r)
                if recalculado is None or not _hash_iguales(recalculado, r.hash):
                    motivos.append("hash recalculado no coincide con el guardado")
                if motivos:
                    estado, detalle = Estado.CADENA_ROTA, "; ".join(motivos)

        resultados.append(ResultadoRegistro(r.seq, estado, detalle))
        hash_anterior = r.hash
        seq_esperado = r.seq + 1 if isinstance(r.seq, int) else seq_esperado + 1

    integro = all(x.estado is Estado.VERIFICADA for x in resultados)
    return ReporteHistorial(sensor_id, integro, len(resultados), resultados)
