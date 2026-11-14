"""Tests de las correcciones de fase 3: N1 (huella del tag en eventos) y N2 (cotas superiores Argon2)."""
import re
import secrets
import time

import pytest

from tests.conftest import VENTANA_MS, ahora_ms
from vigia.config import load_config
from vigia.crypto import keystore
from vigia.crypto.canonical import mensaje_canonico
from vigia.crypto.chain import siguiente_hash
from vigia.crypto.mac import calcular_tag, huella_tag
from vigia.server.app import create_app
from vigia.server.db import ArranqueError

RE_HUELLA = re.compile(r"sha256:[0-9a-f]{64}")


# ---- N1: huella_tag (unidad) --------------------------------------------------------
def test_n1_huella_formato_y_determinismo():
    tag = secrets.token_hex(32)
    h = huella_tag(tag)
    assert RE_HUELLA.fullmatch(h)
    assert len(h) == len("sha256:") + 64
    assert huella_tag(tag) == h


def test_n1_huella_distinta_para_tags_distintos():
    huellas = {huella_tag(secrets.token_hex(32)) for _ in range(50)}
    assert len(huellas) == 50
    assert huella_tag("a" * 64) != huella_tag("b" * 64)


def test_n1_huella_no_contiene_el_tag():
    for _ in range(20):
        tag = secrets.token_hex(32)
        h = huella_tag(tag)
        assert tag not in h
        assert h != tag
        assert h.removeprefix("sha256:") != tag


@pytest.mark.parametrize("entrada", [
    "", "ñandú-€", "\ud800", "\udfff" * 3, "x" * 100_000, "\x00", "ab" * 32 + "\n",
    None, 123, b"bytes", ["lista"], 1.5,
], ids=repr)
def test_n1_huella_no_lanza_con_entradas_raras(entrada):
    assert RE_HUELLA.fullmatch(huella_tag(entrada))


# ---- N1: integración (eventos) ------------------------------------------------------
def _todas_las_filas_eventos(sql):
    return sql("SELECT sensor_id, seq, timestamp_ms, valor, tag, estado, detalle, recibido_ms "
               "FROM eventos")


def _aparece(tag, filas) -> bool:
    return any(tag in str(c) for fila in filas for c in fila)


def _provocar(sensor, estado):
    """Envía un mensaje con tag HMAC AUTÉNTICO que el servidor rechaza con `estado`."""
    if estado == "FUERA DE VENTANA":
        sensor.enviar_ok(1)
        p = sensor.payload(ts=ahora_ms() - 10 * VENTANA_MS)
    elif estado == "REPLAY":
        sensor.enviar_ok(2)
        p = sensor.payload(seq=1)  # reenvío de una seq ya aceptada
    elif estado == "HUECO":
        sensor.enviar_ok(1)
        p = sensor.payload(seq=sensor.seq + 5)
    elif estado == "MANIPULADA":
        sensor.enviar_ok(1)
        p = sensor.payload()
        p["valor"] = "99.999"  # el tag es auténtico para otro valor
    else:
        raise AssertionError(estado)
    return p, sensor.post(p)


@pytest.mark.parametrize("caso, estado_esperado", [
    ("FUERA DE VENTANA", "FUERA DE VENTANA"),
    ("REPLAY", "REPLAY O HUECO"),
    ("HUECO", "REPLAY O HUECO"),
    ("MANIPULADA", "MANIPULADA"),
])
def test_n1_rechazadas_guardan_huella_y_no_el_tag(sensor, cliente, sql, caso, estado_esperado):
    p, r = _provocar(sensor, caso)
    assert r.status_code == 200 and r.json()["estado"] == estado_esperado, r.text
    tag = p["tag"]
    assert re.fullmatch(r"[0-9a-f]{64}", tag)

    # BD: la última fila de eventos es la rechazada y trae la huella.
    (tag_bd, estado_bd), = sql("SELECT tag, estado FROM eventos ORDER BY id DESC LIMIT 1")
    assert estado_bd == estado_esperado
    assert tag_bd == huella_tag(tag)
    # API.
    ev = cliente.get(f"/api/sensores/{sensor.id}/eventos").json()
    rechazado = [e for e in ev if e["estado"] == estado_esperado][0]
    assert rechazado["tag"] == huella_tag(tag)
    # El tag real no aparece en NINGUNA fila de eventos (ningún campo) ni en la respuesta
    # de ninguno de los dos endpoints de eventos, salvo el de las VERIFICADAS (que está en mediciones).
    verificados = {e["tag"] for e in ev if e["estado"] == "VERIFICADA"}
    assert tag not in verificados
    assert not _aparece(tag, _todas_las_filas_eventos(sql))
    assert tag not in cliente.get(f"/api/sensores/{sensor.id}/eventos").text
    assert tag not in cliente.get("/api/eventos").text


def test_n1_replay_correlaciona_por_huella(sensor, cliente):
    """La huella permite correlacionar reintentos idénticos sin conservar el tag."""
    sensor.enviar_ok(1)
    p = sensor.payload(seq=1)
    assert sensor.post(p).json()["estado"] == "REPLAY O HUECO"
    assert sensor.post(p).json()["estado"] == "REPLAY O HUECO"
    ev = [e for e in cliente.get(f"/api/sensores/{sensor.id}/eventos").json()
          if e["estado"] == "REPLAY O HUECO"]
    assert len(ev) == 2 and ev[0]["tag"] == ev[1]["tag"] == huella_tag(p["tag"])


def test_n1_verificada_guarda_tag_completo(sensor, cliente, sql):
    p = sensor.payload()
    r = sensor.post(p)
    assert r.json()["estado"] == "VERIFICADA"
    (tag_ev,), = sql("SELECT tag FROM eventos WHERE estado = 'VERIFICADA'")
    (tag_med,), = sql("SELECT tag FROM mediciones")
    assert tag_ev == tag_med == p["tag"]
    ev = cliente.get(f"/api/sensores/{sensor.id}/eventos").json()
    assert ev[0]["estado"] == "VERIFICADA" and ev[0]["tag"] == p["tag"]


def test_n1_falsa_guarda_huella(cliente, sql):
    """Sensor no registrado: el tag tampoco se guarda tal cual."""
    ts = ahora_ms()
    tag = calcular_tag(secrets.token_bytes(32), mensaje_canonico("fantasma-1", 1, ts, "1.0"))
    r = cliente.post("/api/mediciones", json={"sensor_id": "fantasma-1", "seq": 1,
                                              "timestamp_ms": ts, "valor": "1.0", "tag": tag})
    assert r.json()["estado"] == "FALSA"
    assert sql("SELECT tag FROM eventos WHERE estado = 'FALSA'") == [(huella_tag(tag),)]
    assert tag not in cliente.get("/api/eventos").text


# ---- N1: ataque completo (promover un mensaje rechazado copiando datos de eventos) --------
def _preparar_rechazo_fuera_de_ventana(sensor, cliente, sql):
    """seq 1 aceptada; seq 2 auténtica pero vieja -> FUERA DE VENTANA. Devuelve datos útiles."""
    sensor.enviar_ok(1)
    (h1,), = sql("SELECT hash FROM mediciones WHERE sensor_id = ? AND seq = 1", (sensor.id,))
    p = sensor.payload(seq=2, ts=ahora_ms() - 10 * VENTANA_MS)
    assert sensor.post(p).json()["estado"] == "FUERA DE VENTANA"
    ev, = [e for e in cliente.get(f"/api/sensores/{sensor.id}/eventos").json()
           if e["estado"] == "FUERA DE VENTANA"]
    return p, ev, h1


def _promover(sql, sensor_id, ev, tag, hash_prev, hash_):
    sql("INSERT INTO mediciones (sensor_id, seq, timestamp_ms, valor, tag, hash_prev, hash)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (sensor_id, ev["seq"], ev["timestamp_ms"], ev["valor"], tag, hash_prev, hash_))


def test_n1_control_con_el_tag_real_la_promocion_pasaria(sensor, cliente, sql):
    """Control: demuestra que el ataque era viable SI el tag real estuviera en eventos
    (por eso N1 importa). Aquí se inyecta el tag real a mano, solo para el control."""
    p, ev, h1 = _preparar_rechazo_fuera_de_ventana(sensor, cliente, sql)
    canon = mensaje_canonico(sensor.id, ev["seq"], ev["timestamp_ms"], ev["valor"])
    _promover(sql, sensor.id, ev, p["tag"], h1, siguiente_hash(h1, canon, p["tag"]))
    sensor.seq = 2
    assert sensor.post(sensor.payload()).json()["estado"] == "VERIFICADA"
    rep = cliente.post(f"/api/sensores/{sensor.id}/verificar-historial").json()
    assert rep["integro"] is True  # la promoción habría pasado desapercibida


@pytest.mark.parametrize("variante", ["huella_completa", "hex_de_la_huella_con_hash_recalculado"])
def test_n1_ataque_promover_desde_eventos_ya_no_funciona(sensor, cliente, sql, variante):
    p, ev, h1 = _preparar_rechazo_fuera_de_ventana(sensor, cliente, sql)
    assert ev["tag"] == huella_tag(p["tag"]) and ev["tag"] != p["tag"]
    assert p["tag"] not in str(ev) and p["tag"] not in cliente.get("/api/eventos").text

    canon = mensaje_canonico(sensor.id, ev["seq"], ev["timestamp_ms"], ev["valor"])
    if variante == "huella_completa":
        tag_copiado = ev["tag"]
        hash_ = secrets.token_hex(32)  # siguiente_hash no admite una huella como tag
    else:
        tag_copiado = ev["tag"].removeprefix("sha256:")
        hash_ = siguiente_hash(h1, canon, tag_copiado)  # hash coherente: solo el HMAC delata
    _promover(sql, sensor.id, ev, tag_copiado, h1, hash_)

    # La siguiente medición legítima (seq 3) ya no se encadena sobre la fila falsa.
    r = sensor.post(sensor.payload(seq=3))
    assert r.status_code == 200, r.text
    assert r.json()["estado"] == "CADENA ROTA"
    assert sql("SELECT COUNT(*) FROM mediciones WHERE sensor_id = ? AND seq = 3",
               (sensor.id,)) == [(0,)]

    rep = cliente.post(f"/api/sensores/{sensor.id}/verificar-historial").json()
    assert rep["integro"] is False
    por_seq = {x["seq"]: x["estado"] for x in rep["registros"]}
    assert por_seq[1] == "VERIFICADA" and por_seq[2] == "MANIPULADA"


# ---- N2: cotas superiores de Argon2 -------------------------------------------------
def _params(**cambios):
    p = dict(keystore.PARAMS_ARGON2)
    p.update(cambios)
    return p


def test_n2_constantes_maximas():
    assert keystore.MAX_ARGON2 == {"time_cost": 10, "memory_cost": 1048576, "parallelism": 64}


def test_n2_validar_acepta_exactamente_los_maximos():
    ok = keystore.validar_params_argon2(_params(time_cost=10, memory_cost=1048576, parallelism=64))
    assert (ok["time_cost"], ok["memory_cost"], ok["parallelism"], ok["hash_len"]) == \
        (10, 1048576, 64, 32)


@pytest.mark.parametrize("cambio", [
    {"time_cost": 11}, {"memory_cost": 1048577}, {"parallelism": 65},
    {"memory_cost": 2**40}, {"time_cost": 2**31}, {"parallelism": 2**32},
], ids=str)
def test_n2_validar_rechaza_por_encima_del_maximo(cambio):
    with pytest.raises(ValueError, match="máximo"):
        keystore.validar_params_argon2(_params(**cambio))
    with pytest.raises(ValueError):
        keystore.derivar_kek("x" * 20, b"s" * 16, _params(**cambio))


@pytest.mark.parametrize("cambio", [
    {"memory_cost": 2**40},
    {"memory_cost": 1048577},
    {"time_cost": 11},
    {"parallelism": 65},
    {"time_cost": 2**40, "memory_cost": 2**40, "parallelism": 2**20},
], ids=str)
def test_n2_kdf_params_sobre_el_maximo_en_bd_impiden_arrancar_sin_colgarse(
        entorno, sql, monkeypatch, cambio):
    import json
    sql("UPDATE meta SET valor = ? WHERE clave = 'kdf_params'",
        (json.dumps(_params(**cambio)).encode(),))

    # Si se llegara a Argon2 con estos valores, el test falla (AssertionError no es ArranqueError).
    def _no_debe_llamarse(*a, **k):
        raise AssertionError("se invocó Argon2 con parámetros fuera de cota")
    monkeypatch.setattr(keystore, "hash_secret_raw", _no_debe_llamarse)

    t0 = time.monotonic()
    with pytest.raises(ArranqueError) as ei:
        create_app(load_config())
    assert time.monotonic() - t0 < 5
    msg = str(ei.value).lower()
    assert "contraseña incorrecta" not in msg and "password incorrecta" not in msg
    assert "incorrecta" not in msg
    assert "kdf_params" in msg
