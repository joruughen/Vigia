"""Un test por estado de verificación, vía POST /api/mediciones."""
from tests.conftest import VENTANA_MS, ahora_ms
from vigia.crypto.mac import generar_llave_sensor


def estado(r):
    assert r.status_code == 200, r.text
    return r.json()["estado"]


def ultimo_evento(cliente, sid):
    return cliente.get(f"/api/sensores/{sid}/eventos", params={"limite": 1}).json()[0]


def filas_mediciones(sql, sid):
    return sql("SELECT seq FROM mediciones WHERE sensor_id = ? ORDER BY seq", (sid,))


def test_verificada(sensor, cliente, sql):
    r = sensor.enviar()
    assert estado(r) == "VERIFICADA" and r.json()["detalle"] == "ok"
    assert filas_mediciones(sql, sensor.id) == [(1,)]
    assert ultimo_evento(cliente, sensor.id)["estado"] == "VERIFICADA"


def test_verificada_encadena_varias(sensor, sql):
    sensor.enviar_ok(5)
    assert filas_mediciones(sql, sensor.id) == [(i,) for i in range(1, 6)]


def test_falsa_sensor_inexistente(sensor, cliente, sql):
    p = sensor.payload(sensor_id="sensor-fantasma", llave=generar_llave_sensor())
    assert estado(sensor.post(p)) == "FALSA"
    assert sql("SELECT COUNT(*) FROM mediciones") == [(0,)]
    assert sql("SELECT estado FROM eventos WHERE sensor_id='sensor-fantasma'") == [("FALSA",)]


def test_falsa_sensor_inexistente_aunque_tag_sea_valido_para_otra_llave(sensor):
    # Orden de los pasos: el paso 1 (¿registrado?) va antes que el HMAC.
    p = sensor.payload(sensor_id="no-existe")
    assert estado(sensor.post(p)) == "FALSA"


def test_falsa_sensor_revocado(sensor2, app, cliente, sql):
    sensor2.enviar_ok(2)
    assert app.state.db.revocar_sensor("sensor-02")
    r = sensor2.enviar()                      # llave correcta, seq correcta, pero revocado
    assert estado(r) == "FALSA"
    assert "revocado" in r.json()["detalle"] or "registrado" in r.json()["detalle"]
    assert filas_mediciones(sql, "sensor-02") == [(1,), (2,)]  # no se guarda


def test_manipulada_valor_cambiado_en_transito(sensor, sql):
    p = sensor.payload()
    p["valor"] = "99.999"                     # tag calculado para otro valor
    assert estado(sensor.post(p)) == "MANIPULADA"
    assert sql("SELECT COUNT(*) FROM mediciones") == [(0,)]


def test_manipulada_tag_basura_no_rompe(sensor):
    for tag in ["", "zz", "00" * 32, "AB" * 32, "0" * 63, "0" * 65]:
        p = sensor.payload()
        p["tag"] = tag
        assert estado(sensor.post(p)) == "MANIPULADA", tag


def test_manipulada_campos_alterados_seq_y_timestamp(sensor):
    sensor.enviar_ok()
    p = sensor.payload()
    p["timestamp_ms"] += 1                    # cambia el timestamp, tag viejo
    assert estado(sensor.post(p)) == "MANIPULADA"


def test_replay_detalle_interno(sensor, cliente):
    sensor.enviar_ok(3)
    p = sensor.payload(seq=2)                 # seq ya usada (firmada correctamente)
    r = sensor.post(p)
    assert estado(r) == "REPLAY O HUECO"
    ev = ultimo_evento(cliente, sensor.id)
    assert ev["estado"] == "REPLAY O HUECO" and ev["detalle"].startswith("replay")


def test_hueco_detalle_interno(sensor, cliente, sql):
    sensor.enviar_ok(2)
    r = sensor.post(sensor.payload(seq=5))    # esperaba 3
    assert estado(r) == "REPLAY O HUECO"
    ev = ultimo_evento(cliente, sensor.id)
    assert ev["detalle"].startswith("hueco") and "3" in ev["detalle"] and "5" in ev["detalle"]
    assert filas_mediciones(sql, sensor.id) == [(1,), (2,)]


def test_primera_medicion_con_seq_distinta_de_1_es_hueco(sensor, cliente):
    assert estado(sensor.post(sensor.payload(seq=7))) == "REPLAY O HUECO"
    assert ultimo_evento(cliente, sensor.id)["detalle"].startswith("hueco")


def test_fuera_de_ventana_pasado(sensor, sql):
    r = sensor.enviar(ts=ahora_ms() - VENTANA_MS - 5_000)
    assert estado(r) == "FUERA DE VENTANA"
    assert sql("SELECT COUNT(*) FROM mediciones") == [(0,)]


def test_fuera_de_ventana_futuro(sensor, sql):
    r = sensor.enviar(ts=ahora_ms() + VENTANA_MS + 5_000)
    assert estado(r) == "FUERA DE VENTANA"
    assert sql("SELECT COUNT(*) FROM mediciones") == [(0,)]


def test_dentro_de_ventana_pasa(sensor):
    assert estado(sensor.enviar(ts=ahora_ms() - VENTANA_MS // 2)) == "VERIFICADA"
    assert estado(sensor.enviar(ts=ahora_ms() + VENTANA_MS // 2)) == "VERIFICADA"


def test_fuera_de_ventana_no_consume_la_seq(sensor):
    assert estado(sensor.enviar(ts=ahora_ms() - 10 * VENTANA_MS)) == "FUERA DE VENTANA"
    assert estado(sensor.enviar()) == "VERIFICADA"   # misma seq 1, ahora con timestamp fresco


def test_cadena_rota_hash_del_ultimo_alterado(sensor, sql, cliente):
    sensor.enviar_ok(2)
    sql("UPDATE mediciones SET hash = ? WHERE sensor_id = ? AND seq = 2", ("ab" * 32, sensor.id))
    r = sensor.enviar()
    assert estado(r) == "CADENA ROTA"
    assert ultimo_evento(cliente, sensor.id)["estado"] == "CADENA ROTA"
    assert sql("SELECT COUNT(*) FROM mediciones WHERE sensor_id = ?", (sensor.id,)) == [(2,)]


def test_sensores_son_independientes(sensor, sensor2):
    sensor.enviar_ok(3)
    sensor2.enviar_ok(1)                      # su seq 1 no choca con la de sensor-01
    assert estado(sensor2.enviar()) == "VERIFICADA"


def test_ingesta_registra_evento_de_cada_intento(sensor, cliente):
    sensor.enviar_ok()
    sensor.post(sensor.payload(seq=1))        # replay
    sensor.post(sensor.payload(seq=9))        # hueco
    evs = cliente.get(f"/api/sensores/{sensor.id}/eventos").json()
    assert [e["estado"] for e in evs] == ["REPLAY O HUECO", "REPLAY O HUECO", "VERIFICADA"]
