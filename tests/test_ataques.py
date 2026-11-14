"""Un test por ataque del diseño (docs/diseno-entrega1.md) y propiedades de no filtración."""
import re

import pytest

from tests.conftest import PASSWORD, VENTANA_MS, ahora_ms
from vigia.config import load_config
from vigia.crypto import keystore
from vigia.crypto.mac import generar_llave_sensor
from vigia.sensor import construir_medicion
from vigia.server.app import create_app
from vigia.server.db import ArranqueError, Database


def estado(r):
    assert r.status_code == 200, r.text
    return r.json()["estado"]


def verificar_historial(cliente, sid):
    r = cliente.post(f"/api/sensores/{sid}/verificar-historial")
    assert r.status_code == 200, r.text
    return r.json()


# 1 --------------------------------------------------------------------------------
def test_ataque1_alterar_valor_en_bd(sensor, cliente, sql):
    sensor.enviar_ok(4)
    assert verificar_historial(cliente, sensor.id)["integro"] is True
    sql("UPDATE mediciones SET valor = '99.000' WHERE sensor_id = ? AND seq = 2", (sensor.id,))
    rep = verificar_historial(cliente, sensor.id)
    assert rep["integro"] is False and rep["total"] == 4
    por_seq = {r["seq"]: r["estado"] for r in rep["registros"]}
    assert por_seq[2] == "MANIPULADA"
    assert por_seq[1] == "VERIFICADA"


# 2 --------------------------------------------------------------------------------
def test_ataque2_falsificar_con_id_valido_sin_llave(sensor, sql):
    p = construir_medicion(sensor.id, generar_llave_sensor(), 1, ahora_ms(), "25.000")
    assert estado(sensor.post(p)) == "MANIPULADA"
    assert sql("SELECT COUNT(*) FROM mediciones") == [(0,)]


def test_ataque2_falsificar_con_id_inexistente(sensor, sql):
    p = construir_medicion("sensor-99", generar_llave_sensor(), 1, ahora_ms(), "25.000")
    assert estado(sensor.post(p)) == "FALSA"
    assert sql("SELECT COUNT(*) FROM mediciones") == [(0,)]


# 3 --------------------------------------------------------------------------------
def test_ataque3_replay_de_mensaje_aceptado(sensor, cliente, sql):
    p = sensor.payload()
    assert estado(sensor.post(p)) == "VERIFICADA"
    r = sensor.post(p)                        # mismo mensaje exacto, mismo tag, bytes idénticos
    assert estado(r) == "REPLAY O HUECO"
    ev = cliente.get(f"/api/sensores/{sensor.id}/eventos", params={"limite": 1}).json()[0]
    assert ev["detalle"].startswith("replay")
    assert sql("SELECT COUNT(*) FROM mediciones") == [(1,)]       # no se duplica


# 4 --------------------------------------------------------------------------------
def test_ataque4_borrar_medicion_intermedia_en_bd(sensor, cliente, sql):
    sensor.enviar_ok(5)
    sql("DELETE FROM mediciones WHERE sensor_id = ? AND seq = 3", (sensor.id,))
    rep = verificar_historial(cliente, sensor.id)
    assert rep["integro"] is False
    por_seq = {r["seq"]: r for r in rep["registros"]}
    assert 3 not in por_seq
    assert por_seq[4]["estado"] == "CADENA ROTA"
    assert "hueco" in por_seq[4]["detalle"] and "enlace roto" in por_seq[4]["detalle"]


def test_ataque4_mensaje_perdido_en_transito_es_hueco(sensor, cliente):
    sensor.enviar_ok(2)
    perdido = sensor.payload(seq=3)           # nunca llega al servidor
    del perdido
    r = sensor.enviar(seq=4)
    assert estado(r) == "REPLAY O HUECO"
    ev = cliente.get(f"/api/sensores/{sensor.id}/eventos", params={"limite": 1}).json()[0]
    assert ev["detalle"].startswith("hueco")


# 5 --------------------------------------------------------------------------------
@pytest.mark.parametrize("delta", [-VENTANA_MS - 10_000, VENTANA_MS + 10_000, -86_400_000])
def test_ataque5_timestamp_fuera_de_ventana(sensor, delta):
    assert estado(sensor.enviar(ts=ahora_ms() + delta)) == "FUERA DE VENTANA"


# 6 --------------------------------------------------------------------------------
def test_ataque6_romper_cadena_alterando_hash(sensor, cliente, sql):
    sensor.enviar_ok(4)
    sql("UPDATE mediciones SET hash = ? WHERE sensor_id = ? AND seq = 2", ("cd" * 32, sensor.id))
    rep = verificar_historial(cliente, sensor.id)
    assert rep["integro"] is False
    assert {r["seq"]: r["estado"] for r in rep["registros"]}[2] == "CADENA ROTA"
    # Al ingresar solo se revisa el ÚLTIMO eslabón (seq 4, intacto): la ingesta sigue; el daño
    # del eslabón 2 lo descubre verificar-historial (ya comprobado arriba).
    assert estado(sensor.enviar()) == "VERIFICADA"


def test_ataque6_romper_cadena_alterando_hash_prev(sensor, cliente, sql):
    sensor.enviar_ok(4)
    sql("UPDATE mediciones SET hash_prev = ? WHERE sensor_id = ? AND seq = 3", ("ef" * 32, sensor.id))
    rep = verificar_historial(cliente, sensor.id)
    assert rep["integro"] is False
    r3 = {r["seq"]: r for r in rep["registros"]}[3]
    assert r3["estado"] == "CADENA ROTA"


def test_ataque6_reordenar_tags_entre_registros(sensor, cliente, sql):
    # Intercambiar los tags de dos mediciones: el HMAC ya no corresponde al contenido.
    sensor.enviar_ok(3)
    (t1,), (t2,) = (sql("SELECT tag FROM mediciones WHERE seq = ? AND sensor_id = ?", (s, sensor.id))[0]
                    for s in (1, 2))
    sql("UPDATE mediciones SET tag = ? WHERE seq = 1 AND sensor_id = ?", (t2, sensor.id))
    sql("UPDATE mediciones SET tag = ? WHERE seq = 2 AND sensor_id = ?", (t1, sensor.id))
    rep = verificar_historial(cliente, sensor.id)
    assert rep["integro"] is False
    assert {r["seq"]: r["estado"] for r in rep["registros"]}[1] == "MANIPULADA"


# 7 --------------------------------------------------------------------------------
def test_ataque7_contrasena_incorrecta_no_arranca(entorno, monkeypatch):
    monkeypatch.setenv("VIGIA_MASTER_PASSWORD", PASSWORD + "-mala")
    with pytest.raises(ArranqueError, match="VIGIA_MASTER_PASSWORD incorrecta"):
        create_app(load_config())


# BUG DE PRODUCCIÓN (test fallando a propósito): si el archivo de BD no existe o no tiene el
# esquema, Database.meta_get lanza sqlite3.OperationalError ("no such table: meta") en vez de
# ArranqueError con el mensaje "Ejecuta: python -m vigia.cli init". Ver vigia/server/db.py.
def test_ataque7_bd_sin_inicializar_no_arranca(entorno, monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIA_DB_PATH", str(tmp_path / "otra.db"))
    with pytest.raises(ArranqueError, match="no está inicializada"):
        create_app(load_config())


def test_ataque7_llaves_en_bd_ilegibles_sin_contrasena(entorno, sql):
    for sid in ("sensor-01", "sensor-02"):
        llave = bytes.fromhex((entorno.sensores_dir / f"{sid}.key").read_text().strip())
        (nonce, blob), = sql("SELECT nonce, llave_cifrada FROM sensores WHERE id = ?", (sid,))
        assert llave not in blob and llave.hex().encode() not in blob
        # El archivo completo de la BD tampoco contiene la llave (ni cruda ni en hex).
        crudo = entorno.db_path.read_bytes()
        assert llave not in crudo and llave.hex().encode() not in crudo
        # Con la KEK de otra contraseña no se descifra.
        db = Database(entorno.db_path)
        salt = db.meta_get("kdf_salt")
        kek_mala = keystore.derivar_kek(PASSWORD + "-mala", salt)
        with pytest.raises(keystore.ContrasenaIncorrecta):
            keystore.descifrar_llave_sensor(kek_mala, sid, bytes(nonce), bytes(blob))
        # Con la contraseña correcta sí es la llave del archivo .key (control positivo).
        kek_ok = db.derivar_y_comprobar_kek(PASSWORD)
        assert keystore.descifrar_llave_sensor(kek_ok, sid, bytes(nonce), bytes(blob)) == llave


def test_ataque7_blob_de_un_sensor_pegado_en_otro_no_sirve(entorno, sql):
    (n1, b1), = sql("SELECT nonce, llave_cifrada FROM sensores WHERE id = 'sensor-01'")
    db = Database(entorno.db_path)
    kek = db.derivar_y_comprobar_kek(PASSWORD)
    with pytest.raises(keystore.ContrasenaIncorrecta):
        keystore.descifrar_llave_sensor(kek, "sensor-02", bytes(n1), bytes(b1))


# 8 --------------------------------------------------------------------------------
@pytest.mark.parametrize("cambios", [
    {"sensor_id": "a|b"},
    {"sensor_id": ""},
    {"sensor_id": "x" * 65},
    {"seq": 0},
    {"seq": -3},
    {"seq": "1"},
    {"seq": 1.5},
    {"seq": 2**63},
    {"timestamp_ms": -1},
    {"timestamp_ms": "123"},
    {"valor": "1e3"},
    {"valor": "01"},
    {"valor": "1.1234567"},
    {"valor": "1\n"},
    {"valor": 23.475},          # float JSON
    {"valor": ""},
    {"tag": 123},
    {"extra": "campo-no-permitido"},
])
def test_ataque8_formato_invalido_422_y_no_se_guarda(sensor, sql, cambios):
    p = sensor.payload()
    p.update(cambios)
    r = sensor.post(p)
    assert r.status_code == 422, r.text
    assert sql("SELECT COUNT(*) FROM mediciones") == [(0,)]
    assert sql("SELECT COUNT(*) FROM eventos") == [(0,)]


@pytest.mark.parametrize("campo", ["sensor_id", "seq", "timestamp_ms", "valor", "tag"])
def test_ataque8_campo_faltante_422(sensor, campo):
    p = sensor.payload()
    del p[campo]
    assert sensor.post(p).status_code == 422


def test_ataque8_cuerpo_no_json_422(cliente):
    r = cliente.post("/api/mediciones", content=b"no es json",
                     headers={"content-type": "application/json"})
    assert r.status_code == 422


# No filtración --------------------------------------------------------------------
def test_ninguna_respuesta_contiene_la_llave_en_hex(sensor, sensor2, cliente, app):
    sensor.enviar_ok(3)
    sensor2.enviar_ok(2)
    # Provocamos también respuestas de error y de rechazo.
    sensor.post(sensor.payload(seq=1))                       # replay
    sensor.post({**sensor.payload(), "valor": "9.9"})        # manipulada
    sensor.post({**sensor.payload(), "seq": 0})              # 422
    llaves = [s.llave.hex() for s in (sensor, sensor2)]
    kek_hex = app.state.kek.hex()
    rutas = [("get", "/api/config"), ("get", "/api/sensores"), ("get", "/api/eventos"),
             ("get", f"/api/sensores/{sensor.id}/eventos"), ("get", f"/api/sensores/{sensor.id}/serie"),
             ("post", f"/api/sensores/{sensor.id}/verificar-historial"),
             ("post", f"/api/sensores/{sensor2.id}/verificar-historial"),
             ("get", "/api/sensores/no-existe/eventos"), ("get", "/"), ("get", "/static/app.js")]
    for metodo, ruta in rutas:
        r = getattr(cliente, metodo)(ruta)
        cuerpo = (r.text + str(dict(r.headers))).lower()
        for h in llaves + [kek_hex]:
            assert h not in cuerpo, (ruta, "filtra una llave")


def test_respuesta_sensores_no_incluye_llave_cifrada(sensor, cliente):
    for s in cliente.get("/api/sensores").json():
        assert not ({"llave", "llave_cifrada", "nonce"} & set(s))


def test_nonces_distintos_entre_sensores_registrados(sql):
    filas = sql("SELECT nonce, llave_cifrada FROM sensores")
    assert len(filas) == 2
    assert filas[0][0] != filas[1][0]
    assert filas[0][1] != filas[1][1]
    assert all(len(n) == 12 for n, _ in filas)


def test_llaves_de_sensores_registrados_son_distintas(entorno):
    llaves = [(entorno.sensores_dir / f"{s}.key").read_text().strip() for s in ("sensor-01", "sensor-02")]
    assert llaves[0] != llaves[1] and all(re.fullmatch(r"[0-9a-f]{64}", k) for k in llaves)


def test_archivo_key_tiene_permiso_0600(entorno):
    for f in entorno.sensores_dir.glob("*.key"):
        assert (f.stat().st_mode & 0o777) == 0o600


# Simulador ------------------------------------------------------------------------
def test_simulador_produce_mensajes_que_el_servidor_acepta(sensor, cliente):
    from vigia.sensor import generar_valor
    for i in range(1, 6):
        p = construir_medicion(sensor.id, sensor.llave, i, ahora_ms(), generar_valor(i * 2.0))
        assert set(p) == {"sensor_id", "seq", "timestamp_ms", "valor", "tag"}
        assert estado(cliente.post("/api/mediciones", json=p)) == "VERIFICADA"
    rep = verificar_historial(cliente, sensor.id)
    assert rep["integro"] is True and rep["total"] == 5
