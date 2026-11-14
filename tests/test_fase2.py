"""Tests de las correcciones de la revisión de seguridad (fase 2): M1, B5, B4, B1, I1, I2, I3."""
import json
import os
import secrets
import stat

import httpx
import pytest

from tests.conftest import PASSWORD, VENTANA_MS, ahora_ms
from vigia import cli, sensor as sensor_mod
from vigia.config import (ConfigError, VALOR_EJEMPLO_PROHIBIDO, load_config,
                          validar_password_maestra)
from vigia.crypto import keystore
from vigia.crypto.canonical import mensaje_canonico
from vigia.crypto.chain import GENESIS, siguiente_hash
from vigia.crypto.mac import calcular_tag, generar_llave_sensor
from vigia.crypto.verifier import Estado, Medicion, RegistroGuardado, verificar_medicion
from vigia.server.app import create_app
from vigia.server.db import ArranqueError


# ---- M1: fila final falsa con hash recalculado ------------------------------------
def test_m1_fila_final_falsa_con_hash_correcto_da_cadena_rota(sensor, cliente, sql):
    sensor.enviar_ok(2)
    (h2,), = sql("SELECT hash FROM mediciones WHERE sensor_id = ? AND seq = 2", (sensor.id,))
    tag_falso = secrets.token_hex(32)
    ts = ahora_ms()
    canon = mensaje_canonico(sensor.id, 3, ts, "99.999")
    h3 = siguiente_hash(h2, canon, tag_falso)  # hash consistente: solo el HMAC delata la fila
    sql("INSERT INTO mediciones (sensor_id, seq, timestamp_ms, valor, tag, hash_prev, hash)"
        " VALUES (?, 3, ?, '99.999', ?, ?, ?)", (sensor.id, ts, tag_falso, h2, h3))

    r = sensor.post(sensor.payload(seq=4, valor="23.500"))
    assert r.status_code == 200, r.text
    assert r.json()["estado"] == "CADENA ROTA"
    assert "HMAC inválido" in r.json()["detalle"]
    assert sql("SELECT COUNT(*) FROM mediciones WHERE sensor_id = ? AND seq = 4",
               (sensor.id,)) == [(0,)]
    serie = cliente.get(f"/api/sensores/{sensor.id}/serie").json()
    assert 4 not in [x["seq"] for x in serie]


def _medicion_y_llave(seq=4):
    llave = generar_llave_sensor()
    ts = ahora_ms()
    canon = mensaje_canonico("sensor-01", seq, ts, "23.5")
    return Medicion("sensor-01", seq, ts, "23.5", calcular_tag(llave, canon)), llave, ts


@pytest.mark.parametrize("campos", [
    {"valor": "no-es-numero"},
    {"sensor_id": "a|b"},
    {"timestamp_ms": -5},
    {"seq": "tres"},
    {"seq": True},
    {"seq": None},
    {"tag": 12345},
    {"hash_prev": "zz"},
    {"hash": None},
])
def test_m1_ultimo_registro_de_formato_invalido_da_cadena_rota_sin_excepcion(campos):
    m, llave, ts = _medicion_y_llave(seq=4)
    base = dict(sensor_id="sensor-01", seq=3, timestamp_ms=ts, valor="23.4",
                tag="ab" * 32, hash_prev=GENESIS, hash="cd" * 32)
    base.update(campos)
    res = verificar_medicion(m, llave, RegistroGuardado(**base), ts, VENTANA_MS)
    # Con seq corrupto no se compara en el paso 3; en todos los casos nunca VERIFICADA ni excepción.
    assert res.estado == Estado.CADENA_ROTA
    assert res.hash_nuevo is None


def test_m1_ultimo_con_seq_cero_y_medicion_seq_1_da_cadena_rota():
    # seq=0 es int (el paso 3 espera 1), pero no es un seq canónico válido: paso 5 -> CADENA ROTA.
    m, llave, ts = _medicion_y_llave(seq=1)
    ultimo = RegistroGuardado("sensor-01", 0, ts, "23.4", "ab" * 32, GENESIS, "cd" * 32)
    res = verificar_medicion(m, llave, ultimo, ts, VENTANA_MS)
    assert res.estado == Estado.CADENA_ROTA


# ---- B5: parámetros Argon2id degradados -------------------------------------------
def test_b5_derivar_kek_none_equivale_a_params_por_defecto():
    salt = b"s" * 16
    assert keystore.derivar_kek("x" * 20, salt, None) == \
        keystore.derivar_kek("x" * 20, salt, dict(keystore.PARAMS_ARGON2))
    assert keystore.derivar_kek("x" * 20, salt) == keystore.derivar_kek("x" * 20, salt, None)


def _con(**cambios):
    p = dict(keystore.PARAMS_ARGON2)
    p.update(cambios)
    return p


def _sin(clave):
    p = dict(keystore.PARAMS_ARGON2)
    del p[clave]
    return p


PARAMS_MALOS = [
    _con(time_cost=1),
    _con(memory_cost=8),
    _con(memory_cost=19455),
    _con(parallelism=0),
    _con(hash_len=16),
    _con(hash_len=64),
    _sin("time_cost"),
    _sin("hash_len"),
    {**keystore.PARAMS_ARGON2, "extra": 1},
    _con(time_cost=True),
    _con(memory_cost=True),
    _con(time_cost="3"),
    _con(time_cost=3.0),
    {},
    [],
    "no-es-dict",
]


@pytest.mark.parametrize("params", PARAMS_MALOS)
def test_b5_params_degradados_rechazados_por_validar_y_derivar(params):
    with pytest.raises(ValueError):
        keystore.validar_params_argon2(params)
    with pytest.raises(ValueError):
        keystore.derivar_kek("x" * 20, b"s" * 16, params)


def test_b5_params_en_minimos_aceptados():
    ok = keystore.validar_params_argon2(_con(time_cost=2, memory_cost=19456, parallelism=1))
    assert ok["time_cost"] == 2 and ok["hash_len"] == 32


@pytest.mark.parametrize("valor", [
    json.dumps(_con(time_cost=1)).encode(),
    json.dumps(_con(memory_cost=8, time_cost=1)).encode(),
    json.dumps(_con(hash_len=16)).encode(),
    json.dumps(_sin("parallelism")).encode(),
    json.dumps({**keystore.PARAMS_ARGON2, "x": 1}).encode(),
    json.dumps(_con(time_cost=True)).encode(),
    json.dumps([1, 2, 3]).encode(),
    b"{esto no es json",
    b"\xff\xfe\x00",
], ids=["t1", "t1_m8", "hash16", "falta_p", "extra", "bool", "no_objeto", "json_invalido", "no_utf8"])
def test_b5_kdf_params_alterados_en_bd_impiden_arrancar_sin_decir_contrasena(entorno, sql, valor):
    sql("UPDATE meta SET valor = ? WHERE clave = 'kdf_params'", (valor,))
    with pytest.raises(ArranqueError) as ei:
        create_app(load_config())
    msg = str(ei.value).lower()
    assert "contraseña incorrecta" not in msg and "password incorrecta" not in msg
    assert "kdf_params" in msg


def test_b5_kdf_params_ausentes_impiden_arrancar(entorno, sql):
    sql("DELETE FROM meta WHERE clave = 'kdf_params'")
    with pytest.raises(ArranqueError) as ei:
        create_app(load_config())
    assert "contraseña incorrecta" not in str(ei.value).lower()


def test_b5_contrasena_incorrecta_sigue_diciendo_incorrecta(entorno, monkeypatch):
    monkeypatch.setenv("VIGIA_MASTER_PASSWORD", PASSWORD + "-mala")
    with pytest.raises(ArranqueError, match="incorrecta"):
        create_app(load_config())


# ---- B4: política de contraseña maestra -------------------------------------------
def test_b4_rechaza_valor_de_env_example():
    with pytest.raises(ConfigError):
        validar_password_maestra(VALOR_EJEMPLO_PROHIBIDO)


def test_b4_valor_prohibido_coincide_con_env_example():
    from pathlib import Path
    ejemplo = (Path(__file__).resolve().parent.parent / ".env.example").read_text()
    lineas = [l for l in ejemplo.splitlines() if l.startswith("VIGIA_MASTER_PASSWORD=")]
    assert lineas and lineas[0].split("=", 1)[1] == VALOR_EJEMPLO_PROHIBIDO


@pytest.mark.parametrize("pw", ["a", "corta", "x" * 15])
def test_b4_rechaza_cortas(pw):
    with pytest.raises(ConfigError):
        validar_password_maestra(pw)


@pytest.mark.parametrize("pw", ["x" * 16, secrets.token_urlsafe(24)[:32].ljust(32, "a")])
def test_b4_acepta_largas(pw):
    validar_password_maestra(pw)  # no lanza


def test_b4_load_config_aplica_la_politica(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIA_DB_PATH", str(tmp_path / "d" / "v.db"))
    monkeypatch.setenv("VIGIA_MASTER_PASSWORD", VALOR_EJEMPLO_PROHIBIDO)
    with pytest.raises(ConfigError):
        load_config()
    monkeypatch.setenv("VIGIA_MASTER_PASSWORD", "corta")
    with pytest.raises(ConfigError):
        load_config()
    monkeypatch.setenv("VIGIA_MASTER_PASSWORD", secrets.token_urlsafe(32))
    assert load_config().db_path.name == "v.db"


# ---- B1: simulador ante replay de la seq pendiente --------------------------------
@pytest.mark.parametrize("estado, detalle, enviada, esperado", [
    ("REPLAY O HUECO", "replay: seq 5 <= última 5", 5, True),
    ("REPLAY O HUECO", "replay: seq 5 <= última 7", 5, False),    # el servidor va por delante
    ("REPLAY O HUECO", "replay: seq 4 <= última 5", 5, False),    # no es la seq pendiente
    ("REPLAY O HUECO", "hueco: esperaba 3, llegó 5", 5, False),
    ("REPLAY O HUECO", "hueco: esperaba 5, llegó 5", 5, False),
    ("REPLAY O HUECO", "replay: seq 5 <= última 5 y algo más", 5, False),
    ("MANIPULADA", "replay: seq 5 <= última 5", 5, False),
    ("VERIFICADA", "ok", 5, False),
])
def test_b1_funcion_replay_de_seq_pendiente(estado, detalle, enviada, esperado):
    assert sensor_mod.replay_de_seq_pendiente(estado, detalle, enviada) is esperado


def test_b1_detalle_real_del_servidor_es_reconocido(sensor, cliente):
    """Integración: el detalle que emite el verificador coincide con lo que espera el simulador."""
    sensor.enviar_ok(1)
    p = sensor.payload(seq=1)  # reenvío de la seq ya aceptada (respuesta perdida)
    r = sensor.post(p).json()
    assert r["estado"] == "REPLAY O HUECO"
    assert sensor_mod.replay_de_seq_pendiente(r["estado"], r["detalle"], 1)
    p2 = sensor.payload(seq=5)  # hueco
    r2 = sensor.post(p2).json()
    assert r2["estado"] == "REPLAY O HUECO"
    assert not sensor_mod.replay_de_seq_pendiente(r2["estado"], r2["detalle"], 5)


class _RespFalsa:
    status_code = 200

    def __init__(self, estado, detalle):
        self._d = {"estado": estado, "detalle": detalle}

    def json(self):
        return self._d


def _correr_simulador(monkeypatch, tmp_path, estado, detalle, seq_inicial=3):
    sdir = tmp_path / "sens"
    sdir.mkdir()
    (sdir / "s-1.key").write_text(generar_llave_sensor().hex() + "\n")
    os.chmod(sdir / "s-1.key", 0o600)
    (sdir / "s-1.seq").write_text(f"{seq_inicial}\n")

    class ClienteFalso:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def post(self, url, json=None):
            return _RespFalsa(estado, detalle)

    monkeypatch.setattr(sensor_mod.httpx, "Client", ClienteFalso)
    monkeypatch.setattr(sensor_mod, "contexto_tls", lambda c: None)
    rc = sensor_mod.main(["--sensor", "s-1", "--cacert", "x", "--n", "1",
                          "--sensores-dir", str(sdir), "--intervalo", "0"])
    assert rc == 0
    return int((sdir / "s-1.seq").read_text())


def test_b1_main_avanza_seq_ante_replay_de_la_pendiente(monkeypatch, tmp_path):
    assert _correr_simulador(monkeypatch, tmp_path, "REPLAY O HUECO",
                             "replay: seq 4 <= última 4") == 4


def test_b1_main_no_avanza_ante_hueco(monkeypatch, tmp_path):
    assert _correr_simulador(monkeypatch, tmp_path, "REPLAY O HUECO",
                             "hueco: esperaba 9, llegó 4") == 3


def test_b1_main_no_avanza_ante_replay_con_servidor_adelantado(monkeypatch, tmp_path):
    assert _correr_simulador(monkeypatch, tmp_path, "REPLAY O HUECO",
                             "replay: seq 4 <= última 9") == 3


# ---- I1: blob de llave corrupto -> 500 genérico ------------------------------------
def _corromper_llave(sql, sid):
    (blob,), = sql("SELECT llave_cifrada FROM sensores WHERE id = ?", (sid,))
    malo = bytes([blob[0] ^ 0xFF]) + bytes(blob[1:])
    sql("UPDATE sensores SET llave_cifrada = ? WHERE id = ?", (malo, sid))


def _sin_traceback(r):
    t = r.text
    assert "Traceback" not in t and "File \"" not in t
    assert "InvalidTag" not in t and "keystore" not in t and "cryptography" not in t


def test_i1_post_mediciones_con_llave_corrupta_da_500_generico(sensor, sql):
    _corromper_llave(sql, sensor.id)
    r = sensor.post(sensor.payload())
    assert r.status_code == 500
    assert r.json() == {"error": "llave de sensor ilegible"}
    _sin_traceback(r)
    assert sql("SELECT COUNT(*) FROM mediciones") == [(0,)]


def test_i1_verificar_historial_con_llave_corrupta_da_500_generico(sensor, cliente, sql):
    sensor.enviar_ok(2)
    _corromper_llave(sql, sensor.id)
    r = cliente.post(f"/api/sensores/{sensor.id}/verificar-historial")
    assert r.status_code == 500
    assert r.json() == {"error": "llave de sensor ilegible"}
    _sin_traceback(r)


def test_i1_otro_sensor_no_se_ve_afectado(sensor, sensor2, sql):
    _corromper_llave(sql, sensor.id)
    sensor2.enviar_ok(1)


# ---- I2: leer_llave ---------------------------------------------------------------
@pytest.mark.parametrize("contenido", [
    "zz" * 32,                 # no hex
    "xyz",                     # no hex
    "abc",                     # hex de largo impar
    "",                        # vacío
    "ab" * 16,                 # 16 bytes
    "ab" * 31,                 # 31 bytes
    "ab" * 33,                 # 33 bytes
    "ab" * 64,                 # 64 bytes
])
def test_i2_leer_llave_rechaza_invalidas(tmp_path, contenido):
    f = tmp_path / "k.key"
    f.write_text(contenido + "\n")
    with pytest.raises(ValueError):
        sensor_mod.leer_llave(f)


def test_i2_leer_llave_acepta_32_bytes(tmp_path):
    llave = generar_llave_sensor()
    f = tmp_path / "k.key"
    f.write_text(llave.hex() + "\n")
    assert sensor_mod.leer_llave(f) == llave


def test_i2_main_con_llave_invalida_sale_con_error_y_sin_traceback(tmp_path, capsys):
    sdir = tmp_path / "s"
    sdir.mkdir()
    (sdir / "s-1.key").write_text("no-es-hex\n")
    rc = sensor_mod.main(["--sensor", "s-1", "--cacert", "x", "--n", "1",
                          "--sensores-dir", str(sdir)])
    err = capsys.readouterr().err
    assert rc == 1 and "Error" in err and "Traceback" not in err


# ---- I3: permisos de BD y llaves ---------------------------------------------------
def _modo(ruta) -> int:
    return stat.S_IMODE(os.stat(ruta).st_mode)


def test_i3_permisos_tras_init_y_registrar_sensor(tmp_path, monkeypatch):
    db_dir, sdir = tmp_path / "nuevo" / "datos", tmp_path / "nuevo" / "llaves"
    monkeypatch.setenv("VIGIA_MASTER_PASSWORD", PASSWORD)
    monkeypatch.setenv("VIGIA_DB_PATH", str(db_dir / "vigia.db"))
    monkeypatch.setenv("VIGIA_SENSORES_DIR", str(sdir))
    monkeypatch.setenv("VIGIA_VENTANA_MS", str(VENTANA_MS))
    old = os.umask(0o022)  # umask permisivo: los permisos deben fijarse explícitamente
    try:
        assert cli.main(["init"]) == 0
        assert cli.main(["registrar-sensor", "sensor-x"]) == 0
    finally:
        os.umask(old)
    assert _modo(db_dir) == 0o700
    assert _modo(db_dir / "vigia.db") == 0o600
    assert _modo(sdir) == 0o700
    assert _modo(sdir / "sensor-x.key") == 0o600
