"""Pruebas unitarias de vigia.crypto (canónico, MAC, cadena, keystore)."""
import hashlib
import os

import pytest

from vigia.crypto import keystore
from vigia.crypto.canonical import FormatoInvalido, mensaje_canonico
from vigia.crypto.chain import GENESIS, siguiente_hash
from vigia.crypto.keystore import ContrasenaIncorrecta
from vigia.crypto.mac import calcular_tag, generar_llave_sensor, verificar_tag


# ------------------------------------------------------------------ formato canónico
def test_canonico_ejemplo_del_contrato():
    assert (mensaje_canonico("sensor-01", 42, 1763140000123, "23.475")
            == b"VIGIA-v1|sensor-01|42|1763140000123|23.475")


@pytest.mark.parametrize("sid,seq,ts,valor", [
    ("a", 1, 0, "0"),
    ("S_en-sor_9", 2**63 - 1, 10**13, "-0.5"),
    ("x" * 64, 7, 1, "123456789012.123456"),
    ("s", 1, 1, "-12"),
    ("s", 1, 1, "0.000001"),
])
def test_canonico_validos(sid, seq, ts, valor):
    assert mensaje_canonico(sid, seq, ts, valor) == f"VIGIA-v1|{sid}|{seq}|{ts}|{valor}".encode()


@pytest.mark.parametrize("sid", ["", "a|b", "a b", "sensor\n", "x" * 65, "sénsor", "a/b", "../x"])
def test_canonico_sensor_id_invalido(sid):
    with pytest.raises(FormatoInvalido):
        mensaje_canonico(sid, 1, 0, "1")


def test_canonico_pipe_en_id_no_es_ambiguo():
    # Sin esta regla ("a|1", 2, ...) y ("a", 1, ...) podrían colisionar en bytes.
    with pytest.raises(FormatoInvalido):
        mensaje_canonico("a|1", 2, 5, "7")


@pytest.mark.parametrize("seq", [0, -1, 2**63, True, False, 1.0, "1", None])
def test_canonico_seq_invalido(seq):
    with pytest.raises(FormatoInvalido):
        mensaje_canonico("s", seq, 0, "1")


@pytest.mark.parametrize("ts", [-1, True, 1.5, "1", None])
def test_canonico_timestamp_invalido(ts):
    with pytest.raises(FormatoInvalido):
        mensaje_canonico("s", 1, ts, "1")


@pytest.mark.parametrize("valor", [
    "", "01", "+1", "1.", ".5", "1e3", "NaN", "inf", " 1", "1 ", "1,5", "--1",
    "1234567890123",      # 13 dígitos enteros
    "1.1234567",          # 7 decimales
    "1\n",                # '\n' final: '$' lo aceptaría, fullmatch no
    "\n1", "1\n2", "1|2", "0x10",
])
def test_canonico_valor_invalido(valor):
    with pytest.raises(FormatoInvalido):
        mensaje_canonico("s", 1, 0, valor)


def test_canonico_id_con_salto_de_linea_final_rechazado():
    with pytest.raises(FormatoInvalido):
        mensaje_canonico("sensor-01\n", 1, 0, "1")


def test_canonico_float_no_se_acepta_ni_se_reformatea():
    # El valor se autentica como string; un float python no es un valor canónico.
    with pytest.raises(FormatoInvalido):
        mensaje_canonico("s", 1, 0, 23.475)
    # Y "23.5" y "23.50" son mensajes distintos (no se normaliza): un tag no sirve para el otro.
    a, b = mensaje_canonico("s", 1, 0, "23.5"), mensaje_canonico("s", 1, 0, "23.50")
    assert a != b
    k = generar_llave_sensor()
    assert not verificar_tag(k, b, calcular_tag(k, a))


# ------------------------------------------------------------------ HMAC
def test_tag_roundtrip_y_formato():
    k, msg = generar_llave_sensor(), b"VIGIA-v1|s|1|0|1"
    tag = calcular_tag(k, msg)
    assert len(tag) == 64 and tag == tag.lower() and int(tag, 16) >= 0
    assert verificar_tag(k, msg, tag)


def test_tag_cambia_con_mensaje_y_con_llave():
    k1, k2, msg = generar_llave_sensor(), generar_llave_sensor(), b"VIGIA-v1|s|1|0|1"
    tag = calcular_tag(k1, msg)
    assert not verificar_tag(k1, msg + b"x", tag)
    assert not verificar_tag(k2, msg, tag)


def test_tag_coincide_con_hmac_estandar():
    import hmac
    k, msg = b"\x01" * 32, b"hola"
    assert calcular_tag(k, msg) == hmac.new(k, msg, hashlib.sha256).hexdigest()


@pytest.mark.parametrize("malo", [
    "", "zz" * 32, "00" * 31, "00" * 33, "g" * 64, "ab" * 32 + "\n", " " + "ab" * 32,
    "AB" * 32,          # mayúsculas: el diseño exige una única representación
    None, 123, b"ab" * 32,
])
def test_verificar_tag_robusto_ante_hex_invalido(malo):
    k = generar_llave_sensor()
    assert verificar_tag(k, b"m", malo) is False  # nunca lanza excepción


def test_tag_mayusculas_equivalente_se_rechaza():
    k, msg = generar_llave_sensor(), b"m"
    assert not verificar_tag(k, msg, calcular_tag(k, msg).upper())


def test_llave_de_32_bytes_aleatoria_y_distinta():
    llaves = {generar_llave_sensor() for _ in range(200)}
    assert len(llaves) == 200
    assert all(len(x) == 32 for x in llaves)
    assert all(x != b"\x00" * 32 for x in llaves)


@pytest.mark.parametrize("llave", [b"", b"x" * 16, b"x" * 33, "x" * 32, None])
def test_calcular_tag_rechaza_llave_mal_formada(llave):
    with pytest.raises(ValueError):
        calcular_tag(llave, b"m")


# ------------------------------------------------------------------ cadena
def test_genesis_es_32_bytes_cero():
    assert GENESIS == "00" * 32


def test_cadena_formula_con_genesis():
    k, msg = generar_llave_sensor(), mensaje_canonico("s", 1, 0, "1")
    tag = calcular_tag(k, msg)
    esperado = hashlib.sha256(bytes(32) + msg + bytes.fromhex(tag)).hexdigest()
    assert siguiente_hash(GENESIS, msg, tag) == esperado


def test_cadena_depende_del_tag():
    k1, k2 = generar_llave_sensor(), generar_llave_sensor()
    msg = mensaje_canonico("s", 1, 0, "1")
    assert siguiente_hash(GENESIS, msg, calcular_tag(k1, msg)) != siguiente_hash(GENESIS, msg, calcular_tag(k2, msg))


def test_cadena_depende_del_hash_previo_y_del_mensaje():
    k = generar_llave_sensor()
    m1, m2 = mensaje_canonico("s", 1, 0, "1"), mensaje_canonico("s", 1, 0, "2")
    t1 = calcular_tag(k, m1)
    h1 = siguiente_hash(GENESIS, m1, t1)
    assert siguiente_hash(h1, m1, t1) != h1
    assert siguiente_hash(GENESIS, m2, t1) != h1


@pytest.mark.parametrize("hp,tag", [("00" * 31, "00" * 32), ("00" * 32, "zz" * 32), ("00" * 32, "AB" * 32)])
def test_siguiente_hash_rechaza_hex_invalido(hp, tag):
    with pytest.raises(ValueError):
        siguiente_hash(hp, b"m", tag)


# ------------------------------------------------------------------ keystore
@pytest.fixture(scope="module")
def kdf():
    """Deriva las KEK una sola vez por módulo (Argon2id es deliberadamente costoso)."""
    salt1, salt2 = keystore.nuevo_salt(), keystore.nuevo_salt()
    return {
        "salt1": salt1, "salt2": salt2,
        "a1": keystore.derivar_kek("clave-A", salt1),
        "a1_bis": keystore.derivar_kek("clave-A", salt1),
        "b1": keystore.derivar_kek("clave-B", salt1),
        "a2": keystore.derivar_kek("clave-A", salt2),
    }


def test_params_argon2_razonables():
    p = keystore.PARAMS_ARGON2
    assert p["hash_len"] == 32 and p["time_cost"] >= 2 and p["memory_cost"] >= 19456 and p["parallelism"] >= 1


def test_kek_determinista_32_bytes_y_dependiente_de_contrasena_y_salt(kdf):
    assert len(kdf["a1"]) == 32
    assert kdf["a1"] == kdf["a1_bis"]
    assert kdf["a1"] != kdf["b1"]       # otra contraseña
    assert kdf["a1"] != kdf["a2"]       # otro salt


def test_derivar_kek_rechaza_entradas_malas():
    with pytest.raises(ValueError):
        keystore.derivar_kek("", os.urandom(16))
    with pytest.raises(ValueError):
        keystore.derivar_kek("x", b"corto")


def test_salts_unicos_y_de_16_bytes():
    salts = [keystore.nuevo_salt() for _ in range(500)]
    assert len(set(salts)) == 500 and all(len(s) == 16 for s in salts)


def test_cifrado_roundtrip(kdf):
    llave = generar_llave_sensor()
    nonce, ct = keystore.cifrar_llave_sensor(kdf["a1"], "sensor-01", llave)
    assert len(nonce) == 12 and len(ct) == 32 + 16     # llave + tag GCM
    assert llave not in ct
    assert keystore.descifrar_llave_sensor(kdf["a1"], "sensor-01", nonce, ct) == llave


def test_nonces_unicos_en_n_cifrados_de_la_misma_llave(kdf):
    llave, N = generar_llave_sensor(), 1000
    salidas = [keystore.cifrar_llave_sensor(kdf["a1"], "sensor-01", llave) for _ in range(N)]
    assert len({n for n, _ in salidas}) == N            # nunca se reutiliza (KEK, nonce)
    assert len({c for _, c in salidas}) == N            # ciphertexts distintos para el mismo plano


def test_nonces_de_canario_unicos(kdf):
    nonces = {keystore.crear_canario(kdf["a1"])[0] for _ in range(300)}
    assert len(nonces) == 300


def test_aad_otro_sensor_falla(kdf):
    llave = generar_llave_sensor()
    nonce, ct = keystore.cifrar_llave_sensor(kdf["a1"], "sensor-01", llave)
    with pytest.raises(ContrasenaIncorrecta):
        keystore.descifrar_llave_sensor(kdf["a1"], "sensor-02", nonce, ct)


def test_contrasena_incorrecta(kdf):
    nonce, ct = keystore.cifrar_llave_sensor(kdf["a1"], "s", generar_llave_sensor())
    with pytest.raises(ContrasenaIncorrecta):
        keystore.descifrar_llave_sensor(kdf["b1"], "s", nonce, ct)
    with pytest.raises(ContrasenaIncorrecta):          # mismo password pero otro salt
        keystore.descifrar_llave_sensor(kdf["a2"], "s", nonce, ct)


def test_ciphertext_alterado_se_detecta(kdf):
    nonce, ct = keystore.cifrar_llave_sensor(kdf["a1"], "s", generar_llave_sensor())
    mal = bytes([ct[0] ^ 1]) + ct[1:]
    with pytest.raises(ContrasenaIncorrecta):
        keystore.descifrar_llave_sensor(kdf["a1"], "s", nonce, mal)


def test_cifrar_rechaza_llave_o_kek_mal_formada(kdf):
    with pytest.raises(ValueError):
        keystore.cifrar_llave_sensor(kdf["a1"], "s", b"corta")
    with pytest.raises(ValueError):
        keystore.cifrar_llave_sensor(b"kek-corta", "s", generar_llave_sensor())
    with pytest.raises(ValueError):
        keystore.cifrar_llave_sensor(kdf["a1"], "a|b", generar_llave_sensor())


def test_canario_ok_y_falla_con_otra_kek(kdf):
    nonce, ct = keystore.crear_canario(kdf["a1"])
    keystore.comprobar_canario(kdf["a1"], nonce, ct)    # no lanza
    with pytest.raises(ContrasenaIncorrecta):
        keystore.comprobar_canario(kdf["b1"], nonce, ct)


def test_canario_no_se_confunde_con_llave(kdf):
    # Dominios de AAD distintos: un canario no descifra como llave de sensor.
    nonce, ct = keystore.crear_canario(kdf["a1"])
    with pytest.raises(ContrasenaIncorrecta):
        keystore.descifrar_llave_sensor(kdf["a1"], "s", nonce, ct)
