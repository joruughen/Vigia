"""Fixtures de la suite de VIGÍA.

Aislamiento: todo (BD, llaves de sensores) vive en tmp_path; las variables de entorno se fijan
con monkeypatch (VIGIA_MASTER_PASSWORD, VIGIA_DB_PATH, VIGIA_SENSORES_DIR, VIGIA_VENTANA_MS).
Como vigia.config.load_config usa load_dotenv(override=False), las variables ya presentes en el
entorno ganan sobre cualquier .env real; además fijamos TODAS las variables que lee load_config,
así que un .env real no puede cambiar el comportamiento ni redirigir la BD a data/.

Rendimiento: la BD inicializada (Argon2id + canario) y los sensores se crean UNA vez por sesión
mediante la CLI real; cada test recibe una copia en su tmp_path.
"""
from __future__ import annotations

import shutil
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vigia import cli
from vigia.config import load_config
from vigia.sensor import construir_medicion
from vigia.server.app import create_app

PASSWORD = "contrasena-de-prueba-NO-usar-en-produccion"
VENTANA_MS = 30_000
SENSORES_BASE = ("sensor-01", "sensor-02")


def ahora_ms() -> int:
    return time.time_ns() // 1_000_000


def _fijar_entorno(mp: pytest.MonkeyPatch, db_path: Path, sensores_dir: Path,
                   password: str = PASSWORD) -> None:
    mp.setenv("VIGIA_MASTER_PASSWORD", password)
    mp.setenv("VIGIA_DB_PATH", str(db_path))
    mp.setenv("VIGIA_SENSORES_DIR", str(sensores_dir))
    mp.setenv("VIGIA_VENTANA_MS", str(VENTANA_MS))


@pytest.fixture(scope="session")
def plantilla(tmp_path_factory):
    """BD inicializada con dos sensores registrados vía CLI (una sola vez por sesión)."""
    base = tmp_path_factory.mktemp("plantilla")
    db_path, sdir = base / "vigia.db", base / "sensores"
    with pytest.MonkeyPatch.context() as mp:
        _fijar_entorno(mp, db_path, sdir)
        assert cli.main(["init"]) == 0
        for sid in SENSORES_BASE:
            assert cli.main(["registrar-sensor", sid]) == 0
    return base


@dataclass
class Entorno:
    db_path: Path
    sensores_dir: Path


@pytest.fixture
def entorno(plantilla, tmp_path, monkeypatch) -> Entorno:
    db_path, sdir = tmp_path / "vigia.db", tmp_path / "sensores"
    shutil.copy(plantilla / "vigia.db", db_path)
    shutil.copytree(plantilla / "sensores", sdir)
    _fijar_entorno(monkeypatch, db_path, sdir)
    return Entorno(db_path, sdir)


@pytest.fixture
def app(entorno):
    return create_app(load_config())


@pytest.fixture
def cliente(app):
    return TestClient(app)


class Sensor:
    """Sensor simulado: usa vigia.sensor.construir_medicion con la llave del archivo .key."""

    def __init__(self, sensor_id: str, llave: bytes, cliente: TestClient):
        self.id, self.llave, self.cliente = sensor_id, llave, cliente
        self.seq = 0  # última seq aceptada

    def payload(self, seq: int | None = None, ts: int | None = None, valor: str = "23.475",
                llave: bytes | None = None, sensor_id: str | None = None) -> dict:
        return construir_medicion(sensor_id or self.id, llave or self.llave,
                                  self.seq + 1 if seq is None else seq,
                                  ahora_ms() if ts is None else ts, valor)

    def post(self, payload: dict):
        return self.cliente.post("/api/mediciones", json=payload)

    def enviar(self, **kw):
        """Envía una medición construida con payload(**kw); si queda VERIFICADA avanza seq."""
        p = self.payload(**kw)
        r = self.post(p)
        if r.status_code == 200 and r.json()["estado"] == "VERIFICADA":
            self.seq = p["seq"]
        return r

    def enviar_ok(self, n: int = 1, **kw) -> None:
        for _ in range(n):
            r = self.enviar(**kw)
            assert r.status_code == 200 and r.json()["estado"] == "VERIFICADA", r.text


def _leer_llave(entorno: Entorno, sid: str) -> bytes:
    return bytes.fromhex((entorno.sensores_dir / f"{sid}.key").read_text().strip())


@pytest.fixture
def sensor(entorno, cliente) -> Sensor:
    return Sensor("sensor-01", _leer_llave(entorno, "sensor-01"), cliente)


@pytest.fixture
def sensor2(entorno, cliente) -> Sensor:
    return Sensor("sensor-02", _leer_llave(entorno, "sensor-02"), cliente)


# ---- acceso directo a la BD (simula a un atacante con acceso al archivo) ----------
@pytest.fixture
def sql(entorno):
    """Ejecuta SQL directo sobre la BD de prueba; devuelve las filas."""
    def _sql(consulta: str, params: tuple = ()):
        con = sqlite3.connect(entorno.db_path)
        try:
            filas = con.execute(consulta, params).fetchall()
            con.commit()
            return filas
        finally:
            con.close()
    return _sql
