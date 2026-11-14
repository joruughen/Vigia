"""Persistencia SQLite de VIGÍA. Todas las consultas están parametrizadas."""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from argon2.exceptions import HashingError

from vigia.crypto import keystore
from vigia.crypto.chain import GENESIS
from vigia.crypto.verifier import (Estado, Medicion, RegistroGuardado, Resultado,
                                   verificar_medicion)

ESQUEMA = """
CREATE TABLE IF NOT EXISTS meta (
    clave TEXT PRIMARY KEY,
    valor BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS sensores (
    id            TEXT PRIMARY KEY,
    nonce         BLOB NOT NULL,
    llave_cifrada BLOB NOT NULL,
    activo        INTEGER NOT NULL DEFAULT 1 CHECK (activo IN (0, 1)),
    creado_ms     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS mediciones (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id    TEXT NOT NULL,
    seq          INTEGER NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    valor        TEXT NOT NULL,
    tag          TEXT NOT NULL,
    hash_prev    TEXT NOT NULL,
    hash         TEXT NOT NULL,
    UNIQUE (sensor_id, seq)
);
CREATE TABLE IF NOT EXISTS eventos (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id    TEXT NOT NULL,
    seq          INTEGER NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    valor        TEXT NOT NULL,
    tag          TEXT NOT NULL,
    estado       TEXT NOT NULL,
    detalle      TEXT NOT NULL,
    recibido_ms  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_eventos_sensor ON eventos (sensor_id, id);
"""


class ArranqueError(Exception):
    """Error de arranque con mensaje claro (BD sin inicializar, contraseña incorrecta)."""


def ahora_ms() -> int:
    return time.time_ns() // 1_000_000


def _crear_archivo_privado(ruta: str) -> None:
    """Crea el archivo de BD con 0600 si no existe (SQLite lo crearía según el umask)."""
    if ruta == ":memory:" or ruta.startswith("file:"):
        return
    try:
        os.close(os.open(ruta, os.O_WRONLY | os.O_CREAT, 0o600))
    except OSError:
        return  # que sqlite3 informe el error real al conectar


class Database:
    def __init__(self, ruta: str | Path):
        self.ruta = str(ruta)
        _crear_archivo_privado(self.ruta)

    @contextmanager
    def conexion(self) -> Iterator[sqlite3.Connection]:
        # autocommit: las transacciones se abren explícitamente con BEGIN.
        con = sqlite3.connect(self.ruta, timeout=30, isolation_level=None)
        con.row_factory = sqlite3.Row
        try:
            con.execute("PRAGMA foreign_keys = ON")
            yield con
        finally:
            con.close()

    # ---- inicialización y meta -------------------------------------------------
    def crear_esquema(self) -> None:
        with self.conexion() as con:
            con.executescript(ESQUEMA)

    def meta_get(self, clave: str) -> bytes | None:
        with self.conexion() as con:
            fila = con.execute("SELECT valor FROM meta WHERE clave = ?", (clave,)).fetchone()
        if fila is None:
            return None
        v = fila["valor"]
        return v if isinstance(v, bytes) else str(v).encode()

    def inicializada(self) -> bool:
        return self.meta_get("kdf_salt") is not None

    def inicializar(self, contrasena: str) -> None:
        """Crea esquema, salt Argon2 único y canario. No sobrescribe una BD ya inicializada."""
        self.crear_esquema()
        if self.inicializada():
            raise ArranqueError("La base de datos ya está inicializada.")
        salt = keystore.nuevo_salt()
        kek = keystore.derivar_kek(contrasena, salt, dict(keystore.PARAMS_ARGON2))
        nonce, ct = keystore.crear_canario(kek)
        params = json.dumps(keystore.PARAMS_ARGON2, sort_keys=True).encode()
        with self.conexion() as con:
            con.execute("BEGIN IMMEDIATE")
            con.executemany(
                "INSERT INTO meta (clave, valor) VALUES (?, ?)",
                [("kdf_salt", salt), ("kdf_params", params),
                 ("canario_nonce", nonce), ("canario_ct", ct)],
            )
            con.execute("COMMIT")

    def derivar_y_comprobar_kek(self, contrasena: str) -> bytes:
        """Deriva la KEK (Argon2id) y valida la contraseña con el canario."""
        try:
            salt = self.meta_get("kdf_salt")
            nonce = self.meta_get("canario_nonce")
            ct = self.meta_get("canario_ct")
            params_raw = self.meta_get("kdf_params")
        except sqlite3.OperationalError:  # archivo vacío o sin esquema
            salt = nonce = ct = params_raw = None
        if salt is None or nonce is None or ct is None:
            raise ArranqueError(
                "La base de datos no está inicializada. Ejecuta: python -m vigia.cli init")
        try:
            if params_raw is None:
                raise ValueError("falta kdf_params")
            params = json.loads(params_raw.decode("utf-8"))
            if not isinstance(params, dict):
                raise ValueError("kdf_params no es un objeto JSON")
            kek = keystore.derivar_kek(contrasena, salt, params)
        except (ValueError, TypeError, HashingError) as exc:
            # JSONDecodeError y UnicodeDecodeError son subclases de ValueError.
            raise ArranqueError(
                "Parámetros Argon2id (kdf_params) o salt de la base de datos inválidos o por debajo "
                f"de los mínimos de seguridad: {exc}. La BD pudo ser alterada; no es un problema "
                "de contraseña.") from exc
        try:
            keystore.comprobar_canario(kek, nonce, ct)
        except keystore.ContrasenaIncorrecta as exc:
            raise ArranqueError(
                "VIGIA_MASTER_PASSWORD incorrecta: no descifra el canario de la base de datos."
            ) from exc
        return kek

    # ---- sensores ---------------------------------------------------------------
    def existe_sensor(self, sensor_id: str) -> bool:
        with self.conexion() as con:
            return con.execute("SELECT 1 FROM sensores WHERE id = ?", (sensor_id,)).fetchone() is not None

    def insertar_sensor(self, sensor_id: str, nonce: bytes, llave_cifrada: bytes) -> None:
        with self.conexion() as con:
            con.execute(
                "INSERT INTO sensores (id, nonce, llave_cifrada, activo, creado_ms) VALUES (?, ?, ?, 1, ?)",
                (sensor_id, nonce, llave_cifrada, ahora_ms()),
            )

    def revocar_sensor(self, sensor_id: str) -> bool:
        with self.conexion() as con:
            cur = con.execute("UPDATE sensores SET activo = 0 WHERE id = ?", (sensor_id,))
            return cur.rowcount > 0

    def listar_sensores(self) -> list[dict]:
        """Resumen por sensor. Nunca incluye la llave (ni cifrada)."""
        with self.conexion() as con:
            filas = con.execute(
                """
                SELECT s.id, s.activo, s.creado_ms,
                       (SELECT COUNT(*) FROM mediciones m WHERE m.sensor_id = s.id) AS verificadas,
                       (SELECT COUNT(*) FROM eventos e WHERE e.sensor_id = s.id) AS intentos,
                       (SELECT MAX(seq) FROM mediciones m WHERE m.sensor_id = s.id) AS ultima_seq,
                       (SELECT estado FROM eventos e WHERE e.sensor_id = s.id
                          ORDER BY e.id DESC LIMIT 1) AS ultimo_estado
                FROM sensores s ORDER BY s.id
                """
            ).fetchall()
        return [{"id": f["id"], "activo": bool(f["activo"]), "creado_ms": f["creado_ms"],
                 "verificadas": f["verificadas"], "intentos": f["intentos"],
                 "ultima_seq": f["ultima_seq"], "ultimo_estado": f["ultimo_estado"]}
                for f in filas]

    def _llave(self, con: sqlite3.Connection, sensor_id: str, kek: bytes) -> bytes | None:
        """Descifra la llave bajo demanda. Inexistente o revocado -> None."""
        fila = con.execute(
            "SELECT nonce, llave_cifrada, activo FROM sensores WHERE id = ?", (sensor_id,)
        ).fetchone()
        if fila is None or not fila["activo"]:
            return None
        return keystore.descifrar_llave_sensor(
            kek, sensor_id, bytes(fila["nonce"]), bytes(fila["llave_cifrada"]))

    def llave_para_historial(self, sensor_id: str, kek: bytes) -> bytes | None:
        """Llave para re-verificar el historial; sirve también para sensores revocados."""
        with self.conexion() as con:
            fila = con.execute(
                "SELECT nonce, llave_cifrada FROM sensores WHERE id = ?", (sensor_id,)
            ).fetchone()
        if fila is None:
            return None
        return keystore.descifrar_llave_sensor(
            kek, sensor_id, bytes(fila["nonce"]), bytes(fila["llave_cifrada"]))

    # ---- ingesta atómica ----------------------------------------------------------
    @staticmethod
    def _registro(f: sqlite3.Row) -> RegistroGuardado:
        return RegistroGuardado(sensor_id=f["sensor_id"], seq=f["seq"],
                                timestamp_ms=f["timestamp_ms"], valor=f["valor"], tag=f["tag"],
                                hash_prev=f["hash_prev"], hash=f["hash"])

    def ingestar(self, m: Medicion, kek: bytes, ahora: int, ventana_ms: int) -> Resultado:
        """Leer último -> verificar -> insertar (si VERIFICADA); siempre registra el evento.

        Todo dentro de una transacción BEGIN IMMEDIATE (serializa escritores por BD).
        """
        with self.conexion() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                llave = self._llave(con, m.sensor_id, kek)
                f = con.execute(
                    "SELECT * FROM mediciones WHERE sensor_id = ? ORDER BY seq DESC LIMIT 1",
                    (m.sensor_id,),
                ).fetchone()
                ultimo = self._registro(f) if f is not None else None
                res = verificar_medicion(m, llave, ultimo, ahora, ventana_ms)
                if res.estado == Estado.VERIFICADA:
                    con.execute(
                        "INSERT INTO mediciones (sensor_id, seq, timestamp_ms, valor, tag, hash_prev, hash)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (m.sensor_id, m.seq, m.timestamp_ms, m.valor, m.tag,
                         ultimo.hash if ultimo else GENESIS, res.hash_nuevo),
                    )
                con.execute(
                    "INSERT INTO eventos (sensor_id, seq, timestamp_ms, valor, tag, estado, detalle, recibido_ms)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (m.sensor_id, m.seq, m.timestamp_ms, m.valor, m.tag,
                     res.estado.value, res.detalle, ahora),
                )
                con.execute("COMMIT")
            except BaseException:
                con.execute("ROLLBACK")
                raise
        return res

    # ---- consultas para la API ----------------------------------------------------
    def eventos(self, sensor_id: str | None, limite: int = 200) -> list[dict]:
        """Intentos recibidos (más recientes primero). sensor_id=None: todos los sensores."""
        with self.conexion() as con:
            if sensor_id is None:
                filas = con.execute(
                    "SELECT id, sensor_id, seq, timestamp_ms, valor, tag, estado, detalle, recibido_ms"
                    " FROM eventos ORDER BY id DESC LIMIT ?", (limite,)).fetchall()
            else:
                filas = con.execute(
                    "SELECT id, sensor_id, seq, timestamp_ms, valor, tag, estado, detalle, recibido_ms"
                    " FROM eventos WHERE sensor_id = ? ORDER BY id DESC LIMIT ?",
                    (sensor_id, limite)).fetchall()
        return [dict(f) for f in filas]

    def serie(self, sensor_id: str, limite: int = 1000) -> list[dict]:
        with self.conexion() as con:
            filas = con.execute(
                "SELECT seq, timestamp_ms, valor FROM ("
                "  SELECT seq, timestamp_ms, valor FROM mediciones WHERE sensor_id = ?"
                "  ORDER BY seq DESC LIMIT ?) ORDER BY seq ASC",
                (sensor_id, limite),
            ).fetchall()
        return [dict(f) for f in filas]

    def registros(self, sensor_id: str) -> list[RegistroGuardado]:
        with self.conexion() as con:
            filas = con.execute(
                "SELECT * FROM mediciones WHERE sensor_id = ? ORDER BY seq ASC", (sensor_id,)
            ).fetchall()
        return [self._registro(f) for f in filas]

