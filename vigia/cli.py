"""CLI de administración: python -m vigia.cli init | registrar-sensor <id> | revocar-sensor <id> | listar-sensores"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from vigia.config import Config, ConfigError, crear_directorio_privado, load_config
from vigia.crypto import keystore
from vigia.crypto.canonical import FormatoInvalido, mensaje_canonico
from vigia.crypto.mac import generar_llave_sensor
from vigia.server.db import ArranqueError, Database


def _escribir_llave(ruta: Path, llave: bytes) -> None:
    """Escribe la llave en hex con permiso 0600 (simula la entrega fuera de banda). No sobrescribe."""
    crear_directorio_privado(ruta.parent)
    fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(llave.hex() + "\n")


def cmd_init(cfg: Config, db: Database, _args) -> int:
    try:
        db.inicializar(cfg.master_password)
    except ArranqueError as exc:
        print(f"Aviso: {exc}")
        return 0
    print(f"Base de datos inicializada en {cfg.db_path} (salt Argon2id y canario creados).")
    return 0


def cmd_registrar(cfg: Config, db: Database, args) -> int:
    sensor_id = args.sensor_id
    try:
        mensaje_canonico(sensor_id, 1, 0, "0")  # reutiliza la validación de formato del módulo cripto
    except FormatoInvalido as exc:
        print(f"Error: id de sensor inválido: {exc}", file=sys.stderr)
        return 2
    kek = db.derivar_y_comprobar_kek(cfg.master_password)
    if db.existe_sensor(sensor_id):
        print(f"Error: el sensor '{sensor_id}' ya existe (no se reutilizan ids).", file=sys.stderr)
        return 1
    ruta = cfg.sensores_dir / f"{sensor_id}.key"
    if ruta.exists():
        print(f"Error: ya existe {ruta}; no se sobrescribe.", file=sys.stderr)
        return 1
    llave = generar_llave_sensor()
    nonce, ct = keystore.cifrar_llave_sensor(kek, sensor_id, llave)
    _escribir_llave(ruta, llave)
    try:
        db.insertar_sensor(sensor_id, nonce, ct)
    except Exception:
        ruta.unlink(missing_ok=True)
        raise
    print(f"Sensor '{sensor_id}' registrado. Llave entregada (fuera de banda) en {ruta} [0600].")
    return 0


def cmd_revocar(cfg: Config, db: Database, args) -> int:
    if not db.revocar_sensor(args.sensor_id):
        print(f"Error: el sensor '{args.sensor_id}' no existe.", file=sys.stderr)
        return 1
    print(f"Sensor '{args.sensor_id}' revocado: sus mediciones se rechazarán como FALSA.")
    return 0


def cmd_listar(cfg: Config, db: Database, _args) -> int:
    sensores = db.listar_sensores()
    if not sensores:
        print("No hay sensores registrados.")
        return 0
    print(f"{'ID':<24}{'ESTADO':<10}{'VERIFICADAS':<13}{'INTENTOS':<10}CREADO (UTC)")
    for s in sensores:
        creado = datetime.fromtimestamp(s["creado_ms"] / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        estado = "activo" if s["activo"] else "revocado"
        print(f"{s['id']:<24}{estado:<10}{s['verificadas']:<13}{s['intentos']:<10}{creado}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m vigia.cli", description="Administración de VIGÍA")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="inicializa la BD (salt Argon2id + canario)")
    r = sub.add_parser("registrar-sensor", help="registra un sensor y genera su llave")
    r.add_argument("sensor_id")
    v = sub.add_parser("revocar-sensor", help="desactiva un sensor")
    v.add_argument("sensor_id")
    sub.add_parser("listar-sensores", help="lista los sensores")
    args = p.parse_args(argv)

    try:
        cfg = load_config()
        db = Database(cfg.db_path)
        if args.cmd == "init":
            return cmd_init(cfg, db, args)
        if not db.inicializada():
            print("Error: la base de datos no está inicializada. Ejecuta: python -m vigia.cli init",
                  file=sys.stderr)
            return 1
        return {"registrar-sensor": cmd_registrar, "revocar-sensor": cmd_revocar,
                "listar-sensores": cmd_listar}[args.cmd](cfg, db, args)
    except (ConfigError, ArranqueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
