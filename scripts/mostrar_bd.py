"""Muestra la BD de VIGÍA tal como la vería un atacante que la roba (solo lectura).

Uso: python scripts/mostrar_bd.py [--db RUTA] [--sensores-dir DIR] [-n N]

- Abre SQLite en modo solo lectura (URI mode=ro).
- Muestra nonce y llave_cifrada de cada sensor en hex: ilegibles sin la contraseña maestra.
- Comprueba que la llave en claro de sensores/<id>.key NO aparece en el BLOB.
- Muestra las últimas N mediciones EN CLARO: están protegidas por integridad (HMAC + cadena
  de hashes), no por confidencialidad.
Nunca descifra nada ni lee VIGIA_MASTER_PASSWORD.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv


def _fecha(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _llave_en_archivo(ruta: Path) -> bytes | None:
    """Lee la llave en claro del archivo (solo para comparar; jamás se imprime)."""
    try:
        return bytes.fromhex(ruta.read_text().strip())
    except (OSError, ValueError):
        return None


def main(argv: list[str] | None = None) -> int:
    load_dotenv(override=False)
    p = argparse.ArgumentParser(description="Vista de solo lectura de la BD de VIGÍA")
    p.add_argument("--db", default=os.environ.get("VIGIA_DB_PATH", "data/vigia.db"))
    p.add_argument("--sensores-dir", default=os.environ.get("VIGIA_SENSORES_DIR", "sensores"))
    p.add_argument("-n", type=int, default=5, help="últimas N mediciones por mostrar")
    args = p.parse_args(argv)

    ruta = Path(args.db)
    if not ruta.is_file():
        print(f"Error: no existe la base de datos {ruta}", file=sys.stderr)
        return 1
    try:
        con = sqlite3.connect(f"{ruta.resolve().as_uri()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        print(f"Error al abrir la BD: {exc}", file=sys.stderr)
        return 1
    con.row_factory = sqlite3.Row

    try:
        print(f"BD: {ruta}  (abierta en modo solo lectura)\n")
        print("=== Tabla sensores: lo que ve un atacante con la BD robada ===")
        sensores = con.execute(
            "SELECT id, nonce, llave_cifrada, activo, creado_ms FROM sensores ORDER BY id").fetchall()
        if not sensores:
            print("(sin sensores)")
        for s in sensores:
            nonce, ct = bytes(s["nonce"]), bytes(s["llave_cifrada"])
            print(f"sensor        : {s['id']}  ({'activo' if s['activo'] else 'revocado'}, "
                  f"creado {_fecha(s['creado_ms'])} UTC)")
            print(f"nonce         : {nonce.hex()}  ({len(nonce)} B)")
            print(f"llave_cifrada : {ct.hex()}  ({len(ct)} B = 32 B cifrados + 16 B tag GCM)")
            llave = _llave_en_archivo(Path(args.sensores_dir) / f"{s['id']}.key")
            if llave is None:
                print("¿llave en claro en el BLOB?: no se pudo comparar (no existe "
                      f"{args.sensores_dir}/{s['id']}.key o no es hex válido)")
            elif llave in ct or llave.hex().encode() in ct:
                print("¿llave en claro en el BLOB?: SI  <-- PROBLEMA: la llave aparece sin cifrar")
                return 3
            else:
                print(f"¿llave en claro en el BLOB?: NO  (el contenido de {args.sensores_dir}/"
                      f"{s['id']}.key no aparece en llave_cifrada)")
            print()

        print("=== Tabla meta (parámetros públicos del KDF; la contraseña NO está aquí) ===")
        for f in con.execute("SELECT clave, valor FROM meta ORDER BY clave"):
            v = bytes(f["valor"]) if not isinstance(f["valor"], str) else f["valor"].encode()
            txt = v.decode() if f["clave"] == "kdf_params" else v.hex()
            print(f"{f['clave']:<14}: {txt}")

        print(f"\n=== Últimas {args.n} mediciones (EN CLARO: protegidas por integridad, "
              "no por confidencialidad) ===")
        filas = con.execute(
            "SELECT sensor_id, seq, timestamp_ms, valor, tag, hash_prev, hash FROM mediciones "
            "ORDER BY id DESC LIMIT ?", (max(args.n, 0),)).fetchall()
        if not filas:
            print("(sin mediciones)")
        for m in reversed(filas):
            print(f"{m['sensor_id']} seq={m['seq']} t={_fecha(m['timestamp_ms'])} UTC valor={m['valor']}")
            print(f"  tag       : {m['tag']}")
            print(f"  hash_prev : {m['hash_prev']}")
            print(f"  hash      : {m['hash']}")
        print("\nUn atacante puede LEER estos valores, pero si los modifica el HMAC y la cadena de "
              "hashes dejan de cuadrar\n(botón 'Verificar historial completo' -> MANIPULADA / CADENA ROTA).")
    except sqlite3.Error as exc:
        print(f"Error leyendo la BD: {exc}", file=sys.stderr)
        return 1
    finally:
        con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
