"""Simulador de sensor de VIGÍA.

Uso: python -m vigia.sensor --sensor sensor-01 --url https://127.0.0.1:8443 \
         --intervalo 2 --cacert certs/cert.pem [--n N]
"""
from __future__ import annotations

import argparse
import math
import os
import random
import ssl
import sys
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv

from vigia.crypto.canonical import mensaje_canonico
from vigia.crypto.mac import calcular_tag


def construir_medicion(sensor_id: str, llave: bytes, seq: int, timestamp_ms: int, valor: str) -> dict:
    """Payload del contrato §3 con su tag HMAC-SHA256. `valor` es el string que se autentica tal cual."""
    tag = calcular_tag(llave, mensaje_canonico(sensor_id, seq, timestamp_ms, valor))
    return {"sensor_id": sensor_id, "seq": seq, "timestamp_ms": timestamp_ms, "valor": valor, "tag": tag}


def generar_valor(t_s: float) -> str:
    """Temperatura realista (°C): base + oscilación lenta + ruido; string con 3 decimales."""
    v = 22.0 + 3.0 * math.sin(t_s / 90.0) + random.gauss(0, 0.25)  # nosec B311 (simulación, no cripto)
    return f"{v:.3f}"


def leer_llave(ruta: Path) -> bytes:
    return bytes.fromhex(ruta.read_text().strip())


def leer_seq(ruta: Path) -> int:
    try:
        return int(ruta.read_text().strip())
    except (FileNotFoundError, ValueError):
        return 0


def guardar_seq(ruta: Path, seq: int) -> None:
    tmp = ruta.with_suffix(".seq.tmp")
    tmp.write_text(f"{seq}\n")
    os.replace(tmp, ruta)


def contexto_tls(cacert: str) -> ssl.SSLContext:
    """Verifica el certificado del servidor contra --cacert (nunca verify=False); exige TLS 1.3."""
    ctx = ssl.create_default_context(cafile=cacert)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def main(argv: list[str] | None = None) -> int:
    load_dotenv(override=False)
    p = argparse.ArgumentParser(prog="python -m vigia.sensor", description="Simulador de sensor VIGÍA")
    p.add_argument("--sensor", required=True, help="id del sensor (p.ej. sensor-01)")
    p.add_argument("--url", default="https://127.0.0.1:8443")
    p.add_argument("--intervalo", type=float, default=2.0, help="segundos entre mediciones")
    p.add_argument("--cacert", required=True, help="certificado (CA) con el que se verifica al servidor")
    p.add_argument("--n", type=int, default=0, help="número de mediciones a enviar (0 = sin límite)")
    p.add_argument("--sensores-dir", default=os.environ.get("VIGIA_SENSORES_DIR", "sensores"))
    args = p.parse_args(argv)

    base = Path(args.sensores_dir)
    ruta_llave, ruta_seq = base / f"{args.sensor}.key", base / f"{args.sensor}.seq"
    try:
        llave = leer_llave(ruta_llave)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: no se pudo leer la llave en {ruta_llave}: {exc}", file=sys.stderr)
        return 1

    seq = leer_seq(ruta_seq)
    enviados = 0
    t0 = time.monotonic()
    with httpx.Client(base_url=args.url, verify=contexto_tls(args.cacert), timeout=10.0) as cliente:
        try:
            while args.n == 0 or enviados < args.n:
                siguiente = seq + 1
                valor = generar_valor(time.monotonic() - t0)
                payload = construir_medicion(args.sensor, llave, siguiente, time.time_ns() // 1_000_000, valor)
                try:
                    resp = cliente.post("/api/mediciones", json=payload)
                except httpx.HTTPError as exc:
                    print(f"[seq {siguiente}] error de conexión: {exc}", file=sys.stderr)
                else:
                    if resp.status_code == 200:
                        r = resp.json()
                        print(f"[seq {siguiente}] valor={valor} -> {r['estado']} ({r['detalle']})")
                        if r["estado"] == "VERIFICADA":
                            seq = siguiente
                            guardar_seq(ruta_seq, seq)
                    else:
                        print(f"[seq {siguiente}] HTTP {resp.status_code}: {resp.text}", file=sys.stderr)
                enviados += 1
                if args.n == 0 or enviados < args.n:
                    time.sleep(args.intervalo)
        except KeyboardInterrupt:
            print("\nSimulador detenido.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
