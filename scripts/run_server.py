"""Arranca VIGÍA sobre HTTPS (TLS 1.3 como versión mínima) en 127.0.0.1:8443.

Uso: python scripts/run_server.py   (requiere certs/cert.pem y certs/key.pem; ver scripts/generar_cert.sh)
"""
import os
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn  # noqa: E402

from vigia.config import ConfigError, load_config  # noqa: E402
from vigia.server.app import create_app  # noqa: E402
from vigia.server.db import ArranqueError  # noqa: E402


def main() -> int:
    certs = Path(os.environ.get("VIGIA_CERTS_DIR", "certs"))
    cert, key = certs / "cert.pem", certs / "key.pem"
    host = os.environ.get("VIGIA_HOST", "127.0.0.1")
    port = int(os.environ.get("VIGIA_PORT", "8443"))
    if not (cert.is_file() and key.is_file()):
        print(f"Error: faltan {cert} / {key}. Ejecuta scripts/generar_cert.sh", file=sys.stderr)
        return 1
    try:
        app = create_app(load_config())
    except (ConfigError, ArranqueError) as exc:
        print(f"Error de arranque: {exc}", file=sys.stderr)
        return 1

    config = uvicorn.Config(app, host=host, port=port, ssl_certfile=str(cert), ssl_keyfile=str(key),
                            log_level="info")
    config.load()  # crea config.ssl (SSLContext)
    config.ssl.minimum_version = ssl.TLSVersion.TLSv1_3
    uvicorn.Server(config).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
