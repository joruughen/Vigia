"""Configuración de VIGÍA: variables de entorno (y .env si existe)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


class ConfigError(Exception):
    """Configuración faltante o inválida."""


@dataclass(frozen=True)
class Config:
    master_password: str
    db_path: Path
    ventana_ms: int
    sensores_dir: Path

    def __repr__(self) -> str:  # nunca mostrar la contraseña en logs
        return (f"Config(db_path={self.db_path!s}, ventana_ms={self.ventana_ms}, "
                f"sensores_dir={self.sensores_dir!s}, master_password=***)")


def load_config() -> Config:
    """Lee la configuración. Las variables ya presentes en el entorno tienen prioridad sobre .env."""
    load_dotenv(override=False)
    password = os.environ.get("VIGIA_MASTER_PASSWORD", "")
    if not password:
        raise ConfigError(
            "Falta VIGIA_MASTER_PASSWORD (defínela en .env o en el entorno; ver .env.example)."
        )
    try:
        ventana_ms = int(os.environ.get("VIGIA_VENTANA_MS", "30000"))
    except ValueError as exc:
        raise ConfigError("VIGIA_VENTANA_MS debe ser un entero (milisegundos).") from exc
    if ventana_ms < 0:
        raise ConfigError("VIGIA_VENTANA_MS no puede ser negativo.")
    db_path = Path(os.environ.get("VIGIA_DB_PATH", "data/vigia.db"))
    db_path.parent.mkdir(parents=True, exist_ok=True)
    sensores_dir = Path(os.environ.get("VIGIA_SENSORES_DIR", "sensores"))
    return Config(master_password=password, db_path=db_path,
                  ventana_ms=ventana_ms, sensores_dir=sensores_dir)
