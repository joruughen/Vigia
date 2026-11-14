"""API FastAPI de VIGÍA: ingesta verificada, consulta y dashboard."""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Path as PathParam, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from vigia.config import Config
from vigia.crypto.keystore import ContrasenaIncorrecta
from vigia.crypto.canonical import FormatoInvalido, mensaje_canonico
from vigia.crypto.verifier import Medicion, verificar_historial
from vigia.server.db import Database, ahora_ms

log = logging.getLogger("vigia")
STATIC_DIR = Path(__file__).parent / "static"
ID_PATRON = r"^[A-Za-z0-9_-]{1,64}$"
INT64_MAX = 2**63 - 1

CSP = ("default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; "
       "style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "object-src 'none'; base-uri 'none'; frame-ancestors 'none'")


class MedicionIn(BaseModel):
    """Payload del sensor (contrato §3). El formato fino lo valida vigia.crypto.canonical."""
    model_config = ConfigDict(extra="forbid")

    sensor_id: StrictStr = Field(max_length=64)
    seq: StrictInt = Field(ge=1, le=INT64_MAX)
    timestamp_ms: StrictInt = Field(ge=0, le=INT64_MAX)
    valor: StrictStr = Field(max_length=32)
    tag: StrictStr = Field(max_length=128)


def create_app(config: Config) -> FastAPI:
    """Factoría de la app. Deriva la KEK (Argon2id) una sola vez y valida la contraseña.

    Lanza vigia.server.db.ArranqueError si la BD no está inicializada o la contraseña es incorrecta.
    """
    db = Database(config.db_path)
    kek = db.derivar_y_comprobar_kek(config.master_password)

    app = FastAPI(title="VIGÍA", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.db = db
    app.state.config = config
    app.state.kek = kek  # solo en memoria; nunca se serializa en respuestas

    @app.middleware("http")
    async def cabeceras_seguridad(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        if request.url.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.exception_handler(FormatoInvalido)
    async def formato_invalido(_: Request, exc: FormatoInvalido):
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(ContrasenaIncorrecta)
    async def llave_ilegible(request: Request, _: ContrasenaIncorrecta):
        # Blob de llave corrupto/alterado en la BD: respuesta genérica, sin traceback ni detalles.
        log.error("llave de sensor ilegible (blob corrupto o alterado) en %s", request.url.path)
        return JSONResponse(status_code=500, content={"error": "llave de sensor ilegible"})

    @app.post("/api/mediciones")
    def recibir_medicion(entrada: MedicionIn):
        # Valida el formato canónico ANTES de tocar la BD (FormatoInvalido -> 422).
        mensaje_canonico(entrada.sensor_id, entrada.seq, entrada.timestamp_ms, entrada.valor)
        m = Medicion(sensor_id=entrada.sensor_id, seq=entrada.seq,
                     timestamp_ms=entrada.timestamp_ms, valor=entrada.valor, tag=entrada.tag)
        res = db.ingestar(m, kek, ahora_ms(), config.ventana_ms)
        return {"estado": res.estado.value, "detalle": res.detalle}

    @app.get("/api/config")
    def ver_config():
        return {"ventana_ms": config.ventana_ms,
                "autenticacion": "HMAC-SHA256 (llave de 256 bits por sensor)",
                "cadena": "SHA-256 con tag incluido",
                "llaves_en_reposo": "AES-256-GCM, KEK derivada con Argon2id",
                "transporte": "TLS 1.3"}

    @app.get("/api/sensores")
    def listar_sensores():
        return db.listar_sensores()

    @app.get("/api/eventos")
    def eventos_recientes(limite: int = Query(50, ge=1, le=500)):
        return db.eventos(None, limite)

    def _exigir_sensor(sensor_id: str) -> None:
        if not db.existe_sensor(sensor_id):
            raise HTTPException(status_code=404, detail="Sensor no registrado")

    @app.get("/api/sensores/{sensor_id}/eventos")
    def eventos_sensor(sensor_id: str = PathParam(pattern=ID_PATRON),
                       limite: int = Query(200, ge=1, le=1000)):
        _exigir_sensor(sensor_id)
        return db.eventos(sensor_id, limite)

    @app.get("/api/sensores/{sensor_id}/serie")
    def serie_sensor(sensor_id: str = PathParam(pattern=ID_PATRON),
                     limite: int = Query(500, ge=1, le=5000)):
        _exigir_sensor(sensor_id)
        return db.serie(sensor_id, limite)

    @app.post("/api/sensores/{sensor_id}/verificar-historial")
    def verificar_historial_sensor(sensor_id: str = PathParam(pattern=ID_PATRON)):
        llave = db.llave_para_historial(sensor_id, kek)
        if llave is None:
            raise HTTPException(status_code=404, detail="Sensor no registrado")
        rep = verificar_historial(sensor_id, db.registros(sensor_id), llave)
        return {"sensor_id": rep.sensor_id, "integro": rep.integro, "total": rep.total,
                "registros": [{"seq": r.seq, "estado": r.estado.value, "detalle": r.detalle}
                              for r in rep.registros]}

    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app
