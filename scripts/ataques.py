"""Ataques para la demo en vivo de VIGÍA.

Uso (con la demo levantada por scripts/demo.sh up):
    python scripts/ataques.py <ataque> [--restaurar] [--no-color]
    python scripts/ataques.py todos            # todos, en orden, con tabla resumen
    python scripts/ataques.py restaurar        # deshace el daño en BD de ataques previos

Habla con el servidor por HTTPS validando el certificado (--cacert) y lee la configuración de
demo-run/.env (rutas, host, puerto). NO lee la contraseña maestra ni imprime llaves: las llaves de
sensor se leen de VIGIA_SENSORES_DIR/<id>.key solo para firmar (como lo haría el propio sensor).
Los ataques que alteran la BD usan sensor-02 para no interrumpir a sensor-01.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sqlite3
import sys
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402
from dotenv import dotenv_values  # noqa: E402

from vigia.crypto.chain import siguiente_hash  # noqa: E402
from vigia.crypto.mac import generar_llave_sensor  # noqa: E402
from vigia.sensor import construir_medicion, contexto_tls, generar_valor, leer_llave  # noqa: E402

SENSOR_BD = "sensor-02"        # víctima de los ataques que alteran la BD / consumen secuencia
SENSOR_LECTURA = "sensor-01"   # el que envía el simulador: solo se lee o se usa sin guardar nada
MIN_HISTORIAL = 4              # mediciones previas para tener un registro "intermedio"
VERIFICADA = "VERIFICADA"


class AtaqueError(Exception):
    """Error de preparación/ejecución con mensaje claro para el presentador."""


# ---------------------------------------------------------------- salida en terminal
class Salida:
    def __init__(self, color: bool):
        self.color = color

    def _c(self, codigo: str, txt: str) -> str:
        return f"\033[{codigo}m{txt}\033[0m" if self.color else txt

    def titulo(self, txt: str) -> None:
        print("\n" + self._c("1;36", f"=== {txt} ==="))

    def campo(self, nombre: str, txt: str) -> None:
        print(f"  {self._c('1', f'{nombre:<10}')}: {txt}")

    def nota(self, txt: str) -> None:
        print(self._c("2", f"  {txt}"))

    def estado(self, estado: str, ok: bool | None = None) -> str:
        if estado == VERIFICADA:
            return self._c("1;32", estado)
        return self._c("1;31" if ok is not False else "1;33", estado)

    def veredicto(self, ok: bool) -> str:
        return self._c("1;32", "OK") if ok else self._c("1;31", "FALLO")

    def error(self, txt: str) -> None:
        print(self._c("1;31", f"Error: {txt}"), file=sys.stderr)


@dataclass
class Resultado:
    nombre: str
    esperado: str
    obtenido: str

    @property
    def ok(self) -> bool:
        return self.obtenido == self.esperado


# ---------------------------------------------------------------- contexto (config, HTTP, BD)
class Contexto:
    def __init__(self, env: Path, cacert: str | None, url: str | None, out: Salida):
        if not env.is_file():
            raise AtaqueError(f"no existe {env}; levanta la demo con: scripts/demo.sh up")
        cfg = dotenv_values(env)  # solo se leen rutas y host/puerto (nunca la contraseña maestra)
        self.db = Path(cfg.get("VIGIA_DB_PATH") or "data/vigia.db")
        self.sensores_dir = Path(cfg.get("VIGIA_SENSORES_DIR") or "sensores")
        certs = Path(cfg.get("VIGIA_CERTS_DIR") or "certs")
        host, puerto = cfg.get("VIGIA_HOST") or "127.0.0.1", cfg.get("VIGIA_PORT") or "8443"
        self.url = url or f"https://{host}:{puerto}"
        self.cacert = cacert or str(certs / "cert.pem")
        self.estado_restauracion = env.parent / "ataques-restaurar.json"
        self.out = out
        if not Path(self.cacert).is_file():
            raise AtaqueError(f"no existe el certificado {self.cacert} (usa --cacert)")
        if not self.db.is_file():
            raise AtaqueError(f"no existe la BD {self.db}; levanta la demo con: scripts/demo.sh up")
        self.http = httpx.Client(base_url=self.url, verify=contexto_tls(self.cacert), timeout=15.0)
        try:
            self.ventana_ms = int(self.http.get("/api/config").json()["ventana_ms"])
        except httpx.HTTPError as exc:
            raise AtaqueError(f"el servidor no responde en {self.url} ({type(exc).__name__}: {exc}); "
                              "¿está levantado? scripts/demo.sh status") from exc

    def llave(self, sensor_id: str) -> bytes:
        ruta = self.sensores_dir / f"{sensor_id}.key"
        try:
            return leer_llave(ruta)
        except (OSError, ValueError) as exc:
            raise AtaqueError(f"no se pudo leer la llave de {sensor_id} en {ruta}: {exc}") from exc

    def conectar_bd(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db, timeout=30)
        con.row_factory = sqlite3.Row
        return con

    # --- API
    def enviar(self, payload: dict) -> tuple[str, str]:
        """POST /api/mediciones -> (estado, detalle). Errores HTTP se devuelven como 'HTTP <código>'."""
        resp = self.http.post("/api/mediciones", json=payload)
        if resp.status_code == 200:
            r = resp.json()
            return r["estado"], r["detalle"]
        return f"HTTP {resp.status_code}", resp.text[:200]

    def ultima_seq(self, sensor_id: str) -> int:
        for s in self.http.get("/api/sensores").json():
            if s["id"] == sensor_id:
                return s["ultima_seq"] or 0
        raise AtaqueError(f"el sensor {sensor_id} no está registrado (scripts/demo.sh up lo registra)")

    def historial(self, sensor_id: str) -> dict:
        resp = self.http.post(f"/api/sensores/{sensor_id}/verificar-historial")
        if resp.status_code != 200:
            raise AtaqueError(f"verificar-historial de {sensor_id}: HTTP {resp.status_code}")
        return resp.json()


def ahora_ms() -> int:
    return time.time_ns() // 1_000_000


def hora(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%H:%M:%S")


def resumen(p: dict) -> str:
    return (f"{p['sensor_id']} seq={p['seq']} t={hora(p['timestamp_ms'])}Z valor={p['valor']} "
            f"tag={p['tag'][:16]}…")


def firmar(ctx: Contexto, sensor_id: str, seq: int, ts_ms: int | None = None, valor: str | None = None) -> dict:
    return construir_medicion(sensor_id, ctx.llave(sensor_id), seq, ts_ms if ts_ms is not None else ahora_ms(),
                              valor if valor is not None else generar_valor(0.0))


def asegurar_historial(ctx: Contexto, minimo: int = MIN_HISTORIAL) -> None:
    """Envía (firmadas con la llave de sensor-02) las mediciones válidas necesarias para el ataque."""
    seq = ctx.ultima_seq(SENSOR_BD)
    while seq < minimo:
        estado, detalle = ctx.enviar(firmar(ctx, SENSOR_BD, seq + 1))
        if estado != VERIFICADA:
            raise AtaqueError(
                f"no se pudo preparar el historial de {SENSOR_BD}: {estado} ({detalle}). "
                "¿Daño de un ataque previo en la BD? Ejecuta: scripts/ataques.py restaurar "
                "(o scripts/demo.sh reset && scripts/demo.sh up)")
        seq += 1


# ---------------------------------------------------------------- estado para restaurar la BD
def guardar_restauracion(ctx: Contexto, op: dict) -> None:
    ops = json.loads(ctx.estado_restauracion.read_text()) if ctx.estado_restauracion.is_file() else []
    ops.append(op)
    tmp = ctx.estado_restauracion.with_suffix(".tmp")
    tmp.write_text(json.dumps(ops))
    os.replace(tmp, ctx.estado_restauracion)


def restaurar(ctx: Contexto, silencioso: bool = False) -> int:
    """Deshace (en orden inverso) los daños registrados por los ataques sobre la BD."""
    if not ctx.estado_restauracion.is_file():
        if not silencioso:
            ctx.out.nota("No hay daños en BD pendientes de restaurar.")
        return 0
    ops = json.loads(ctx.estado_restauracion.read_text())
    with closing(ctx.conectar_bd()) as con, con:
        for op in reversed(ops):
            if op["tipo"] == "valor":
                con.execute("UPDATE mediciones SET valor = ? WHERE sensor_id = ? AND seq = ?",
                            (op["valor"], op["sensor_id"], op["seq"]))
            elif op["tipo"] == "hash":
                con.execute("UPDATE mediciones SET hash = ? WHERE sensor_id = ? AND seq = ?",
                            (op["hash"], op["sensor_id"], op["seq"]))
            elif op["tipo"] == "fila":
                f = op["fila"]
                con.execute(
                    "INSERT OR IGNORE INTO mediciones (id, sensor_id, seq, timestamp_ms, valor, tag, hash_prev, hash)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (f["id"], f["sensor_id"], f["seq"], f["timestamp_ms"], f["valor"], f["tag"],
                     f["hash_prev"], f["hash"]))
    ctx.estado_restauracion.unlink()
    if not silencioso:
        ctx.out.nota(f"BD restaurada ({len(ops)} operación(es) deshecha(s)).")
    return 0


# ---------------------------------------------------------------- ataques por la API
def _mostrar_envio(ctx: Contexto, payload: dict, esperado: str, detalle_esperado: str | None = None
                   ) -> tuple[str, str]:
    ctx.out.campo("Enviado", resumen(payload))
    estado, detalle = ctx.enviar(payload)
    ok = estado == esperado and (detalle_esperado is None or detalle.startswith(detalle_esperado))
    ctx.out.campo("Respuesta", f"{ctx.out.estado(estado, ok)} ({detalle})")
    return estado, detalle


def ataque_manipulada(ctx: Contexto, _args) -> Resultado:
    ctx.out.titulo("ATAQUE: manipulada (valor alterado en tránsito)")
    ctx.out.campo("Qué hace", f"firma una medición válida de {SENSOR_BD} y cambia el valor antes de enviarla; "
                  "el tag ya no corresponde al contenido")
    seq = ctx.ultima_seq(SENSOR_BD) + 1
    payload = firmar(ctx, SENSOR_BD, seq, valor="22.500")
    ctx.out.campo("Firmado", f"valor={payload['valor']}")
    payload["valor"] = "99.900"
    estado, _ = _mostrar_envio(ctx, payload, "MANIPULADA")
    ctx.out.nota("El atacante no conoce la llave K: no puede recalcular el HMAC del valor nuevo.")
    return Resultado("manipulada", "MANIPULADA", estado)


def ataque_falsa(ctx: Contexto, args) -> Resultado:
    if args.id_valido:
        ctx.out.titulo(f"ATAQUE: falsa --id-valido (se hace pasar por {SENSOR_LECTURA} sin su llave)")
        ctx.out.campo("Qué hace", f"envía como {SENSOR_LECTURA} (seq correcta) una medición firmada con una "
                      "llave aleatoria distinta de la suya")
        seq = ctx.ultima_seq(SENSOR_LECTURA) + 1
        payload = construir_medicion(SENSOR_LECTURA, generar_llave_sensor(), seq, ahora_ms(), "21.000")
        estado, _ = _mostrar_envio(ctx, payload, "MANIPULADA")
        ctx.out.nota("Id existente pero tag inválido: el servidor lo trata como MANIPULADA (HMAC no verifica).")
        return Resultado("falsa --id-valido", "MANIPULADA", estado)
    ctx.out.titulo("ATAQUE: falsa (sensor inexistente)")
    ctx.out.campo("Qué hace", "envía una medición de un sensor no registrado (sensor-99) con un tag aleatorio")
    payload = {"sensor_id": "sensor-99", "seq": 1, "timestamp_ms": ahora_ms(), "valor": "21.000",
               "tag": secrets.token_hex(32)}
    estado, _ = _mostrar_envio(ctx, payload, "FALSA")
    ctx.out.nota("Sin llave registrada no hay con qué verificar: se rechaza en el paso 1.")
    return Resultado("falsa", "FALSA", estado)


def _ultima_verificada(ctx: Contexto, sensor_id: str) -> dict:
    with closing(ctx.conectar_bd()) as con:
        f = con.execute("SELECT sensor_id, seq, timestamp_ms, valor, tag FROM mediciones "
                        "WHERE sensor_id = ? ORDER BY seq DESC LIMIT 1", (sensor_id,)).fetchone()
    if f is None:
        raise AtaqueError(f"{sensor_id} aún no tiene mediciones VERIFICADAS (¿corre el simulador? "
                          "scripts/demo.sh status)")
    return dict(f)


def ataque_replay(ctx: Contexto, _args) -> Resultado:
    ctx.out.titulo("ATAQUE: replay (reenvío exacto de una medición ya aceptada)")
    ctx.out.campo("Qué hace", f"captura la última medición VERIFICADA de {SENSOR_LECTURA} (leyéndola de la BD) "
                  "y la reenvía idéntica, con su tag original")
    payload = _ultima_verificada(ctx, SENSOR_LECTURA)
    estado, detalle = _mostrar_envio(ctx, payload, "REPLAY O HUECO", "replay")
    ctx.out.nota("El tag es válido, pero la seq ya fue consumida: el paso 3 exige seq == última + 1.")
    obtenido = estado if detalle.startswith("replay") else f"{estado} (detalle: {detalle})"
    return Resultado("replay", "REPLAY O HUECO", obtenido)


def ataque_hueco(ctx: Contexto, _args) -> Resultado:
    ctx.out.titulo("ATAQUE: hueco (mensaje perdido o suprimido)")
    asegurar_historial(ctx, 1)
    ultima = ctx.ultima_seq(SENSOR_BD)
    ctx.out.campo("Qué hace", f"con la llave de {SENSOR_BD} envía la seq {ultima + 2} (última aceptada: {ultima}), "
                  "como si el mensaje intermedio se hubiera perdido")
    payload = firmar(ctx, SENSOR_BD, ultima + 2)
    estado, detalle = _mostrar_envio(ctx, payload, "REPLAY O HUECO", "hueco")
    obtenido = estado if detalle.startswith("hueco") else f"{estado} (detalle: {detalle})"
    ctx.out.nota("El rechazado NO se guarda en mediciones, así que no bloquea al sensor: "
                 f"su siguiente seq correcta ({ultima + 1}) sigue siendo aceptada.")
    rec_estado, rec_det = ctx.enviar(firmar(ctx, SENSOR_BD, ultima + 1))
    ctx.out.campo("Recupera", f"seq {ultima + 1} -> {ctx.out.estado(rec_estado)} ({rec_det})")
    if rec_estado != VERIFICADA:
        obtenido += f" [sin recuperación: {rec_estado}]"
    return Resultado("hueco", "REPLAY O HUECO", obtenido)


def ataque_fuera_ventana(ctx: Contexto, _args) -> Resultado:
    ctx.out.titulo("ATAQUE: fuera-ventana (mensaje retenido y entregado tarde)")
    asegurar_historial(ctx, 1)
    atraso_ms = max(120_000, 2 * ctx.ventana_ms)
    seq = ctx.ultima_seq(SENSOR_BD) + 1
    ctx.out.campo("Qué hace", f"mensaje válido de {SENSOR_BD} con seq correcta ({seq}) pero firmado con timestamp "
                  f"de hace {atraso_ms // 1000} s, como si un atacante lo hubiera retenido "
                  f"(ventana permitida: {ctx.ventana_ms // 1000} s)")
    payload = firmar(ctx, SENSOR_BD, seq, ts_ms=ahora_ms() - atraso_ms)
    estado, _ = _mostrar_envio(ctx, payload, "FUERA DE VENTANA")
    ctx.out.nota("HMAC y seq son correctos; solo el paso 4 (frescura del timestamp) lo detiene.")
    return Resultado("fuera-ventana", "FUERA DE VENTANA", estado)


# ---------------------------------------------------------------- ataques directos a la BD
def _estados(rep: dict) -> dict[int, str]:
    return {r["seq"]: r["estado"] for r in rep["registros"]}


def _mostrar_historial(ctx: Contexto, rep: dict, cambiados: dict[int, str]) -> None:
    ctx.out.campo("Historial", f"integro={str(rep['integro']).lower()} ({rep['total']} registros)")
    detalles = {r["seq"]: r["detalle"] for r in rep["registros"]}
    for seq, estado in sorted(cambiados.items()):
        ctx.out.campo(f"  seq {seq}", f"{ctx.out.estado(estado, True)} ({detalles.get(seq, '')})")


def _registro_intermedio(ctx: Contexto) -> sqlite3.Row:
    with closing(ctx.conectar_bd()) as con:
        filas = con.execute("SELECT * FROM mediciones WHERE sensor_id = ? ORDER BY seq", (SENSOR_BD,)).fetchall()
    if len(filas) < 3:
        raise AtaqueError(f"{SENSOR_BD} necesita al menos 3 registros (hay {len(filas)})")
    return filas[len(filas) // 2]  # nunca el primero ni el último (len >= 3)


def _cambios(antes: dict[int, str], despues: dict[int, str]) -> dict[int, str]:
    return {s: e for s, e in despues.items() if e != VERIFICADA and antes.get(s) != e}


def _verificar_tras_ataque(ctx: Contexto, antes: dict[int, str], esperado: dict[int, str]) -> tuple[str, dict]:
    rep = ctx.historial(SENSOR_BD)
    cambiados = _cambios(antes, _estados(rep))
    _mostrar_historial(ctx, rep, cambiados)
    if cambiados == esperado and not rep["integro"]:
        return next(iter(esperado.values())), rep
    return f"inesperado: {cambiados or 'sin cambios'}", rep


def ataque_bd_alterar_valor(ctx: Contexto, args) -> Resultado:
    ctx.out.titulo("ATAQUE: bd-alterar-valor (atacante con escritura en la BD edita un valor)")
    asegurar_historial(ctx)
    antes = _estados(ctx.historial(SENSOR_BD))
    fila = _registro_intermedio(ctx)
    try:
        nuevo = f"{float(fila['valor']) + 10:.3f}"
    except ValueError:
        nuevo = "99.999"
    ctx.out.campo("Qué hace", f"UPDATE directo en SQLite: valor de {SENSOR_BD} seq {fila['seq']} "
                  f"{fila['valor']} -> {nuevo} (el tag y los hashes quedan como estaban)")
    guardar_restauracion(ctx, {"tipo": "valor", "sensor_id": SENSOR_BD, "seq": fila["seq"], "valor": fila["valor"]})
    with closing(ctx.conectar_bd()) as con, con:
        con.execute("UPDATE mediciones SET valor = ? WHERE sensor_id = ? AND seq = ?",
                    (nuevo, SENSOR_BD, fila["seq"]))
    ctx.out.campo("Acción", "POST /api/sensores/sensor-02/verificar-historial")
    obtenido, _ = _verificar_tras_ataque(ctx, antes, {fila["seq"]: "MANIPULADA"})
    ctx.out.nota("El HMAC del registro editado ya no cuadra; el resto de la cadena sigue íntegra.")
    _fin_bd(ctx, args)
    return Resultado("bd-alterar-valor", "MANIPULADA", obtenido)


def ataque_bd_borrar(ctx: Contexto, args) -> Resultado:
    ctx.out.titulo("ATAQUE: bd-borrar (atacante con escritura en la BD borra una medición)")
    asegurar_historial(ctx)
    antes = _estados(ctx.historial(SENSOR_BD))
    fila = _registro_intermedio(ctx)
    ctx.out.campo("Qué hace", f"DELETE directo en SQLite del registro de {SENSOR_BD} seq {fila['seq']} "
                  "(intermedio)")
    guardar_restauracion(ctx, {"tipo": "fila", "fila": dict(fila)})
    with closing(ctx.conectar_bd()) as con, con:
        con.execute("DELETE FROM mediciones WHERE sensor_id = ? AND seq = ?", (SENSOR_BD, fila["seq"]))
    ctx.out.campo("Acción", "POST /api/sensores/sensor-02/verificar-historial")
    obtenido, _ = _verificar_tras_ataque(ctx, antes, {fila["seq"] + 1: "CADENA ROTA"})
    ctx.out.nota("El registro siguiente apunta (hash_prev) a un hash que ya no existe: se localiza el borrado.")
    _fin_bd(ctx, args)
    return Resultado("bd-borrar", "CADENA ROTA", obtenido)


def ataque_cadena_rota(ctx: Contexto, args) -> Resultado:
    ctx.out.titulo("ATAQUE: cadena-rota (se corrompe el último eslabón y llega la siguiente medición)")
    asegurar_historial(ctx, 1)
    with closing(ctx.conectar_bd()) as con:
        ultimo = con.execute("SELECT seq, hash FROM mediciones WHERE sensor_id = ? ORDER BY seq DESC LIMIT 1",
                             (SENSOR_BD,)).fetchone()
    corrupto = ("1" if ultimo["hash"][0] == "0" else "0") + ultimo["hash"][1:]
    ctx.out.campo("Qué hace", f"UPDATE del hash guardado del último registro de {SENSOR_BD} (seq {ultimo['seq']}) "
                  f"{ultimo['hash'][:16]}… -> {corrupto[:16]}… y luego envía la siguiente medición válida")
    guardar_restauracion(ctx, {"tipo": "hash", "sensor_id": SENSOR_BD, "seq": ultimo["seq"], "hash": ultimo["hash"]})
    with closing(ctx.conectar_bd()) as con, con:
        con.execute("UPDATE mediciones SET hash = ? WHERE sensor_id = ? AND seq = ?",
                    (corrupto, SENSOR_BD, ultimo["seq"]))
    estado, _ = _mostrar_envio(ctx, firmar(ctx, SENSOR_BD, ultimo["seq"] + 1), "CADENA ROTA")
    ctx.out.nota("HMAC, seq y timestamp son correctos, pero el servidor no encadena sobre una base corrupta: "
                 f"{SENSOR_BD} queda bloqueado hasta restaurar (scripts/ataques.py restaurar).")
    _fin_bd(ctx, args)
    return Resultado("cadena-rota", "CADENA ROTA", estado)


def _fin_bd(ctx: Contexto, args) -> None:
    if getattr(args, "restaurar", False) or getattr(args, "_restaurar_auto", False):
        restaurar(ctx)
    else:
        ctx.out.nota("Daño dejado en la BD (visible con 'Verificar historial' en el dashboard). "
                     "Deshacer: scripts/ataques.py restaurar")


# ---------------------------------------------------------------- todos
def ataque_todos(ctx: Contexto, args) -> None:
    ctx.out.titulo("TODOS LOS ATAQUES")
    restaurar(ctx, silencioso=True)  # parte de una BD sana
    asegurar_historial(ctx)
    args._restaurar_auto = True      # cada ataque a la BD se deshace al terminar
    ns = argparse.Namespace
    plan = [
        ("manipulada", ataque_manipulada, ns()),
        ("falsa", ataque_falsa, ns(id_valido=False)),
        ("falsa --id-valido", ataque_falsa, ns(id_valido=True)),
        ("replay", ataque_replay, ns()),
        ("fuera-ventana", ataque_fuera_ventana, ns()),
        ("hueco", ataque_hueco, ns()),
        ("bd-alterar-valor", ataque_bd_alterar_valor, args),
        ("bd-borrar", ataque_bd_borrar, args),
        ("cadena-rota", ataque_cadena_rota, args),  # bloquea a sensor-02: siempre al final
    ]
    esperados = {"manipulada": "MANIPULADA", "falsa": "FALSA", "falsa --id-valido": "MANIPULADA",
                 "replay": "REPLAY O HUECO", "fuera-ventana": "FUERA DE VENTANA", "hueco": "REPLAY O HUECO",
                 "bd-alterar-valor": "MANIPULADA", "bd-borrar": "CADENA ROTA", "cadena-rota": "CADENA ROTA"}
    resultados: list[Resultado] = []
    for nombre, fn, a in plan:
        try:
            resultados.append(fn(ctx, a))
        except AtaqueError as exc:
            ctx.out.error(f"{nombre}: {exc}")
            resultados.append(Resultado(nombre, esperados[nombre], "ERROR"))
            restaurar(ctx, silencioso=True)
    tabla_resumen(ctx.out, resultados)
    args._resultados = resultados
    return None


def tabla_resumen(out: Salida, resultados: list[Resultado]) -> None:
    out.titulo("RESUMEN")
    print(f"  {'ATAQUE':<20}{'ESPERADO':<20}{'OBTENIDO':<20}RESULTADO")
    for r in resultados:
        print(f"  {r.nombre:<20}{r.esperado:<20}{r.obtenido:<20}{out.veredicto(r.ok)}")
    ok = all(r.ok for r in resultados)
    print(f"\n  {'Todos los estados coinciden con lo esperado.' if ok else 'HAY DIFERENCIAS con lo esperado.'}")


# ---------------------------------------------------------------- CLI
ATAQUES = {
    "manipulada": ataque_manipulada, "falsa": ataque_falsa, "replay": ataque_replay, "hueco": ataque_hueco,
    "fuera-ventana": ataque_fuera_ventana, "bd-alterar-valor": ataque_bd_alterar_valor,
    "bd-borrar": ataque_bd_borrar, "cadena-rota": ataque_cadena_rota,
}


def _comunes(p: argparse.ArgumentParser, principal: bool) -> None:
    """Opciones globales: en el parser principal con valor por defecto y en los subparsers sin él
    (SUPPRESS), para que valgan antes o después del subcomando."""
    d = (lambda v: v) if principal else (lambda v: argparse.SUPPRESS)
    p.add_argument("--env", default=d(str(ROOT / "demo-run" / ".env")), help="archivo .env de la demo")
    p.add_argument("--cacert", default=d(None), help="certificado con el que se valida al servidor "
                   "(por defecto: VIGIA_CERTS_DIR/cert.pem del .env)")
    p.add_argument("--url", default=d(None), help="URL del servidor (por defecto: del .env)")
    p.add_argument("--no-color", action="store_true", default=d(False), help="sin colores ANSI")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ataques.py", description="Ataques para la demo en vivo de VIGÍA")
    _comunes(p, True)
    sub = p.add_subparsers(dest="cmd", required=True, metavar="ataque")

    def nuevo(nombre: str, ayuda: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(nombre, help=ayuda)
        _comunes(sp, False)
        return sp

    nuevo("manipulada", "valor alterado antes de enviar -> MANIPULADA")
    f = nuevo("falsa", "sensor inexistente con tag aleatorio -> FALSA")
    f.add_argument("--id-valido", action="store_true", help="usa sensor-01 con llave aleatoria -> MANIPULADA")
    nuevo("replay", "reenvía la última medición VERIFICADA de sensor-01 -> REPLAY O HUECO")
    nuevo("hueco", "seq última+2 de sensor-02 -> REPLAY O HUECO (hueco)")
    nuevo("fuera-ventana", "timestamp de hace 2 min -> FUERA DE VENTANA")
    for n, h in (("bd-alterar-valor", "UPDATE del valor en la BD -> MANIPULADA en verificar-historial"),
                 ("bd-borrar", "DELETE de un registro en la BD -> CADENA ROTA en verificar-historial"),
                 ("cadena-rota", "altera el hash del último registro -> CADENA ROTA en la ingesta")):
        nuevo(n, h).add_argument("--restaurar", action="store_true", help="deshace el daño al terminar")
    nuevo("todos", "todos los ataques en orden + tabla resumen (restaura la BD al terminar cada uno)")
    nuevo("restaurar", "deshace el daño en BD dejado por ataques previos")
    args = p.parse_args(argv)

    out = Salida(color=not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ)
    try:
        ctx = Contexto(Path(args.env), args.cacert, args.url, out)
        with closing(ctx.http):
            if args.cmd == "restaurar":
                return restaurar(ctx)
            if args.cmd == "todos":
                ataque_todos(ctx, args)
                return 0 if all(r.ok for r in args._resultados) else 1
            r = ATAQUES[args.cmd](ctx, args)
            print(f"\n  Esperado: {r.esperado} | Obtenido: {out.estado(r.obtenido, r.ok)} -> {out.veredicto(r.ok)}")
            return 0 if r.ok else 1
    except AtaqueError as exc:
        out.error(str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
