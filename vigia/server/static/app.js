"use strict";
// Dashboard de VIGÍA. Todo texto proveniente de la API se inserta con textContent (nunca innerHTML).
(function () {
  const REFRESCO_MS = 5000;
  const CLASE_ESTADO = {
    "VERIFICADA": "e-verificada", "MANIPULADA": "e-manipulada", "FALSA": "e-falsa",
    "REPLAY O HUECO": "e-replay", "FUERA DE VENTANA": "e-ventana", "CADENA ROTA": "e-cadena",
  };
  const estado = { sensor: null, vista: "resumen", sensores: [], graficos: {} };

  const $ = (id) => document.getElementById(id);

  function el(tag, clase, texto) {
    const e = document.createElement(tag);
    if (clase) e.className = clase;
    if (texto !== undefined && texto !== null) e.textContent = String(texto);
    return e;
  }
  function celda(texto, clase) { return el("td", clase, texto); }
  function etiqueta(est) {
    return el("span", "etiqueta " + (CLASE_ESTADO[est] || ""), est);
  }
  function fecha(ms) { return new Date(ms).toLocaleString(); }
  function abreviar(tag) {
    return tag.length > 14 ? tag.slice(0, 8) + "…" + tag.slice(-4) : tag;
  }
  function vaciar(nodo) { while (nodo.firstChild) nodo.removeChild(nodo.firstChild); }

  async function api(ruta, opciones) {
    const r = await fetch(ruta, opciones);
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  }

  // ---- gráficos -----------------------------------------------------------------
  function css(nombre) { return getComputedStyle(document.documentElement).getPropertyValue(nombre).trim(); }

  function actualizarGrafico(clave, canvasId, msgId, serie) {
    const msg = $(msgId);
    if (typeof Chart === "undefined") {
      msg.textContent = "No se pudo cargar Chart.js (¿sin acceso a cdnjs?).";
      return;
    }
    msg.textContent = serie.length ? "" : "Aún no hay mediciones verificadas.";
    const etiquetas = serie.map((p) => new Date(p.timestamp_ms).toLocaleTimeString());
    const datos = serie.map((p) => parseFloat(p.valor));
    let g = estado.graficos[clave];
    if (!g) {
      g = new Chart($(canvasId), {
        type: "line",
        data: { labels: etiquetas, datasets: [{ label: "Valor", data: datos, borderColor: css("--linea"),
          backgroundColor: css("--linea"), tension: 0.2, pointRadius: 2 }] },
        options: { responsive: true, maintainAspectRatio: false, animation: false,
          plugins: { legend: { display: false } },
          scales: { x: { ticks: { color: css("--muted"), maxTicksLimit: 8 } },
                    y: { ticks: { color: css("--muted") } } } },
      });
      estado.graficos[clave] = g;
    } else {
      g.data.labels = etiquetas;
      g.data.datasets[0].data = datos;
      g.update();
    }
  }

  // ---- render de vistas ----------------------------------------------------------
  function renderTarjetas(eventos, serie) {
    const cont = $("tarjetas");
    vaciar(cont);
    const verificadas = eventos.filter((e) => e.estado === "VERIFICADA").length;
    const ultima = serie.length ? serie[serie.length - 1] : null;
    const datos = [
      ["Intentos recibidos", eventos.length],
      ["Verificadas", verificadas],
      ["Rechazadas", eventos.length - verificadas],
      ["Último valor", ultima ? ultima.valor : "—"],
      ["Última medición", ultima ? fecha(ultima.timestamp_ms) : "—"],
    ];
    for (const [t, v] of datos) {
      const c = el("div", "tarjeta");
      c.appendChild(el("div", "t", t));
      c.appendChild(el("div", "v", v));
      cont.appendChild(c);
    }
  }

  function renderEventos(eventos) {
    const tb = $("tabla-eventos").querySelector("tbody");
    vaciar(tb);
    for (const e of eventos) {
      const tr = el("tr");
      tr.appendChild(celda(fecha(e.timestamp_ms)));
      tr.appendChild(celda(e.seq));
      tr.appendChild(celda(e.valor, "mono"));
      const tdTag = celda(abreviar(e.tag), "mono");
      tdTag.title = e.tag;
      tr.appendChild(tdTag);
      const tdEst = el("td");
      tdEst.appendChild(etiqueta(e.estado));
      tr.appendChild(tdEst);
      tr.appendChild(celda(e.detalle));
      tb.appendChild(tr);
    }
    if (!eventos.length) {
      const tr = el("tr"); const td = celda("Sin eventos todavía."); td.colSpan = 6; tr.appendChild(td); tb.appendChild(tr);
    }
  }

  function renderGlobal(eventos) {
    const tb = $("tabla-global").querySelector("tbody");
    vaciar(tb);
    for (const e of eventos.slice(0, 15)) {
      const tr = el("tr");
      tr.appendChild(celda(fecha(e.recibido_ms)));
      tr.appendChild(celda(e.sensor_id));
      tr.appendChild(celda(e.seq));
      const tdEst = el("td"); tdEst.appendChild(etiqueta(e.estado)); tr.appendChild(tdEst);
      tr.appendChild(celda(e.detalle));
      tb.appendChild(tr);
    }
  }

  function renderConfig(cfg) {
    const dl = $("config-lista");
    vaciar(dl);
    const filas = [["Ventana de frescura", cfg.ventana_ms + " ms"], ["Autenticación", cfg.autenticacion],
      ["Cadena de hashes", cfg.cadena], ["Llaves en reposo", cfg.llaves_en_reposo], ["Transporte", cfg.transporte]];
    for (const [k, v] of filas) { dl.appendChild(el("dt", null, k)); dl.appendChild(el("dd", null, v)); }
    const tb = $("tabla-sensores").querySelector("tbody");
    vaciar(tb);
    for (const s of estado.sensores) {
      const tr = el("tr");
      tr.appendChild(celda(s.id));
      tr.appendChild(celda(s.activo ? "activo" : "revocado"));
      tr.appendChild(celda(s.verificadas));
      tr.appendChild(celda(s.intentos));
      tr.appendChild(celda(s.ultima_seq === null ? "—" : s.ultima_seq));
      const td = el("td");
      if (s.ultimo_estado) td.appendChild(etiqueta(s.ultimo_estado)); else td.textContent = "—";
      tr.appendChild(td);
      tb.appendChild(tr);
    }
  }

  function poblarSelector(sensores) {
    const sel = $("sensor-select");
    const ids = sensores.map((s) => s.id);
    const actuales = Array.from(sel.options).map((o) => o.value);
    if (ids.join("|") !== actuales.join("|")) {
      vaciar(sel);
      for (const s of sensores) {
        const o = el("option", null, s.activo ? s.id : s.id + " (revocado)");
        o.value = s.id;
        sel.appendChild(o);
      }
    }
    if (!ids.includes(estado.sensor)) estado.sensor = ids.length ? ids[0] : null;
    if (estado.sensor) sel.value = estado.sensor;
  }

  // ---- ciclo de refresco ---------------------------------------------------------
  async function refrescar() {
    try {
      estado.sensores = await api("/api/sensores");
      poblarSelector(estado.sensores);
      $("sin-sensores").hidden = estado.sensores.length > 0;
      const global = await api("/api/eventos?limite=50");
      renderGlobal(global);
      if (estado.sensor) {
        const id = encodeURIComponent(estado.sensor);
        const [eventos, serie] = await Promise.all([
          api("/api/sensores/" + id + "/eventos"), api("/api/sensores/" + id + "/serie")]);
        renderTarjetas(eventos, serie);
        renderEventos(eventos);
        if (estado.vista === "resumen") actualizarGrafico("resumen", "grafico-resumen", "grafico-resumen-msg", serie);
        if (estado.vista === "historial") actualizarGrafico("historial", "grafico-historial", "grafico-historial-msg", serie);
      }
      if (estado.vista === "configuracion") renderConfig(await api("/api/config"));
      $("estado-conexion").textContent = "Actualizado " + new Date().toLocaleTimeString();
    } catch (err) {
      $("estado-conexion").textContent = "Error al actualizar: " + err.message;
    }
  }

  function mostrarVista(nombre) {
    estado.vista = nombre;
    for (const v of document.querySelectorAll(".vista")) v.hidden = v.id !== "vista-" + nombre;
    for (const b of document.querySelectorAll(".menu-btn")) b.classList.toggle("activo", b.dataset.vista === nombre);
    refrescar();
  }

  async function verificarHistorial() {
    if (!estado.sensor) return;
    const btn = $("btn-verificar"), cont = $("reporte");
    btn.disabled = true;
    vaciar(cont);
    try {
      const rep = await api("/api/sensores/" + encodeURIComponent(estado.sensor) + "/verificar-historial", { method: "POST" });
      const malas = rep.registros.filter((r) => r.estado !== "VERIFICADA");
      const banner = el("div", "banner " + (rep.integro ? "ok" : "mal"),
        rep.integro ? "Historial ÍNTEGRO: " + rep.total + " registros verificados."
                    : "Historial ALTERADO: " + malas.length + " de " + rep.total + " registros con problemas.");
      cont.appendChild(banner);
      const wrap = el("div", "tabla-wrap");
      const tabla = el("table");
      const th = el("thead"), trh = el("tr");
      for (const h of ["Seq", "Estado", "Detalle"]) trh.appendChild(el("th", null, h));
      th.appendChild(trh); tabla.appendChild(th);
      const tb = el("tbody");
      for (const r of rep.registros) {
        const tr = el("tr");
        tr.appendChild(celda(r.seq));
        const td = el("td"); td.appendChild(etiqueta(r.estado)); tr.appendChild(td);
        tr.appendChild(celda(r.detalle));
        tb.appendChild(tr);
      }
      tabla.appendChild(tb); wrap.appendChild(tabla); cont.appendChild(wrap);
    } catch (err) {
      cont.appendChild(el("div", "banner mal", "No se pudo verificar: " + err.message));
    } finally {
      btn.disabled = false;
    }
  }

  document.querySelectorAll(".menu-btn").forEach((b) =>
    b.addEventListener("click", () => mostrarVista(b.dataset.vista)));
  $("sensor-select").addEventListener("change", (e) => {
    estado.sensor = e.target.value;
    vaciar($("reporte"));
    refrescar();
  });
  $("btn-verificar").addEventListener("click", verificarHistorial);

  refrescar();
  setInterval(refrescar, REFRESCO_MS);
})();
