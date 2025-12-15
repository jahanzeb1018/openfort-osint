/*
  popup.js
  Este archivo controla TODA la parte visual del popup
  de la extensión:
 
  - Lee la IP introducida por el usuario
  - Se comunica con el background (service worker)
  - Recibe los resultados OSINT
  - Renderiza tarjetas
  - Maneja errores y estados
*/


/* 
   REFERENCIAS A ELEMENTOS DEL HTML
*/

// Input donde el usuario escribe la IP
const ipInput = document.getElementById("ipAddress");

// Botón "Get Intel"
const fetchButton = document.getElementById("fetchButton");

// Texto de estado 
const statusEl = document.getElementById("status");

// Contenedor donde se dibujan las tarjetas
const cardsEl = document.getElementById("cards");

// Contenedor del resumen superior
const summaryEl = document.getElementById("summary");


/* 
   UTILIDADES VISUALES
 */

/**
 * Muestra un mensaje de estado al usuario
 * @param {string} text Texto a mostrar
 * @param {boolean} isError Si es error, se pinta en rojo
 */
function setStatus(text, isError = false) {
  statusEl.textContent = text || "";
  statusEl.classList.toggle("error", !!isError);
}


/**
 * Escapa texto HTML para evitar inyecciones
 */
function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}


/**
 * Convierte un objeto JS en JSON
 */
function prettyJSON(obj) {
  return escapeHtml(JSON.stringify(obj, null, 2));
}


/**
 * Crea una etiqueta visual
 */
function badge(text, kind = "") {
  const cls = kind ? `badge ${kind}` : "badge";
  return `<span class="${cls}">${escapeHtml(text)}</span>`;
}


/**
 * Renderiza una fila clave → valor
 */
function row(k, v, mono = false) {
  const val = v == null || v === "" ? "—" : String(v);
  return `
    <div class="row">
      <div class="key">${escapeHtml(k)}</div>
      <div class="val ${mono ? "mono" : ""}">${escapeHtml(val)}</div>
    </div>
  `;
}


/* 
   ACCIONES DEL USUARIO
    */

/**
 * Abre una URL externa en una pestaña normal
 */
function openUrl(url) {
  if (!url) return;
  chrome.tabs.create({ url, active: true });
}


/**
 * Copia texto al portapapeles
 */
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    setStatus("Copied ✅");
    setTimeout(() => setStatus(""), 900);
  } catch {
    setStatus("Copy failed", true);
  }
}


/* 
   RESUMEN GLOBAL (AGREGACIÓN DE FUENTES)
    */

/**
 * Combina VirusTotal + IPinfo + AbuseIPDB
 */
function computeSummary(result) {
  const ip = result?.ip || "—";

  const vt = result?.sources?.virustotal?.data;
  const ipinfo = result?.sources?.ipinfo?.data;
  const abuse = result?.sources?.abuseipdb?.data;

  // ASN (se intenta sacar de varias fuentes)
  const asn =
    vt?.asn ||
    ipinfo?.summary?.asn ||
    (abuse?.info?.ASN
      ? Number(String(abuse.info.ASN).replace(/[^\d]/g, ""))
      : null);

  const asName = vt?.asName || ipinfo?.summary?.asnName || null;

  const country = ipinfo?.geolocation?.country || abuse?.info?.Country || null;
  const city = ipinfo?.geolocation?.city || abuse?.info?.City || null;

  const det = vt?.detectionRatio?.detected;
  const tot = vt?.detectionRatio?.total;

  const abuseConf = abuse?.abuseConfidence;

  // Cálculo simple de riesgo
  let risk = { label: "Unknown", kind: "info" };

  if (typeof det === "number" && typeof tot === "number") {
    if (det === 0) risk = { label: "Low", kind: "ok" };
    if (det >= 1 && det <= 2) risk = { label: "Elevated", kind: "warn" };
    if (det >= 3) risk = { label: "High", kind: "bad" };
  }

  // AbuseIPDB puede subir el riesgo
  if (typeof abuseConf === "number" && abuseConf >= 50)
    risk = { label: "High", kind: "bad" };

  if (
    typeof abuseConf === "number" &&
    abuseConf >= 15 &&
    abuseConf < 50 &&
    risk.kind === "ok"
  ) {
    risk = { label: "Elevated", kind: "warn" };
  }

  return { ip, asn, asName, country, city, det, tot, abuseConf, risk };
}


/* 
   RENDER DEL RESUMEN SUPERIOR
    */

function renderSummary(result) {
  const s = computeSummary(result);

  const chips = [];

  if (s.risk)
    chips.push(badge(`Risk: ${s.risk.label}`, s.risk.kind));

  if (typeof s.det === "number" && typeof s.tot === "number")
    chips.push(
      badge(`VT: ${s.det}/${s.tot}`, s.det === 0 ? "ok" : "warn")
    );

  if (typeof s.abuseConf === "number")
    chips.push(
      badge(
        `Abuse: ${s.abuseConf}%`,
        s.abuseConf >= 50
          ? "bad"
          : s.abuseConf >= 15
          ? "warn"
          : "ok"
      )
    );

  const ipinfoChips = result?.sources?.ipinfo?.data?.chips || [];
  ipinfoChips.slice(0, 6).forEach((c) =>
    chips.push(badge(c, "info"))
  );

  summaryEl.classList.remove("hidden");
  summaryEl.innerHTML = `
    <div class="summaryTop">
      <div>
        <div class="cardTitle">Target</div>
        <div class="cardSub mono">${escapeHtml(s.ip)}</div>
        <div class="badges">${chips.join("")}</div>
      </div>
    </div>

    <div class="kpis">
      <div class="kpi">
        <div class="k">ASN</div>
        <div class="v mono">${escapeHtml(s.asn ?? "—")}</div>
      </div>
      <div class="kpi">
        <div class="k">Org</div>
        <div class="v">${escapeHtml(s.asName ?? "—")}</div>
      </div>
      <div class="kpi">
        <div class="k">Location</div>
        <div class="v">${escapeHtml(
          [s.city, s.country].filter(Boolean).join(", ") || "—"
        )}</div>
      </div>
      <div class="kpi">
        <div class="k">Updated</div>
        <div class="v">${escapeHtml(
          new Date(result?.timestamp || Date.now()).toLocaleString()
        )}</div>
      </div>
    </div>
  `;
}


/* 
   TARJETA GENÉRICA PARA CADA FUENTE
    */

function sourceCard(title, subtitle, url, rowsHtml, dataObj, hintHtml = "") {
  const canOpen = !!url;

  return `
    <section class="card">
      <div class="cardHeader">
        <div>
          <div class="cardTitle">${escapeHtml(title)}</div>
          <div class="cardSub">${escapeHtml(subtitle || "")}</div>
        </div>

        <div class="cardActions">
          ${
            canOpen
              ? `<button class="btn small" data-open="${escapeHtml(url)}">Open</button>`
              : ""
          }
          <button class="btn small" data-copy="${escapeHtml(
            JSON.stringify(dataObj || {}, null, 2)
          )}">Copy JSON</button>
        </div>
      </div>

      ${hintHtml ? `<div class="badges" style="margin-top:10px;">${hintHtml}</div>` : ""}

      ${rowsHtml}

      <details>
        <summary>Raw JSON</summary>
        <pre>${prettyJSON(dataObj || {})}</pre>
      </details>
    </section>
  `;
}


/* 
   RENDER DE CADA FUENTE
    */

function renderVirusTotalBlock(result) {
  const src = result?.sources?.virustotal;
  const url = src?.url;
  const d = src?.data || {};

  const requires = !!d.requires_user_action;
  const hint = requires ? badge("requires_user_action", "warn") : badge("ok", "ok");

  const rows = []
    .concat(row("Detections", d?.detectionRatio
      ? `${d.detectionRatio.detected}/${d.detectionRatio.total}`
      : "—", true))
    .concat(row("ASN", d?.asn ?? "—", true))
    .concat(row("AS Name", d?.asName ?? "—"))
    .concat(row("Last analysis", d?.lastAnalysisDate ?? "—"))
    .join("");

  return sourceCard("VirusTotal", d?.title || "IP reputation", url, rows, d, hint);
}


function renderIPinfoBlock(result) {
  const src = result?.sources?.ipinfo;
  const url = src?.url;
  const d = src?.data || {};
  const s = d?.summary || {};
  const g = d?.geolocation || {};

  const rows = []
    .concat(row("ASN", s?.asn ? `AS${s.asn}` : "—", true))
    .concat(row("Org", s?.asnName ?? "—"))
    .concat(row("Hostname", s?.hostname ?? "—", true))
    .concat(row("Range", s?.range ?? "—", true))
    .concat(row("Company", s?.company ?? "—"))
    .concat(row("Location", [g?.city, g?.region, g?.country].filter(Boolean).join(", ") || "—"))
    .concat(row("Timezone", g?.timezone ?? "—"))
    .join("");

  const chips = Array.isArray(d?.chips)
    ? d.chips.slice(0, 8).map((c) => badge(c, "info")).join("")
    : "";

  return sourceCard("IPinfo", d?.title || "Geolocation & ASN", url, rows, d, chips || badge("ok", "ok"));
}


function renderAbuseIPDBBlock(result) {
  const src = result?.sources?.abuseipdb;
  const url = src?.url;
  const d = src?.data || {};

  const requires = !!d.requires_user_action;
  const hint = requires ? badge("requires_user_action", "warn") : badge("ok", "ok");

  const info = d?.info || {};

  const rows = []
    .concat(row("Confidence of Abuse", typeof d?.abuseConfidence === "number" ? `${d.abuseConfidence}%` : "—"))
    .concat(row("Reports", d?.reportsCount ?? "—", true))
    .concat(row("ISP", info?.ISP ?? "—"))
    .concat(row("Usage", info?.["Usage Type"] ?? "—"))
    .concat(row("ASN", info?.ASN ?? "—", true))
    .concat(row("Country", info?.Country ?? "—"))
    .concat(row("City", info?.City ?? "—"))
    .join("");

  return sourceCard("AbuseIPDB", d?.title || "Reports & abuse confidence", url, rows, d, hint);
}


/* 
   RENDER GLOBAL
    */

function renderAll(result) {
  cardsEl.innerHTML = [
    renderVirusTotalBlock(result),
    renderIPinfoBlock(result),
    renderAbuseIPDBBlock(result),
  ].join("");

  // Conectar botones
  cardsEl.querySelectorAll("[data-open]").forEach((btn) => {
    btn.addEventListener("click", () => openUrl(btn.getAttribute("data-open")));
  });

  cardsEl.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", () =>
      copyToClipboard(btn.getAttribute("data-copy"))
    );
  });
}


/* 
   COMUNICACIÓN CON EL BACKGROUND
    */

async function fetchIntel(ip) {
  setStatus("Recolectando intel…");
  fetchButton.disabled = true;
  summaryEl.classList.add("hidden");
  cardsEl.innerHTML = "";

  try {
    const resp = await chrome.runtime.sendMessage({
      type: "FETCH_INTEL",
      ip,
    });

    if (!resp?.ok) {
      setStatus(resp?.error || "Error", true);
      return;
    }

    setStatus("Results received ✅");
    renderSummary(resp.result);
    renderAll(resp.result);

  } catch (e) {
    setStatus("Unhandled error", true);
  } finally {
    fetchButton.disabled = false;
  }
}


/* 
   EVENTOS
    */

// Click en botón
fetchButton.addEventListener("click", () => {
  const ip = ipInput.value.trim();
  fetchIntel(ip);
});

// Cargar último resultado guardado
chrome.runtime.sendMessage({ type: "GET_LAST" }).then((resp) => {
  if (resp?.ok && resp.result) {
    renderSummary(resp.result);
    renderAll(resp.result);
  }
});
