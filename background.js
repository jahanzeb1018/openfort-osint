// background.js (MV3)

// - El popup te manda un IP
// - Este service worker crea 3 pestañas en segundo plano (no activas para que el popu no se cierre)
// - En cada pestaña se “conecta” con Chrome DevTools Protocol (CDP) usando chrome.debugger
// - Navega a VirusTotal / IPinfo / AbuseIPDB
// - Extrae texto/DOM ejecutando JS dentro de la página (Runtime.evaluate)
// - Parsea ese texto a JSON estructurado
// - Guarda el resultado en chrome.storage.local y lo devuelve al popup

const CDP_VERSION = "1.3"; 

// ---------------- utils ----------------

// Sleep simple para esperar X ms
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Validador básico de IPv4
const isValidIPv4 = (ip) => {
  const p = ip.trim().split(".");
  return p.length === 4 && p.every((x) => /^\d+$/.test(x) && +x >= 0 && +x <= 255);
};

// Convierte un error a string
const errToString = (e) => e?.stack || e?.message || String(e);

// Crea una pestaña.
// clave UX: active:false -> NO se cierra el popup.
async function createTab(url, active) {
  return new Promise((res, rej) => {
    chrome.tabs.create({ url, active: !!active }, (t) => {
      const err = chrome.runtime.lastError;
      if (err) return rej(new Error(`TabCreateError: ${err.message}`));
      if (!t?.id) return rej(new Error("TabCreateError: tab.id missing"));
      res(t);
    });
  });
}

async function closeTab(id) {
  return new Promise((r) => chrome.tabs.remove(id, () => r()));
}

// ---------------- CDP session ----------------

// Encapsula: attach/detach, sendCommand, evaluate JS en la página, y goto(url).
class CDPSession {
  constructor(tabId) {
    this.tabId = tabId;
    this.target = { tabId }; // “target” para chrome.debugger
    this.attached = false;

    // Listener de eventos CDP
    this._onEvent = this._onEvent.bind(this);
    this._loadResolve = null;
  }

  // Maneja eventos de CDP
  _onEvent(src, method) {
    if (!src || src.tabId !== this.tabId) return;

    if (method === "Page.loadEventFired" && this._loadResolve) {
      this._loadResolve();
      this._loadResolve = null;
    }
  }

  // Conecta chrome.debugger al tab
  async attach() {
    if (this.attached) return;

    // 1) attach
    await new Promise((res, rej) => {
      chrome.debugger.attach(this.target, CDP_VERSION, () => {
        const err = chrome.runtime.lastError;
        if (err) return rej(new Error(`AttachError: ${err.message}`));
        res();
      });
    });

    this.attached = true;

    // 2) escuchar eventos
    chrome.debugger.onEvent.addListener(this._onEvent);

    // 3) habilitar dominios CDP que vamos a usar
    await this.send("Page.enable");
    await this.send("Runtime.enable");
    await this.send("Network.enable");

    // 4) header extra para idioma
    await this.send("Network.setExtraHTTPHeaders", {
      headers: { "Accept-Language": "en-US,en;q=0.9" },
    });
  }

  async detach() {
    if (!this.attached) return;
    try {
      chrome.debugger.onEvent.removeListener(this._onEvent);
    } catch {}
    await new Promise((r) => chrome.debugger.detach(this.target, () => r()));
    this.attached = false;
  }

  // Wrapper de chrome.debugger.sendCommand
  send(method, params = {}) {
    return new Promise((res, rej) => {
      chrome.debugger.sendCommand(this.target, method, params, (out) => {
        const err = chrome.runtime.lastError;
        if (err) return rej(new Error(`CDPCommandError(${method}): ${err.message}`));
        res(out);
      });
    });
  }

  // Ejecuta JS dentro de la página y devuelve el resultado
  async eval(expression) {
    const r = await this.send("Runtime.evaluate", {
      expression,
      returnByValue: true, 
      awaitPromise: true,  
    });
    return r.result?.value;
  }

  // Navega a una URL y espera a que Page.loadEventFired dispare
  async goto(url) {
    await this.send("Page.navigate", { url });

    await new Promise((res) => (this._loadResolve = res));

    await sleep(700);
  }
}

// ---------------- parsing helpers ----------------
//
// Estas funciones NO tocan CDP. Solo convierten texto sucio -> texto limpio -> datos.

// Normaliza texto
function normalizeText(t) {
  return String(t || "")
    .replace(/\r/g, "")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

// Elimina duplicados
const uniq = (arr) => Array.from(new Set(arr));

// Busca un “Key” en un array de líneas y devuelve la línea siguiente.

function pickLineAfter(lines, key) {
  const idx = lines.findIndex((l) => l.toLowerCase() === key.toLowerCase());
  if (idx >= 0 && lines[idx + 1]) return lines[idx + 1];

  // fallback: "Key: value"
  const kv = lines.find((l) => l.toLowerCase().startsWith(key.toLowerCase() + ":"));
  if (kv) return kv.split(":").slice(1).join(":").trim();

  return null;
}

// Busca ratios tipo "2/95" y devuelve el primero
function parseFirstReasonableRatio(text) {
  const re = /(\d{1,3})\s*\/\s*(\d{1,4})/g;
  let m;
  while ((m = re.exec(text))) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    if (b >= 1 && b <= 5000 && a <= b) return { detected: a, total: b };
  }
  return null;
}

// Encuentra el índice de la N-ésima ocurrencia de algo en lines.
function findNthIndex(arr, regex, nth = 1) {
  let count = 0;
  for (let i = 0; i < arr.length; i++) {
    if (regex.test(arr[i])) {
      count++;
      if (count === nth) return i;
    }
  }
  return -1;
}

// ---------------- VirusTotal helpers ----------------
//
// “Heurísticas” para entender si ya estás en la página de resultados real
function isVirusTotalResultsPage(fullText) {
  const t = String(fullText || "").toLowerCase();
  return (
    t.includes("security vendors' analysis") ||
    t.includes("community score") ||
    /\b\d+\s*\/\s*\d+\b/.test(t) ||
    /\bas\s+\d+/.test(t)
  );
}

// Extrae ASN y nombre desde texto (AS13335, etc.)
function parseASNFromText(fullText, lines) {
  let asn = null;
  let asName = null;

  const line1 = lines.find((l) => /^AS\s+\d+/i.test(l));
  if (line1) {
    const m = line1.match(/^AS\s+(\d+)\s*(?:\(([^)]+)\))?/i);
    if (m) {
      asn = m[1] ? Number(m[1]) : null;
      asName = m[2] || null;
      return { asn, asName: asName ? asName.trim() : null };
    }
  }

  const m2 = fullText.match(/\bAS\s*?(\d{3,10})\s*\(([^)]+)\)/i);
  if (m2) return { asn: Number(m2[1]), asName: (m2[2] || "").trim() || null };

  const m3 = fullText.match(/\bAS(\d{3,10})\b/i);
  if (m3) return { asn: Number(m3[1]), asName: null };

  return { asn: null, asName: null };
}

// Extrae el CIDR desde texto
function parseIPCidrFromText(ip, fullText, lines) {
  const ipLine = (lines || []).find(
    (l) => l.includes(ip) && /\(\s*\d+\.\d+\.\d+\.\d+\/\d+\s*\)/.test(l)
  );
  if (ipLine) {
    const m = ipLine.match(/(\d+\.\d+\.\d+\.\d+)\s*\(\s*([^)]+\/\d+)\s*\)/);
    if (m) return { ip: m[1], cidr: m[2] };
  }

  const escaped = String(ip).replaceAll(".", "\\.");
  const m2 = String(fullText || "").match(
    new RegExp(`\\b${escaped}\\b\\s*\\(\\s*(\\d+\\.\\d+\\.\\d+\\.\\d+\\/\\d+)\\s*\\)`)
  );
  if (m2) return { ip, cidr: m2[1] };

  const m3 = String(fullText || "").match(/\b(\d+\.\d+\.\d+\.\d+\/\d+)\b/);
  if (m3 && m3[1]) return { ip, cidr: m3[1] };

  return null;
}

// ---------------- IPinfo ----------------
//
// Parsea el texto de IPinfo a un JSON “ordenado”
function parseIPinfoFromText(ip, title, fullText) {
  const text = normalizeText(fullText);
  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);

  // “chips” = etiquetas tipo Anycast, CDN, etc (se ven en IPinfo arriba)
  const knownHeaderChips = [
    "Anycast",
    "CDN",
    "Hosting",
    "Internet Exchange",
    "Nameserver",
    "Resolver",
    "Webserver",
  ];

  // Cortamos el “header” antes del menú Summary/Privacy
  const idxSummaryMenu = lines.findIndex((l) => /^summary$/i.test(l));
  const idxPrivacyMenu = lines.findIndex((l) => /^privacy$/i.test(l) || /^privacy detection$/i.test(l));
  const cut = [idxSummaryMenu, idxPrivacyMenu].filter((x) => x > 0);
  const headerEnd = cut.length ? Math.min(...cut) : 120;
  const headerLines = lines.slice(0, headerEnd).join("\n");

  // Detecta qué chips aparecen realmente en ese header
  const chips = uniq(
    knownHeaderChips.filter((c) =>
      new RegExp(`\\b${c.replace(/ /g, "\\s+")}\\b`, "i").test(headerLines)
    )
  );

  // Alias de campos (por si cambia mayúsculas/minúsculas)
  const KEY_ALIASES = {
    ASN: ["ASN"],
    Hostname: ["Hostname"],
    Range: ["Range"],
    Company: ["Company"],
    "Hosted domains": ["Hosted domains", "Hosted Domains"],
    Privacy: ["Privacy"],
    Anycast: ["Anycast"],
    "ASN type": ["ASN type", "ASN Type"],
    "Abuse contact": ["Abuse contact", "Abuse Contact"],
    City: ["City"],
    State: ["State", "Region"],
    Country: ["Country"],
    Postal: ["Postal", "Postcode", "ZIP"],
    "Local time": ["Local time", "Local Time"],
    Timezone: ["Timezone", "Time zone", "Time Zone"],
    Coordinates: ["Coordinates"],
  };

  // Lector genérico “Key Value”
  function readKeyValue(blockLines, keyCanonical) {
    const aliases = KEY_ALIASES[keyCanonical] || [keyCanonical];
    for (let i = 0; i < blockLines.length; i++) {
      const line = blockLines[i];
      for (const alias of aliases) {
        const escapedAlias = alias.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const reInline = new RegExp(`^${escapedAlias}\\s+(.+)$`, "i");
        const m1 = line.match(reInline);
        if (m1 && m1[1]) return m1[1].trim();

        if (line.toLowerCase() === alias.toLowerCase() && blockLines[i + 1]) {
          return blockLines[i + 1].trim();
        }
      }
    }
    return null;
  }

  // Corta un trozo del array lines por índices
  function sliceBlockByIndexes(startIdx, endIdx, maxScan = 600) {
    if (startIdx < 0) return [];
    const end = endIdx > startIdx ? endIdx : Math.min(lines.length, startIdx + maxScan);
    return lines.slice(startIdx, end);
  }

  // Corta un bloque desde una label hasta otra label
  function sliceBlock(startLabelRegex, endLabelRegexList, maxScan = 600) {
    const start = lines.findIndex((l) => startLabelRegex.test(l));
    if (start < 0) return [];
    const endCandidates = endLabelRegexList
      .map((re) => lines.findIndex((l, idx) => idx > start && re.test(l)))
      .filter((x) => x >= 0);
    const end = endCandidates.length ? Math.min(...endCandidates) : Math.min(lines.length, start + maxScan);
    return lines.slice(start, end);
  }

  // IPinfo suele tener "Summary" repetido (tomamos la 2ª ocurrencia real)
  const idxSummaryReal = findNthIndex(lines, /^summary$/i, 2);
  const idxGeoReal = lines.findIndex((l) => /^ip geolocation$/i.test(l));

  // Bloque Summary
  let summaryBlock = [];
  if (idxSummaryReal >= 0) {
    summaryBlock = sliceBlockByIndexes(idxSummaryReal, idxGeoReal, 260);
  } else {
    const idxSummaryAny = lines.findIndex((l) => /^summary$/i.test(l));
    summaryBlock = sliceBlockByIndexes(idxSummaryAny, idxGeoReal, 260);
  }

  // Bloque Geolocation
  const geoBlock = sliceBlock(
    /^ip geolocation$/i,
    [/^privacy detection$/i, /^asn$/i, /^company$/i, /^abuse details$/i, /^hosted domains/i],
    420
  );

  // Bloque Abuse details (para extraer email/phone/address)
  const abuseBlock = sliceBlock(
    /^abuse details$/i,
    [/^hosted domains/i, /^our ip tools/i, /^company$/i],
    420
  );

  // ASN de summary
  const asnRaw = readKeyValue(summaryBlock, "ASN");
  let asn = null;
  let asnName = null;
  if (asnRaw) {
    const m = asnRaw.match(/\bAS(\d+)\b(?:\s*-\s*(.+))?/i);
    if (m) {
      asn = Number(m[1]);
      asnName = (m[2] || "").trim() || null;
    }
  }

  // Campos summary
  const hostname = readKeyValue(summaryBlock, "Hostname");
  const range = readKeyValue(summaryBlock, "Range");
  const company = readKeyValue(summaryBlock, "Company");
  const hostedDomains = readKeyValue(summaryBlock, "Hosted domains");
  const privacyRaw = readKeyValue(summaryBlock, "Privacy");
  const anycastRaw = readKeyValue(summaryBlock, "Anycast");
  const asnType = readKeyValue(summaryBlock, "ASN type");
  const abuseContact = readKeyValue(summaryBlock, "Abuse contact");

  // Convierte "True/False" string a boolean
  const toBool = (v) => {
    if (typeof v !== "string") return v;
    if (/^true$/i.test(v)) return true;
    if (/^false$/i.test(v)) return false;
    return v;
  };

  // Campos geolocation
  const city = readKeyValue(geoBlock, "City");
  const region = readKeyValue(geoBlock, "State");
  let country = readKeyValue(geoBlock, "Country");
  if (country) country = country.replace(/\s+/g, " ").trim();

  const postal = readKeyValue(geoBlock, "Postal");
  const localTime = readKeyValue(geoBlock, "Local time");
  const timezone = readKeyValue(geoBlock, "Timezone");
  const coordinates = readKeyValue(geoBlock, "Coordinates");

  // Parse de coordenadas "22.2 N, 114.1 E" a {lat, lon}
  let coords = null;
  if (coordinates) {
    const m = coordinates.match(/([0-9.]+)\s*([NS])\s*,\s*([0-9.]+)\s*([EW])/i);
    if (m) {
      const lat = Number(m[1]) * (m[2].toUpperCase() === "S" ? -1 : 1);
      const lon = Number(m[3]) * (m[4].toUpperCase() === "W" ? -1 : 1);
      coords = { lat, lon, raw: coordinates };
    } else {
      coords = { raw: coordinates };
    }
  }

  // Abuse details: buscamos un email/phone en el texto del bloque
  const abuseText = abuseBlock.join("\n");
  const abuseEmail =
    (abuseText.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i) || [])[0] || null;

  const abusePhone =
    (abuseText.match(/\+\d[\d\s().-]{5,}/) || [])[0]?.trim() || null;

  // Línea heurística que parece dirección
  const abuseAddressLine =
    abuseBlock.find((l) => /po box|street|ave|road|australia|address/i.test(l)) || null;

  // Resultado final “ordenado” para el popup
  return {
    title,
    ip,
    chips,
    summary: {
      asn,
      asnName,
      hostname: hostname || null,
      range: range || null,
      company: company || null,
      hostedDomains: hostedDomains || null,
      privacy: toBool(privacyRaw) ?? null,
      anycast: toBool(anycastRaw) ?? null,
      asnType: asnType || null,
      abuseContact: abuseContact || abuseEmail || null,
    },
    geolocation: {
      city: city || null,
      region: region || null,
      country: country || null,
      postal: postal || null,
      timezone: timezone || null,
      localTime: localTime || null,
      coordinates: coordinates || null,
      coords,
    },
    abuseDetails: {
      email: abuseEmail,
      phone: abusePhone,
      address: abuseAddressLine,
    },
    debug: {
      excerpt: text.slice(0, 700),
      summaryMenuIndex: idxSummaryMenu,
      summaryRealIndex: idxSummaryReal,
      geoRealIndex: idxGeoReal,
    },
  };
}

// Hace la navegación + lectura del body text en IPinfo, y luego parsea
async function scrapeIPInfo(ip, s) {
  const url = `https://ipinfo.io/${encodeURIComponent(ip)}`;
  await s.goto(url);
  await sleep(2200); 

  const title = await s.eval(`document.title || ""`).catch(() => "");

  // Extraemos texto de la página para parsearlo
  const fullText = await s
    .eval(`document.body ? (document.body.innerText || "") : ""`)
    .catch(() => "");

  const data = parseIPinfoFromText(ip, title, fullText);
  return { url, data };
}

// ---------------- VT helpers ----------------
//
// Extrae “tags” tipo dns, scanner, etc desde la parte alta del texto
function extractVTTags(lines) {
  const topChunk = lines.slice(0, 160).join("\n");

  // Busca tokens
  const candidates = (topChunk.match(/\b[a-z0-9]{2,25}-[a-z0-9]{2,25}\b/gi) || []).map((x) =>
    x.toLowerCase()
  );

  // Lista de cosas que NO queremos como tags
  const deny = [
    "real-world",
    "step-by",
    "gemini-powered",
    "large-scale",
    "ai-powered",
    "on-demand",
    "real-life",
    "powered",
    "cookies",
  ];


  const looksSecurityish = (t) =>
    /udp|tcp|dns|tor|proxy|vpn|scanner|bot|malware|phish|spam|abuse|bruteforce|exploit|ransom|ddos|c2|suspicious/i.test(
      t
    );

  const filtered = candidates.filter((t) => !deny.includes(t)).filter((t) => looksSecurityish(t));
  return uniq(filtered).slice(0, 10);
}

// Limpia el snippet
function cleanSnippet(fullText) {
  const lines = String(fullText || "").split("\n");
  const cleaned = lines
    .filter(
      (l) =>
        !/assistant bot|ui demo|not connected to an agent|cancel task|jump to bottom|from intel to action/i.test(l)
    )
    .join("\n");
  return normalizeText(cleaned).slice(0, 900);
}

// Lee texto “visible” de VT, incluyendo shadow DOM.
// Esto es necesario porque VT usa muchos web components.
async function readVirusTotalVisibleText(s) {
  const collected = await s.eval(`(() => {
    // Recorre el DOM y recoge nodos de texto visibles.
    // También entra a shadowRoot cuando existe.
    function collectVisibleText(root, limit = 250000) {
      let out = "";
      const seen = new Set();

      function isSkippableElement(el) {
        if (!el || el.nodeType !== Node.ELEMENT_NODE) return false;
        const tag = (el.tagName || "").toLowerCase();
        return tag === "script" || tag === "style" || tag === "noscript";
      }

      function walk(n) {
        if (!n || seen.has(n) || out.length > limit) return;
        seen.add(n);

        if (n.nodeType === Node.ELEMENT_NODE && isSkippableElement(n)) return;

        if (n.nodeType === Node.TEXT_NODE) {
          const p = n.parentElement;
          if (p) {
            const tag = (p.tagName || "").toLowerCase();
            if (tag === "script" || tag === "style" || tag === "noscript") return;
          }
          const v = (n.nodeValue || "").trim();
          if (v) out += v + "\\n";
        }

        if (n.shadowRoot) walk(n.shadowRoot);

        if (n.childNodes && n.childNodes.length) {
          for (const c of n.childNodes) walk(c);
        }
      }

      walk(root);
      return out;
    }

    const title = document.title || "";
    const fullText = collectVisibleText(document.documentElement, 180000);
    const bodyText = document.body ? (document.body.innerText || "") : "";
    return { title, fullText, bodyText, href: location.href };
  })()`);

  const title = collected?.title || "";
  const href = collected?.href || "";

  // fullText (con shadow DOM) o fallback a bodyText
  const fullText = normalizeText(collected?.fullText || collected?.bodyText || "");
  const lower = fullText.toLowerCase();
  const lines = fullText.split("\n").map((l) => l.trim()).filter(Boolean);

  // Detecta si VT está bloqueando (cloudflare / verify human / access denied...)
  const challenge =
    /checking your browser|verify you are human|access denied|unusual traffic|temporarily blocked|cloudflare/i.test(
      lower
    );

  return { title, href, fullText, lower, lines, challenge };
}

// Convierte el texto de VT en un JSON con datos de interés
function parseVirusTotalFromText(ip, title, fullText, lines) {
  const topLines = lines.slice(0, 260);
  const topText = topLines.join("\n");

  // Detections “0/95”
  const detectionRatio = parseFirstReasonableRatio(topText) || parseFirstReasonableRatio(fullText);

  // Community score
  let communityScore = null;
  const csInline =
    topLines.find((l) => /community\s*score/i.test(l)) ||
    lines.find((l) => /community\s*score/i.test(l));

  if (csInline) {
    const m = csInline.match(/community\s*score\s*(\d{1,4})/i);
    if (m) communityScore = Number(m[1]);
  }

  // Last analysis date
  const lastAnalysisDate =
    pickLineAfter(topLines, "Last Analysis Date") || pickLineAfter(lines, "Last Analysis Date");

  // ASN + CIDR
  const { asn, asName } = parseASNFromText(topText, topLines);
  const ipCidr = parseIPCidrFromText(ip, topText, topLines) || parseIPCidrFromText(ip, fullText, lines);

  // Tags extraídos arriba
  const tags = extractVTTags(topLines);

  
  const verdictKeywords = ["clean", "malicious", "suspicious", "unrated", "timeout"];
  const vendorVerdictCounts = {};
  for (const k of verdictKeywords) {
    const re = new RegExp(`\\b${k}\\b`, "gi");
    const matches = fullText.match(re);
    vendorVerdictCounts[k] = matches ? matches.length : 0;
  }

  return {
    title,
    ipCidr,
    asn,
    asName: asName ? asName.trim() : null,
    communityScore,
    detectionRatio,
    lastAnalysisDate,
    tags,
    vendorVerdictCounts,
    snippet: cleanSnippet(fullText),
  };
}

// Scraper principal de VirusTotal
async function scrapeVirusTotal(ip, backgroundSession, { allowUserFallback = false } = {}) {
  const url = `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`;

  // Navega
  await backgroundSession.goto(url);
  await sleep(3500);

  // Lee texto visible
  const r = await readVirusTotalVisibleText(backgroundSession);

  // Si detectamos que ya es página valida, parseamos
  if (isVirusTotalResultsPage(r.fullText)) {
    const data = parseVirusTotalFromText(ip, r.title, r.fullText, r.lines);
    return { url, data };
  }

  // Si NO es página valida:
  // Devolvemos “requires_user_action”
  return {
    url,
    data: {
      title: r.title,
      requires_user_action: true,
      reason: "VirusTotal blocked automation / challenge detected (no visible fallback to keep popup open).",
      instruction:
        "Open VirusTotal manually in a normal tab, solve the challenge/login if needed, then click 'Get Intel' again.",
      open_url: url,
    },
  };
}

// ---------------- AbuseIPDB (NO visible fallback) ----------------
//
// Aquí se hace lo mismo: detectar si hay challenge o si la página ya tiene el resultado.

// Lee “estado” rápido:
async function readAbuseIPDBState(s) {
  return await s.eval(`(() => {
    const title = document.title || "";
    const href = location.href || "";

    // Señales de que estamos en la página “de resultados”
    const hasReportWrapper = !!document.querySelector("#report-wrapper");
    const hasWell = !!document.querySelector("#report-wrapper .well, .well");
    const hasReportsTable = !!document.querySelector("table#reports");
    const hasFoundMsg = Array.from(document.querySelectorAll("#report-wrapper h3, h3"))
      .some(h => /was found in our database/i.test(h.innerText || ""));

    const looksLikeResult = (hasReportWrapper || hasWell || hasReportsTable || hasFoundMsg);

    // Texto de la página para detectar challenge por palabras
    const bodyText = (document.body && document.body.innerText) ? document.body.innerText : "";
    const lower = bodyText.toLowerCase();

    // Señales de Cloudflare interstitial
    const hasCfInterstitial =
      !!document.querySelector("#cf-challenge-running, form#challenge-form, .cf-browser-verification") ||
      !!document.querySelector('iframe[src*="challenges.cloudflare.com"], iframe[src*="challenge"]');

    const challengeText =
      /checking your browser|verify you are human|attention required|access denied|unusual traffic|temporarily blocked|please wait/i;

    // Solo es “challenge” si NO parece página de resultados y además vemos señales de bloqueo
    const challenge = !looksLikeResult && (hasCfInterstitial || challengeText.test(lower));

    const hasCookieBanner = !!document.querySelector("#cookies-eu-banner");

    return {
      title, href, challenge, looksLikeResult,
      markers: { hasReportWrapper, hasWell, hasReportsTable, hasFoundMsg, hasCfInterstitial, hasCookieBanner }
    };
  })()`);
}

// Intenta aceptar cookies si aparece el banner (para que no bloquee el contenido)
async function acceptAbuseIPDBCookiesIfPresent(s) {
  return await s.eval(`(() => {
    const banner = document.querySelector("#cookies-eu-banner");
    if (!banner) return { ok: false, reason: "no_banner" };

    const style = window.getComputedStyle(banner);
    const visible = style && style.display !== "none" && style.visibility !== "hidden" && style.opacity !== "0";

    const btnAccept = document.querySelector("#cookies-eu-accept");
    const btnNecessary = document.querySelector("#cookies-eu-reject");

    function click(el) {
      try { el && el.click(); return true; } catch { return false; }
    }

    if (btnAccept && (visible || banner.style.display !== "none")) {
      const did = click(btnAccept);
      return { ok: did, clicked: "accept_all" };
    }
    if (btnNecessary && (visible || banner.style.display !== "none")) {
      const did = click(btnNecessary);
      return { ok: did, clicked: "necessary_only" };
    }
    return { ok: false, reason: "no_button_or_hidden" };
  })()`);
}

// Extrae los datos importantes del DOM de AbuseIPDB (tabla, reports, etc.)
async function extractAbuseIPDBDOM(s) {
  return await s.eval(`(() => {
    function txt(el) {
      if (!el) return null;
      const t = (el.innerText || el.textContent || "").replace(/\\s+/g, " ").trim();
      return t || null;
    }
    function pctFrom(text) {
      if (!text) return null;
      const m = String(text).match(/(\\d{1,3})\\s*%/);
      return m ? Number(m[1]) : null;
    }
    function qs(sel, root) { return (root || document).querySelector(sel); }
    function qsa(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }

    const href = location.href || "";
    const title = document.title || "";

    // Si aún no está el wrapper, no podemos extraer
    const reportWrapper = qs("#report-wrapper");
    const hasReportsTable = !!qs("table#reports");
    const hasWell = !!qs("#report-wrapper .well, .well");
    const looksLikeResult = !!reportWrapper || hasReportsTable || hasWell;

    // Challenge detection (por si acaso)
    const bodyText = (document.body && document.body.innerText) ? document.body.innerText : "";
    const lower = bodyText.toLowerCase();

    const hasCfInterstitial =
      !!document.querySelector("#cf-challenge-running, form#challenge-form, .cf-browser-verification") ||
      !!document.querySelector('iframe[src*="challenges.cloudflare.com"], iframe[src*="challenge"]');

    const challengeText =
      /checking your browser|verify you are human|attention required|access denied|unusual traffic|temporarily blocked|please wait/i;

    const challenge = !looksLikeResult && (hasCfInterstitial || challengeText.test(lower));
    if (challenge) return { title, href, challenge: true };

    if (!reportWrapper) return { title, href, challenge: false, not_ready: true };

    // IP desde el H1
    const ip = (() => {
      const h1 = txt(qs("h1")) || "";
      const m = h1.match(/\\b(\\d+\\.\\d+\\.\\d+\\.\\d+)\\b/);
      return m ? m[1] : null;
    })();

    // Caja principal con “reported X times” y “confidence Y%”
    const well = qs("#report-wrapper .well") || qs(".well");
    const wellText = well ? (well.innerText || "") : "";

    const reportsCount = (() => {
      const m = wellText.replace(/,/g, "").match(/reported\\s+(\\d+)\\s+times/i);
      return m ? Number(m[1]) : null;
    })();

    const abuseConfidence = (() => {
      const m = wellText.match(/Confidence\\s+of\\s+Abuse\\s+is\\s+(\\d{1,3})%/i);
      if (m) return Number(m[1]);
      const bar = qs(".progress .progress-bar", well);
      return pctFrom(txt(bar));
    })();

    const foundMsgEl = qsa("#report-wrapper h3").find(h => /was found in our database/i.test(h.innerText || ""));
    const foundMessage = txt(foundMsgEl);

    // Tabla “info” (ISP, ASN, Country, etc.)
    const info = {};
    const infoRows = qsa("table.table tr", well);
    for (const tr of infoRows) {
      const th = txt(qs("th", tr));
      const td = txt(qs("td", tr));
      if (th && td) info[th] = td;
    }

    // Nota importante (whitelist etc.)
    const importantNoteEl = qsa("p", well).find(p => /important note/i.test(p.innerText || ""));
    const importantNote = txt(importantNoteEl);

    // Historia “first reported / most recent”
    const reportIntro = qsa("#report-wrapper p").find(p =>
      /first reported on/i.test(p.innerText || "") && /most recent report/i.test(p.innerText || "")
    );
    const reportIntroText = txt(reportIntro);

    const firstReportedTime = (() => {
      if (!reportIntro) return null;
      const times = qsa("time[datetime]", reportIntro);
      return times[0] ? times[0].getAttribute("datetime") : null;
    })();

    const mostRecentTime = (() => {
      if (!reportIntro) return null;
      const times = qsa("time[datetime]", reportIntro);
      return times[1] ? times[1].getAttribute("datetime") : null;
    })();

    const recentWarning = (() => {
      const el = qs("#report-wrapper p.alert.alert-warning");
      return txt(el);
    })();

    // Extrae las filas “recientes” (hasta 15)
    const reportRows = qsa("table#reports tbody tr");
    const reports = reportRows.slice(0, 15).map(tr => {
      const reporterCell = qs('td[data-title="Reporter"]', tr);
      const reporter = txt(reporterCell);
      const reporterProfile = (() => {
        const a = reporterCell ? reporterCell.querySelector("a[href]") : null;
        return a ? a.href : null;
      })();

      const tsCell = qs('td[data-title="IoA Timestamp (UTC)"]', tr);
      const timeEl = tsCell ? tsCell.querySelector("time[datetime]") : null;
      const ioaTimestamp = timeEl ? timeEl.getAttribute("datetime") : null;
      const relative = (() => {
        const sm = tsCell ? tsCell.querySelector(".text-muted") : null;
        return txt(sm);
      })();

      const commentCell = qs('td[data-title="Comment"]', tr);
      const comment = txt(commentCell);

      const catCell = qs('td[data-title="Categories"]', tr);
      const categories = catCell
        ? Array.from(catCell.querySelectorAll(".label")).map(x => txt(x)).filter(Boolean)
        : [];

      return { reporter, reporterProfile, ioaTimestamp, relative, comment, categories };
    });

    // Devuelve todo estructurado
    return {
      title,
      href,
      challenge: false,
      ip,
      foundMessage,
      reportsCount,
      abuseConfidence,
      info,
      importantNote,
      reportHistory: {
        intro: reportIntroText,
        firstReportedDatetime: firstReportedTime,
        mostRecentDatetime: mostRecentTime,
        recentWarning
      },
      reports
      
    };
  })()`);
}

// Scraper principal de AbuseIPDB
async function scrapeAbuseIPDB(ip, backgroundSession, { allowUserFallback = false } = {}) {
  const url = `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`;

  await backgroundSession.goto(url);
  await sleep(1600);

  // intenta aceptar cookies (si hay banner)
  try {
    await acceptAbuseIPDBCookiesIfPresent(backgroundSession);
  } catch {}

  const maxWaitMs = 18000;
  const start = Date.now();

  while (Date.now() - start < maxWaitMs) {
    const st = await readAbuseIPDBState(backgroundSession).catch(() => null);
    if (!st) break;

    // si hay challenge, devolvemos requires_user_action (para NO abrir tabs activas)
    if (st.challenge) {
      return {
        url,
        data: {
          title: st.title || "",
          requires_user_action: true,
          reason: "AbuseIPDB challenge detected (no visible fallback to keep popup open).",
          instruction:
            "Open AbuseIPDB manually, solve the challenge / accept cookies if prompted, then click 'Get Intel' again.",
          open_url: url,
        },
      };
    }

    // si parece resultado, extraemos DOM
    if (st.looksLikeResult) {
      const data = await extractAbuseIPDBDOM(backgroundSession).catch(() => null);
      if (data && !data.challenge && !data.not_ready) {
        return { url, data };
      }
    }

    await sleep(1200);
  }

  // timeout: no listo a tiempo
  return {
    url,
    data: {
      title: (await backgroundSession.eval(`document.title || ""`).catch(() => "")) || "",
      requires_user_action: true,
      reason: "AbuseIPDB page not ready in time (no visible fallback to keep popup open).",
      instruction: "Open AbuseIPDB manually (cookies/challenge), then click 'Get Intel' again.",
      open_url: url,
    },
  };
}

// ---------------- orchestrator ----------------
//
// Esta es la función principal que ejecuta los 3 scrapers uno por uno.
async function runAllSources(ip) {
  const out = { ip, timestamp: Date.now(), sources: {} };

  // Lista de fuentes: [nombre, función(scraper)]
  const sources = [
    ["virustotal", async (sess) => scrapeVirusTotal(ip, sess, { allowUserFallback: false })],
    ["ipinfo", async (sess) => scrapeIPInfo(ip, sess)],
    ["abuseipdb", async (sess) => scrapeAbuseIPDB(ip, sess, { allowUserFallback: false })],
  ];

  // Itera cada fuente
  for (const [key, fn] of sources) {
    let tab = null;
    let sess = null;

    try {
      // 1) crear tab NO activa
      tab = await createTab("about:blank", false);

      // 2) attach CDP
      sess = new CDPSession(tab.id);
      await sess.attach();

      // 3) ejecutar el scraper de esa fuente (navegar + extraer + parsear)
      const result = await fn(sess);
      out.sources[key] = result;
    } catch (e) {
      // si falla una fuente, no rompe las otras
      out.sources[key] = { url: null, error: errToString(e) };
    } finally {
      // 4) cleanup: detach + cerrar tab
      try {
        if (sess) await sess.detach();
      } catch {}
      try {
        if (tab) await closeTab(tab.id);
      } catch {}
    }
  }

  // Guarda el último resultado (para que el popup pueda mostrarlo si se reabre)
  await new Promise((resolve) => chrome.storage.local.set({ lastIntel: out }, resolve));

  return out;
}

// ---------------- messaging ----------------
//
// Aquí se conectan popup.js -> background.js.
// El popup manda mensajes y el background responde con los datos.
chrome.runtime.onMessage.addListener((msg, _, sendResponse) => {
  (async () => {
    try {
      // Caso principal donde el popup pide intel de un IP
      if (msg?.type === "FETCH_INTEL") {
        const ip = String(msg.ip || "").trim();

        // Validación rápida
        if (!isValidIPv4(ip)) {
          sendResponse({ ok: false, error: "Invalid IPv4" });
          return;
        }

        // Ejecuta todo el pipeline (VT + IPinfo + AbuseIPDB)
        const result = await runAllSources(ip);

        // Devuelve al popup
        sendResponse({ ok: true, result });
        return;
      }

      // Caso: el popup se abre y pide el último resultado guardado
      if (msg?.type === "GET_LAST") {
        chrome.storage.local.get(["lastIntel"], (res) => {
          sendResponse({ ok: true, result: res.lastIntel || null });
        });
        return;
      }

      // Default: mensaje desconocido
      sendResponse({ ok: false, error: "Unknown message type" });
    } catch (e) {
      sendResponse({ ok: false, error: errToString(e) });
    }
  })();

  // Importante: true = “voy a responder async”
  return true;
});
