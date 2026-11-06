"use strict";
// Compact view (/mini): the Windows tray window, the counterpart of the macOS
// menu bar popover (macos-app/Sources/Views.swift) with the same layout:
// header, network card, stat tiles, the two tabs, the footer. In a plain
// `autodpi ui` it works too, without the tray actions (GET /api/tray lists
// the ones this server has). The shared helpers are in common.js, loaded
// first.
const WIN = /Win/.test(navigator.platform);

const setGlyph = (id, sym) => $(id).setAttribute("href", "#" + sym);

// States: class, title and badge glyph; the colors are in style.css (the
// AppState colors of the macOS app).
const STATES = {
  active: ["st-active", T("Aktif", "Active"), "st-active"],
  starting: ["st-starting", T("Başlıyor", "Starting"), "st-half"],
  standby: ["st-standby", T("Beklemede", "Standby"), "st-half"],
  paused: ["st-paused", T("Duraklatıldı", "Paused"), "st-paused"],
  offline: ["st-offline", T("Çevrimdışı", "Offline"), "st-offline"],
  error: ["st-error", T("Hata", "Error"), "st-error"],
  unreachable: ["st-unreachable", T("Ulaşılamıyor", "Unreachable"), "st-unreachable"],
};

const nf = new Intl.NumberFormat(LOC);
const num = (v) => nf.format(v || 0);
const clock = new Intl.DateTimeFormat(LOC, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const dateTime = new Intl.DateTimeFormat(LOC, { dateStyle: "medium", timeStyle: "short" });
const rtf = new Intl.RelativeTimeFormat(LOC, { style: "short", numeric: "always" });
// ago says "3 hr. ago" the way the macOS app's RelativeDateTimeFormatter does.
function ago(d) {
  const s = (Date.now() - d.getTime()) / 1000;
  if (s < 60) return T("az önce", "just now");
  const units = [["year", 31536000], ["month", 2592000], ["week", 604800], ["day", 86400], ["hour", 3600], ["minute", 60]];
  for (const [u, n] of units) if (s >= n) return rtf.format(-Math.round(s / n), u);
  return "";
}
const sourceLabel = (s) => (s === "auto" ? T("Otomatik", "Automatic") : s === "manual" ? T("Elle", "Manual") : s || "—");

let tray = [];
let paused = false;
let st = "";
let busy = false;
let query = "";
let logEntries = [];
let listEntries = null; // null: no list for this network yet

let msgTimer = 0;
function msg(text, isErr) {
  const m = $("msg");
  clearTimeout(msgTimer);
  $("msgtext").textContent = text || "";
  m.className = "m-msg" + (isErr ? " err" : "");
  m.hidden = !text;
  if (text) msgTimer = setTimeout(() => { m.hidden = true; }, isErr ? 8000 : 5000);
}

/* ---------- status ---------- */

function setState(cls, title, glyph) {
  $("head").className = "m-head " + cls;
  $("badgetext").textContent = title;
  setGlyph("badgeglyph", glyph);
}

async function loadStatus() {
  let s;
  try {
    s = await api("GET", "/api/status");
  } catch (e) {
    setState(...STATES.unreachable);
    $("detail").hidden = true;
    $("toggle").hidden = true;
    $("down").hidden = false;
    $("downerr").textContent = e.message;
    $("body").hidden = true;
    $("updated").textContent = "";
    renderUpdate(null);
    return false;
  }
  $("down").hidden = true;
  $("body").hidden = false;
  setState(...(STATES[s.state] || ["st-error", s.state, "st-error"]));
  const d = $("detail");
  d.textContent = s.detail || "";
  d.title = s.detail || "";
  d.hidden = !s.detail;

  paused = s.state === "paused";
  st = s.state;
  const t = $("toggle");
  t.hidden = false;
  t.className = "m-pill" + (paused ? " resume" : "");
  $("toggletext").textContent = paused ? T("Sürdür", "Resume") : T("Duraklat", "Pause");
  setGlyph("toggleglyph", paused ? "i-play" : "i-pause");
  t.title = paused ? T("Sürdür", "Resume") : T("Duraklat: tüm trafik serbest bırakılır (servis açık kalır)", "Pause: all traffic is let go (the service stays on)");
  t.disabled = busy;

  const n = s.network || {}, o = s.observer || {};
  const online = !!n.Online;
  $("netcard").classList.toggle("online", online);
  setGlyph("netglyph", online ? "i-wifi" : "i-wifi-slash");
  $("netlabel").textContent = n.Label || (online ? T("Henüz belirlenmedi", "Not identified yet") : T("Bağlantı yok", "No connection"));
  $("netlabel").title = n.Label || "";
  const parts = [];
  if (n.Iface) parts.push(n.Iface);
  if (n.Gateway) parts.push(T("ağ geçidi ", "gateway ") + n.Gateway);
  if (n.Provisional) parts.push(T("AS aranıyor", "looking up the AS"));
  $("netmeta").textContent = parts.join(" · ");
  $("netmeta").hidden = !parts.length;

  $("t-list").textContent = num(s.entries);
  $("t-direct").textContent = num(o.Direct);
  $("t-fallback").textContent = num(o.Fallback);
  $("engines").textContent = T("Motorlar: ", "Engines: ") + (s.engines || []).join(" › ");
  $("t-open").textContent = T(num(s.open) + " açık alan adı", num(s.open) + " open names");
  $("updated").textContent = T("autodpi " + s.version + " · pid " + s.pid + " · çalışma süresi " + s.uptime, "autodpi " + s.version + " · pid " + s.pid + " · up " + s.uptime);
  $("updated").title = T("Son güncelleme ", "Last update ") + clock.format(new Date());
  renderUpdate(s.update);
  return true;
}

/* ---------- updates ---------- */

let update = null;
function renderUpdate(u) {
  update = u || null;
  $("updcheck").hidden = !u;
  const n = updateNotice(u);
  $("updbanner").hidden = !n;
  if (!n) return;
  $("updtitle").textContent = n.title;
  $("updtext").textContent = n.text;
  $("updacts").replaceChildren(...n.acts.map((a, i) => {
    const b = el("button", (a === "install" && n.installLabel) || UPDATE_LABELS[a], i ? "" : "primary");
    b.type = "button";
    b.onclick = () => updateAct(a);
    return b;
  }));
}

async function updateAct(a) {
  if (a === "notes") {
    if (tray.includes("notes")) trayAct("notes");
    else if (update && update.url) window.open(update.url, "_blank", "noopener");
    return;
  }
  try {
    renderUpdate(await api("POST", "/api/update/" + a));
    if (a === "install") msg(T("Güncelleme başladı; servis birazdan yeniden başlayacak.", "The update started; the service restarts shortly."));
  } catch (e) { msg(e.message, true); }
}

// The answer goes right above the button that asked.
let updResultTimer;
function updResult(text, isErr, keep) {
  const r = $("updresult");
  clearTimeout(updResultTimer);
  r.textContent = text;
  r.className = "m-updres" + (isErr ? " err" : "");
  r.hidden = !text;
  if (text && !keep) updResultTimer = setTimeout(() => { r.hidden = true; }, isErr ? 12000 : 8000);
}

$("updcheck").onclick = async () => {
  const b = $("updcheck");
  b.disabled = true;
  updResult(T("Denetleniyor…", "Checking…"), false, true);
  try {
    const u = await api("POST", "/api/update/check");
    renderUpdate(u);
    if (u.error) updResult(T("Denetlenemedi: ", "The check failed: ") + u.error, true);
    else if (u.latest) updResult(T("Sürüm " + u.latest + " hazır.", "Version " + u.latest + " is out."));
    else updResult(T("AutoDPI güncel.", "AutoDPI is up to date."));
  } catch (e) { updResult(e.message, true); }
  b.disabled = false;
};

/* ---------- recent events ---------- */

async function loadLog() {
  try { logEntries = ((await api("GET", "/api/log")) || []).slice().reverse(); }
  catch (e) { logEntries = []; }
  renderLog();
}

function renderLog() {
  const ul = $("log");
  ul.replaceChildren();
  ul.hidden = !logEntries.length;
  $("logempty").hidden = logEntries.length > 0;
  for (const x of logEntries) {
    const [sym, color, label] = kindOf(x.kind);
    const li = el("li", null, "k-" + String(x.kind).replace(/[^a-z]/g, ""));
    const ic = el("span", null, "ic kc-" + color);
    ic.append(icon(sym));
    const txt = el("div", null, "txt");
    txt.append(el("div", x.subject || label, "t1"));
    const t2 = el("div", null, "t2");
    t2.append(el("span", label, "kl kc-" + color));
    if (x.detail) t2.append(x.detail);
    txt.append(t2);
    const tm = parseTime(x.time);
    li.append(ic, txt, el("span", tm ? clock.format(tm) : "", "time"));
    li.title = label + (x.subject ? " · " + x.subject : "") + (x.detail ? "\n" + x.detail : "");
    ul.append(li);
  }
}

/* ---------- learned list ---------- */

async function loadList() {
  try {
    const r = await api("GET", "/api/list");
    const net = ((r && r.networks) || []).find((x) => x.current);
    listEntries = net ? net.entries || [] : null;
  } catch (e) { listEntries = null; }
  renderList();
}

function renderList() {
  const ul = $("list");
  ul.replaceChildren();
  const all = listEntries || [];
  const q = query.trim().toLowerCase();
  const rows = (q ? all.filter((e) => e.domain.toLowerCase().includes(q)) : all.slice())
    .sort((a, b) => ((parseTime(b.added) || 0) - (parseTime(a.added) || 0)));
  $("listcount").textContent = num(rows.length);
  $("lclear").hidden = !query;
  const empty = $("listempty");
  ul.hidden = !rows.length;
  empty.hidden = rows.length > 0;
  if (!all.length) {
    setGlyph("listemptyglyph", "i-list");
    $("listemptytext").textContent = T("Bu ağ için öğrenilmiş alan adı yok", "No domain learned for this network");
    return;
  }
  if (!rows.length) {
    setGlyph("listemptyglyph", "i-search");
    $("listemptytext").textContent = T("Eşleşme yok", "No match");
    return;
  }
  for (const e of rows) {
    const manual = e.source === "manual";
    const li = el("li", null, "e");
    const ic = el("span", null, "ic " + (manual ? "kc-gray" : "kc-green"));
    ic.append(icon(manual ? "i-person" : "i-seal"));
    const txt = el("div", null, "txt");
    txt.append(el("div", e.domain, "t1"));
    const added = parseTime(e.added);
    txt.append(el("div", sourceLabel(e.source) + (added ? " · " + ago(added) : ""), "t2"));
    li.append(ic, txt, el("span", e.engine || T("ilk motor", "first engine"), "cap"));
    let help = e.domain;
    if (e.host && e.host !== e.domain) help += T("\nSınanan: ", "\nProbe: ") + e.host;
    const c = parseTime(e.checked);
    if (c) help += T("\nSon kontrol: ", "\nLast check: ") + dateTime.format(c);
    li.title = help;
    ul.append(li);
  }
}

function showTab(t) {
  for (const b of document.querySelectorAll(".m-seg [data-tab]")) {
    const on = b.dataset.tab === t;
    b.classList.toggle("on", on);
    b.setAttribute("aria-selected", String(on));
  }
  $("pane-log").hidden = t !== "log";
  $("pane-list").hidden = t !== "list";
}
for (const b of document.querySelectorAll(".m-seg [data-tab]")) b.onclick = () => showTab(b.dataset.tab);
$("lsearch").oninput = (ev) => { query = ev.target.value; renderList(); };
$("lclear").onclick = () => { query = ""; $("lsearch").value = ""; renderList(); $("lsearch").focus(); };

/* ---------- actions ---------- */

async function refresh() {
  if (await loadStatus()) await Promise.all([loadList(), loadLog()]);
}

async function trayAct(a) {
  try { await api("POST", "/api/tray/" + a); } catch (e) { msg(e.message, true); }
}

$("toggle").onclick = async () => {
  busy = true;
  $("toggle").disabled = true;
  const resuming = paused;
  try { await api("POST", resuming ? "/api/resume" : "/api/pause"); } catch (e) { msg(e.message, true); busy = false; refresh(); return; }
  // The service applies it in the background: follow the state until it
  // settles, as the macOS popover does.
  for (let i = 0; i < 16; i++) {
    if (!(await loadStatus()) || (resuming ? !paused && st !== "starting" : paused)) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  busy = false;
  refresh();
};
$("settings").onclick = () => {
  if (tray.includes("panel")) trayAct("panel");
  else window.open("/?t=" + encodeURIComponent(TOKEN), "_blank", "noopener");
};
$("startsvc").onclick = async () => {
  $("startsvc").disabled = true;
  await trayAct("start-service");
  setTimeout(() => { $("startsvc").disabled = false; refresh(); }, 3000);
};

const pop = $("powermenu");
function menu(open) {
  pop.hidden = !open;
  $("power").setAttribute("aria-expanded", String(open));
  if (open) pop.querySelector("button:not([hidden])").focus();
}
$("power").onclick = (e) => { e.stopPropagation(); menu(pop.hidden); };
document.addEventListener("click", () => menu(false));
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { if (!pop.hidden) menu(false); else if (tray.includes("close")) trayAct("close"); }
});
pop.onclick = async (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  menu(false);
  const a = b.dataset.act;
  if (a === "shutdown") {
    if (!confirm(T("Servis kapatılsın mı? Yeniden başlatılana kadar engelli siteler açılmaz.",
      "Shut the service down? Blocked sites do not open until it is started again."))) return;
    try { await api("POST", "/api/maint/shutdown"); }
    catch (err) { msg(T("Servis kapatılamadı: ", "The service did not shut down: ") + err.message, true); return; }
    if (tray.includes("quit")) trayAct("quit");
    else { msg(T("Servis kapatıldı.", "The service was shut down.")); refresh(); }
    return;
  }
  if (a === "hide" && !confirm(T("Simge gizlenecek ve açılışta da gelmeyecek. AutoDPI arka planda çalışmaya devam eder.\n\nSimgeyi geri getirmek için Başlat menüsünden AutoDPI'yi açın.",
    "The icon goes away and does not come back at sign-in. AutoDPI keeps running in the background.\n\nOpen AutoDPI from the Start menu to bring the icon back."))) return;
  trayAct(a);
};

(async () => {
  try { tray = (await api("GET", "/api/tray")).actions || []; } catch (e) { tray = []; }
  for (const b of pop.querySelectorAll("[data-tray]")) b.hidden = !tray.includes(b.dataset.act);
  const canStart = tray.includes("start-service");
  $("startsvc").hidden = !canStart;
  $("installhint").hidden = canStart;
  $("installtext").textContent = WIN ? T("Kurmak için yönetici terminalinde:", "To install, in an administrator terminal:") : T("Kurmak için Terminal'de:", "To install, in Terminal:");
  $("installcmd").textContent = WIN ? ".\\autodpi.exe install" : "sudo autodpi install";
  // A plain `autodpi ui` has no icon to close: only the service goes down.
  const hasIcon = tray.includes("quit");
  $("power").title = hasIcon ? T("Servisi kapat ya da yalnızca simgeyi kapat", "Shut the service down or close the icon only") : T("Servisi kapat", "Shut the service down");
  if (!hasIcon) pop.querySelector('[data-act="shutdown"]').textContent = T("Servisi kapat", "Shut down the service");
  refresh();
  setInterval(() => { if (document.visibilityState === "visible") refresh(); }, 3000);
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") refresh(); });
})();
