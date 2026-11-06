"use strict";
// The settings page (index.html). common.js, loaded first, has the shared
// helpers: $, T, LOC, api, el, icon, parseTime and the journal KINDS.

const state = {
  paused: false, st: "", current: "", engines: [], known: [], running: [],
  networks: [], log: [], cfg: null, cfgSaved: "", lastOk: null,
  scope: "current", source: "", query: "", sort: { key: "added", dir: -1 },
  gquery: "", gkind: "", update: null,
};

// emptyState: the icon, title and line a card shows when it has nothing.
function emptyState(sym, title, text, err) {
  const d = el("div", null, "empty");
  const i = el("div", null, "eic" + (err ? " err" : ""));
  i.append(icon(sym));
  d.append(i, el("b", title));
  if (text) d.append(el("p", text, err ? "mono small" : ""));
  return d;
}

let msgTimer = 0;
function msg(text, isErr, sticky) {
  const m = $("msg");
  clearTimeout(msgTimer);
  $("msgtext").textContent = text || "";
  $("msgglyph").setAttribute("href", isErr ? "#k-failed" : "#k-check");
  m.className = "toast" + (isErr ? " err" : "");
  m.hidden = !text;
  if (text && !isErr && !sticky) msgTimer = setTimeout(() => { m.hidden = true; }, 7000);
}
$("msgclose").onclick = () => msg("");

/* ---------- tabs ---------- */

const TABS = ["overview", "list", "settings", "maint", "log"];
function showTab(name) {
  if (!TABS.includes(name)) name = "overview";
  for (const v of document.querySelectorAll(".view")) v.hidden = v.dataset.view !== name;
  for (const a of document.querySelectorAll("#tabs a")) {
    const on = a.dataset.tab === name;
    a.classList.toggle("on", on);
    if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  }
}
// Links into a tab live in the hash (#list, #settings…), so reload and back keep it.
window.addEventListener("hashchange", () => { showTab(location.hash.slice(1)); window.scrollTo(0, 0); });
document.addEventListener("click", (ev) => {
  const a = ev.target.closest("a[data-focus]");
  if (a) setTimeout(() => $(a.dataset.focus).focus(), 0);
});
showTab(location.hash.slice(1));

/* ---------- names ---------- */

const STATE_LABEL = {
  active: T("Aktif", "Active"), standby: T("Beklemede", "Standby"), paused: T("Duraklatıldı", "Paused"),
  offline: T("Çevrimdışı", "Offline"), error: T("Hata", "Error"), starting: T("Başlıyor", "Starting"),
};
// What each state means for the traffic, under the hero's title.
const STATE_LEAD = {
  active: T("Engelli siteler motorla açılıyor; diğer trafik doğrudan gidiyor.", "Blocked sites go through an engine; everything else goes direct."),
  standby: T("Yakalama kurulu değil; trafik doğrudan gidiyor. Engel kalkınca servis kendisi devralır.", "The capture is not set up; traffic goes direct. The service takes over once it can."),
  paused: T("Tüm trafik serbest; engelli siteler açılmaz. Servis açık kalır.", "All traffic is let go; blocked sites do not open. The service stays on."),
  offline: T("Ağ bağlantısı yok.", "There is no network connection."),
  error: T("Servis yakalamayı kuramadı; yeniden deneyecek.", "The service could not set up the capture; it will try again."),
  starting: T("Servis yakalamayı kuruyor; bu sırada trafiğe dokunulmuyor.", "The service is setting up the capture; traffic is untouched meanwhile."),
};
const STATE_CLS = { active: "st-active", standby: "st-standby", paused: "st-paused", offline: "st-offline", error: "st-error", starting: "st-starting" };
// The header's badge glyph per state, from the sprite in the page (the macOS app's symbols).
const STATE_GLYPH = { "st-active": "st-active", "st-standby": "st-half", "st-starting": "st-half", "st-paused": "st-paused", "st-offline": "st-offline", "st-error": "st-error", "st-unreach": "st-unreachable", "st-unknown": "st-half" };
const kindLabel = (k) => kindOf(k)[2];
const SOURCE_LABEL = { auto: T("otomatik", "automatic"), manual: T("elle", "manual") };

/* ---------- time ---------- */

function fmtTime(s) {
  const d = parseTime(s);
  return d ? d.toLocaleString(LOC) : "";
}
function fmtShort(s) {
  const d = parseTime(s);
  if (!d) return "";
  const today = new Date();
  const sameDay = d.toDateString() === today.toDateString();
  return sameDay
    ? d.toLocaleTimeString(LOC)
    : d.toLocaleDateString(LOC, { day: "2-digit", month: "2-digit" }) + " " + d.toLocaleTimeString(LOC, { hour: "2-digit", minute: "2-digit" });
}
const rtf = new Intl.RelativeTimeFormat(LOC, { numeric: "always", style: "short" });
// ago: "3 sa. önce", as the popover's list says it.
function ago(s) {
  const d = parseTime(s);
  if (!d) return "";
  const sec = (d.getTime() - Date.now()) / 1000, a = Math.abs(sec);
  if (a < 60) return T("az önce", "just now");
  if (a < 3600) return rtf.format(Math.round(sec / 60), "minute");
  if (a < 86400) return rtf.format(Math.round(sec / 3600), "hour");
  return rtf.format(Math.round(sec / 86400), "day");
}
// dayLabel heads a day of the log: today, yesterday, or the date.
function dayLabel(d) {
  const y = new Date(); y.setDate(y.getDate() - 1);
  const date = d.toLocaleDateString(LOC, { day: "numeric", month: "long" });
  if (d.toDateString() === new Date().toDateString()) return T("Bugün", "Today");
  if (d.toDateString() === y.toDateString()) return T("Dün", "Yesterday") + " · " + date;
  return date;
}
const nf = new Intl.NumberFormat(LOC);
const num = (v) => (v === undefined || v === null ? "-" : nf.format(v));
const put = (id, v) => { $(id).textContent = v === undefined || v === null || v === "" ? "-" : String(v); };
function count(id, n) { $(id).textContent = n ? nf.format(n) : ""; $(id).hidden = !n; }

/* ---------- status ---------- */

// setBadge paints the header, the hero and the tab title with one state.
function setBadge(cls, title, lead, detail) {
  document.body.className = "page " + cls;
  const glyph = "#" + (STATE_GLYPH[cls] || "st-half");
  $("badgeglyph").setAttribute("href", glyph);
  $("herobadge").setAttribute("href", glyph);
  $("badgetext").textContent = title;
  $("herotitle").textContent = title;
  $("herolead").textContent = lead || "";
  $("herodet").textContent = detail || "";
  $("herodet").hidden = !detail;
  document.title = "AutoDPI · " + title;
}

function setCTA(which) {
  $("herocta").hidden = !which;
  $("heroresume").hidden = which !== "resume";
  $("heroretry").hidden = which !== "retry";
  $("herotiles").hidden = which === "resume";
}

async function loadStatus() {
  try {
    const s = await api("GET", "/api/status");
    state.paused = s.state === "paused";
    state.st = s.state;
    state.lastOk = new Date();
    setBadge(STATE_CLS[s.state] || "st-unknown", STATE_LABEL[s.state] || s.state, STATE_LEAD[s.state], s.detail);
    $("toggletext").textContent = state.paused ? T("Sürdür", "Resume") : T("Duraklat", "Pause");
    $("toggleglyph").setAttribute("href", state.paused ? "#i-play" : "#i-pause");
    const t = $("toggle");
    t.className = "pill" + (state.paused ? " resume" : "");
    t.title = state.paused ? T("Sürdür", "Resume") : T("Duraklat: tüm trafik serbest bırakılır (servis açık kalır)", "Pause: all traffic is let go (the service stays on)");
    t.disabled = false;
    setCTA(state.paused ? "resume" : "");
    $("hero").classList.remove("unreach");

    const n = s.network || {}, o = s.observer || {};
    put("s-version", s.version); put("s-pid", s.pid); put("s-uptime", s.uptime);
    $("s-sbpid").textContent = s.singbox_pid ? "· sing-box " + s.singbox_pid : "";
    $("f-version").textContent = s.version || "";
    $("m-svc").textContent = [s.version, s.pid ? "pid " + s.pid : "", s.uptime].filter(Boolean).join(" · ");
    renderUpdate(s.update);
    put("s-netlabel", n.Label || n.Key);
    put("s-iface", n.Iface); put("s-gw", n.Gateway); put("s-key", n.Key);
    const on = $("s-online");
    on.textContent = n.Online ? T("çevrimiçi", "online") : T("çevrimdışı", "offline");
    on.className = "tag " + (n.Online ? "on" : "off");
    on.hidden = false;
    put("s-entries", num(s.entries)); put("s-open", num(s.open));
    count("n-list", s.entries);

    const ch = $("s-engines");
    ch.replaceChildren();
    const eng = s.engines || [];
    if (!eng.length) ch.append(el("li", "-"));
    eng.forEach((e, i) => { const li = el("li"); li.append(el("span", e, "chip" + (i ? "" : " first"))); ch.append(li); });
    renderAddEngines(eng);

    // Flows no path could open are not counted (observer.Stats): no box for them.
    put("o-conns", num(o.Conns)); put("o-direct", num(o.Direct)); put("o-fallback", num(o.Fallback));
    put("o-pass", num(o.Passthrough));
    const tot = (o.Direct || 0) + (o.Fallback || 0) + (o.Passthrough || 0);
    const bar = $("o-bar").children;
    $("o-bar").classList.toggle("none", !tot);
    [o.Direct, o.Fallback, o.Passthrough].forEach((v, i) => { bar[i].style.width = tot ? (100 * (v || 0) / tot).toFixed(2) + "%" : "0"; });

    state.current = n.Key || "";
    $("updated").textContent = T("Canlı · ", "Live · ") + state.lastOk.toLocaleTimeString(LOC);
    $("updated").classList.remove("stale");
  } catch (e) {
    state.st = "";
    setBadge("st-unreach", T("Servise ulaşılamıyor", "The service does not answer"),
      T("Servis kapalı ya da yeniden başlıyor. Sayfa her 5 saniyede bir yeniden dener.", "The service is off or restarting. The page tries again every 5 seconds."), e.message);
    $("toggle").disabled = true;
    setCTA("retry");
    if (!$("s-engines").children.length) $("s-engines").append(el("li", "-"));
    $("hero").classList.add("unreach");
    $("updated").textContent = state.lastOk ? T("Son yanıt ", "Last answer ") + state.lastOk.toLocaleTimeString(LOC) : "";
    $("updated").classList.add("stale");
  }
}
$("heroretry").onclick = () => refresh();

/* ---------- learned list ---------- */

async function loadList() {
  try {
    const r = await api("GET", "/api/list");
    state.networks = (r && r.networks) || [];
    state.listErr = "";
  } catch (e) {
    state.networks = [];
    state.listErr = e.message;
  }
  renderList();
  renderListPreview();
}

function flatRows() {
  const rows = [];
  for (const n of state.networks) {
    if (state.scope === "current" && !n.current) continue;
    for (const e of n.entries || []) {
      rows.push({ e, net: n.label || n.key, cur: !!n.current });
    }
  }
  return rows;
}

function sortVal(r, key) {
  switch (key) {
    case "domain": return r.e.domain.toLowerCase();
    case "net": return r.net.toLowerCase();
    case "engine": return r.e.engine || "";
    case "source": return r.e.source || "";
    case "status": { const d = parseTime(r.e.checked); return d ? d.getTime() : 0; }
    case "added": { const d = parseTime(r.e.added); return d ? d.getTime() : 0; }
  }
  return 0;
}

function sourceTag(src) {
  const tag = el("span", null, "tag src-" + String(src).replace(/[^a-z]/g, ""));
  if (src === "manual" || src === "auto") tag.append(icon(src === "manual" ? "i-person" : "i-seal"));
  tag.append(el("span", SOURCE_LABEL[src] || src || "-"));
  return tag;
}

function emptyRow(body, node) {
  const tr = body.insertRow();
  tr.className = "none";
  const td = tr.insertCell();
  td.colSpan = 7;
  td.append(node);
}

function renderList() {
  const body = $("lbody");
  $("ltable").classList.toggle("one-net", state.scope === "current");
  const all = flatRows();
  const q = state.query.trim().toLowerCase();
  const rows = all.filter((r) => {
    if (state.source && r.e.source !== state.source) return false;
    if (!q) return true;
    return (r.e.domain + " " + (r.e.host || "") + " " + (r.e.engine || "") + " " + r.net + " " + (SOURCE_LABEL[r.e.source] || r.e.source || "")).toLowerCase().includes(q);
  });
  const { key, dir } = state.sort;
  rows.sort((a, b) => {
    const x = sortVal(a, key), y = sortVal(b, key);
    const c = x < y ? -1 : x > y ? 1 : 0;
    return c ? c * dir : a.e.domain.localeCompare(b.e.domain);
  });

  for (const th of document.querySelectorAll("#ltable th[data-k]")) th.removeAttribute("aria-sort");
  const active = document.querySelector('#ltable button[data-sort="' + key + '"]');
  if (active) active.parentElement.setAttribute("aria-sort", dir > 0 ? "ascending" : "descending");

  const cur = state.networks.find((n) => n.current);
  const where = state.scope === "current" ? (cur ? " · " + (cur.label || cur.key) : "") : T(" · tüm ağlar", " · all networks");
  $("l-count").textContent = state.listErr ? "" : (rows.length === all.length ? all.length : rows.length + " / " + all.length) + T(" kayıt", " entries") + where;
  body.replaceChildren();
  if (!rows.length) {
    emptyRow(body, state.listErr ? emptyState("i-warn", T("Liste okunamadı", "The list could not be read"), state.listErr, true)
      : all.length ? emptyState("i-search", T("Aramayla eşleşen kayıt yok", "No entry matches the search"))
        : emptyState("i-seal", state.networks.length || state.scope === "current" ? T("Bu ağda henüz kayıt yok", "No entries on this network yet") : T("Henüz kayıtlı ağ yok", "No network recorded yet"),
          T("AutoDPI engellenen bir siteye rastlayınca onu buraya kendisi ekler. Yukarıdan elle de ekleyebilirsin.", "AutoDPI adds a blocked site here on its own when it meets one. You can also add one above.")));
    return;
  }
  for (const r of rows) {
    const e = r.e, tr = body.insertRow();
    const d = tr.insertCell();
    d.className = "dom";
    d.textContent = e.domain;
    if (e.host && e.host !== e.domain) d.title = T("görülen: ", "seen: ") + e.host;
    const nc = tr.insertCell();
    nc.className = "net";
    nc.textContent = r.net;
    if (r.cur) nc.append(el("span", T("geçerli", "current"), "tag cur"));
    tr.insertCell().append(el("span", e.engine || T("varsayılan", "default"), "chip" + (e.engine ? "" : " def")));
    const sc = tr.insertCell();
    sc.className = "src";
    sc.append(sourceTag(e.source));
    const st = tr.insertCell();
    st.className = "time wide";
    st.textContent = e.source === "manual" ? T("elle (kontrol edilmez)", "manual (not checked)") : (fmtShort(e.checked) || "-");
    if (e.checked) st.title = fmtTime(e.checked);
    const ad = tr.insertCell();
    ad.className = "time wide";
    ad.textContent = fmtShort(e.added);
    ad.title = fmtTime(e.added);
    const act = tr.insertCell();
    act.className = "act";
    if (r.cur) {
      const b = el("button", T("Kaldır", "Remove"), "btn sm ghost");
      b.type = "button";
      b.setAttribute("aria-label", T("Kaldır: ", "Remove: ") + e.domain);
      b.onclick = () => removeDomain(e.domain);
      act.append(b);
    }
  }
}

// The overview's list card: this network's newest entries, as popover rows.
function renderListPreview() {
  const ul = $("p-list");
  ul.replaceChildren();
  const cur = state.networks.find((n) => n.current);
  const ents = ((cur && cur.entries) || []).slice().sort((a, b) => sortVal({ e: b }, "added") - sortVal({ e: a }, "added"));
  $("p-listcount").textContent = state.listErr ? "" : T("bu ağ · ", "this network · ") + ents.length + T(" kayıt", " entries");
  if (!ents.length) {
    const li = el("li", null, "empty-li");
    li.append(state.listErr ? emptyState("i-warn", T("Liste okunamadı", "The list could not be read"), state.listErr, true)
      : emptyState("i-seal", T("Bu ağda henüz kayıt yok", "No entries on this network yet"), T("AutoDPI engellenen bir siteye rastlayınca onu buraya kendisi ekler.", "AutoDPI adds a blocked site here on its own when it meets one.")));
    ul.append(li);
    return;
  }
  for (const e of ents.slice(0, 6)) {
    const li = el("li");
    const ic = el("span", null, "ic " + (e.source === "manual" ? "kc-blue" : "kc-green"));
    ic.append(icon(e.source === "manual" ? "i-person" : "i-seal"));
    const txt = el("div", null, "txt");
    const when = ago(e.added);
    txt.append(el("div", e.domain, "t1"), el("div", (SOURCE_LABEL[e.source] || e.source || "-").replace(/^./, (c) => c.toLocaleUpperCase(LOC)) + (when ? " · " + when : ""), "t2"));
    txt.lastChild.title = fmtTime(e.added);
    li.append(ic, txt, el("span", e.engine || T("varsayılan", "default"), "end chip" + (e.engine ? "" : " def")));
    ul.append(li);
  }
}

for (const th of document.querySelectorAll("#ltable thead th")) {
  const b = th.querySelector("button[data-sort]");
  if (!b) continue;
  th.dataset.k = b.dataset.sort;
  b.onclick = () => {
    const k = b.dataset.sort;
    state.sort = state.sort.key === k ? { key: k, dir: -state.sort.dir } : { key: k, dir: k === "added" ? -1 : 1 };
    renderList();
  };
}
$("lsearch").oninput = (ev) => { state.query = ev.target.value; renderList(); };
$("lsource").onchange = (ev) => { state.source = ev.target.value; renderList(); };
for (const b of document.querySelectorAll("#lscope button")) {
  b.onclick = () => {
    state.scope = b.dataset.scope;
    for (const o of document.querySelectorAll("#lscope button")) o.classList.toggle("on", o === b);
    renderList();
  };
}

async function removeDomain(d) {
  if (!confirm(T(d + " listeden çıkarılsın mı?", "Remove " + d + " from the list?"))) return;
  try { await api("POST", "/api/remove", { domain: d }); msg(T("Çıkarıldı: ", "Removed: ") + d); }
  catch (e) { msg(e.message, true); }
  refresh();
}

$("addform").onsubmit = async (ev) => {
  ev.preventDefault();
  const d = $("adddomain").value.trim();
  try {
    const r = await api("POST", "/api/add", { domain: d, engine: $("addengine").value });
    msg((r.added ? T("Eklendi: ", "Added: ") : T("Zaten listede: ", "Already listed: ")) + r.domain);
    $("adddomain").value = "";
  } catch (e) { msg(e.message, true); }
  refresh();
};

async function toggle() {
  const b = $("toggle");
  b.disabled = true;
  $("heroresume").disabled = true;
  const resuming = state.paused;
  try { await api("POST", resuming ? "/api/resume" : "/api/pause"); msg(resuming ? T("Sürdürüldü.", "Resumed.") : T("Duraklatıldı.", "Paused.")); }
  catch (e) { msg(e.message, true); $("heroresume").disabled = false; refresh(); return; }
  await settle(resuming);
  $("heroresume").disabled = false;
  refresh();
}
$("toggle").onclick = toggle;
$("heroresume").onclick = toggle;

// settle follows the state for a few seconds after a pause or resume: the
// service applies it in the background (it stops or starts the capture), so
// the state right after the request is often the old one. As the macOS app.
async function settle(resuming) {
  for (let i = 0; i < 16; i++) {
    await loadStatus();
    if (resuming ? !state.paused && state.st !== "starting" : state.paused) return;
    await new Promise((r) => setTimeout(r, 500));
  }
}

/* ---------- log ---------- */

async function loadLog() {
  try {
    state.log = ((await api("GET", "/api/log")) || []).slice().reverse();
    state.logErr = "";
  } catch (e) {
    state.log = [];
    state.logErr = e.message;
  }
  renderLog();
  renderLogPreview();
}

// kindMark: the colored icon and label of a journal kind.
function kindMark(kind, cls) {
  const [sym, color, label] = kindOf(kind);
  const k = el("span", null, cls + " kc-" + color);
  k.append(icon(sym), el("span", label));
  k.title = kind;
  return k;
}

// The kind chips: one per kind in the journal, with its count; "all" first.
function renderKinds() {
  const box = $("gkinds");
  const n = new Map();
  for (const j of state.log) n.set(j.kind, (n.get(j.kind) || 0) + 1);
  if (state.gkind && !n.has(state.gkind)) n.set(state.gkind, 0);
  const kinds = [...n.keys()].sort((a, b) => n.get(b) - n.get(a) || kindLabel(a).localeCompare(kindLabel(b), LOC));
  box.replaceChildren();
  const chip = (kind, label, c) => {
    const b = el("button", null, "kchip" + (state.gkind === kind ? " on" : ""));
    b.type = "button";
    b.setAttribute("aria-pressed", state.gkind === kind ? "true" : "false");
    if (kind) { const [sym, color] = kindOf(kind); b.append(icon(sym, "kc-" + color)); }
    b.append(el("span", label), el("i", nf.format(c)));
    b.onclick = () => { state.gkind = kind; renderLog(); };
    box.append(b);
  };
  chip("", T("Tümü", "All"), state.log.length);
  for (const k of kinds) chip(k, kindLabel(k), n.get(k));
  box.hidden = !state.log.length;
}

function renderLog() {
  const box = $("log");
  renderKinds();
  const q = state.gquery.trim().toLowerCase();
  const rows = state.log.filter((j) =>
    (!state.gkind || j.kind === state.gkind) &&
    (!q || (kindLabel(j.kind) + " " + j.kind + " " + (j.subject || "") + " " + (j.detail || "")).toLowerCase().includes(q)));
  $("g-count").textContent = state.logErr ? "" : (rows.length === state.log.length ? state.log.length : rows.length + " / " + state.log.length) + T(" olay", " events");
  count("n-log", state.log.length);
  box.replaceChildren();
  if (!rows.length) {
    box.append(state.logErr ? emptyState("i-warn", T("Günlük okunamadı", "The log could not be read"), state.logErr, true)
      : state.log.length ? emptyState("i-search", T("Eşleşen olay yok", "No event matches"))
        : emptyState("i-text", T("Henüz olay yok", "Nothing recorded yet"), T("Servis bir siteyi onardığında, listeye eklediğinde ya da ağ değiştiğinde burada görünür.", "Shows up here when the service repairs a site, lists one or the network changes.")));
    return;
  }
  const frag = document.createDocumentFragment();
  let day = "";
  for (const j of rows) {
    const d = parseTime(j.time);
    const dk = d ? d.toDateString() : "";
    if (dk !== day) { day = dk; if (d) frag.append(el("div", dayLabel(d), "day")); }
    const r = el("div", null, "lrow");
    const tm = el("span", d ? d.toLocaleTimeString(LOC) : "", "time");
    tm.title = fmtTime(j.time);
    r.append(tm, kindMark(j.kind, "k"), el("span", j.subject || "", "subj"), el("span", j.detail || "", "det"));
    r.lastChild.previousSibling.title = j.subject || "";
    frag.append(r);
  }
  box.append(frag);
}
$("gsearch").oninput = (ev) => { state.gquery = ev.target.value; renderLog(); };

// The overview's events card: the newest entries, as popover rows.
function renderLogPreview() {
  const ul = $("p-log");
  ul.replaceChildren();
  $("p-logcount").textContent = state.logErr ? "" : nf.format(state.log.length) + T(" olay", " events");
  if (!state.log.length) {
    const li = el("li", null, "empty-li");
    li.append(state.logErr ? emptyState("i-warn", T("Günlük okunamadı", "The log could not be read"), state.logErr, true)
      : emptyState("i-text", T("Henüz olay yok", "Nothing recorded yet"), T("Servis bir siteyi onardığında, listeye eklediğinde ya da ağ değiştiğinde burada görünür.", "Shows up here when the service repairs a site, lists one or the network changes.")));
    ul.append(li);
    return;
  }
  for (const j of state.log.slice(0, 6)) {
    const [sym, color, label] = kindOf(j.kind);
    const li = el("li");
    const ic = el("span", null, "ic kc-" + color);
    ic.append(icon(sym));
    const txt = el("div", null, "txt");
    const t2 = el("div", null, "t2");
    t2.append(el("b", label, "kc-" + color), document.createTextNode(j.detail || ""));
    t2.title = j.detail || "";
    txt.append(el("div", j.subject || label, "t1"), t2);
    const tm = el("span", fmtShort(j.time), "time");
    tm.title = fmtTime(j.time);
    li.append(ic, txt, tm);
    ul.append(li);
  }
}

/* ---------- settings ---------- */

function renderEngines() {
  const ol = $("engines");
  ol.replaceChildren();
  if (!state.engines.length) ol.append(el("li", T("Motor yok; en az bir motor ekleyin.", "No engine; add at least one."), "empty-note"));
  state.engines.forEach((name, i) => {
    const li = el("li");
    li.append(el("span", String(i + 1), "n"), el("span", name, "e"));
    const mk = (sym, title, fn, dis, cls) => {
      const b = el("button", null, "btn icon" + (cls ? " " + cls : ""));
      b.type = "button"; b.disabled = dis; b.title = title; b.setAttribute("aria-label", title + ": " + name); b.onclick = fn;
      b.append(icon(sym));
      return b;
    };
    li.append(
      mk("i-up", T("Yukarı taşı", "Move up"), () => { [state.engines[i - 1], state.engines[i]] = [state.engines[i], state.engines[i - 1]]; renderEngines(); }, i === 0),
      mk("i-down", T("Aşağı taşı", "Move down"), () => { [state.engines[i + 1], state.engines[i]] = [state.engines[i], state.engines[i + 1]]; renderEngines(); }, i === state.engines.length - 1),
      mk("i-x", T("Sil", "Delete"), () => { state.engines.splice(i, 1); renderEngines(); }, false, "del"));
    ol.append(li);
  });
  const sel = $("engineadd");
  sel.replaceChildren();
  for (const k of state.known) if (!state.engines.includes(k)) sel.append(new Option(k, k));
  $("engineaddbtn").disabled = !sel.options.length;
  sel.disabled = !sel.options.length;
  markDirty();
}

// The add form offers the engines the service runs: it refuses any other (one
// not in its ladder, tlsspoof without root).
function renderAddEngines(names) {
  if (names.join("|") === state.running.join("|")) return;
  state.running = names.slice();
  const ae = $("addengine"), keep = ae.value;
  ae.replaceChildren(new Option(T("varsayılan motor", "default engine"), ""));
  for (const k of names) ae.append(new Option(k, k));
  ae.value = names.includes(keep) ? keep : "";
}

$("engineaddbtn").onclick = () => {
  const v = $("engineadd").value;
  if (v) { state.engines.push(v); renderEngines(); }
};

function cfgBody() {
  return {
    engines: state.engines,
    spoof_sni: $("spoof_sni").value,
    dns_takeover: $("dns_takeover").checked,
    block_quic: $("block_quic").checked,
    escalate_on_silence: $("escalate_on_silence").checked,
    local_domains: $("local_domains").value.split(/[\s,]+/).map((d) => d.trim().replace(/^\./, "").toLowerCase()).filter(Boolean),
    retest_hours: parseInt($("retest_hours").value, 10) || 0,
    hedge_ms: parseInt($("hedge_ms").value, 10) || 0,
    language: $("language").value,
    auto_update: $("auto_update").checked,
    update_check_hours: parseInt($("update_check_hours").value, 10) || 0,
  };
}

// markDirty lights the save bar while the form differs from the file.
function markDirty() {
  if (!state.cfg) return;
  const dirty = JSON.stringify(cfgBody()) !== state.cfgSaved;
  $("savebar").classList.toggle("on", dirty);
  $("dirtytext").textContent = dirty ? T("Kaydedilmemiş değişiklik", "Unsaved changes") : T("Değişiklik yok", "No changes");
  $("cfgsave").disabled = !dirty;
  $("cfgreset").disabled = !dirty;
}
$("cfgform").addEventListener("input", markDirty);
$("cfgform").addEventListener("change", markDirty);

// The overview's engine card shows the values the file holds.
function renderCfgSummary() {
  const s = state.cfg || {};
  put("c-sni", s.spoof_sni);
  put("c-hedge", s.hedge_ms ? nf.format(s.hedge_ms) + " ms" : "");
  put("c-retest", s.retest_hours ? T(s.retest_hours + " saatte bir", "every " + s.retest_hours + " h") : "");
}

async function loadConfig() {
  try {
    const c = await api("GET", "/api/config");
    const s = c.settings;
    state.known = c.known_engines;
    state.engines = s.engines.slice();
    $("cfgpath").textContent = c.path;
    put("s-cfgpath", c.path);
    $("spoof_sni").value = s.spoof_sni;
    $("retest_hours").value = s.retest_hours;
    $("hedge_ms").value = s.hedge_ms;
    $("dns_takeover").checked = s.dns_takeover;
    $("block_quic").checked = s.block_quic;
    $("escalate_on_silence").checked = !!s.escalate_on_silence;
    $("local_domains").value = (s.local_domains || []).join(", ");
    $("language").value = s.language || "";
    $("auto_update").checked = !!s.auto_update;
    setHoursOption(s.update_check_hours);
    state.language = s.language || "";
    state.cfg = s;
    state.cfgSaved = JSON.stringify(cfgBody());
    renderEngines();
    renderCfgSummary();
    if (c.warning) msg(T("config.json uyarısı: ", "config.json warning: ") + c.warning, true);
  } catch (e) { msg(e.message, true); }
}
$("cfgreset").onclick = async () => { await loadConfig(); msg(T("Ayarlar dosyadaki haline döndürüldü.", "Settings reverted to the file.")); };

$("cfgform").onsubmit = async (ev) => {
  ev.preventDefault();
  const body = cfgBody();
  msg(T("Yönetici izni bekleniyor...", "Waiting for administrator permission..."), false, true);
  try {
    const r = await api("POST", "/api/config", body);
    msg(r.message);
    state.cfgSaved = JSON.stringify(body);
    state.cfg = Object.assign({}, state.cfg, body);
    renderCfgSummary();
    markDirty();
    if (body.language !== state.language) setTimeout(() => location.reload(), 1500); // the page in the new language
  } catch (e) { msg(T("Kaydedilemedi: ", "Not saved: ") + e.message, true); }
};

/* ---------- updates ---------- */

// A value the select does not list (written by hand in config.json) gets an
// option of its own, so saving keeps it.
function setHoursOption(h) {
  const sel = $("update_check_hours");
  const v = String(h || 0);
  if (![...sel.options].some((o) => o.value === v)) {
    const o = el("option", T(v + " saatte bir", "Every " + v + " hours"));
    o.value = v;
    sel.append(o);
  }
  sel.value = v;
}

function updateLine(u) {
  if (!u) return "";
  const parts = [];
  const checked = parseTime(u.checked);
  parts.push(checked ? T("Son denetim ", "Last checked ") + fmtShort(u.checked) : T("Henüz denetlenmedi", "Not checked yet"));
  if (u.latest) parts.push(T(u.latest + " hazır", u.latest + " is out"));
  else if (checked) parts.push(T(u.current + " güncel", u.current + " is up to date"));
  if (u.error) parts.push(T("son deneme başarısız: ", "the last try failed: ") + u.error);
  const l = u.last;
  if (l && l.to) parts.push(l.ok ? T("son güncelleme " + l.from + " → " + l.to, "last update " + l.from + " → " + l.to) : T(l.to + " geri alındı", l.to + " was rolled back"));
  return parts.join(" · ");
}

function renderUpdate(u) {
  state.update = u || null;
  const n = updateNotice(u);
  $("updbanner").hidden = !n;
  if (n) {
    $("updtitle").textContent = n.title;
    $("updtext").textContent = n.text;
    $("updacts").replaceChildren(...n.acts.map((a, i) => {
      const b = el("button", (a === "install" && n.installLabel) || UPDATE_LABELS[a], "btn sm" + (i ? "" : " primary"));
      b.type = "button";
      b.onclick = () => updateAct(a);
      return b;
    }));
  }
  $("updstate").textContent = updateLine(u);
  put("s-update", !u ? "" : u.latest ? T(u.latest + " hazır", u.latest + " is out") : parseTime(u.checked) ? T("güncel", "up to date") : "");
}

async function updateAct(a) {
  const u = state.update || {};
  if (a === "notes") { if (u.url) window.open(u.url, "_blank", "noopener"); return; }
  try {
    renderUpdate(await api("POST", "/api/update/" + a));
    if (a === "install") msg(T("Güncelleme başladı; servis birazdan yeniden başlayacak.", "The update started; the service restarts shortly."));
  } catch (e) { msg(e.message, true); }
}

$("updcheck").onclick = async () => {
  const b = $("updcheck");
  const r = $("updresult");
  const show = (text, isErr) => {
    r.textContent = text;
    r.className = "updresult" + (isErr ? " err" : "");
    r.hidden = !text;
  };
  b.disabled = true;
  show(T("Denetleniyor…", "Checking…"));
  try {
    const u = await api("POST", "/api/update/check");
    renderUpdate(u);
    if (u.error) show(T("Denetlenemedi: ", "The check failed: ") + u.error, true);
    else show(u.latest ? T("Sürüm " + u.latest + " hazır.", "Version " + u.latest + " is out.") : T("AutoDPI güncel.", "AutoDPI is up to date."));
  } catch (e) { show(e.message, true); }
  b.disabled = false;
};

/* ---------- maintenance ---------- */

// group: the card it sits in; confirm: asked first, none = harmless, runs at once.
const MAINT = [
  { id: "reconcile", group: "net", sym: "k-waves", color: "teal", label: T("Yenile", "Refresh"), title: T("Yakalamayı yeniden değerlendir", "Re-evaluate the capture"),
    note: T("Ağ ve sağlık durumuna bakıp yakalamayı hemen yeniden kurmayı dener (bekleme süresini atlar).", "Looks at the network and health and tries to set the capture up again right away (skips the wait)."),
    done: () => T("Yeniden değerlendiriliyor.", "Re-evaluating.") },
  { id: "flush-dns", group: "net", sym: "k-globe", color: "indigo", label: T("Temizle", "Flush"), title: T("DNS önbelleğini temizle", "Flush the DNS cache"),
    note: T("Sistemin çözümleme önbelleği boşaltılır; zehirli ya da eski cevaplar atılır.", "The system's resolver cache is emptied; poisoned or stale answers go."),
    done: () => T("DNS önbelleği temizlendi.", "DNS cache flushed.") },
  { id: "retest", group: "net", sym: "k-pulse", color: "mint", label: T("Sına", "Re-test"), title: T("Listeyi şimdi yeniden sına", "Re-test the list now"),
    note: T("Otomatik kayıtlar arka planda sınanır; artık engelli olmayanlar listeden düşer.", "Automatic entries are tested in the background; those no longer blocked leave the list."),
    done: () => T("Yeniden sınama başladı.", "Re-test started.") },
  { id: "open-reset", group: "net", path: "/api/open/reset", sym: "k-ccw", color: "blue", label: T("Sıfırla", "Reset"), title: T("Açık alan adlarını sıfırla", "Reset open names"),
    note: T("Bu ağın açık alan adları unutulur; yeniden tam yoldan geçer.", "This network's open names are forgotten and take the full path again."),
    confirm: T("Bu ağın açık alan adları sıfırlansın mı?", "Reset this network's open names?"),
    done: (r) => T("Açık alan adları sıfırlandı: " + r.removed + " alan adı.", "Open names reset: " + r.removed + " names.") },
  { id: "restart", group: "svc", sym: "i-power", color: "orange", label: T("Yeniden başlat", "Restart"), title: T("Servisi yeniden başlat", "Restart the service"),
    note: T("Yeni ayarlar uygulanır. Servis kapanır ve yaklaşık 10 sn içinde geri gelir.", "New settings apply. The service stops and comes back in about 10 s."),
    confirm: T("Servis yeniden başlatılsın mı? Birkaç saniye bypass olmaz.", "Restart the service? There is no bypass for a few seconds."),
    done: () => T("Yeniden başlatılıyor; sayfa birkaç saniye servise ulaşamayabilir.", "Restarting; the page may not reach the service for a few seconds.") },
  { id: "reset-list", group: "reset", danger: true, sym: "i-trash", color: "red", label: T("Sıfırla", "Reset"), title: T("Bu ağın listesini sıfırla", "Reset this network's list"),
    note: T("Otomatik öğrenilenler silinir ve yeniden öğrenilir.", "Automatically learned entries are deleted and learned again."),
    confirm: T("Bu ağın otomatik öğrenilen listesi silinsin mi?", "Delete this network's automatically learned list?"),
    done: (r) => r.removed + T(" kayıt silindi.", " entries deleted.") },
  { id: "reset-all-lists", group: "reset", danger: true, sym: "i-trash", color: "red", label: T("Hepsini sıfırla", "Reset all"), title: T("Tüm listeleri sıfırla", "Reset all lists"),
    note: T("Bilinen bütün ağlardaki otomatik kayıtlar silinir.", "Automatic entries on every known network are deleted."),
    confirm: T("TÜM ağların otomatik öğrenilen listeleri silinsin mi?", "Delete the automatically learned lists of ALL networks?"),
    done: (r) => r.removed + T(" kayıt silindi.", " entries deleted.") },
];

const CLEAR_LOGS = {
  id: "clear-logs", group: "svc", sym: "i-trash", color: "gray", label: T("Temizle", "Clear"), title: T("Günlükleri temizle", "Clear logs"),
  note: T("Servis günlüğü, çökme günlüğü ve olay kaydı silinir.", "The service log, the crash log and the event journal are deleted."),
  confirm: T("Servis günlüğü, çökme günlüğü ve olay kaydı silinsin mi?", "Delete the service log, the crash log and the event journal?"),
  done: (r) => T("Günlükler temizlendi (", "Logs cleared (") + Math.round((r.freed_bytes || 0) / 1024) + " KB).",
};

function runMaint(a, b) {
  return async () => {
    if (a.confirm && !confirm(a.confirm)) return;
    b.disabled = true;
    try { msg(a.done(await api("POST", a.path || "/api/maint/" + a.id))); }
    catch (e) { msg(a.title + ": " + e.message, true); }
    b.disabled = false;
    refresh();
  };
}
$("logclear").onclick = runMaint(CLEAR_LOGS, $("logclear"));

function renderMaint() {
  for (const a of [...MAINT, CLEAR_LOGS]) {
    const li = el("li"), ic = el("span", null, "ico lg " + a.color), t = el("div", null, "t");
    ic.append(icon(a.sym));
    t.append(el("b", a.title), el("small", a.note));
    const b = el("button", a.label, "btn" + (a.danger ? " danger" : ""));
    b.type = "button";
    b.onclick = runMaint(a, b);
    li.append(ic, t, b);
    $("maint-" + a.group).append(li);
  }
}
renderMaint();

function refresh() { loadStatus(); loadList(); loadLog(); }
refresh();
loadConfig();
setInterval(() => { if (!document.hidden) refresh(); }, 5000);
