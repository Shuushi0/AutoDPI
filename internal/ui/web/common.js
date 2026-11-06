"use strict";
// Shared by the settings page (app.js) and the compact view (mini.js), and
// loaded before either: the token, the language, the API call, the DOM and
// icon helpers and the journal kinds.
const TOKEN = new URLSearchParams(location.search).get("t") || "";
const $ = (id) => document.getElementById(id);
// The server sets the page's language (internal/i18n); texts come in pairs.
const TR = document.documentElement.lang === "tr";
const T = (tr, en) => (TR ? tr : en);
const LOC = TR ? "tr-TR" : "en-GB";
const SVG_NS = "http://www.w3.org/2000/svg";

async function api(method, path, body) {
  const opt = { method, headers: { "X-Token": TOKEN } };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(path, opt);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

// icon returns an <svg><use href="#sym"/></svg> from the sprite in the page.
function icon(sym, cls) {
  const s = document.createElementNS(SVG_NS, "svg");
  const u = document.createElementNS(SVG_NS, "use");
  u.setAttribute("href", "#" + sym);
  s.setAttribute("aria-hidden", "true");
  if (cls) s.setAttribute("class", cls);
  s.append(u);
  return s;
}

function parseTime(s) {
  if (!s || String(s).startsWith("0001")) return null;
  const d = new Date(s);
  return isNaN(d) ? null : d;
}

// Journal kinds (the daemon's note calls): symbol, color and label, as
// KindStyle in the macOS app (macos-app/Sources/Views.swift) shows them.
// Anything else shows as a gray dot with the raw kind.
const KINDS = {
  repaired: ["k-repaired", "green", T("Onarıldı", "Repaired")],
  listed: ["k-plus", "blue", T("Listeye eklendi", "Listed")],
  removed: ["k-minus", "orange", T("Listeden çıkarıldı", "Removed")],
  capture: ["k-waves", "teal", T("Yakalama", "Capture")],
  dns: ["k-globe", "indigo", "DNS"],
  engine: ["k-gear", "purple", T("Motor", "Engine")],
  network: ["i-wifi", "blue", T("Ağ", "Network")],
  state: ["k-bolt", "orange", T("Durum", "State")],
  pause: ["k-pause", "gray", T("Duraklatıldı", "Paused")],
  resume: ["k-play", "green", T("Sürdürüldü", "Resumed")],
  restart: ["k-cw", "orange", T("Yeniden başlatma", "Restart")],
  shutdown: ["k-power", "red", T("Kapatma", "Shutdown")],
  "list-reset": ["k-trash", "orange", T("Liste sıfırlandı", "List reset")],
  update: ["k-update", "blue", T("Güncelleme", "Update")],
};
const kindOf = (k) => KINDS[k] || ["k-dot", "gray", k];

// updateNotice is what the update banner says for the status's "update"
// part, null when there is nothing to announce. acts are the buttons, the
// first one the primary: install, notes, skip.
function updateNotice(u) {
  if (!u || !u.latest) return null;
  const v = u.latest;
  const title = T("Sürüm " + v + " hazır", "Version " + v + " is out");
  if (u.phase === "installing") {
    return { title: T(v + " kuruluyor", "Installing " + v), text: T("Servis yeniden başlıyor; bağlantılar birkaç saniye kesilebilir.", "The service is restarting; connections may drop for a few seconds."), acts: [] };
  }
  if (u.skipped) return null;
  if (u.failed) {
    return { title: T(v + " kurulamadı", v + " did not install"), text: T("Yeni sürüm düzgün çalışmadı, önceki sürüme dönüldü.", "The new version did not run properly; the previous one is back."), acts: ["install", "notes", "skip"] };
  }
  if (u.phase === "downloading") return { title, text: T("İndiriliyor…", "Downloading…"), acts: ["notes"] };
  if (!u.supported) return { title, text: T("Bu kurulum kendini güncelleyemiyor; yeni sürümü elle kurun.", "This install cannot update itself; install the new version by hand."), acts: ["notes"] };
  if (u.auto) {
    return { title, text: u.phase === "ready" ? T("İndirildi; bağlantı boşta kalınca kendiliğinden kurulacak.", "Downloaded; it installs by itself once the connection is idle.") : T("Uygun bir anda kendiliğinden kurulacak.", "It installs by itself at a quiet moment."), acts: ["install", "notes"], installLabel: T("Şimdi kur", "Install now") };
  }
  return { title, text: u.error || T("Kurmak için Güncelle'ye basın; servis birkaç saniyeliğine yeniden başlar.", "Press Update to install it; the service restarts for a few seconds."), acts: ["install", "notes", "skip"] };
}

const UPDATE_LABELS = { install: T("Güncelle", "Update"), notes: T("Notlar", "Notes"), skip: T("Bu sürümü atla", "Skip this version") };
