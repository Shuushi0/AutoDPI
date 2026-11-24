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
  // err.kind says why there is no answer: "gone" (this page's own server is
  // no longer there: the window that started it was closed), or what the
  // server says about the service: "down", "denied", "busy", "" (it answered
  // with an error).
  let r;
  try { r = await fetch(path, opt); }
  catch (e) {
    const err = new Error(T("Bu sayfanın bağlantısı koptu. Sayfayı kapatıp ayarları yeniden açın.", "This page lost its connection. Close it and open the settings again."));
    err.kind = "gone";
    throw err;
  }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    const err = new Error(j.error || r.statusText);
    err.kind = r.status === 403 ? "gone" : j.kind || "";
    if (r.status === 403) err.message = T("Bu sayfanın bağlantısı koptu. Sayfayı kapatıp ayarları yeniden açın.", "This page lost its connection. Close it and open the settings again.");
    throw err;
  }
  return j;
}

// unreachText is what to show when the status could not be read, by the
// error's kind: [title, explanation, whether starting the service could help].
function unreachText(e) {
  switch (e && e.kind) {
    case "gone":
      return [T("Sayfa bağlı değil", "Page disconnected"), T("Bu sayfayı açan pencere ya da komut kapanmış; servis bundan etkilenmez. Sayfayı kapatıp ayarları yeniden açın.", "The window or command that opened this page has ended; the service is not affected. Close the page and open the settings again."), false];
    case "denied":
      return [T("Erişim izni yok", "No permission"), T("Servis çalışıyor, ama bu kullanıcı hesabının ona erişim izni yok.", "The service runs, but this user account is not allowed to talk to it."), false];
    case "busy":
      return [T("Servis yanıt vermiyor", "The service is not answering"), T("Servis çalışıyor ama yanıtı gecikiyor; kendiliğinden yeniden denenecek.", "The service runs but its answer is late; this is tried again by itself."), false];
  }
  return [T("Servis çalışmıyor", "The service is not running"), T("Servis kapalı ya da yeniden başlıyor. Durum her 5 saniyede yeniden denenir.", "The service is off or restarting. The state is checked again every 5 seconds."), true];
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
  // An error from looking for releases says nothing about this version: the
  // settings line shows it, the banner does not pass it off as the reason.
  const instErr = u.error && u.error_kind !== "check" ? u.error : "";
  if (u.phase === "installing") {
    // First the new version checks itself here, which can take a minute or
    // two; only then is anything replaced and restarted.
    return { title: T(v + " kuruluyor", "Installing " + v), text: T("Yeni sürüm bu bilgisayarda denetleniyor, ardından kurulacak; servis birkaç saniyeliğine yeniden başlayabilir.", "The new version is being checked on this computer, then installed; the service may restart for a few seconds."), acts: [] };
  }
  if (u.skipped) return null;
  if (u.phase === "downloading") return { title, text: T("İndiriliyor…", "Downloading…"), acts: ["notes"] };
  if (u.failed) {
    // Taken back after it was installed, or never installed at all (its own
    // check on this computer said no): not the same thing to be told.
    const text = u.rolled_back
      ? T("Yeni sürüm düzgün çalışmadı, önceki sürüme dönüldü.", "The new version did not run properly; the previous one is back.")
      : T("Bu bilgisayarda kurulamadı; kurulu sürüm çalışmaya devam ediyor.", "It could not be installed on this computer; the installed version keeps running.") + (instErr ? " " + instErr : "");
    // The button tries the same version once more; "Update" here read as
    // if nothing had been tried.
    return { title: T(v + " kurulamadı", v + " did not install"), text, acts: ["install", "notes", "skip"], installLabel: T("Yeniden dene", "Try again") };
  }
  if (!u.supported) return { title, text: T("Bu kurulum kendini güncelleyemiyor; yeni sürümü elle kurun.", "This install cannot update itself; install the new version by hand."), acts: ["notes"] };
  return { title, text: instErr || T("Kurmak için Güncelle'ye basın; servis birkaç saniyeliğine yeniden başlar.", "Press Update to install it; the service restarts for a few seconds."), acts: ["install", "notes", "skip"] };
}

const UPDATE_LABELS = { install: T("Güncelle", "Update"), notes: T("Notlar", "Notes"), skip: T("Bu sürümü atla", "Skip this version") };
