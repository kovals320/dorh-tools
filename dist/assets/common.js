// Shared helpers. No network access is used anywhere on this site.
"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

function copyText(text, btn) {
  const done = () => { if (btn) { const t = btn.textContent; btn.textContent = "Copied"; setTimeout(() => btn.textContent = t, 1200); } };
  if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, () => fallback());
  else fallback();
  function fallback() {
    const ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta);
    ta.select(); try { document.execCommand("copy"); done(); } catch (e) {} ta.remove();
  }
}

// Delegated copy buttons: <button data-copy="#selector">
document.addEventListener("click", e => {
  const b = e.target.closest("[data-copy]");
  if (!b) return;
  const t = $(b.dataset.copy);
  if (t) copyText(t.value ?? t.textContent, b);
});

function setupDrop(zone, input, onFiles) {
  zone.addEventListener("click", () => input.click());
  zone.addEventListener("dragover", e => { e.preventDefault(); zone.classList.add("over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("over"));
  zone.addEventListener("drop", e => { e.preventDefault(); zone.classList.remove("over"); onFiles(Array.from(e.dataTransfer.files)); });
  input.addEventListener("change", () => { onFiles(Array.from(input.files)); input.value = ""; });
}

function fmtDuration(sec) {
  if (sec == null || isNaN(sec)) return "";
  const neg = sec < 0; sec = Math.abs(Math.round(sec));
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
  let out = d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : m ? `${m}m ${s}s` : `${s}s`;
  return (neg ? "-" : "") + out;
}
