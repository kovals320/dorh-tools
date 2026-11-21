// Server-rendered "what is my IP" page. Never logs or stores anything.
const { clientInfo } = require("./_lib.js");
const { TEMPLATE } = require("./_template.js");
const esc = s => String(s || "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

module.exports = (req, res) => {
  const i = clientInfo(req);
  let flag = "";
  if (/^[A-Z]{2}$/.test(i.country)) flag = String.fromCodePoint(...[...i.country].map(c => 0x1f1a5 + c.charCodeAt(0))) + " ";
  const loc = [i.city, i.region, i.country].filter(Boolean).join(", ");
  const html = TEMPLATE
    .replace(/__IP__/g, esc(i.ip))
    .replace("__VER__", "IPv" + i.version)
    .replace("__LOC__", loc ? flag + esc(loc) : "Unknown")
    .replace("__TZ__", esc(i.timezone) || "Unknown")
    .replace("__UA__", esc(i.ua) || "—");
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(html);
};
