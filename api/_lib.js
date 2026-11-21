const h = (req, k) => { const v = req.headers[k]; return Array.isArray(v) ? v[0] : (v || ""); };
const dec = s => { try { return decodeURIComponent(s); } catch (e) { return s; } };
function clientInfo(req) {
  const ip = (h(req, "x-real-ip") || h(req, "x-forwarded-for").split(",")[0] || (req.socket && req.socket.remoteAddress) || "").trim();
  return {
    ip, version: ip.includes(":") ? 6 : 4,
    country: h(req, "x-vercel-ip-country"), region: dec(h(req, "x-vercel-ip-country-region")),
    city: dec(h(req, "x-vercel-ip-city")), timezone: h(req, "x-vercel-ip-timezone"),
    ua: h(req, "user-agent"),
  };
}
module.exports = { clientInfo };
