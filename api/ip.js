// Returns the caller's public IP. Never logs or stores anything.
const { clientInfo } = require("./_lib.js");

module.exports = (req, res) => {
  const i = clientInfo(req);
  const fmt = (req.query && req.query.format) || "";
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("X-Content-Type-Options", "nosniff");
  if (fmt === "json") {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify({ ip: i.ip, version: i.version, country: i.country, region: i.region, city: i.city, timezone: i.timezone }) + "\n");
  } else {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end(i.ip + "\n");
  }
};
