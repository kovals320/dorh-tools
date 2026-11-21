"use strict";
const DM = (() => {
  // --- decompression via native DecompressionStream ---
  async function inflate(bytes, format) {
    const ds = new DecompressionStream(format);
    const stream = new Blob([bytes]).stream().pipeThrough(ds);
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }
  // minimal ZIP reader (central directory), supports stored + deflate
  async function unzip(buf) {
    const u8 = new Uint8Array(buf), dv = new DataView(buf);
    let eocd = -1;
    for (let i = u8.length - 22; i >= Math.max(0, u8.length - 65557); i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) throw new Error("Not a valid ZIP file");
    const n = dv.getUint16(eocd + 10, true);
    let p = dv.getUint32(eocd + 16, true);
    const files = [];
    for (let k = 0; k < n; k++) {
      if (dv.getUint32(p, true) !== 0x02014b50) break;
      const method = dv.getUint16(p + 10, true), csize = dv.getUint32(p + 20, true);
      const nlen = dv.getUint16(p + 28, true), xlen = dv.getUint16(p + 30, true), clen = dv.getUint16(p + 32, true);
      const lho = dv.getUint32(p + 42, true);
      const name = new TextDecoder().decode(u8.subarray(p + 46, p + 46 + nlen));
      p += 46 + nlen + xlen + clen;
      if (name.endsWith("/")) continue;
      const start = lho + 30 + dv.getUint16(lho + 26, true) + dv.getUint16(lho + 28, true);
      const data = u8.subarray(start, start + csize);
      if (method === 0) files.push({ name, data });
      else if (method === 8) files.push({ name, data: await inflate(data, "deflate-raw") });
      else throw new Error(`${name}: unsupported ZIP compression method ${method}`);
    }
    return files;
  }
  async function extract(name, buf) {
    const u8 = new Uint8Array(buf);
    if (u8[0] === 0x1f && u8[1] === 0x8b) return [{ name, data: await inflate(u8, "gzip") }];
    if (u8[0] === 0x50 && u8[1] === 0x4b) return unzip(buf);
    return [{ name, data: u8 }];
  }

  // --- XML parsing ---
  function parseReport(xmlText, DOMParserImpl) {
    const P = DOMParserImpl || DOMParser;
    const doc = new P().parseFromString(xmlText, "application/xml");
    if (doc.getElementsByTagName("parsererror").length) throw new Error("XML parse error");
    const q = (el, path) => {
      let cur = el;
      for (const t of path.split("/")) { if (!cur) return ""; cur = Array.from(cur.childNodes).find(c => c.nodeName === t || c.localName === t); }
      return cur ? cur.textContent.trim() : "";
    };
    const kids = (el, t) => el ? Array.from(el.childNodes).filter(c => c.nodeName === t || c.localName === t) : [];
    const fb = kids(doc, "feedback")[0] || doc.documentElement;
    if (!fb || (fb.localName || fb.nodeName) !== "feedback") throw new Error("Not a DMARC aggregate report (no <feedback> root)");
    const meta = kids(fb, "report_metadata")[0], pol = kids(fb, "policy_published")[0];
    const rep = {
      org: q(meta, "org_name"), email: q(meta, "email"), id: q(meta, "report_id"),
      begin: +q(meta, "date_range/begin") * 1000, end: +q(meta, "date_range/end") * 1000,
      policy: { domain: q(pol, "domain"), p: q(pol, "p"), sp: q(pol, "sp"), pct: q(pol, "pct"), adkim: q(pol, "adkim") || "r", aspf: q(pol, "aspf") || "r" },
      records: []
    };
    for (const r of kids(fb, "record")) {
      const row = kids(r, "row")[0], ids = kids(r, "identifiers")[0], ar = kids(r, "auth_results")[0];
      rep.records.push({
        ip: q(row, "source_ip"), count: +q(row, "count") || 0,
        disposition: q(row, "policy_evaluated/disposition"),
        dkimAligned: q(row, "policy_evaluated/dkim"), spfAligned: q(row, "policy_evaluated/spf"),
        reason: kids(kids(row, "policy_evaluated")[0], "reason").map(x => q(x, "type")).join(", "),
        headerFrom: q(ids, "header_from"), envelopeFrom: q(ids, "envelope_from"),
        dkim: kids(ar, "dkim").map(d => ({ domain: q(d, "domain"), selector: q(d, "selector"), result: q(d, "result") })),
        spf: kids(ar, "spf").map(s => ({ domain: q(s, "domain"), result: q(s, "result") }))
      });
    }
    return rep;
  }

  function aggregate(reports) {
    const bySrc = new Map(), byOrg = new Map();
    let total = 0, pass = 0, dkimOk = 0, spfOk = 0;
    const domains = new Set();
    let begin = Infinity, end = 0;
    for (const rep of reports) {
      domains.add(rep.policy.domain);
      begin = Math.min(begin, rep.begin || Infinity); end = Math.max(end, rep.end || 0);
      const o = byOrg.get(rep.org) || { org: rep.org, reports: 0, count: 0, pass: 0 };
      o.reports++;
      for (const r of rep.records) {
        const ok = r.dkimAligned === "pass" || r.spfAligned === "pass";
        total += r.count; if (ok) pass += r.count;
        if (r.dkimAligned === "pass") dkimOk += r.count;
        if (r.spfAligned === "pass") spfOk += r.count;
        o.count += r.count; if (ok) o.pass += r.count;
        const key = r.ip + "|" + r.headerFrom;
        const s = bySrc.get(key) || { ip: r.ip, headerFrom: r.headerFrom, count: 0, pass: 0, dkimPass: 0, spfPass: 0,
          dispositions: {}, dkimDomains: new Set(), spfDomains: new Set(), reporters: new Set() };
        s.count += r.count; if (ok) s.pass += r.count;
        if (r.dkimAligned === "pass") s.dkimPass += r.count;
        if (r.spfAligned === "pass") s.spfPass += r.count;
        s.dispositions[r.disposition || "none"] = (s.dispositions[r.disposition || "none"] || 0) + r.count;
        r.dkim.forEach(d => d.domain && s.dkimDomains.add(`${d.domain}${d.selector ? "/" + d.selector : ""}:${d.result}`));
        r.spf.forEach(d => d.domain && s.spfDomains.add(`${d.domain}:${d.result}`));
        s.reporters.add(rep.org);
        bySrc.set(key, s);
      }
      byOrg.set(rep.org, o);
    }
    return { total, pass, dkimOk, spfOk, domains: [...domains], begin, end,
      sources: [...bySrc.values()].sort((a, b) => b.count - a.count),
      orgs: [...byOrg.values()].sort((a, b) => b.count - a.count) };
  }
  return { extract, parseReport, aggregate, unzip };
})();
if (typeof module !== "undefined") module.exports = DM;

if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", () => {
  const reports = [], seen = new Set(), errors = [];
  const out = $("#out"), status = $("#status");
  let onlyFail = false;

  async function addFiles(files) {
    status.textContent = "Processing…";
    for (const f of files) {
      try {
        const parts = await DM.extract(f.name, await f.arrayBuffer());
        for (const p of parts) {
          try {
            const rep = DM.parseReport(new TextDecoder().decode(p.data));
            const k = rep.org + "|" + rep.id;
            if (seen.has(k)) continue;
            seen.add(k); reports.push(rep);
          } catch (e) { errors.push(`${p.name}: ${e.message}`); }
        }
      } catch (e) { errors.push(`${f.name}: ${e.message}`); }
    }
    status.textContent = `${reports.length} report(s) loaded.`;
    render();
  }

  function pct(a, b) { return b ? (100 * a / b).toFixed(1) + "%" : "—"; }
  const resCls = r => /pass/.test(r) ? "pass" : /fail/.test(r) ? "fail" : "neutral";
  const day = t => t && isFinite(t) ? new Date(t).toISOString().slice(0, 10) : "?";

  function render() {
    if (!reports.length) { out.innerHTML = errors.length ? errors.map(e => `<p class="err">${esc(e)}</p>`).join("") : ""; return; }
    const a = DM.aggregate(reports);
    const pols = [...new Set(reports.map(r => `p=${r.policy.p}${r.policy.sp ? " sp=" + r.policy.sp : ""}${r.policy.pct && r.policy.pct !== "100" ? " pct=" + r.policy.pct : ""} adkim=${r.policy.adkim} aspf=${r.policy.aspf}`))];
    let h = `<div class="stats">
      <div class="stat"><b>${a.total.toLocaleString()}</b><span>Messages</span></div>
      <div class="stat"><b class="${a.pass / a.total > .98 ? "pass" : a.pass / a.total > .9 ? "neutral" : "fail"}">${pct(a.pass, a.total)}</b><span>DMARC pass</span></div>
      <div class="stat"><b>${pct(a.dkimOk, a.total)}</b><span>DKIM aligned</span></div>
      <div class="stat"><b>${pct(a.spfOk, a.total)}</b><span>SPF aligned</span></div>
      <div class="stat"><b>${a.sources.length}</b><span>Source IPs</span></div>
      <div class="stat"><b>${reports.length}</b><span>Reports</span></div></div>
      <p class="mono u-muted">Domain(s): ${esc(a.domains.join(", "))} · ${day(a.begin)} → ${day(a.end)} · Published: ${esc(pols.join(" | "))}</p>`;
    if (errors.length) h += errors.map(e => `<div class="alert bad">${esc(e)}</div>`).join("");
    const fails = a.sources.filter(s => s.pass < s.count);
    if (fails.length) h += `<div class="alert ${fails.reduce((x, s) => x + s.count - s.pass, 0) / a.total > .05 ? "bad" : ""}">${fails.length} source(s) sent mail that failed DMARC. If one of them is a service you actually use, such as a CRM, ticketing system or newsletter tool, set up aligned DKIM for it before tightening your policy.</div>`;
    else h += `<div class="alert ok">Every message passed DMARC. If you're still on p=none, you can probably move toward quarantine or reject.</div>`;

    h += `<h2>Sending sources</h2><div class="row u-mb8 u-m0"><label class="u-m0"><input type="checkbox" id="onlyfail" ${onlyFail ? "checked" : ""}> Show only sources with failures</label></div>
    <div class="card scroll"><table><tr><th>Source IP</th><th>Header From</th><th>Messages</th><th>DMARC pass</th><th>DKIM (auth results)</th><th>SPF (auth results)</th><th>Disposition</th><th>Reported by</th></tr>` +
      a.sources.filter(s => !onlyFail || s.pass < s.count).map(s => `<tr>
        <td class="mono">${esc(s.ip)}</td><td class="mono">${esc(s.headerFrom)}</td><td>${s.count.toLocaleString()}</td>
        <td class="${s.pass === s.count ? "pass" : s.pass === 0 ? "fail" : "neutral"}">${pct(s.pass, s.count)}</td>
        <td class="mono">${[...s.dkimDomains].map(d => `<span class="${resCls(d.split(":").pop())}">${esc(d)}</span>`).join("<br>") || "—"}</td>
        <td class="mono">${[...s.spfDomains].map(d => `<span class="${resCls(d.split(":").pop())}">${esc(d)}</span>`).join("<br>") || "—"}</td>
        <td class="mono">${esc(Object.entries(s.dispositions).map(([k, v]) => `${k}:${v}`).join(" "))}</td>
        <td>${esc([...s.reporters].join(", "))}</td></tr>`).join("") + `</table></div>`;
    h += `<h2>By reporter</h2><div class="card scroll"><table><tr><th>Reporter</th><th>Reports</th><th>Messages</th><th>DMARC pass</th></tr>` +
      a.orgs.map(o => `<tr><td>${esc(o.org)}</td><td>${o.reports}</td><td>${o.count.toLocaleString()}</td><td>${pct(o.pass, o.count)}</td></tr>`).join("") + `</table></div>`;
    out.innerHTML = h;
    $("#onlyfail").addEventListener("change", e => { onlyFail = e.target.checked; render(); });
  }

  setupDrop($("#drop"), $("#file"), addFiles);
  $("#clear").addEventListener("click", () => { reports.length = 0; seen.clear(); errors.length = 0; status.textContent = ""; out.innerHTML = ""; });
  $("#sample").addEventListener("click", () => addFiles([new File([$("#sample-data").textContent.trim()], "sample.xml")]));
});
