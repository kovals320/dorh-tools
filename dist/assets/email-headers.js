"use strict";
// ---------- parsing (pure, testable) ----------
const EH = (() => {
  function unfold(raw) {
    raw = raw.replace(/\r\n?/g, "\n");
    // headers end at first blank line (if a full message was pasted)
    const blank = raw.search(/\n[ \t]*\n/);
    if (blank > 0 && /^[\x21-\x39\x3b-\x7e]+:/.test(raw.trimStart())) raw = raw.slice(0, blank);
    const out = [];
    for (const line of raw.split("\n")) {
      if (/^[ \t]/.test(line) && out.length) out[out.length - 1].value += " " + line.trim();
      else {
        const m = line.match(/^([\x21-\x39\x3b-\x7e]+):\s?(.*)$/);
        if (m) out.push({ name: m[1], value: m[2].trim() });
        else if (line.trim() && out.length) out[out.length - 1].value += " " + line.trim();
      }
    }
    return out;
  }

  function parseDate(s) {
    if (!s) return null;
    let t = s.replace(/\([^)]*\)/g, " ").replace(/\s+/g, " ").trim();
    // drop trailing junk after timezone, e.g. "+0000 (UTC)" handled above
    let d = Date.parse(t);
    if (isNaN(d)) {
      // try "Mon, 1 Jan 2024 10:00:00.123 +0000" style fractional seconds
      d = Date.parse(t.replace(/(\d\d:\d\d:\d\d)\.\d+/, "$1"));
    }
    return isNaN(d) ? null : new Date(d);
  }

  function parseReceived(v) {
    const semi = v.lastIndexOf(";");
    const body = semi >= 0 ? v.slice(0, semi) : v;
    let date = semi >= 0 ? parseDate(v.slice(semi + 1)) : null;
    if (!date) {
      const m = v.match(/(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(\.\d{1,3})?\d*\s*([+-]\d{2}):?(\d{2})/);
      if (m) { const d = Date.parse(`${m[1]}T${m[2]}${m[3] || ""}${m[4]}:${m[5]}`); if (!isNaN(d)) date = new Date(d); }
    }
    const grab = kw => {
      const m = body.match(new RegExp("(?:^|\\s)" + kw + "\\s+(.+?)(?=\\s+(?:from|by|via|with|id|for)\\s|$)", "i"));
      return m ? m[1].trim() : "";
    };
    const from = grab("from"), by = grab("by"), withp = grab("with");
    const ipm = (from.match(/\[([0-9a-fA-F:.]+)\]/) || from.match(/\(([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)/) || [])[1] || "";
    return { from, by, with: withp.split(/\s/)[0] || "", ip: ipm.replace(/^IPv6:/i, ""), date, raw: v };
  }

  function parseAuthResults(v) {
    // Authentication-Results: authserv-id; method=result (comment) prop=val; ...
    const parts = v.split(";").map(s => s.trim()).filter(Boolean);
    const server = parts.shift() || "";
    const res = [];
    for (const p of parts) {
      const m = p.match(/^([a-z0-9_.-]+)\s*=\s*([a-z]+)\b(.*)$/i);
      if (!m) continue;
      const props = {};
      for (const pm of m[3].matchAll(/([a-z]+\.[a-z0-9_-]+)\s*=\s*("?)([^\s";]+)\2/gi)) props[pm[1].toLowerCase()] = pm[3];
      res.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase(), props, raw: p });
    }
    return { server, results: res };
  }

  function tags(v) {
    const o = {};
    for (const part of v.split(";")) {
      const i = part.indexOf("=");
      if (i > 0) o[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).replace(/\s+/g, "").trim();
    }
    return o;
  }

  const addr = v => { const m = (v || "").match(/<([^>]+)>/); return (m ? m[1] : (v || "").trim()).toLowerCase(); };
  const domainOf = a => { const i = a.lastIndexOf("@"); return i >= 0 ? a.slice(i + 1).replace(/[>\s]/g, "") : ""; };
  // crude organizational domain: last two labels, or three for common 2nd-level ccTLDs
  const orgDomain = d => {
    const p = d.toLowerCase().split(".").filter(Boolean);
    if (p.length <= 2) return p.join(".");
    const sl = p[p.length - 2];
    return (/^(co|com|net|org|ac|gov|edu)$/.test(sl) && p[p.length - 1].length === 2) ? p.slice(-3).join(".") : p.slice(-2).join(".");
  };

  function analyze(raw) {
    const headers = unfold(raw);
    if (!headers.length) throw new Error("No headers found. Paste the raw headers, starting with a line like \"Received: …\" or \"From: …\".");
    const get = n => headers.filter(h => h.name.toLowerCase() === n);
    const first = n => (get(n)[0] || {}).value || "";
    // Received: topmost = most recent; reverse to chronological
    const hops = get("received").map(h => parseReceived(h.value)).reverse();
    let prev = null;
    for (const h of hops) { h.delay = (prev && h.date) ? (h.date - prev) / 1000 : null; if (h.date) prev = h.date; }
    const auth = get("authentication-results").map(h => parseAuthResults(h.value));
    const arcAuth = get("arc-authentication-results").map(h => parseAuthResults(h.value.replace(/^\s*i=\d+\s*;/, "")));
    const dkimSigs = get("dkim-signature").map(h => tags(h.value));
    const spfRecv = get("received-spf").map(h => h.value);

    const summary = { from: first("from"), to: first("to"), cc: first("cc"), subject: first("subject"), date: first("date"),
      messageId: first("message-id"), returnPath: first("return-path"), replyTo: first("reply-to"), sender: first("sender"),
      mailer: first("x-mailer") || first("user-agent"), listUnsub: first("list-unsubscribe") };

    // pick verdicts from the first (topmost = final receiver) Authentication-Results
    const verdict = {};
    const ar = auth[0] || arcAuth[0];
    if (ar) for (const r of ar.results) if (!verdict[r.method]) verdict[r.method] = r;
    if (!verdict.spf && spfRecv[0]) {
      const m = spfRecv[0].match(/^\s*([a-z]+)/i);
      if (m) verdict.spf = { method: "spf", result: m[1].toLowerCase(), props: {}, raw: spfRecv[0] };
    }

    // red flags
    const flags = [];
    const fromA = addr(summary.from), fromD = domainOf(fromA);
    const rpD = domainOf(addr(summary.returnPath)), rtD = domainOf(addr(summary.replyTo));
    if (verdict.dmarc && verdict.dmarc.result !== "pass") flags.push(["bad", `DMARC result is "${verdict.dmarc.result}" for the From domain.`]);
    if (verdict.spf && /fail|softfail|permerror/.test(verdict.spf.result)) flags.push(["bad", `SPF ${verdict.spf.result}.`]);
    if (verdict.dkim && verdict.dkim.result !== "pass") flags.push(["bad", `DKIM ${verdict.dkim.result}.`]);
    if (!ar && !spfRecv.length) flags.push(["warn", "No Authentication-Results header. The receiving server didn't record SPF/DKIM/DMARC checks, or the headers are incomplete."]);
    if (fromD && rpD && orgDomain(fromD) !== orgDomain(rpD)) flags.push(["warn", `Return-Path domain (${rpD}) differs from From domain (${fromD}). Normal for ESPs and mailing lists, but SPF then can't align for DMARC.`]);
    if (fromD && rtD && orgDomain(fromD) !== orgDomain(rtD)) flags.push(["warn", `Reply-To goes to a different domain (${rtD}) than From (${fromD}). This is common in phishing.`]);
    if (fromD && dkimSigs.length && !dkimSigs.some(s => s.d && orgDomain(s.d) === orgDomain(fromD)))
      flags.push(["warn", `No DKIM signature from the From domain. Signing domains: ${dkimSigs.map(s => s.d).join(", ")}.`]);
    if (/<[^>]*>/.test(summary.from)) {
      const disp = summary.from.replace(/<[^>]*>/, "");
      const dm = disp.match(/[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})/i);
      if (dm && orgDomain(dm[1]) !== orgDomain(fromD)) flags.push(["bad", `The From display name contains a different address (${dm[0]}) than the actual sender (${fromA}).`]);
    }
    const bigDelay = hops.find(h => h.delay != null && h.delay > 300);
    if (bigDelay) flags.push(["warn", `A hop took ${fmtDuration(bigDelay.delay)} (at ${bigDelay.by || "unknown server"}).`]);
    if (hops.some(h => h.delay != null && h.delay < -60)) flags.push(["warn", "Some hop timestamps go backwards. Clocks are skewed, or a header was forged or reordered."]);
    const dated = hops.filter(h => h.date); const total = dated.length > 1 ? (dated[dated.length - 1].date - dated[0].date) / 1000 : null;
    if (!flags.length) flags.push(["ok", "No obvious problems found."]);

    return { headers, hops, auth, arcAuth, dkimSigs, spfRecv, summary, verdict, flags, total };
  }
  return { unfold, parseReceived, parseAuthResults, parseDate, analyze, orgDomain };
})();
if (typeof module !== "undefined") module.exports = EH;

// ---------- UI ----------
if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", () => {
  const ta = $("#in"), out = $("#out");
  const cls = r => r === "pass" ? "pass" : /fail|permerror|temperror/.test(r) ? "fail" : "neutral";

  function render() {
    out.innerHTML = "";
    if (!ta.value.trim()) return;
    let r;
    try { r = EH.analyze(ta.value); } catch (e) { out.innerHTML = `<p class="err">${esc(e.message)}</p>`; return; }
    const s = r.summary;
    const v = m => r.verdict[m] ? `<span class="${cls(r.verdict[m].result)}">${esc(r.verdict[m].result.toUpperCase())}</span>` : `<span class="neutral">—</span>`;
    let h = `<div class="stats">
      <div class="stat"><b>${v("spf")}</b><span>SPF</span></div>
      <div class="stat"><b>${v("dkim")}</b><span>DKIM</span></div>
      <div class="stat"><b>${v("dmarc")}</b><span>DMARC</span></div>
      <div class="stat"><b>${r.hops.length}</b><span>Hops</span></div>
      <div class="stat"><b>${r.total != null ? esc(fmtDuration(r.total)) : "—"}</b><span>Total delivery time</span></div></div>`;
    h += `<h2>Findings</h2>` + r.flags.map(([k, t]) => `<div class="alert ${k === "bad" ? "bad" : k === "ok" ? "ok" : ""}">${esc(t)}</div>`).join("");
    h += `<h2>Summary</h2><div class="card kv">` + [["From", s.from], ["Reply-To", s.replyTo], ["Return-Path", s.returnPath], ["Sender", s.sender], ["To", s.to], ["Cc", s.cc],
      ["Subject", s.subject], ["Date", s.date], ["Message-ID", s.messageId], ["Mailer", s.mailer], ["List-Unsubscribe", s.listUnsub]]
      .filter(x => x[1]).map(([k, x]) => `<div>${k}</div><div>${esc(x)}</div>`).join("") + `</div>`;
    if (r.hops.length) {
      h += `<h2>Delivery path (oldest → newest)</h2><div class="card scroll"><table><tr><th>#</th><th>Delay</th><th>From</th><th>By</th><th>With</th><th>Time (UTC)</th></tr>` +
        r.hops.map((x, i) => `<tr><td>${i + 1}</td><td class="mono ${x.delay > 300 ? "fail" : x.delay > 60 ? "neutral" : ""}">${i ? esc(fmtDuration(x.delay)) : "—"}</td>
        <td class="mono">${esc(x.from)}</td><td class="mono">${esc(x.by)}</td><td class="mono">${esc(x.with)}</td>
        <td class="mono">${x.date ? esc(x.date.toISOString().replace("T", " ").replace(".000Z", "")) : "?"}</td></tr>`).join("") + `</table></div>`;
    }
    const authBlocks = [...r.auth.map(a => ["Authentication-Results", a]), ...r.arcAuth.map(a => ["ARC-Authentication-Results", a])];
    if (authBlocks.length) {
      h += `<h2>Authentication results</h2>`;
      for (const [label, a] of authBlocks) {
        h += `<div class="card scroll"><div class="mono u-muted u-mb6">${label} · ${esc(a.server)}</div><table><tr><th>Method</th><th>Result</th><th>Details</th></tr>` +
          a.results.map(x => `<tr><td>${esc(x.method)}</td><td class="${cls(x.result)}">${esc(x.result)}</td><td class="mono">${esc(Object.entries(x.props).map(([k, y]) => k + "=" + y).join("  "))}</td></tr>`).join("") + `</table></div>`;
      }
    }
    if (r.dkimSigs.length) {
      h += `<h2>DKIM signatures</h2><div class="card scroll"><table><tr><th>Domain (d=)</th><th>Selector (s=)</th><th>Algorithm</th><th>Signed headers</th></tr>` +
        r.dkimSigs.map(d => `<tr><td class="mono">${esc(d.d)}</td><td class="mono">${esc(d.s)}</td><td class="mono">${esc(d.a)}</td><td class="mono">${esc((d.h || "").replace(/:/g, ": "))}</td></tr>`).join("") + `</table></div>`;
    }
    h += `<h2>All headers (${r.headers.length})</h2><div class="card scroll"><table>` +
      r.headers.map(x => `<tr><td class="mono u-nowrap u-muted">${esc(x.name)}</td><td class="mono">${esc(x.value)}</td></tr>`).join("") + `</table></div>`;
    out.innerHTML = h;
  }
  $("#go").addEventListener("click", render);
  $("#clear").addEventListener("click", () => { ta.value = ""; out.innerHTML = ""; });
  $("#sample").addEventListener("click", () => { ta.value = $("#sample-data").textContent.trim(); render(); });
});
