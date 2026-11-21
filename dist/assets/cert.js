"use strict";
const CD = (() => {
  const OID = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.9": "street", "2.5.4.10": "O", "2.5.4.11": "OU",
    "2.5.4.5": "serialNumber", "2.5.4.15": "businessCategory", "2.5.4.17": "postalCode", "2.5.4.97": "organizationIdentifier",
    "2.5.4.42": "GN", "2.5.4.4": "SN", "2.5.4.12": "title", "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID",
    "1.2.840.113549.1.9.1": "emailAddress", "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC", "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
    "1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC", "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption", "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption", "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.10": "RSASSA-PSS", "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256", "1.2.840.10045.4.3.3": "ecdsa-with-SHA384", "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65", "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521", "1.3.132.0.10": "secp256k1",
    "1.3.6.1.5.5.7.3.1": "serverAuth", "1.3.6.1.5.5.7.3.2": "clientAuth", "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection", "1.3.6.1.5.5.7.3.8": "timeStamping", "1.3.6.1.5.5.7.3.9": "OCSPSigning",
    "2.5.29.37.0": "anyExtendedKeyUsage", "1.3.6.1.4.1.311.20.2.2": "smartcardLogon",
    "2.23.140.1.2.1": "DV (domain validated)", "2.23.140.1.2.2": "OV (organization validated)", "2.23.140.1.2.3": "IV (individual validated)",
    "2.23.140.1.1": "EV (extended validation)", "2.5.29.32.0": "anyPolicy",
    "1.3.6.1.5.5.7.48.1": "OCSP", "1.3.6.1.5.5.7.48.2": "CA Issuers",
  };
  const EXT = {
    "2.5.29.17": "Subject Alternative Name", "2.5.29.19": "Basic Constraints", "2.5.29.15": "Key Usage", "2.5.29.37": "Extended Key Usage",
    "2.5.29.14": "Subject Key Identifier", "2.5.29.35": "Authority Key Identifier", "2.5.29.31": "CRL Distribution Points",
    "1.3.6.1.5.5.7.1.1": "Authority Information Access", "2.5.29.32": "Certificate Policies", "1.3.6.1.4.1.11129.2.4.2": "Signed Certificate Timestamps (CT)",
    "1.3.6.1.5.5.7.1.24": "TLS Feature (OCSP Must-Staple)", "2.5.29.30": "Name Constraints", "1.3.6.1.4.1.11129.2.4.3": "CT Precertificate Poison",
  };
  const KU = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"];

  // ----- DER -----
  function parse(b, off = 0, end = b.length) {
    const nodes = [];
    while (off < end) {
      const tag = b[off]; let p = off + 1;
      if ((tag & 0x1f) === 0x1f) throw new Error("High-tag-number form not supported");
      let len = b[p++];
      if (len & 0x80) {
        const n = len & 0x7f; if (!n || n > 4) throw new Error("Bad DER length");
        len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[p++];
      }
      if (p + len > end) throw new Error("DER truncated. Is this a complete certificate?");
      const node = { tag, start: off, hstart: p, end: p + len, len };
      if (tag & 0x20) node.kids = parse(b, p, p + len);
      nodes.push(node); off = p + len;
    }
    return nodes;
  }
  const bytes = (b, n) => b.subarray(n.hstart, n.end);
  const hex = (u8, sep = ":") => Array.from(u8, x => x.toString(16).padStart(2, "0").toUpperCase()).join(sep);
  function oid(b, n) {
    const u = bytes(b, n); const out = [Math.floor(u[0] / 40), u[0] % 40]; let v = 0;
    if (u[0] >= 80) { out[0] = 2; out[1] = u[0] - 80; }
    for (let i = 1; i < u.length; i++) { v = v * 128 + (u[i] & 0x7f); if (!(u[i] & 0x80)) { out.push(v); v = 0; } }
    return out.join(".");
  }
  function str(b, n) {
    const u = bytes(b, n);
    switch (n.tag) {
      case 0x0c: return new TextDecoder("utf-8").decode(u);
      case 0x1e: { let s = ""; for (let i = 0; i + 1 < u.length; i += 2) s += String.fromCharCode(u[i] << 8 | u[i + 1]); return s; }
      case 0x1c: { let s = ""; for (let i = 0; i + 3 < u.length; i += 4) s += String.fromCodePoint(((u[i] << 24) | (u[i + 1] << 16) | (u[i + 2] << 8) | u[i + 3]) >>> 0); return s; }
      default: try { return new TextDecoder("utf-8", { fatal: true }).decode(u); } catch (e) { return Array.from(u, c => String.fromCharCode(c)).join(""); }
    }
  }
  function time(b, n) {
    const s = str(b, n); let y, r;
    if (n.tag === 0x17) { y = +s.slice(0, 2); y += y >= 50 ? 1900 : 2000; r = s.slice(2); } else { y = +s.slice(0, 4); r = s.slice(4); }
    return new Date(Date.UTC(y, +r.slice(0, 2) - 1, +r.slice(2, 4), +r.slice(4, 6), +r.slice(6, 8), +(r.slice(8, 10) || 0)));
  }
  function name(b, n) {
    const parts = [];
    for (const set of n.kids || []) for (const atv of set.kids || []) {
      const [o, v] = atv.kids; const k = oid(b, o);
      parts.push([OID[k] || k, str(b, v)]);
    }
    return parts;
  }
  const nameStr = parts => parts.map(([k, v]) => `${k}=${v}`).join(", ");
  function fmtDays(d) {
    const whole = Math.floor(d + 1e-9), sec = Math.round((d - whole) * 86400);
    return sec ? `${whole} days + ${sec >= 3600 ? (sec / 3600).toFixed(1) + " h" : sec + " s"}` : `${whole} days`;
  }
  function intHex(b, n) { let u = bytes(b, n); while (u.length > 1 && u[0] === 0) u = u.subarray(1); return hex(u); }
  function bitLen(u) { let i = 0; while (i < u.length && u[i] === 0) i++; if (i === u.length) return 0; return (u.length - i - 1) * 8 + (32 - Math.clz32(u[i])); }

  function spki(b, n) {
    const [alg, bits] = n.kids; const algOid = oid(b, alg.kids[0]);
    const k = { alg: OID[algOid] || algOid, bits: null, curve: null };
    if (k.alg === "RSA") {
      const inner = parse(b, bits.hstart + 1, bits.end)[0];
      k.bits = bitLen(bytes(b, inner.kids[0]));
      const e = bytes(b, inner.kids[1]); k.exponent = e.reduce((a, x) => a * 256 + x, 0);
    } else if (k.alg === "EC") {
      const p = alg.kids[1]; if (p && p.tag === 0x06) { const c = oid(b, p); k.curve = OID[c] || c; }
      k.bits = { "P-256": 256, "P-384": 384, "P-521": 521, secp256k1: 256 }[k.curve] || null;
    } else if (k.alg === "Ed25519") k.bits = 256; else if (k.alg === "Ed448") k.bits = 456;
    return k;
  }

  function collect(b, n, tag, out = []) { if (n.tag === tag) out.push(n); (n.kids || []).forEach(c => collect(b, c, tag, out)); return out; }

  function generalName(b, g) {
    const u = bytes(b, g);
    switch (g.tag) {
      case 0x82: return ["DNS", str(b, g)];
      case 0x81: return ["email", str(b, g)];
      case 0x86: return ["URI", str(b, g)];
      case 0x87: return ["IP", u.length === 4 ? Array.from(u).join(".") : u.length === 16 ? Array.from({ length: 8 }, (_, i) => ((u[2 * i] << 8) | u[2 * i + 1]).toString(16)).join(":").replace(/(^|:)0(:0)+(:|$)/, "::") : hex(u)];
      case 0xa4: return ["dirName", nameStr(name(b, g.kids[0]))];
      case 0xa0: return ["otherName", oid(b, g.kids[0])];
      default: return ["?", hex(u)];
    }
  }

  function extensions(b, seq) {
    const out = [];
    for (const e of seq.kids || []) {
      const id = oid(b, e.kids[0]);
      const critical = e.kids.length === 3 && e.kids[1].tag === 0x01 && b[e.kids[1].hstart] !== 0;
      const oct = e.kids[e.kids.length - 1];
      const x = { oid: id, name: EXT[id] || id, critical, value: null };
      try {
        const v = parse(b, oct.hstart, oct.end)[0];
        switch (id) {
          case "2.5.29.17": x.value = (v.kids || []).map(g => generalName(b, g)); break;
          case "2.5.29.19": {
            const ca = v.kids && v.kids[0] && v.kids[0].tag === 0x01 ? b[v.kids[0].hstart] !== 0 : false;
            const pl = (v.kids || []).find(k => k.tag === 0x02);
            x.value = { ca, pathLen: pl ? bytes(b, pl).reduce((a, y) => a * 256 + y, 0) : null }; break;
          }
          case "2.5.29.15": {
            const u = bytes(b, v).subarray(1); const on = [];
            KU.forEach((k, i) => { if (u[i >> 3] & (0x80 >> (i & 7))) on.push(k); }); x.value = on; break;
          }
          case "2.5.29.37": x.value = v.kids.map(k => { const o = oid(b, k); return OID[o] || o; }); break;
          case "2.5.29.14": x.value = hex(bytes(b, v)); break;
          case "2.5.29.35": { const k = (v.kids || []).find(k => k.tag === 0x80); x.value = k ? hex(bytes(b, k)) : ""; break; }
          case "2.5.29.31": x.value = collect(b, v, 0x86).map(n => str(b, n)); break;
          case "1.3.6.1.5.5.7.1.1": x.value = v.kids.map(ad => { const m = oid(b, ad.kids[0]); return [OID[m] || m, generalName(b, ad.kids[1])[1]]; }); break;
          case "2.5.29.32": x.value = v.kids.map(pi => { const o = oid(b, pi.kids[0]); return OID[o] ? `${OID[o]} (${o})` : o; }); break;
          case "1.3.6.1.4.1.11129.2.4.2": x.value = "present"; break;
          default: x.value = hex(bytes(b, oct)).slice(0, 120) + (oct.len > 40 ? "…" : "");
        }
      } catch (err) { x.value = "(could not decode)"; }
      out.push(x);
    }
    return out;
  }

  // ----- input -----
  function pemBlocks(text) {
    const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g; const out = []; let m;
    while ((m = re.exec(text))) {
      const b64 = m[2].replace(/^[A-Za-z-]+:.*$/gm, "").replace(/[^A-Za-z0-9+/=]/g, "");
      out.push({ label: m[1], der: b64decode(b64) });
    }
    if (!out.length) {
      const t = text.replace(/\s+/g, "");
      if (/^[A-Za-z0-9+/=]{100,}$/.test(t)) out.push({ label: "", der: b64decode(t) });
    }
    return out;
  }
  function b64decode(s) {
    const bin = typeof atob === "function" ? atob(s) : Buffer.from(s, "base64").toString("binary");
    const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u;
  }
  const b64encode = u => { let s = ""; u.forEach(c => s += String.fromCharCode(c)); return typeof btoa === "function" ? btoa(s) : Buffer.from(s, "binary").toString("base64"); };

  function decode(der, label = "") {
    if (/PRIVATE KEY/.test(label)) throw new Error("That's a private key. Never paste private keys into any website. This tool doesn't decode them.");
    const root = parse(der)[0];
    if (!root || root.tag !== 0x30 || !root.kids || root.kids.length < 3) throw new Error("Not an X.509 certificate or PKCS#10 CSR");
    const info = root.kids[0];
    const isCSR = /REQUEST/.test(label) || (info.kids[0].tag !== 0xa0 && info.kids.length === 4 && info.kids[3].tag === 0xa0);
    const sigAlgOid = oid(der, root.kids[1].kids[0]);
    const r = { type: isCSR ? "CSR" : "Certificate", sigAlg: OID[sigAlgOid] || sigAlgOid, der, extensions: [] };
    if (isCSR) {
      const [, subj, pk, attrs] = info.kids;
      r.subject = name(der, subj); r.key = spki(der, pk);
      r.spkiDer = der.subarray(pk.start, pk.end);
      for (const a of attrs.kids || []) {
        if (oid(der, a.kids[0]) === "1.2.840.113549.1.9.14") r.extensions = extensions(der, a.kids[1].kids[0]);
      }
    } else {
      let i = 0; const k = info.kids;
      r.version = k[0].tag === 0xa0 ? bytes(der, k[0].kids[0])[0] + 1 : 1; if (k[0].tag === 0xa0) i++;
      r.serial = intHex(der, k[i++]); i++; // skip inner sigalg
      r.issuer = name(der, k[i++]);
      const val = k[i++]; r.notBefore = time(der, val.kids[0]); r.notAfter = time(der, val.kids[1]);
      r.subject = name(der, k[i++]);
      r.key = spki(der, k[i]); r.spkiDer = der.subarray(k[i].start, k[i].end); i++;
      const extWrap = k.find(n => n.tag === 0xa3);
      if (extWrap) r.extensions = extensions(der, extWrap.kids[0]);
      r.selfSigned = nameStr(r.subject) === nameStr(r.issuer);
    }
    const ext = id => r.extensions.find(e => e.oid === id);
    r.sans = (ext("2.5.29.17") || {}).value || [];
    r.isCA = !!((ext("2.5.29.19") || {}).value || {}).ca;
    r.eku = (ext("2.5.29.37") || {}).value || [];
    return r;
  }

  // CA/Browser Forum Ballot SC-081 schedule (publicly trusted TLS server certificates)
  const LIMITS = [["2029-03-15", 47], ["2027-03-15", 100], ["2026-03-15", 200], ["2020-09-01", 398]];
  function maxLifetime(issued) {
    for (const [d, days] of LIMITS) if (issued >= new Date(d + "T00:00:00Z")) return { days, since: d };
    return { days: 825, since: "2018-03-01" };
  }
  function lifetime(r, now = new Date()) {
    if (r.type !== "Certificate") return null;
    // CA/B counts validity inclusively: notAfter - notBefore + 1 second
    const days = (r.notAfter - r.notBefore + 1000) / 86400000;
    const lim = maxLifetime(r.notBefore);
    const tls = !r.isCA && (r.eku.includes("serverAuth") || (!r.eku.length && r.sans.some(s => s[0] === "DNS")));
    return { days, limit: lim, tls, exceeds: tls && days > lim.days + 1e-9, left: (r.notAfter - now) / 86400000,
      notYet: now < r.notBefore, expired: now > r.notAfter };
  }

  function matchHost(r, host) {
    host = host.trim().toLowerCase().replace(/\.$/, "");
    const names = r.sans.filter(s => s[0] === "DNS").map(s => s[1].toLowerCase());
    const ips = r.sans.filter(s => s[0] === "IP").map(s => s[1].toLowerCase());
    if (ips.includes(host)) return host;
    if (!names.length) { const cn = (r.subject.find(p => p[0] === "CN") || [])[1]; if (cn) names.push(cn.toLowerCase()); }
    for (const n of names) {
      if (n === host) return n;
      if (n.startsWith("*.")) { const rest = n.slice(2); const i = host.indexOf("."); if (i > 0 && host.slice(i + 1) === rest) return n; }
    }
    return null;
  }
  return { fmtDays, pemBlocks, decode, lifetime, matchHost, maxLifetime, nameStr, hex, b64encode, LIMITS };
})();
if (typeof module !== "undefined") module.exports = CD;

if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", () => {
  const ta = $("#in"), out = $("#out");
  let decoded = [];

  async function fp(u8, alg) { const h = new Uint8Array(await crypto.subtle.digest(alg, u8)); return h; }
  const d10 = d => d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");

  async function run(blocks) {
    out.innerHTML = ""; decoded = [];
    if (!blocks.length) { out.innerHTML = `<p class="err">No PEM block found. Paste text starting with -----BEGIN CERTIFICATE----- (or CERTIFICATE REQUEST), or drop a .crt/.cer/.der/.pem/.csr file.</p>`; return; }
    let h = "";
    for (let idx = 0; idx < blocks.length; idx++) {
      const bl = blocks[idx];
      let r;
      try { r = CD.decode(bl.der, bl.label); } catch (e) { h += `<div class="alert bad">${blocks.length > 1 ? `Block ${idx + 1}: ` : ""}${esc(e.message)}</div>`; continue; }
      decoded.push(r);
      const sha256 = CD.hex(await fp(r.der, "SHA-256")), sha1 = CD.hex(await fp(r.der, "SHA-1"));
      const pin = CD.b64encode(await fp(r.spkiDer, "SHA-256"));
      const cn = (r.subject.find(p => p[0] === "CN") || [])[1] || (r.sans[0] || [])[1] || "(no CN)";
      h += `<h2>${blocks.length > 1 ? `#${idx + 1} · ` : ""}${esc(r.type)}: ${esc(cn)}</h2>`;
      const lt = CD.lifetime(r);
      if (lt) {
        if (lt.expired) h += `<div class="alert bad">Expired ${esc(fmtDuration(-lt.left * 86400))} ago.</div>`;
        else if (lt.notYet) h += `<div class="alert bad">Not valid yet. Validity starts ${esc(d10(r.notBefore))}.</div>`;
        else h += `<div class="alert ${lt.left < 14 ? "bad" : lt.left < 30 ? "" : "ok"}">Valid. Expires in ${Math.floor(lt.left)} days.</div>`;
        if (lt.tls) {
          h += lt.exceeds
            ? `<div class="alert bad">Lifetime ${CD.fmtDays(lt.days)} exceeds the ${lt.limit.days}-day maximum for publicly trusted TLS certificates issued on or after ${lt.limit.since}. Fine for a private CA; a public CA shouldn't have issued it.</div>`
            : `<div class="alert ok">Lifetime ${CD.fmtDays(lt.days)}, within the ${lt.limit.days}-day CA/B Forum limit for its issue date.</div>`;
        }
        if (r.selfSigned) h += `<div class="alert">Self-signed (subject = issuer).</div>`;
      }
      const rows = [["Subject", CD.nameStr(r.subject)]];
      if (r.issuer) rows.push(["Issuer", CD.nameStr(r.issuer)]);
      if (r.notBefore) rows.push(["Valid from", d10(r.notBefore)], ["Valid until", d10(r.notAfter)]);
      if (r.serial) rows.push(["Serial", r.serial]);
      rows.push(["Public key", `${r.key.alg}${r.key.bits ? " " + r.key.bits + "-bit" : ""}${r.key.curve ? " (" + r.key.curve + ")" : ""}${r.key.exponent ? ", e=" + r.key.exponent : ""}`],
        ["Signature", r.sigAlg]);
      if (r.version) rows.push(["Version", "v" + r.version]);
      rows.push(["SHA-256 fingerprint", sha256], ["SHA-1 fingerprint", sha1], ["SPKI pin (sha256/base64)", pin]);
      h += `<div class="card kv">${rows.map(([k, v]) => `<div>${esc(k)}</div><div>${esc(v)}</div>`).join("")}</div>`;
      if (r.sans.length) h += `<h3>Subject Alternative Names (${r.sans.length})</h3><pre class="out">${esc(r.sans.map(s => `${s[0]}: ${s[1]}`).join("\n"))}</pre>`;
      if (r.extensions.length) {
        h += `<h3>Extensions</h3><div class="card scroll"><table><tr><th>Extension</th><th>Value</th></tr>` + r.extensions.map(e => {
          let v = e.value;
          if (Array.isArray(v)) v = v.map(x => Array.isArray(x) ? `${x[0]}: ${x[1]}` : x).join("\n");
          else if (v && typeof v === "object") v = `CA: ${v.ca}${v.pathLen != null ? ", pathLen: " + v.pathLen : ""}`;
          return `<tr><td>${esc(e.name)}${e.critical ? ' <span class="neutral">critical</span>' : ""}</td><td class="mono u-pre">${esc(v)}</td></tr>`;
        }).join("") + `</table></div>`;
      }
      if (r.sigAlg.startsWith("sha1") || r.sigAlg.startsWith("md5")) h += `<div class="alert bad">Weak signature algorithm (${esc(r.sigAlg)}).</div>`;
      if (r.key.alg === "RSA" && r.key.bits < 2048) h += `<div class="alert bad">RSA key below 2048 bits.</div>`;
    }
    // chain order check
    const certs = decoded.filter(r => r.type === "Certificate");
    if (certs.length > 1) {
      const issues = [];
      for (let i = 0; i + 1 < certs.length; i++) if (CD.nameStr(certs[i].issuer) !== CD.nameStr(certs[i + 1].subject)) issues.push(i + 1);
      h = (issues.length ? `<div class="alert">Chain order: certificate #${issues.join(", #")} isn't followed by its issuer. Servers should send leaf → intermediate(s), usually without the root.</div>`
        : `<div class="alert ok">Chain of ${certs.length} certificates is in the correct order (each one followed by its issuer).</div>`) + h;
    }
    out.innerHTML = h;
    $("#hostbox").classList.toggle("hidden", !decoded.length);
  }

  $("#go").addEventListener("click", () => run(CD.pemBlocks(ta.value)));
  $("#clear").addEventListener("click", () => { ta.value = ""; out.innerHTML = ""; $("#hostbox").classList.add("hidden"); });
  $("#host").addEventListener("input", e => {
    const v = e.target.value.trim(), r = decoded[0]; const o = $("#hostres");
    if (!v || !r) { o.textContent = ""; return; }
    const m = CD.matchHost(r, v);
    o.innerHTML = m ? `<span class="pass">✓ matches ${esc(m)}</span>` : `<span class="fail">✗ ${esc(v)} isn't covered by this ${r.type === "CSR" ? "CSR" : "certificate"}</span>`;
  });
  setupDrop($("#drop"), $("#file"), async files => {
    const blocks = [];
    for (const f of files) {
      const u8 = new Uint8Array(await f.arrayBuffer());
      if (u8[0] === 0x30) blocks.push({ label: /csr|req/i.test(f.name) ? "CERTIFICATE REQUEST" : "", der: u8 });
      else { const t = new TextDecoder().decode(u8); ta.value = t; blocks.push(...CD.pemBlocks(t)); }
    }
    run(blocks);
  });
  // lifetime planner
  const plan = () => {
    const before = +$("#renew").value || 0; const o = [];
    for (const [d, days] of [["2026-03-15", 200], ["2027-03-15", 100], ["2029-03-15", 47]]) {
      const cycle = Math.max(1, days - before);
      o.push(`<tr><td>${d}</td><td>${days} days</td><td>every ~${cycle} days</td><td>${(365 / cycle).toFixed(1)}×/year</td></tr>`);
    }
    $("#plan").innerHTML = `<tr><th>Issued from</th><th>Max lifetime</th><th>You renew</th><th>Renewals</th></tr>` + o.join("");
  };
  $("#renew").addEventListener("input", plan); plan();
});
