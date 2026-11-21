"use strict";
const IP = (() => {
  const B = n => BigInt(n);
  function parseIP(s) {
    s = s.trim().replace(/^\[|\]$/g, "").replace(/%.*$/, "");
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
      const p = s.split(".").map(Number);
      if (p.some(x => x > 255)) throw new Error(`Invalid IPv4 address: ${s}`);
      return { v: 4, n: p.reduce((a, x) => a * 256n + B(x), 0n) };
    }
    if (s.includes(":")) {
      let tail = [];
      const m4 = s.match(/^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/);
      if (m4) { const v4 = parseIP(m4[2]).n; tail = [(v4 >> 16n).toString(16), (v4 & 0xffffn).toString(16)]; s = m4[1] + "X"; }
      const halves = s.split("::");
      if (halves.length > 2) throw new Error(`Invalid IPv6 address: ${s}`);
      const conv = h => h ? h.split(":").flatMap(x => x === "X" ? tail : [x]) : [];
      const a = conv(halves[0]), b = halves.length === 2 ? conv(halves[1]) : [];
      const fill = 8 - a.length - b.length;
      if ((halves.length === 2 && fill < 1) || (halves.length === 1 && fill !== 0)) throw new Error(`Invalid IPv6 address: ${s}`);
      const groups = [...a, ...Array(halves.length === 2 ? fill : 0).fill("0"), ...b];
      if (groups.some(g => !/^[0-9a-f]{1,4}$/i.test(g))) throw new Error(`Invalid IPv6 address: ${s}`);
      return { v: 6, n: groups.reduce((acc, g) => acc * 65536n + B(parseInt(g, 16)), 0n) };
    }
    throw new Error(`Not an IP address: ${s}`);
  }
  const bits = v => v === 4 ? 32 : 128;
  const maskOf = (v, p) => ((1n << B(bits(v))) - 1n) ^ ((1n << B(bits(v) - p)) - 1n);
  function fmt(v, n) {
    if (v === 4) return [24n, 16n, 8n, 0n].map(s => ((n >> s) & 255n).toString()).join(".");
    if ((n >> 32n) === 0xffffn) return "::ffff:" + fmt(4, n & 0xffffffffn);
    const g = []; for (let i = 7; i >= 0; i--) g.push(Number((n >> B(i * 16)) & 0xffffn));
    let best = -1, bl = 0;
    for (let i = 0; i < 8;) { if (g[i] !== 0) { i++; continue; } let j = i; while (j < 8 && g[j] === 0) j++; if (j - i > bl && j - i >= 2) { best = i; bl = j - i; } i = j; }
    const hx = g.map(x => x.toString(16));
    if (best < 0) return hx.join(":");
    return hx.slice(0, best).join(":") + "::" + hx.slice(best + bl).join(":");
  }
  function expand6(n) { const g = []; for (let i = 7; i >= 0; i--) g.push(((n >> B(i * 16)) & 0xffffn).toString(16).padStart(4, "0")); return g.join(":"); }

  function parseCIDR(s) {
    s = s.trim();
    let ip, pfx;
    const mm = s.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (mm) {
      ip = parseIP(mm[1]); const m = parseIP(mm[2]).n;
      const s2 = m.toString(2).padStart(32, "0"); if (!/^1*0*$/.test(s2)) throw new Error(`Non-contiguous netmask: ${mm[2]}`);
      pfx = s2.indexOf("0") < 0 ? 32 : s2.indexOf("0");
    } else {
      const [a, p] = s.split("/");
      ip = parseIP(a);
      pfx = p === undefined ? bits(ip.v) : /^\d+$/.test(p) ? +p : NaN;
      if (!(pfx >= 0 && pfx <= bits(ip.v))) throw new Error(`Invalid prefix length in ${s}`);
    }
    const mask = maskOf(ip.v, pfx), net = ip.n & mask;
    const last = net | (((1n << B(bits(ip.v))) - 1n) ^ mask);
    return { v: ip.v, ip: ip.n, prefix: pfx, net, last, mask, hostBits: ip.n !== net, text: s };
  }

  const R = (v, a, b) => ({ v, a, b });
  const in4 = (n, c) => { const x = parseCIDR(c); return n >= x.net && n <= x.last; };
  function kind(c) {
    const t = (list) => list.find(([cidr]) => { const x = parseCIDR(cidr); return x.v === c.v && c.net >= x.net && c.last <= x.last; });
    const v4 = [["10.0.0.0/8", "Private (RFC 1918)"], ["172.16.0.0/12", "Private (RFC 1918)"], ["192.168.0.0/16", "Private (RFC 1918)"],
      ["100.64.0.0/10", "Carrier-grade NAT (RFC 6598)"], ["127.0.0.0/8", "Loopback"], ["169.254.0.0/16", "Link-local"],
      ["192.0.2.0/24", "Documentation (TEST-NET-1)"], ["198.51.100.0/24", "Documentation (TEST-NET-2)"], ["203.0.113.0/24", "Documentation (TEST-NET-3)"],
      ["198.18.0.0/15", "Benchmarking (RFC 2544)"], ["224.0.0.0/4", "Multicast"], ["240.0.0.0/4", "Reserved"], ["0.0.0.0/8", "\"This network\""]];
    const v6 = [["::1/128", "Loopback"], ["::/128", "Unspecified"], ["::ffff:0:0/96", "IPv4-mapped"], ["64:ff9b::/96", "NAT64 well-known prefix"],
      ["fc00::/7", "Unique local (ULA)"], ["fe80::/10", "Link-local"], ["ff00::/8", "Multicast"], ["2001:db8::/32", "Documentation"],
      ["2002::/16", "6to4"], ["2001::/32", "Teredo"], ["2000::/3", "Global unicast"]];
    const hit = t(c.v === 4 ? v4 : v6);
    return hit ? hit[1] : c.v === 4 ? (c.prefix === 0 ? "Everything" : "Public / global") : (c.prefix === 0 ? "Everything" : "Reserved / other");
  }

  function reverseZone(c) {
    if (c.v === 4) {
      const oct = fmt(4, c.net).split(".");
      const full = Math.floor(c.prefix / 8);
      const z = oct.slice(0, full).reverse().join(".");
      const base = (z ? z + "." : "") + "in-addr.arpa";
      if (c.prefix % 8 === 0) return base;
      if (c.prefix > 24) return `${base} (smaller than /24: needs RFC 2317 classless delegation, e.g. ${oct[3]}/${c.prefix}.${base})`;
      const nb = (full + 1) * 8, n = 1 << (nb - c.prefix);
      const zone = k => [String(+oct[full] + k), ...oct.slice(0, full).reverse()].join(".") + ".in-addr.arpa";
      return `${n} zones: ${zone(0)} … ${zone(n - 1)}`;
    }
    const nib = expand6(c.net).replace(/:/g, "").split("");
    const full = Math.floor(c.prefix / 4);
    const z = nib.slice(0, full).reverse().join(".");
    return (z ? z + "." : "") + "ip6.arpa" + (c.prefix % 4 ? " (prefix isn't on a nibble boundary)" : "");
  }

  function info(s) {
    const c = parseCIDR(s);
    const total = c.last - c.net + 1n;
    const r = { c, total, kind: kind(c), network: fmt(c.v, c.net) + "/" + c.prefix, reverse: reverseZone(c) };
    if (c.v === 4) {
      r.netmask = fmt(4, c.mask); r.wildcard = fmt(4, 0xffffffffn ^ c.mask);
      if (c.prefix >= 31) { r.first = fmt(4, c.net); r.lastUsable = fmt(4, c.last); r.usable = total; r.broadcast = c.prefix === 32 ? "—" : "— (/31 point-to-point, RFC 3021)"; }
      else { r.first = fmt(4, c.net + 1n); r.lastUsable = fmt(4, c.last - 1n); r.usable = total - 2n; r.broadcast = fmt(4, c.last); }
      r.binary = c.net.toString(2).padStart(32, "0").replace(/(.{8})(?!$)/g, "$1.");
      r.hex = "0x" + c.net.toString(16).padStart(8, "0").toUpperCase();
      r.mapped6 = "::ffff:" + fmt(4, c.ip);
    } else {
      r.first = fmt(6, c.net); r.lastUsable = fmt(6, c.last); r.usable = total;
      r.expanded = expand6(c.net); r.lastExpanded = expand6(c.last);
      if (c.prefix <= 64) r.slash64 = 1n << B(64 - c.prefix);
    }
    return r;
  }

  function split(s, newPrefix, max = 512) {
    const c = parseCIDR(s);
    if (newPrefix < c.prefix || newPrefix > bits(c.v)) throw new Error(`New prefix must be between /${c.prefix} and /${bits(c.v)}`);
    const step = 1n << B(bits(c.v) - newPrefix), count = 1n << B(newPrefix - c.prefix);
    const out = [];
    for (let i = 0n; i < count && i < B(max); i++) out.push(fmt(c.v, c.net + i * step) + "/" + newPrefix);
    return { list: out, count };
  }

  function rangeToCIDRs(v, a, b) {
    const W = bits(v), out = [];
    while (a <= b) {
      let size = 0;
      while (size < W) {
        const nb = 1n << B(size + 1);
        if ((a & (nb - 1n)) !== 0n || a + nb - 1n > b) break;
        size++;
      }
      out.push(fmt(v, a) + "/" + (W - size));
      a += 1n << B(size);
    }
    return out;
  }
  function parseRange(s) {
    const m = s.split(/\s*(?:-|–|\s)\s*/).filter(Boolean);
    if (m.length !== 2) throw new Error(`Expected "start - end", got: ${s}`);
    const a = parseIP(m[0]), b = parseIP(m[1]);
    if (a.v !== b.v) throw new Error("Start and end must be the same IP version");
    if (a.n > b.n) throw new Error("Start address is after end address");
    return R(a.v, a.n, b.n);
  }

  const lines = t => t.split(/[\n,;]+/).map(x => x.replace(/#.*$/, "").trim()).filter(Boolean);
  function aggregate(text) {
    const errs = [], rs = [];
    for (const l of lines(text)) {
      try { rs.push(/[-–]/.test(l) && !l.includes("/") ? parseRange(l) : (c => R(c.v, c.net, c.last))(parseCIDR(l))); }
      catch (e) { errs.push(e.message); }
    }
    const out = [];
    for (const v of [4, 6]) {
      const s = rs.filter(r => r.v === v).sort((x, y) => x.a < y.a ? -1 : x.a > y.a ? 1 : 0);
      const merged = [];
      for (const r of s) {
        const last = merged[merged.length - 1];
        if (last && r.a <= last.b + 1n) { if (r.b > last.b) last.b = r.b; } else merged.push({ ...r });
      }
      for (const m of merged) out.push(...rangeToCIDRs(v, m.a, m.b));
    }
    return { input: rs.length, out, errs };
  }

  function overlaps(text) {
    const errs = [], cs = [];
    for (const l of lines(text)) { try { cs.push(parseCIDR(l)); } catch (e) { errs.push(e.message); } }
    const res = [];
    for (let i = 0; i < cs.length; i++) for (let j = i + 1; j < cs.length; j++) {
      const a = cs[i], b = cs[j];
      if (a.v !== b.v || a.net > b.last || b.net > a.last) continue;
      const A = fmt(a.v, a.net) + "/" + a.prefix, Bn = fmt(b.v, b.net) + "/" + b.prefix;
      const rel = a.net === b.net && a.last === b.last ? "identical" : (a.net <= b.net && a.last >= b.last) ? "contains" : "is inside";
      res.push({ a: A, b: Bn, rel, ia: i + 1, ib: j + 1 });
    }
    return { count: cs.length, res, errs };
  }

  function contains(cidr, ip) { const c = parseCIDR(cidr), x = parseIP(ip); return c.v === x.v && x.n >= c.net && x.n <= c.last; }
  return { parseIP, parseCIDR, fmt, info, split, rangeToCIDRs, parseRange, aggregate, overlaps, contains };
})();
if (typeof module !== "undefined") module.exports = IP;

if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", () => {
  const big = n => n.toLocaleString("en-US");
  const human = n => n >= 10n ** 15n ? `${big(n)} (2^${n.toString(2).length - 1})` : big(n);
  $$(".tabs button").forEach(b => b.addEventListener("click", () => {
    $$(".tabs button").forEach(x => x.classList.toggle("active", x === b));
    $$(".pane").forEach(p => p.classList.toggle("hidden", p.id !== b.dataset.pane));
  }));

  function calc() {
    const o = $("#calc-out"), v = $("#cidr").value.trim();
    if (!v) { o.innerHTML = ""; return; }
    try {
      const r = IP.info(v), c = r.c;
      const rows = [["Network", r.network], ["Type", r.kind]];
      if (c.v === 4) rows.push(["Netmask", r.netmask], ["Wildcard (ACL)", r.wildcard], ["Broadcast", r.broadcast]);
      rows.push([c.v === 4 ? "First usable" : "First address", r.first], [c.v === 4 ? "Last usable" : "Last address", r.lastUsable],
        ["Total addresses", human(r.total)], [c.v === 4 ? "Usable hosts" : "Addresses", human(r.usable)]);
      if (r.slash64 != null) rows.push(["/64 subnets", human(r.slash64)]);
      if (r.expanded) rows.push(["Expanded", r.expanded], ["Last (expanded)", r.lastExpanded]);
      if (r.binary) rows.push(["Binary", r.binary], ["Hex", r.hex], ["IPv4-mapped IPv6", r.mapped6]);
      rows.push(["Reverse DNS zone", r.reverse]);
      let h = c.hostBits ? `<div class="alert">Host bits are set in ${esc(v)}. The network address is ${esc(r.network)}.</div>` : "";
      h += `<div class="card kv">${rows.map(([k, x]) => `<div>${esc(k)}</div><div>${esc(x)}</div>`).join("")}</div>`;
      o.innerHTML = h;
      const sp = $("#splitp"); if (!sp.value) sp.value = Math.min(c.prefix + (c.v === 4 ? 2 : 16), c.v === 4 ? 32 : 128);
      doSplit();
    } catch (e) { o.innerHTML = `<p class="err">${esc(e.message)}</p>`; $("#split-out").innerHTML = ""; }
  }
  function doSplit() {
    const o = $("#split-out"); const v = $("#cidr").value.trim(), p = +$("#splitp").value;
    if (!v || !p) { o.innerHTML = ""; return; }
    try { const r = IP.split(v, p); o.innerHTML = `<p class="u-note">${big(r.count)} × /${p}${r.count > BigInt(r.list.length) ? ` (first ${r.list.length} shown)` : ""}</p><pre class="out">${esc(r.list.join("\n"))}</pre>`; }
    catch (e) { o.innerHTML = `<p class="err">${esc(e.message)}</p>`; }
  }
  $("#cidr").addEventListener("input", calc); $("#splitp").addEventListener("input", doSplit);
  $("#chk").addEventListener("input", () => {
    const v = $("#chk").value.trim(), o = $("#chk-out");
    if (!v) { o.textContent = ""; return; }
    try { o.innerHTML = IP.contains($("#cidr").value, v) ? `<span class="pass">✓ ${esc(v)} is inside</span>` : `<span class="fail">✗ ${esc(v)} is outside</span>`; }
    catch (e) { o.innerHTML = `<span class="err">${esc(e.message)}</span>`; }
  });

  $("#ov-go").addEventListener("click", () => {
    const r = IP.overlaps($("#ov-in").value), o = $("#ov-out");
    let h = r.errs.map(e => `<div class="alert bad">${esc(e)}</div>`).join("");
    h += r.res.length ? `<div class="alert bad">${r.res.length} overlap(s) among ${r.count} prefixes.</div><div class="card scroll"><table><tr><th>Line</th><th>Prefix</th><th>Relation</th><th>Line</th><th>Prefix</th></tr>` +
      r.res.map(x => `<tr><td>${x.ia}</td><td class="mono">${esc(x.a)}</td><td>${esc(x.rel)}</td><td>${x.ib}</td><td class="mono">${esc(x.b)}</td></tr>`).join("") + `</table></div>`
      : r.count ? `<div class="alert ok">No overlaps among ${r.count} prefixes.</div>` : "";
    o.innerHTML = h;
  });
  $("#rg-go").addEventListener("click", () => {
    const o = $("#rg-out");
    try { const r = IP.parseRange($("#rg-in").value); const l = IP.rangeToCIDRs(r.v, r.a, r.b);
      o.innerHTML = `<p class="u-note">${l.length} prefix(es)</p><pre class="out" id="rg-res">${esc(l.join("\n"))}</pre><button class="secondary" data-copy="#rg-res">Copy</button>`; }
    catch (e) { o.innerHTML = `<p class="err">${esc(e.message)}</p>`; }
  });
  $("#ag-go").addEventListener("click", () => {
    const r = IP.aggregate($("#ag-in").value), o = $("#ag-out");
    o.innerHTML = r.errs.map(e => `<div class="alert bad">${esc(e)}</div>`).join("") +
      `<p class="u-note">${r.input} entries → ${r.out.length} prefix(es)</p><pre class="out" id="ag-res">${esc(r.out.join("\n"))}</pre><button class="secondary" data-copy="#ag-res">Copy</button>`;
  });
  calc();
});
