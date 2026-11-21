"use strict";
const CR = (() => {
  const MON = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
  const DOW = { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 };
  const SDNAME = ["", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  const SPECIAL = { "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *", "@weekly": "0 0 * * 0",
    "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *" };
  const FIELDS = [["minute", 0, 59], ["hour", 0, 23], ["day-of-month", 1, 31], ["month", 1, 12, MON], ["day-of-week", 0, 7, DOW]];

  function expand(spec, idx) {
    const [label, min, max, names] = FIELDS[idx];
    const val = t => {
      const k = t.toLowerCase();
      if (names && names[k] !== undefined) return names[k];
      if (!/^\d+$/.test(t)) throw new Error(`Invalid ${label} value "${t}"`);
      const n = +t; if (n < min || n > max) throw new Error(`${label} value ${n} out of range ${min}-${max}`); return n;
    };
    const set = new Set();
    for (const part of spec.split(",")) {
      if (!part) throw new Error(`Empty list item in ${label} field`);
      let [range, step] = part.split("/");
      if (step !== undefined && !/^\d+$/.test(step)) throw new Error(`Invalid step "${step}" in ${label}`);
      step = step === undefined ? 1 : +step; if (step < 1) throw new Error(`Step must be ≥ 1 in ${label}`);
      let a, b;
      if (range === "*") { a = min; b = max; }
      else if (range.includes("-")) { const [x, y] = range.split("-"); a = val(x); b = val(y); if (a > b) throw new Error(`Range ${range} is reversed in ${label}`); }
      else { a = val(range); b = part.includes("/") ? max : a; }
      for (let v = a; v <= b; v += step) set.add(idx === 4 && v === 7 ? 0 : v);
    }
    return set;
  }

  function compress(values, min, max, pad, fmt = String) {
    const s = [...values].sort((a, b) => a - b);
    if (s.length === max - min + 1) return "*";
    const p = v => pad ? String(v).padStart(2, "0") : fmt(v);
    if (s.length >= 3 && fmt === String) {
      const k = s[1] - s[0];
      if (k > 1 && s.every((v, i) => v === s[0] + i * k) && s[s.length - 1] + k > max) return `${p(s[0])}/${k}`;
    }
    const out = []; let i = 0;
    while (i < s.length) {
      let j = i; while (j + 1 < s.length && s[j + 1] === s[j] + 1) j++;
      if (j - i >= 2) out.push(`${p(s[i])}..${p(s[j])}`); else for (let k = i; k <= j; k++) out.push(p(s[k]));
      i = j + 1;
    }
    return out.join(",");
  }

  function parseLine(line, hasUser) {
    let t = line.trim();
    const sp = t.match(/^(@\w+)\s*(.*)$/);
    let fields, rest, special = null;
    if (sp) {
      const key = sp[1].toLowerCase();
      if (key === "@reboot") { special = "reboot"; rest = sp[2]; fields = null; }
      else if (SPECIAL[key]) { fields = SPECIAL[key].split(" "); rest = sp[2]; special = key; }
      else throw new Error(`Unknown special schedule ${sp[1]}`);
    } else {
      const parts = t.split(/\s+/);
      if (parts.length < 5) throw new Error("A cron schedule needs 5 fields: minute hour day-of-month month day-of-week");
      fields = parts.slice(0, 5);
      rest = t.replace(/^(\S+\s+){5}/, "").trim();
      if (parts.length === 5) rest = "";
    }
    let user = null;
    if (hasUser && rest) { const m = rest.match(/^(\S+)\s*(.*)$/); user = m[1]; rest = m[2]; }
    return { fields, command: rest, user, special };
  }

  function convert(line, opts = {}) {
    const p = parseLine(line, opts.hasUser);
    const res = { ...p, onCalendar: [], notes: [] };
    if (p.special === "reboot") { res.onBoot = true; return res; }
    const sets = p.fields.map((f, i) => expand(f, i));
    const [mi, hr, dom, mon, dow] = sets;
    const domStar = p.fields[2].startsWith("*"), dowStar = p.fields[4].startsWith("*");
    const M = compress(mi, 0, 59, true), H = compress(hr, 0, 23, true);
    const D = compress(dom, 1, 31, true), MO = compress(mon, 1, 12, true);
    const dowSd = new Set([...dow].map(v => v === 0 ? 7 : v));
    const W = dowSd.size === 7 ? "" : compress(dowSd, 1, 7, false, v => SDNAME[v]) + " ";
    const tz = opts.tz ? " " + opts.tz : "";
    const mk = (w, d) => `${w}*-${MO}-${d} ${H}:${M}:00${tz}`;
    if (!domStar && !dowStar) {
      res.onCalendar.push(mk("", D), mk(W, "*"));
      res.notes.push("Both day-of-month and day-of-week are restricted. Cron runs when EITHER matches, but systemd requires both to match, so this needs two OnCalendar= lines.");
    } else res.onCalendar.push(mk(W, D));
    if (p.command && /(^|[^\\])%/.test(p.command)) res.notes.push("The command contains an unescaped %. In cron that means newline, and everything after it is sent as stdin. That isn't converted. Rewrite the command (e.g. with a here-doc) before using the unit.");
    res.sets = sets; res.domStar = domStar; res.dowStar = dowStar;
    return res;
  }

  function unitName(cmd, i) {
    const first = (cmd || "").replace(/^(sudo|nice|ionice|flock\s+\S+|timeout\s+\S+)\s+/g, "").split(/\s+/)[0] || "";
    let n = first.split("/").pop().replace(/\.(sh|py|pl|rb|php)$/, "").replace(/[^A-Za-z0-9_.-]/g, "-").replace(/^-+|-+$/g, "").toLowerCase();
    if (!n || n.length < 2) n = "cron-job";
    return i ? `${n}-${i + 1}` : n;
  }
  function escExec(cmd) {
    const c = cmd.replace(/\\%/g, "%");
    return c.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\$/g, "$$$$").replace(/%/g, "%%");
  }

  function units(r, name) {
    const desc = (r.command || name).replace(/\s+/g, " ").slice(0, 70);
    const svc = `[Unit]
Description=${desc}

[Service]
Type=oneshot
${r.user ? `User=${r.user}\n` : ""}ExecStart=/bin/sh -c "${escExec(r.command || "/path/to/command")}"
`;
    const timer = `[Unit]
Description=Timer for ${name}.service

[Timer]
${r.onBoot ? "OnBootSec=1min" : r.onCalendar.map(c => `OnCalendar=${c}`).join("\n")}
# Fire within the same second as cron would (default accuracy is 1min):
AccuracySec=1s
# Uncomment to run missed jobs after downtime (cron does NOT do this):
#Persistent=true

[Install]
WantedBy=timers.target
`;
    return { svc, timer };
  }

  function nextRuns(r, n = 5, from = new Date()) {
    if (!r.sets) return [];
    const [mi, hr, dom, mon, dow] = r.sets;
    const out = []; const d = new Date(from); d.setSeconds(0, 0); d.setMinutes(d.getMinutes() + 1);
    const limit = new Date(from); limit.setFullYear(limit.getFullYear() + 5);
    const dayOk = x => {
      const a = dom.has(x.getDate()), b = dow.has(x.getDay());
      return (!r.domStar && !r.dowStar) ? (a || b) : (a && b);
    };
    while (out.length < n && d < limit) {
      if (!mon.has(d.getMonth() + 1) || !dayOk(d)) { d.setDate(d.getDate() + 1); d.setHours(0, 0, 0, 0); continue; }
      if (!hr.has(d.getHours())) { d.setHours(d.getHours() + 1, 0, 0, 0); continue; }
      if (!mi.has(d.getMinutes())) { d.setMinutes(d.getMinutes() + 1); continue; }
      out.push(new Date(d)); d.setMinutes(d.getMinutes() + 1);
    }
    return out;
  }

  function convertCrontab(text, opts = {}) {
    const jobs = []; let tz = opts.tz || "";
    text.split(/\r?\n/).forEach((raw, ln) => {
      const line = raw.trim();
      if (!line || line.startsWith("#")) return;
      const env = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
      if (env) { if (/^(CRON_TZ|TZ)$/.test(env[1])) tz = env[2].replace(/^["']|["']$/g, ""); return; }
      try { jobs.push({ line, ln: ln + 1, ...convert(line, { ...opts, tz }) }); }
      catch (e) { jobs.push({ line, ln: ln + 1, error: e.message }); }
    });
    let k = 0;
    const used = new Map();
    for (const j of jobs) if (!j.error) {
      let n = unitName(j.command, 0);
      const c = used.get(n) || 0; used.set(n, c + 1); if (c) n = `${n}-${c + 1}`;
      j.name = n; Object.assign(j, units(j, n)); k++;
    }
    return jobs;
  }
  return { expand, compress, convert, convertCrontab, nextRuns, escExec };
})();
if (typeof module !== "undefined") module.exports = CR;

if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", () => {
  const ta = $("#in"), out = $("#out");
  const fmt = d => d.toLocaleString(undefined, { weekday: "short", year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
  function run() {
    out.innerHTML = "";
    if (!ta.value.trim()) return;
    const jobs = CR.convertCrontab(ta.value, { hasUser: $("#user").checked });
    if (!jobs.length) { out.innerHTML = `<p class="err">No cron lines found.</p>`; return; }
    let h = "";
    jobs.forEach((j, i) => {
      h += `<div class="card"><div class="mono u-muted">line ${j.ln}: ${esc(j.line)}</div>`;
      if (j.error) { h += `<p class="err">${esc(j.error)}</p></div>`; return; }
      h += `<h3 class="u-mt10">${j.onBoot ? "OnBootSec=1min" : j.onCalendar.map(c => `OnCalendar=${esc(c)}`).join("<br>")}</h3>`;
      j.notes.forEach(n => h += `<div class="alert">${esc(n)}</div>`);
      const runs = CR.nextRuns(j);
      if (runs.length) h += `<p class="u-note u-my6">Next runs (your local time): ${runs.map(fmt).map(esc).join(" · ")}</p>`;
      h += `<div class="row u-between"><b class="mono">/etc/systemd/system/${esc(j.name)}.service</b><button class="secondary" data-copy="#svc${i}">Copy</button></div>
        <pre class="out" id="svc${i}">${esc(j.svc)}</pre>
        <div class="row u-between"><b class="mono">/etc/systemd/system/${esc(j.name)}.timer</b><button class="secondary" data-copy="#tmr${i}">Copy</button></div>
        <pre class="out" id="tmr${i}">${esc(j.timer)}</pre>
        <pre class="out">systemctl daemon-reload &amp;&amp; systemctl enable --now ${esc(j.name)}.timer
${j.onCalendar.map(c => `systemd-analyze calendar --iterations=3 '${esc(c)}'`).join("\n")}</pre></div>`;
    });
    out.innerHTML = h;
  }
  $("#go").addEventListener("click", run);
  ta.addEventListener("keydown", e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) run(); });
  $$("[data-ex]").forEach(b => b.addEventListener("click", () => { ta.value = b.dataset.ex; run(); }));
});
