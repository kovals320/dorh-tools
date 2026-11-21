#!/usr/bin/env python3
"""Tiny static site builder: wraps src/pages/*.html fragments in the shared layout -> dist/."""
import json, re, shutil, pathlib, datetime

ROOT = pathlib.Path(__file__).parent
SRC, DIST = ROOT / "src", ROOT / "dist"
SITE = "https://dorh.fyi"
NAME = "dorh.fyi"

TOOLS = [
    ("email-header-analyzer", "Email Header Analyzer", "Trace hops, delays and SPF/DKIM/DMARC results from raw email headers."),
    ("dmarc-report-viewer", "DMARC Report Viewer", "Drop DMARC aggregate (RUA) XML, .gz or .zip files and see who sends as your domain."),
    ("certificate-decoder", "Certificate & CSR Decoder", "Decode PEM/DER certificates and CSRs, with 200/100/47-day lifetime checks."),
    ("cron-to-systemd", "Cron to systemd Timer Converter", "Convert crontab lines to systemd OnCalendar timers, with correct day-of-month/day-of-week semantics."),
    ("cidr-calculator", "CIDR Toolkit (IPv4 & IPv6)", "Subnet calculator, overlap checker, range-to-CIDR and prefix aggregation."),
]

def layout(title, desc, path, body, scripts=(), jsonld=None):
    canon = SITE + path
    ld = ""
    if jsonld:
        for block in jsonld:
            ld += '<script type="application/ld+json">' + json.dumps(block, ensure_ascii=False) + "</script>\n"
    sc = "".join(f'<script src="/assets/{s}" defer></script>\n' for s in scripts)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<meta name="description" content="{desc}">
<link rel="canonical" href="{canon}">
<meta property="og:type" content="website">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{desc}">
<meta property="og:url" content="{canon}">
<meta name="twitter:card" content="summary">
<meta name="theme-color" content="#0f1115">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/style.css">
{ld}{sc}<script src="/_vercel/insights/script.js" defer></script>
</head>
<body>
<header class="site"><div class="wrap">
<a class="logo" href="/">dorh<span>.fyi</span></a>
<nav class="top"><a href="/#tools">Tools</a><a href="/privacy">Privacy</a><a href="/about">About</a></nav>
</div></header>
<main><div class="wrap">
{body}
</div></main>
<footer class="site"><div class="wrap">
Every tool runs locally in your browser. Nothing you paste or drop is uploaded. &nbsp;·&nbsp;
<a href="/privacy">Privacy</a> · <a href="/about">About</a> · © {datetime.date.today().year} {NAME}
</div></footer>
</body>
</html>
"""

def faq_ld(body):
    """Build FAQPage JSON-LD from <h3 class="q">…</h3><p>…</p> pairs in the fragment."""
    pairs = re.findall(r'<h3 class="q">(.*?)</h3>\s*<p>(.*?)</p>', body, re.S)
    if not pairs:
        return None
    strip = lambda s: re.sub(r"<[^>]+>", "", s).strip()
    return {"@context": "https://schema.org", "@type": "FAQPage",
            "mainEntity": [{"@type": "Question", "name": strip(q),
                            "acceptedAnswer": {"@type": "Answer", "text": strip(a)}} for q, a in pairs]}

def main():
    if DIST.exists():
        for f in DIST.iterdir():
            if f.name != ".vercel":
                shutil.rmtree(f) if f.is_dir() else f.unlink()
    DIST.mkdir(exist_ok=True)
    shutil.copytree(ROOT / "assets", DIST / "assets")
    for f in (SRC / "static").iterdir():
        shutil.copy(f, DIST / f.name)
    (DIST / "api").mkdir()
    for f in (ROOT / "api").glob("*.js"):
        shutil.copy(f, DIST / "api" / f.name)

    urls = ["/"]
    pages = SRC / "pages"
    for frag in sorted(pages.glob("*.html")):
        raw = frag.read_text()
        meta = json.loads(re.match(r"<!--(.*?)-->", raw, re.S).group(1))
        body = raw.split("-->", 1)[1]
        slug = frag.stem
        path = "/" if slug == "index" else "/" + slug
        jsonld = []
        if meta.get("app"):
            jsonld.append({"@context": "https://schema.org", "@type": "WebApplication",
                           "name": meta["h"], "url": SITE + path, "applicationCategory": "DeveloperApplication",
                           "operatingSystem": "Any (browser)", "isAccessibleForFree": True,
                           "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
                           "description": meta["desc"]})
        f = faq_ld(body)
        if f:
            jsonld.append(f)
        html = layout(meta["title"], meta["desc"], path, body, meta.get("scripts", []), jsonld)
        if meta.get("template"):
            (DIST / "api" / "_template.js").write_text("module.exports = { TEMPLATE: " + json.dumps(html) + " };\n")
        else:
            out = DIST / ("index.html" if slug == "index" else f"{slug}.html")
            out.write_text(html)
        if slug != "index":
            urls.append(path)

    today = datetime.date.today().isoformat()
    sm = ['<?xml version="1.0" encoding="UTF-8"?>',
          '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    sm += [f"<url><loc>{SITE}{u}</loc><lastmod>{today}</lastmod></url>" for u in urls]
    sm.append("</urlset>")
    (DIST / "sitemap.xml").write_text("\n".join(sm) + "\n")
    print("built", len(urls), "pages")

if __name__ == "__main__":
    main()
