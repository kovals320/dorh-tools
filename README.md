# dorh.fyi tools

Static site: every tool runs client-side. CSP has connect-src 'none'.

## Deploy
Push to `main`. Vercel (project "dorh-tools", Root Directory = `dist`) deploys automatically.

## Edit and rebuild
Edit src/pages/*.html (page content and SEO) or assets/*.js|css (tool logic), then:
    python3 build.py        # regenerates dist/, then commit dist/ with the source
