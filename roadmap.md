# Second Look® — analysis fixes

## Current request
- [ ] Priority 1: actionable verdicts, caution fallback, scanner links, Cloudflare security DNS.
- [ ] Priority 2: unknown-domain scoring and reliable parallel checks, core coverage, URL cache.
- [ ] Priority 3: Quad9, scheduled threat lists, destination checks, screenshot rules, honesty text.
- [ ] Run requested regression tests and live checks; report completed rules and blockers.

## Original build reference

Full spec is in the user's brief (Build "Second Look®"). Reference design: minimalist studio site.

## Build order
1. [ ] Design tokens + layout shell (nav, footer, dark CTA, wordmark), Inter Tight font
2. [ ] Home page static sections (hero, process, what we check, score explainer, results actions, trust grid, FAQ)
3. [ ] Submission panel (screenshot + link tabs, full client validation, preview, errors)
4. [ ] Lovable Cloud: tables (jobs, reports, rate_limits), RLS, security-definer reads, storage bucket
5. [ ] Server pipeline: create-job, analyze-url (parse, SSRF guard, redirects, DoH, RDAP, crt.sh, heuristics, scoring), analyze-screenshot (OCR + regex extraction + AI signals + delete)
6. [ ] Threat intel (key-gated: Safe Browsing, URLhaus, PhishTank, VirusTotal) + demo mode
7. [ ] Analysis stage UI (/check/:jobId, real statuses) + results page (score, findings, accordions, export, save)
8. [ ] Save/delete report + /report/:id
9. [ ] Methodology, Privacy, Terms, 404
10. [ ] Scheduled purge-expired
11. [ ] Rate limiting (10/h, 30/day), honeypot, 429 + Retry-After
12. [ ] Unit tests: IP blocklist, prompt injection fixture, scoring reconciliation, upload validation
13. [ ] Accessibility + responsive pass (375/768/1280), no horizontal scroll
14. [ ] Secrets README section (SAFE_BROWSING_API_KEY, URLHAUS_AUTH_KEY, PHISHTANK_API_KEY, VIRUSTOTAL_API_KEY)

## Platform adaptations (fixed by Lovable stack)
- No Supabase Edge Functions: pipeline runs as TanStack server functions + server routes.
- No react-router: TanStack Router file routes.
- Spec's "edge function" names map to server functions in src/lib/*.functions.ts.
