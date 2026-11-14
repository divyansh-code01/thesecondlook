# Second Look® — analysis fixes

## Current request
- [x] SEO expansion: four practical guides, relevant homepage wording, descriptive public-page headings and internal links.
- [x] SEO expansion verification: eight public sitemap entries, private-page exclusions and single brand schema verified in server HTML; 60 tests pass; guide-to-submission navigation and all eight pages checked at 1280px, 375px and 320px with no overflow or browser errors. Local development observations: LCP 468ms, CLS 0.00059; field Core Web Vitals remain unverified.
- [x] Widen the shared page layout and rebalance the homepage columns; verified 320–1920px alignment and upload tabs, plus public pages at desktop/mobile sizes; 40 existing tests passed.
- [x] SEO: router-derived sitemap for public pages, crawler discovery, self-canonicals, and crawlable homepage description.
- [x] SEO: preview XML and homepage verified; three sitemap/routing tests pass; live readiness checked.
- [ ] SEO publication: current live sitemap works with four pages; publishing is required for the four new guides, updated wording and alternate-name schema. Search Console submission and field performance checks require direct access not available here.
- [x] Priority 1: actionable verdicts, caution fallback, scanner links, Cloudflare security DNS.
- [x] Rule 2: unknown-domain points, age points, and minimum 50 for domain plus message warnings.
- [x] Rule 4: parallel URL checks, shared 15-second budget, core coverage, ten-minute cache, caution fallback.
- [x] Rule 3a/b/d/e: Cloudflare security DNS, Quad9, existing keyed feeds, URL heuristics and destination checks.
- [ ] Rule 3c: six-hour refresh is configured and OpenPhish loaded; Phishing.Database import has not completed in the available request time. Partial list coverage remains unavailable with a reason.
- [x] Rules 5/6: screenshot links and message rules, sender mismatch, honesty text.
- [x] Tests: 58 passed; live phishing 85, Driver License screenshot 100, nonexistent domain 45, example.com 0.

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
