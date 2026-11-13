# Improve The SecondLook search discovery

## Audit results
- The published homepage, methodology, privacy and terms return HTTP 200, have unique metadata and one correct HTTPS canonical each.
- The live robots.txt permits crawlers. The existing XML sitemap contains exactly the four public pages, with no private URLs or invented modification dates.
- The homepage has one valid WebSite declaration. Its requested alternate name is saved in preview but not yet published.
- The methodology, privacy and terms headings are slogans rather than explicit page topics; their social type is currently article.
- The four requested educational pages and links to them are missing. Existing homepage wording can explain phishing and suspicious-message checks more precisely.
- Search Console is not accessible here; indexing, rankings and field Core Web Vitals cannot currently be verified. Stored SEO scanner findings are stale, so current source and live responses are the audit evidence.

## Changes
1. Preserve the homepage headline, slogan, layout, verification tag, submission tools and all detection logic.
2. Refine existing homepage explanatory copy with natural scam/phishing terminology; retain the exact homepage title and official brand schema.
3. Create four distinct, substantive guides at the requested URLs, using the existing editorial page style. Include practical, clearly fictional examples, independent verification advice, recovery steps, tool limitations and authoritative references.
4. Link guides from existing homepage, methodology and footer areas, and cross-link relevant guides. Give each a unique title, description, social metadata and self-canonical.
5. Make the three informational headings descriptive while retaining their typography and layout; use website social type for those pages and remove redundant root social titles/descriptions.
6. Include the guides through existing route-level sitemap decisions. Keep checks, reports and API endpoints excluded and noindex unchanged.

## Verification and handoff
- Run existing regression tests and update the concrete sitemap inventory test to eight public pages.
- Check rendered and server-returned metadata, one homepage WebSite schema, verification token, internal navigation and private noindex.
- Check desktop/mobile overflow and submission controls without submitting private user material.
- Measure local loading and layout stability as lab observations, not field Core Web Vitals; inspect media before adding optimisations.
- Report the exact changes, remaining publication and Search Console actions. No claim of guaranteed ranking or indexing.

## Technical approach
Use four TanStack content routes and a shared browser-safe guide presentation module; no new server handlers, data tables, integrations or scoring changes. Preserve the existing router-derived sitemap helper.