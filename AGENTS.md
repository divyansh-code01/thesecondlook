<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## Second Look architecture
- Scores are computed only in `src/shared/scoring.ts` from typed signals; weights live only in `src/shared/signals.config.ts`. Why: scores must be deterministic and reproducible from the report.
- AI is used only for OCR and enum-constrained message signals (`src/lib/ai.server.ts`); quotes are validated as substrings in code. Why: the model must never set the score or be steerable by content.
- Deterministic message rules (`src/shared/message-rules.ts`, source "rules") run before AI; AI signals with the same id are dropped, never replacing rules. Why: scoring must work with no AI or keys.
- Every outbound fetch from user input goes through `resolveAndGuard` (DoH + `src/shared/ip-guard.ts`), re-checked on each redirect hop. Why: SSRF defence.
- Jobs/reports tables have no client policies; reads go through security-definer RPCs via server functions. Why: anonymous app with no direct table access.
- Pipeline "edge functions" from the spec are TanStack server functions in `src/lib/*.functions.ts`. Why: platform uses server functions, not edge functions.
- URL checks publish completed evidence independently under a shared 15-second cancellation budget, with a private hashed-URL cache; coverage is informational. Why: slow optional providers must not erase evidence or dead-end reports.
- Scheduled phishing-list refresh uses a managed-authenticated TanStack public server route and private threat tables. Why: no API key or client table access is needed.
- Sitemap entries derive from required route-level sitemap decisions; private reports, checks, and API endpoints are excluded. Why: public page discovery stays synchronized with routing without exposing submissions.
