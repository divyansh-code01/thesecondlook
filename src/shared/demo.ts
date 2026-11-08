import type { ReportPayload } from "./types";

/** Clearly labeled sample shown only when the real analyzers are unavailable. Never persisted. */
export const DEMO_REPORT: ReportPayload = {
  kind: "url",
  demo: true,
  inputDisplay: "hxxps://secure-paypa1-verify[.]example",
  score: 58,
  classification: "high",
  coverage: 0.6,
  completedChecks: 3,
  applicableChecks: 5,
  summary: "SAMPLE DATA. This shows what a report looks like. It is not a real scan of anything you submitted.",
  checks: [
    { name: "Link pattern heuristics", status: "completed", source: "heuristic" },
    { name: "DNS records", status: "completed", source: "dns" },
    { name: "Domain registration (RDAP)", status: "completed", source: "rdap" },
    { name: "Google Safe Browsing", status: "unavailable", source: "safe_browsing" },
    { name: "URLhaus", status: "unavailable", source: "urlhaus" },
  ],
  signals: [
    { id: "brand_lookalike_domain", category: "url", status: "suspicious", source: "heuristic", weight: 25, confidence: 0.9, title: "Domain closely imitates a well-known brand", found: "Sample: resembles PayPal.", why: "Impersonating a trusted name is a standard phishing pattern." },
    { id: "credential_keywords_in_path", category: "url", status: "suspicious", source: "heuristic", weight: 8, confidence: 0.9, title: "Address contains credential-related words", found: "Sample: secure, verify.", why: "Used to make a page look like a security check." },
    { id: "domain_very_new", category: "domain", status: "info", source: "rdap", weight: 15, confidence: 1, title: "Domain registered less than 30 days ago", found: "Sample: registered 6 days ago.", why: "Context, not proof." },
    { id: "suspicious_tld", category: "url", status: "suspicious", source: "heuristic", weight: 8, confidence: 0.8, title: "Domain ending is frequently misused", found: "Sample data.", why: "Weak signal on its own." },
  ],
};
