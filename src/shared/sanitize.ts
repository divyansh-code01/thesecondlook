/**
 * Second Look® — text sanitizing helpers. Isomorphic; no secrets here.
 * User-derived text is always rendered through React escaping; these helpers
 * only normalize and defang for display.
 */

/** Strip control characters (except newline/tab) from user-derived text. */
export function stripControlChars(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
}

/** Truncate for evidence quotes / summaries. */
export function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return text.slice(0, max - 1).trimEnd() + "…";
}

const URL_RE = /\bhttps?:\/\/[^\s<>"')\]]+/gi;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const PHONE_RE = /(?:\+\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,4}\d{2,4}/g;

export type ExtractedRefs = {
  urls: string[];
  emails: string[];
  phones: string[];
};

/** Regex-based extraction — done in code, never by the LLM (spec §7). */
/**
 * OCR often splits a link across lines. Rejoin a line ending in "-", "/", "." or "?"
 * with the next line when the next line starts without a space and the joined
 * text forms a hostname with a TLD.
 */
export function rejoinSplitLinks(text: string): string {
  return text.replace(/(https?:\/\/[^\s<>"')\]]*[-/.?])\r?\n(?=\S)([^\s<>"')\]]+)/gi, (m, a: string, b: string) => {
    try {
      const host = new URL(a + b).hostname;
      return /\.[a-z]{2,63}$/i.test(host) && !/-$/.test(host) ? a + b : m;
    } catch {
      return m;
    }
  });
}

export function extractRefs(rawText: string): ExtractedRefs {
  const text = rejoinSplitLinks(rawText);
  const urls = Array.from(new Set(text.match(URL_RE) ?? [])).map((u) => u.replace(/[.,;]+$/, ""));
  const emails = Array.from(new Set(text.match(EMAIL_RE) ?? []));
  // Phone-like runs that are not part of a URL or email
  const cleaned = text.replace(URL_RE, " ").replace(EMAIL_RE, " ");
  const phones = Array.from(new Set((cleaned.match(PHONE_RE) ?? []).map((p) => p.trim())))
    .filter((p) => p.replace(/\D/g, "").length >= 7)
    .slice(0, 20);
  return { urls, emails, phones };
}

/** Defang URLs, emails and phone-like numbers for safe display. */
export function defangForDisplay(text: string): string {
  return text
    .replace(URL_RE, (m) => m.replace(/^https?:\/\//i, (p) => (p.toLowerCase().startsWith("https") ? "hxxps://" : "hxxp://")).replace(/\./g, "[.]"))
    .replace(EMAIL_RE, (m) => m.replace("@", "[@]").replace(/\./g, "[.]"))
    .replace(PHONE_RE, (m) => (m.replace(/\D/g, "").length >= 7 ? m.replace(/\d(?=\d{2})/g, (d) => d + "") : m));
}

/** UPI IDs, IBANs and crypto addresses (spec §7 screenshot pipeline). */
export function extractPaymentIdentifiers(text: string): { kind: string; value: string }[] {
  const out: { kind: string; value: string }[] = [];
  const upi = text.match(/\b[A-Za-z0-9._-]{2,}@(?:upi|ok(?:hdfcbank|icici|sbi|axis|paytm)|ybl|paytm|axl|ibl)\b/gi);
  if (upi) out.push(...upi.map((v) => ({ kind: "UPI ID", value: v })));
  const iban = text.match(/\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g);
  if (iban) out.push(...iban.map((v) => ({ kind: "IBAN", value: v })));
  const crypto = text.match(/\b(?:bc1[a-z0-9]{20,71}|0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g);
  if (crypto) out.push(...crypto.map((v) => ({ kind: "Crypto address", value: v })));
  return out;
}

export function isPromptInjectionAttempt(text: string): boolean {
  const t = text.toLowerCase();
  const patterns = [
    /ignore\s+(?:all\s+|any\s+)?(?:previous|prior|earlier|above)\s+instructions?/,
    /disregard\s+(?:all\s+|any\s+)?(?:previous|prior|earlier|above)\s+instructions?/,
    /(?:declare|say|state|mark|label|rate)\s+this\s+(?:message|screenshot|link|url)?\s*(?:as\s+)?safe/,
    /(?:you\s+are|act\s+as|from\s+now\s+on\s+you\s+are)\s+(?:a|an|now)\s+/,
    /system\s*[:\-]?\s*prompt/,
    /(?:tell|tell\s+the\s+user|report|conclude)\s+(?:them\s+|the\s+user\s+)?(?:that\s+)?(?:it'?s|this\s+is)\s+(?:safe|legitimate|not\s+a\s+scam)/,
  ];
  return patterns.some((p) => p.test(t));
}
