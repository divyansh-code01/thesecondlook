/**
 * Second Look® — deterministic message rules (no AI).
 * Case-insensitive regex rules over OCR / pasted text. Each rule emits a
 * catalogue signal with source "rules" and the catalogue weight.
 * Rules run first; AI signals may only add to them, never remove them.
 */
import { SIGNALS } from "./signals.config";
import type { Signal } from "./types";

type Rule = { id: string; patterns: RegExp[] };

export const GOV_CLAIM =
  /\b(department of|dept\.? of|dmv|secretary of state|irs|internal revenue|police|customs|tax (office|department|authority|refund)|hmrc|court|ministry of|government|federal|state of|office of the)\b/i;

export const MESSAGE_RULES: Rule[] = [
  { id: "impersonation_org", patterns: [GOV_CLAIM] },
  {
    id: "urgency_pressure",
    patterns: [
      /\ball\b[^.\n]{0,60}\bmust\b[^.\n]{0,20}\bupdate\b/i,
      /\b(need|needs|must) to (update|verify|confirm)\b/i,
      /\bwithin \d+\s*(hours?|hrs?|days?|minutes?)\b/i,
      /\bfinal (notice|warning|reminder)\b/i,
      /\b(suspended|suspension|expires?|expiring|expired|deadline|immediately|act now|last chance)\b/i,
      /\bstarting \d{1,2}[/\-. ][a-z]{3,9}[/\-. ]\d{2,4}\b/i,
    ],
  },
  {
    id: "credential_request",
    patterns: [
      /\b(update|verify|confirm|validate|re-?activate)\b[^\n]{0,60}\b(info|information|details|account|licen[cs]e|card|kyc|identity|password|pin)\b/i,
      /\b(follow|click|tap|open|use)\b[^\n]{0,30}\blink\b[^\n]{0,60}\b(update|verify|confirm)\b/i,
    ],
  },
  { id: "otp_request", patterns: [/\b(otp|one[- ]time (pass)?code|verification code|security code)\b/i] },
  {
    id: "prize_or_lottery",
    patterns: [
      /\b(you('ve| have)? won|winner|prize|lottery|jackpot|reward|refund|cashback)\b/i,
      /\b(parcel|package|delivery|shipment)\b[^\n]{0,60}\b(fee|pay|held|failed|unpaid|customs)\b/i,
      /\b(unpaid|outstanding|overdue)\b[^\n]{0,30}\b(toll|fine|penalty|bill|invoice)\b/i,
      /\btoll\b[^\n]{0,40}\b(due|balance|pay)\b/i,
    ],
  },
  {
    id: "payment_request",
    patterns: [
      /\b(pay|payment|deposit|transfer|send)\b[^\n]{0,40}\b(now|fee|amount|usd|\$|₹|£|€|gift ?card|bitcoin|crypto|upi|wire)\b/i,
    ],
  },
  {
    id: "unsolicited_job_or_investment",
    patterns: [
      /\b(invest|investment|trading|guaranteed returns?|double your)\b/i,
      /\b(tasks?|likes|reviews|part[- ]time)\b[^\n]{0,40}\b(earn|paid|commission|salary|per day|daily)\b/i,
    ],
  },
  { id: "off_platform_move", patterns: [/\b(whats ?app|telegram|signal app|wechat)\b/i] },
];

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i;

function makeRuleSignal(id: string, quote: string, extra: Partial<Signal> = {}): Signal {
  const meta = SIGNALS[id];
  return {
    id,
    category: meta.category,
    status: "suspicious",
    source: "rules",
    weight: meta.weight,
    confidence: 1,
    title: meta.title,
    found: quote ? `“${quote}”` : meta.title,
    why: meta.why,
    evidence: quote || undefined,
    ...extra,
  };
}

/** Run the deterministic rules. `senderLabel` is the sender shown in the screenshot, if any. */
export function runMessageRules(text: string, senderLabel?: string | null): Signal[] {
  const out: Signal[] = [];
  for (const rule of MESSAGE_RULES) {
    for (const re of rule.patterns) {
      const m = text.match(re);
      if (m) {
        out.push(makeRuleSignal(rule.id, m[0].slice(0, 160)));
        break;
      }
    }
  }
  const sender = (senderLabel ?? "").trim();
  if (sender && EMAIL_RE.test(sender)) {
    out.push(
      makeRuleSignal("sender_name_mismatch", "", {
        found: `The sender is shown as an email address (${sender.slice(0, 80)}) rather than a phone number or verified name.`,
      }),
    );
  }
  return out;
}

/** True when the text claims to come from a government agency. */
export function claimsGovernment(text: string): boolean {
  return GOV_CLAIM.test(text);
}

/** Government claim + a link whose host is not a .gov (or gov.xx) domain. */
export function govLinkMismatch(text: string, urls: string[]): Signal[] {
  if (!claimsGovernment(text)) return [];
  const out: Signal[] = [];
  for (const u of urls) {
    let host = "";
    try {
      host = new URL(u).hostname.toLowerCase();
    } catch {
      continue;
    }
    const isGov = /(^|\.)gov(\.[a-z]{2})?$/.test(host) || /\.gov\.[a-z]{2,3}$/.test(host);
    if (!isGov) {
      out.push(
        makeRuleSignal("link_text_mismatch", "", {
          found: `The message claims to be from a government agency, but the link goes to ${host}, which is not a government (.gov) domain.`,
        }),
      );
      break;
    }
  }
  return out;
}
