/**
 * Second Look® — starting signal weights and metadata.
 * Single source of truth for scoring and report copy (spec §7).
 */

export const CATEGORY_CAPS = { url: 45, domain: 25, message: 40, screenshot: 15 } as const;

export const AI_SIGNAL_CAP = 40;
export const THREAT_FEED_FLOOR = 85;
export const MITIGATION_FLOOR = 5;

export type SignalMeta = {
  category: "url" | "domain" | "message" | "screenshot";
  weight: number;
  source: string;
  title: string;
  why: string;
};

export const SIGNALS: Record<string, SignalMeta> = {
  // ---------- URL layer ----------
  threat_feed_hit: {
    category: "url",
    weight: 60,
    source: "safe_browsing",
    title: "Link is flagged by a threat-intelligence source",
    why: "A threat-intelligence database has listed this address as dangerous. This is the strongest single signal in the analysis.",
  },
  ip_literal_host: {
    category: "url",
    weight: 20,
    source: "heuristic",
    title: "Address points at a raw IP number instead of a name",
    why: "Legitimate services almost always use a domain name. Raw numeric addresses are common in phishing infrastructure that is set up quickly and thrown away.",
  },
  punycode_homograph: {
    category: "url",
    weight: 25,
    source: "heuristic",
    title: "Domain uses lookalike Unicode characters",
    why: "Some alphabets contain characters that look identical to Latin letters, so a domain can visually imitate a well-known name while being a different address.",
  },
  brand_lookalike_domain: {
    category: "url",
    weight: 25,
    source: "heuristic",
    title: "Domain closely imitates a well-known brand",
    why: "The domain resembles a known organisation's name without being that organisation's own address. Impersonating a trusted name is a standard phishing pattern.",
  },
  brand_in_subdomain_or_path: {
    category: "url",
    weight: 15,
    source: "heuristic",
    title: "Brand name appears in a subdomain or path",
    why: "A trusted name in a subdomain or path does not mean the site belongs to that organisation — the true owner is whoever controls the main domain.",
  },
  excessive_subdomains: {
    category: "url",
    weight: 8,
    source: "heuristic",
    title: "Unusually many subdomains",
    why: "Long chains of subdomains are used to push a trusted-looking word to the front of an address while the real domain sits at the end.",
  },
  suspicious_tld: {
    category: "url",
    weight: 8,
    source: "heuristic",
    title: "Domain ending is frequently misused",
    why: "Some domain endings are cheap and disproportionately appear in scam links. This is a weak signal on its own.",
  },
  deceptive_hostname_keywords: {
    category: "url",
    weight: 10,
    source: "heuristic",
    title: "Hostname uses trust words",
    why: "Hostnames like 'secure-login-update' string together reassuring words to look official. Real organisations rarely build their main address this way.",
  },
  gov_claim_non_gov_link: {
    category: "url",
    weight: 15,
    source: "rules",
    title: "Claims to be a government agency, but the link isn't a .gov domain",
    why: "Government agencies use official government domains. A message claiming to be from one that links elsewhere is a strong impersonation sign.",
  },
  url_shortener: {
    category: "url",
    weight: 10,
    source: "heuristic",
    title: "Link goes through a URL shortener",
    why: "Shorteners hide the true destination until the link is resolved. We follow the redirect server-side and analyze the destination instead.",
  },
  long_or_obfuscated_url: {
    category: "url",
    weight: 6,
    source: "heuristic",
    title: "Long or obfuscated address",
    why: "Encoded characters, a '@' in the address or long hyphenated strings are often used to disguise where a link really goes.",
  },
  redirect_chain_long: {
    category: "url",
    weight: 8,
    source: "heuristic",
    title: "Link bounces through many redirects",
    why: "Several redirects in a row can be used to hide the final destination or to pass tracking data to scam infrastructure.",
  },
  redirect_cross_domain: {
    category: "url",
    weight: 8,
    source: "heuristic",
    title: "Redirect leaves the original domain",
    why: "The link hands you from one domain to a different one. This is normal for some services, and a common trick when the destination is the point.",
  },
  credential_keywords_in_path: {
    category: "url",
    weight: 8,
    source: "heuristic",
    title: "Address contains credential-related words",
    why: "Words like 'login', 'verify' or 'wallet' in the address are used to make a page look like an account or security check.",
  },
  non_standard_port: {
    category: "url",
    weight: 6,
    source: "heuristic",
    title: "Address uses an unusual port",
    why: "Standard sites serve traffic on port 80 or 443. Other ports are unusual for public websites and common in hastily built phishing pages.",
  },

  // ---------- Domain layer ----------
  domain_very_new: {
    category: "domain",
    weight: 15,
    source: "rdap",
    title: "Domain registered less than 30 days ago",
    why: "Scam infrastructure is often very new. This is context, not proof — new domains are also created for legitimate projects every day.",
  },
  domain_new: {
    category: "domain",
    weight: 8,
    source: "rdap",
    title: "Domain registered less than 90 days ago",
    why: "The domain is young. This is context, not proof — new domains are also created for legitimate projects every day.",
  },
  registrar_privacy_hidden: {
    category: "domain",
    weight: 0,
    source: "rdap",
    title: "Registrant details are hidden behind a privacy service",
    why: "Many legitimate sites hide registration details too. Recorded for completeness; it adds no points.",
  },
  dns_no_mx_for_email_claim: {
    category: "domain",
    weight: 5,
    source: "dns",
    title: "Domain sends no mail, but the message claims it does",
    why: "The message presents this domain as an email sender, yet the domain publishes no mail servers. That combination is inconsistent.",
  },
  tls_cert_very_new: {
    category: "domain",
    weight: 4,
    source: "crtsh",
    title: "Certificate first seen very recently",
    why: "The HTTPS certificate was issued only days ago. Anyone can get a free certificate in minutes — HTTPS does not indicate that a site is trustworthy.",
  },
  domain_unresolvable: {
    category: "domain",
    weight: 6,
    source: "dns",
    title: "Domain does not resolve",
    why: "The domain has no working address records. It may be new, defunct or configured to appear only in certain regions.",
  },

  // ---------- Message layer ----------
  urgency_pressure: {
    category: "message",
    weight: 10,
    source: "ai",
    title: "Message creates urgency",
    why: "Countdowns, deadlines and 'act now' wording pressure you into acting before you can think or verify.",
  },
  credential_request: {
    category: "message",
    weight: 18,
    source: "ai",
    title: "Message asks for credentials",
    why: "No legitimate service asks you to hand over passwords, PINs or card numbers by message. This is a direct credential-harvesting attempt.",
  },
  otp_request: {
    category: "message",
    weight: 22,
    source: "ai",
    title: "Message asks for a one-time code",
    why: "One-time codes guard your accounts. Anyone asking for yours — by message, or 'to stop a payment' — is trying to get in.",
  },
  payment_request: {
    category: "message",
    weight: 15,
    source: "ai",
    title: "Message asks for payment",
    why: "Requests for gift cards, crypto, wire transfers or unusual payment apps are hallmarks of scams because such payments are hard to reverse.",
  },
  impersonation_org: {
    category: "message",
    weight: 15,
    source: "ai",
    title: "Message appears to impersonate an organisation",
    why: "The message presents itself as a bank, delivery firm or government body. Impersonation of trusted organisations is the most common scam pattern.",
  },
  impersonation_person: {
    category: "message",
    weight: 12,
    source: "ai",
    title: "Message appears to impersonate a person you know",
    why: "Patterns like 'Hi Mum, this is my new number' impersonate a friend or relative to extract money.",
  },
  prize_or_lottery: {
    category: "message",
    weight: 15,
    source: "ai",
    title: "Message announces a prize or windfall",
    why: "Unexpected prizes, refunds or investment returns that require you to act or pay first are bait, not luck.",
  },
  threat_or_fear: {
    category: "message",
    weight: 10,
    source: "ai",
    title: "Message uses threats or fear",
    why: "Warnings about locked accounts, fines or legal action are designed to make you comply before you can check.",
  },
  off_platform_move: {
    category: "message",
    weight: 8,
    source: "ai",
    title: "Message asks to move to another platform",
    why: "Switching the conversation to WhatsApp, Telegram or another app moves you away from the platform's own protections.",
  },
  inconsistent_sender_context: {
    category: "message",
    weight: 10,
    source: "ai",
    title: "Sender context doesn't add up",
    why: "Details in the message contradict each other — a bank texting from a personal number, a name that doesn't match the service, mixed languages.",
  },
  unsolicited_job_or_investment: {
    category: "message",
    weight: 14,
    source: "ai",
    title: "Unsolicited job or investment offer",
    why: "Out-of-the-blue job offers, easy tasks for pay, or guaranteed investment returns are leading recruitment paths for modern scams.",
  },
  prompt_injection_attempt: {
    category: "message",
    weight: 10,
    source: "heuristic",
    title: "Message tries to instruct the analyzer",
    why: "The text contains instructions aimed at this tool rather than at you. That is itself a strong scam signal, and we do not follow it.",
  },
  grammar_anomalies: {
    category: "message",
    weight: 3,
    source: "ai",
    title: "Unusual wording or grammar",
    why: "Awkward phrasing, odd spacing or inconsistent formatting can indicate a hastily produced or machine-translated message. Weak signal on its own.",
  },

  // ---------- Screenshot layer ----------
  sender_name_mismatch: {
    category: "screenshot",
    weight: 10,
    source: "heuristic",
    title: "Sender name doesn't match the claimed organisation",
    why: "The name shown as the sender does not match the organisation the message claims to represent.",
  },
  link_text_mismatch: {
    category: "screenshot",
    weight: 10,
    source: "heuristic",
    title: "Visible link text doesn't match its address",
    why: "The text shown for a link points to one organisation while the address behind it belongs to another.",
  },
  unknown_sender_number: {
    category: "screenshot",
    weight: 4,
    source: "heuristic",
    title: "Message from an unknown number",
    why: "The message arrives from a number or handle outside your contacts, unsolicited.",
  },
  ocr_low_confidence: {
    category: "screenshot",
    weight: 0,
    source: "ai",
    title: "Text extraction had low confidence",
    why: "Some of the screenshot's text was hard to read, so the analysis may have missed details. This lowers evidence coverage; it adds no points.",
  },

  // ---------- Mitigation ----------
  established_domain_allowlist: {
    category: "domain",
    weight: -15,
    source: "heuristic",
    title: "Exact match to a well-established domain",
    why: "The address is an exact match for a curated list of major, long-established domains, which reduces the score. It is not a verdict of safety.",
  },
};

export const SIGNAL_LABELS: Record<string, string> = Object.fromEntries(
  Object.entries(SIGNALS).map(([id, meta]) => [id, meta.title]),
);
