/**
 * Second Look® — URL analysis (spec §7): parse, SSRF guard, DoH, safe redirects,
 * RDAP, crt.sh, key-gated threat intel, heuristics. Returns signals + checks.
 * Never downloads page bodies, never renders content.
 */

import { classifyHost, expandIpV4Literal, isPrivateV4, isPrivateV6 } from "@/shared/ip-guard";
import { SIGNALS } from "@/shared/signals.config";
import {
  BRAND_DOMAINS,
  CREDENTIAL_KEYWORDS,
  ESTABLISHED_DOMAINS,
  SUSPICIOUS_TLDS,
  URL_SHORTENERS,
} from "@/shared/suspicious";
import type { Check, RedirectHop, Signal, TechnicalDetails } from "@/shared/types";
import { defangUrl } from "@/shared/types";
import { fetchWithTimeout } from "./stages.server";

const UA = "Mozilla/5.0 (compatible; LinkCheck/1.0)";

export function makeSignal(
  id: string,
  opts: { found: string; status?: Signal["status"]; confidence?: number; source?: string; evidence?: string; title?: string },
): Signal {
  const meta = SIGNALS[id];
  return {
    id,
    category: meta.category,
    status: opts.status ?? "suspicious",
    source: opts.source ?? meta.source,
    weight: meta.weight,
    confidence: opts.confidence ?? 1,
    title: opts.title ?? meta.title,
    found: opts.found,
    why: meta.why,
    evidence: opts.evidence,
  };
}

/** Registrable domain approximation (handles common 2-level public suffixes). */
export function registrableDomain(host: string): string {
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const sld2 = new Set(["co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.in", "co.jp", "com.br", "co.nz", "co.za", "com.mx", "com.sg"]);
  const last2 = parts.slice(-2).join(".");
  if (sld2.has(last2)) return parts.slice(-3).join(".");
  return last2;
}

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const d = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 1; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[m][n];
}

/** Pure, local heuristics on the URL. Exported for tests. */
export function urlHeuristics(rawUrl: string): Signal[] {
  const out: Signal[] = [];
  const u = new URL(rawUrl);
  const host = u.hostname.toLowerCase();
  const reg = registrableDomain(host);
  const label = reg.split(".")[0];
  const full = rawUrl.toLowerCase();

  if (expandIpV4Literal(host) || host.startsWith("[")) {
    out.push(makeSignal("ip_literal_host", { found: `The address uses ${host} instead of a domain name.` }));
  }
  if (host.split(".").some((p) => p.startsWith("xn--"))) {
    out.push(makeSignal("punycode_homograph", { found: `The domain contains encoded international characters (${host}).` }));
  }

  const exactOfficial = BRAND_DOMAINS.some((b) => reg === b.domain || host === b.domain);
  if (!exactOfficial && label.length >= 3) {
    const lookalike = BRAND_DOMAINS.find((b) => {
      const bl = b.domain.split(".")[0];
      if (bl.length < 3) return false;
      if (label === bl) return true; // same name, different TLD
      if (bl.length >= 5 && label.includes(bl)) return true;
      return bl.length >= 5 && levenshtein(label, bl) <= (bl.length >= 8 ? 2 : 1);
    });
    if (lookalike) {
      out.push(
        makeSignal("brand_lookalike_domain", {
          found: `"${reg}" resembles ${lookalike.brand}, whose official domain is ${lookalike.domain}.`,
          confidence: 0.9,
        }),
      );
    } else {
      const sub = host.slice(0, Math.max(0, host.length - reg.length));
      const rest = `${sub} ${u.pathname}`.toLowerCase();
      const inSub = BRAND_DOMAINS.find((b) => {
        const bl = b.domain.split(".")[0];
        return bl.length >= 4 && rest.includes(bl);
      });
      if (inSub) {
        out.push(
          makeSignal("brand_in_subdomain_or_path", {
            found: `"${inSub.brand}" appears in the address, but the domain that controls it is ${reg}.`,
            confidence: 0.85,
          }),
        );
      }
    }
  }

  if (host.split(".").length - reg.split(".").length >= 3) {
    out.push(makeSignal("excessive_subdomains", { found: `The address has ${host.split(".").length - reg.split(".").length} subdomain levels.` }));
  }
  const tld = host.split(".").pop() ?? "";
  if (SUSPICIOUS_TLDS.has(tld)) {
    out.push(makeSignal("suspicious_tld", { found: `The domain ends in .${tld}.`, confidence: 0.8 }));
  }
  if (URL_SHORTENERS.has(host) || URL_SHORTENERS.has(reg)) {
    out.push(makeSignal("url_shortener", { found: `${host} is a link-shortening service.` }));
  }
  const hyphens = (reg.match(/-/g) ?? []).length;
  if (rawUrl.includes("@") || /%[0-9a-f]{2}/i.test(u.hostname + u.pathname) || hyphens >= 3 || rawUrl.length > 200) {
    out.push(makeSignal("long_or_obfuscated_url", { found: "The address uses encoding, '@', many hyphens or unusual length.", confidence: 0.9 }));
  }
  const kw = CREDENTIAL_KEYWORDS.filter((k) => (u.pathname + u.search + " " + host).toLowerCase().includes(k));
  if (kw.length > 0 && !exactOfficial) {
    out.push(makeSignal("credential_keywords_in_path", { found: `The address contains: ${kw.slice(0, 4).join(", ")}.`, confidence: 0.9 }));
  }
  if (u.port && u.port !== "80" && u.port !== "443") {
    out.push(makeSignal("non_standard_port", { found: `The address uses port ${u.port}.` }));
  }
  if (ESTABLISHED_DOMAINS.has(host) || (ESTABLISHED_DOMAINS.has(reg) && host === `www.${reg}`)) {
    out.push(
      makeSignal("established_domain_allowlist", {
        found: `${host} exactly matches a curated list of long-established domains.`,
        status: "info",
      }),
    );
  }
  void full;
  return out;
}

type DohAnswer = { type: number; data: string };

async function doh(name: string, type: string): Promise<DohAnswer[] | null> {
  try {
    const res = await fetchWithTimeout(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { accept: "application/dns-json" } },
      3000,
    );
    if (!res.ok) return null;
    const j = (await res.json()) as { Answer?: DohAnswer[] };
    return j.Answer ?? [];
  } catch {
    return null;
  }
}

/** Resolve and verify every A/AAAA is public. */
export async function resolveAndGuard(host: string): Promise<{ ok: boolean; reason?: string; ips: string[]; dnsFailed?: boolean }> {
  const c = classifyHost(host);
  if (c.kind === "blocked") return { ok: false, reason: c.reason, ips: [] };
  const v4 = expandIpV4Literal(host);
  if (v4) return isPrivateV4(v4) ? { ok: false, reason: "private_or_reserved_ip", ips: [v4] } : { ok: true, ips: [v4] };
  if (host.startsWith("[")) return { ok: true, ips: [host] }; // classifyHost already checked v6 literals
  const [a, aaaa] = await Promise.all([doh(host, "A"), doh(host, "AAAA")]);
  if (a === null && aaaa === null) return { ok: false, reason: "dns_failed", ips: [], dnsFailed: true };
  const ips = [...(a ?? []).filter((x) => x.type === 1), ...(aaaa ?? []).filter((x) => x.type === 28)].map((x) => x.data);
  for (const ip of ips) {
    if (ip.includes(":")) {
      if (classifyHost(ip).kind === "blocked" || isPrivateV6Safe(ip)) return { ok: false, reason: "resolves_to_private_ip", ips };
    } else if (isPrivateV4(ip)) return { ok: false, reason: "resolves_to_private_ip", ips };
  }
  return { ok: true, ips };
}

function isPrivateV6Safe(ip: string): boolean {
  try {
    return classifyHost(ip).kind === "blocked";
  } catch {
    return true;
  }
}
void isPrivateV6;

export type UrlAnalysis = {
  normalizedUrl: string;
  defangedUrl: string;
  finalUrl: string;
  hops: RedirectHop[];
  signals: Signal[];
  checks: Check[];
  technical: TechnicalDetails;
  blocked?: string;
};

type StageFn = (id: string, status: "running" | "done" | "skipped" | "unavailable") => Promise<void>;

export async function analyzeUrl(rawUrl: string, stage: StageFn = async () => {}, opts: { emailClaim?: boolean } = {}): Promise<UrlAnalysis> {
  const signals: Signal[] = [];
  const checks: Check[] = [];
  const technical: TechnicalDetails = { redirectChain: [], threatIntel: [], rawSignals: [], dns: null, rdap: null, tls: null };

  await stage("validate", "running");
  const u = new URL(rawUrl);
  u.username = "";
  u.password = "";
  const normalizedUrl = u.toString();
  const host = u.hostname.toLowerCase();
  const guard = await resolveAndGuard(host);
  if (!guard.ok && guard.reason !== "dns_failed") {
    await stage("validate", "done");
    return {
      normalizedUrl,
      defangedUrl: defangUrl(normalizedUrl),
      finalUrl: normalizedUrl,
      hops: [],
      signals,
      checks,
      technical,
      blocked: guard.reason,
    };
  }
  checks.push({ name: "Link parsing and normalization", status: "completed", source: "heuristic" });
  await stage("validate", "done");

  // Threat intel (key-gated)
  await stage("threatintel", "running");
  const ti = await threatIntel(normalizedUrl, host);
  checks.push(...ti.checks);
  signals.push(...ti.signals);
  technical.threatIntel = ti.verdicts;
  await stage("threatintel", ti.checks.every((c) => c.status === "unavailable") ? "unavailable" : "done");

  // Domain
  await stage("domain", "running");
  const reg = registrableDomain(host);
  const dom = await domainIntel(reg, host, guard, opts.emailClaim ?? false);
  checks.push(...dom.checks);
  signals.push(...dom.signals);
  technical.dns = dom.dns;
  technical.rdap = dom.rdap;
  technical.tls = dom.tls;
  await stage("domain", "done");

  // Redirects
  await stage("redirects", "running");
  let finalUrl = normalizedUrl;
  if (guard.ok && (!u.port || u.port === "80" || u.port === "443")) {
    const r = await followRedirects(normalizedUrl);
    technical.redirectChain = r.hops;
    finalUrl = r.finalUrl;
    if (r.blocked) {
      checks.push({ name: "Safe redirect following", status: "completed", source: "heuristic", note: "Stopped at a hop pointing to a private network." });
      signals.push(
        makeSignal("redirect_cross_domain", {
          found: "The link redirects toward a private or internal network address. We stopped and did not follow it.",
          title: "Redirect points to a private network (blocked)",
        }),
      );
    } else {
      checks.push({ name: "Safe redirect following", status: r.failed ? "unavailable" : "completed", source: "heuristic" });
    }
    if (r.hops.length > 3) signals.push(makeSignal("redirect_chain_long", { found: `The link passes through ${r.hops.length} redirects.` }));
    const domains = new Set(r.hops.map((h) => registrableDomain(new URL(h.to).hostname)));
    domains.delete(reg);
    if (domains.size > 0 && !r.blocked) {
      signals.push(makeSignal("redirect_cross_domain", { found: `The link ends up on ${[...domains].slice(0, 3).join(", ")}.` }));
    }
    await stage("redirects", r.failed ? "unavailable" : "done");
  } else {
    checks.push({ name: "Safe redirect following", status: "skipped", source: "heuristic", note: "Not followed (non-standard port or unresolvable)." });
    await stage("redirects", "skipped");
  }

  // Heuristics on the original and (if different) final destination
  await stage("patterns", "running");
  const h = urlHeuristics(normalizedUrl);
  if (finalUrl !== normalizedUrl) {
    for (const s of urlHeuristics(finalUrl)) {
      if (!h.some((x) => x.id === s.id)) h.push({ ...s, found: `Destination: ${s.found}` });
    }
  }
  signals.push(...h);
  checks.push({ name: "Link pattern heuristics", status: "completed", source: "heuristic" });
  await stage("patterns", "done");

  return { normalizedUrl, defangedUrl: defangUrl(normalizedUrl), finalUrl, hops: technical.redirectChain, signals, checks, technical };
}

async function followRedirects(start: string): Promise<{ hops: RedirectHop[]; finalUrl: string; blocked?: boolean; failed?: boolean }> {
  const hops: RedirectHop[] = [];
  let current = start;
  for (let i = 0; i < 5; i++) {
    let res: Response;
    let method = "HEAD";
    try {
      res = await fetchWithTimeout(current, { method: "HEAD", redirect: "manual", headers: { "user-agent": UA }, credentials: "omit" }, 4000);
      if (res.status === 405 || res.status === 403 || res.status === 501) {
        method = "GET";
        res = await fetchWithTimeout(current, { method: "GET", redirect: "manual", headers: { "user-agent": UA, range: "bytes=0-0" }, credentials: "omit" }, 4000);
      }
      try {
        await res.body?.cancel();
      } catch {
        /* ignore */
      }
    } catch {
      return { hops, finalUrl: current, failed: hops.length === 0 };
    }
    const loc = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && loc) {
      let next: URL;
      try {
        next = new URL(loc, current);
      } catch {
        break;
      }
      if (next.protocol !== "http:" && next.protocol !== "https:") break;
      hops.push({ from: current, to: next.toString(), status: res.status, method });
      const g = await resolveAndGuard(next.hostname);
      if (!g.ok) return { hops, finalUrl: current, blocked: true };
      current = next.toString();
      continue;
    }
    break;
  }
  return { hops, finalUrl: current };
}

async function domainIntel(
  reg: string,
  host: string,
  guard: { ok: boolean; ips: string[]; dnsFailed?: boolean },
  emailClaim: boolean,
) {
  const checks: Check[] = [];
  const signals: Signal[] = [];
  let dns: TechnicalDetails["dns"] = null;
  let rdap: TechnicalDetails["rdap"] = null;
  let tls: TechnicalDetails["tls"] = null;

  if (expandIpV4Literal(host) || host.startsWith("[")) {
    checks.push({ name: "Domain registration (RDAP)", status: "skipped", source: "rdap", note: "IP address, no domain" });
    return { checks, signals, dns, rdap, tls };
  }

  // DNS
  const types = ["A", "AAAA", "MX", "NS", "TXT"] as const;
  const results = await Promise.all(types.map((t) => doh(t === "MX" || t === "NS" || t === "TXT" ? reg : host, t)));
  if (results.every((r) => r === null)) {
    checks.push({ name: "DNS records", status: "unavailable", source: "dns" });
  } else {
    const records = results.flatMap((r, i) => (r ?? []).map((a) => ({ type: types[i], value: a.data.slice(0, 200) })));
    dns = { records: records.slice(0, 30), source: "Cloudflare DNS-over-HTTPS" };
    checks.push({ name: "DNS records", status: "completed", source: "dns" });
    if (guard.ips.length === 0) signals.push(makeSignal("domain_unresolvable", { found: `${host} returned no address records.` }));
    const mx = results[2] ?? [];
    if (emailClaim && mx.length === 0) signals.push(makeSignal("dns_no_mx_for_email_claim", { found: `${reg} publishes no mail servers.` }));
  }

  // RDAP
  try {
    const res = await fetchWithTimeout(`https://rdap.org/domain/${encodeURIComponent(reg)}`, { headers: { accept: "application/rdap+json" } }, 5000);
    if (!res.ok) throw new Error(String(res.status));
    const j = (await res.json()) as {
      events?: { eventAction: string; eventDate: string }[];
      entities?: { roles?: string[]; vcardArray?: unknown[] }[];
    };
    const created = j.events?.find((e) => e.eventAction === "registration")?.eventDate;
    const registrarEnt = j.entities?.find((e) => e.roles?.includes("registrar"));
    const vcard = registrarEnt?.vcardArray?.[1] as unknown[] | undefined;
    const fn = (vcard?.find((x) => Array.isArray(x) && x[0] === "fn") as unknown[] | undefined)?.[3] as string | undefined;
    const ageDays = created ? Math.floor((Date.now() - new Date(created).getTime()) / 86400000) : null;
    rdap = { registrar: fn, created, ageDays, status: "ok" };
    checks.push({ name: "Domain registration (RDAP)", status: "completed", source: "rdap" });
    if (ageDays !== null && ageDays < 30) {
      signals.push(makeSignal("domain_very_new", { found: `${reg} was registered ${ageDays} days ago (${created?.slice(0, 10)}).`, status: "info" }));
    } else if (ageDays !== null && ageDays < 90) {
      signals.push(makeSignal("domain_new", { found: `${reg} was registered ${ageDays} days ago (${created?.slice(0, 10)}).`, status: "info" }));
    }
    const raw = JSON.stringify(j).toLowerCase();
    if (raw.includes("redacted for privacy") || raw.includes("privacy") && raw.includes("proxy")) {
      signals.push(makeSignal("registrar_privacy_hidden", { found: "Registrant details are redacted.", status: "info" }));
    }
  } catch {
    rdap = { status: "unavailable" };
    checks.push({ name: "Domain registration (RDAP)", status: "unavailable", source: "rdap" });
  }

  // TLS via Certificate Transparency
  try {
    const res = await fetchWithTimeout(`https://crt.sh/?q=${encodeURIComponent(reg)}&output=json&exclude=expired`, {}, 6000);
    if (!res.ok) throw new Error(String(res.status));
    const text = await res.text();
    const certs = JSON.parse(text.slice(0, 2_000_000)) as { not_before: string; issuer_name: string }[];
    if (certs.length === 0) {
      tls = { status: "none found" };
    } else {
      const earliest = certs.reduce((a, b) => (a.not_before < b.not_before ? a : b));
      const latest = certs.reduce((a, b) => (a.not_before > b.not_before ? a : b));
      tls = { issuer: latest.issuer_name.slice(0, 160), firstSeen: earliest.not_before, status: "ok" };
      const days = (Date.now() - new Date(earliest.not_before + "Z").getTime()) / 86400000;
      if (days < 14) signals.push(makeSignal("tls_cert_very_new", { found: `The earliest certificate for ${reg} was issued ${Math.max(0, Math.floor(days))} days ago.`, status: "info" }));
    }
    checks.push({ name: "TLS certificate history", status: "completed", source: "crtsh", note: "HTTPS does not indicate that a site is trustworthy." });
  } catch {
    tls = { status: "unavailable" };
    checks.push({ name: "TLS certificate history", status: "unavailable", source: "crtsh" });
  }

  return { checks, signals, dns, rdap, tls };
}

async function threatIntel(url: string, host: string) {
  const checks: Check[] = [];
  const signals: Signal[] = [];
  const verdicts: { name: string; verdict: string; source: string }[] = [];

  const hit = (source: string, label: string, detail: string) => {
    signals.push(
      makeSignal("threat_feed_hit", {
        status: "confirmed",
        source,
        confidence: 1,
        title: `Link is flagged by ${label}`,
        found: detail,
      }),
    );
  };

  // Google Safe Browsing
  const sb = process.env["SAFE_BROWSING_API_KEY"];
  if (!sb) {
    checks.push({ name: "Google Safe Browsing", status: "unavailable", source: "safe_browsing", note: "Not configured" });
    verdicts.push({ name: "Google Safe Browsing", verdict: "unavailable", source: "safe_browsing" });
  } else {
    try {
      const res = await fetchWithTimeout(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(sb)}`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            client: { clientId: "second-look", clientVersion: "1.0" },
            threatInfo: {
              threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"],
              threatEntries: [{ url }],
            },
          }),
        },
        5000,
      );
      if (!res.ok) throw new Error(String(res.status));
      const j = (await res.json()) as { matches?: { threatType: string }[] };
      if (j.matches?.length) {
        hit("safe_browsing", "Google Safe Browsing", `Listed as ${j.matches.map((m) => m.threatType.toLowerCase().replace(/_/g, " ")).join(", ")}.`);
        verdicts.push({ name: "Google Safe Browsing", verdict: "listed", source: "safe_browsing" });
      } else verdicts.push({ name: "Google Safe Browsing", verdict: "not listed", source: "safe_browsing" });
      checks.push({ name: "Google Safe Browsing", status: "completed", source: "safe_browsing" });
    } catch {
      checks.push({ name: "Google Safe Browsing", status: "unavailable", source: "safe_browsing" });
      verdicts.push({ name: "Google Safe Browsing", verdict: "unavailable", source: "safe_browsing" });
    }
  }

  // URLhaus
  const uh = process.env["URLHAUS_AUTH_KEY"];
  if (!uh) {
    checks.push({ name: "URLhaus", status: "unavailable", source: "urlhaus", note: "Not configured" });
    verdicts.push({ name: "URLhaus", verdict: "unavailable", source: "urlhaus" });
  } else {
    try {
      const res = await fetchWithTimeout(
        "https://urlhaus-api.abuse.ch/v1/url/",
        { method: "POST", headers: { "Auth-Key": uh, "content-type": "application/x-www-form-urlencoded" }, body: `url=${encodeURIComponent(url)}` },
        5000,
      );
      if (!res.ok) throw new Error(String(res.status));
      const j = (await res.json()) as { query_status: string; threat?: string };
      if (j.query_status === "ok") {
        hit("urlhaus", "URLhaus", `Listed as ${j.threat ?? "malicious"}.`);
        verdicts.push({ name: "URLhaus", verdict: "listed", source: "urlhaus" });
      } else verdicts.push({ name: "URLhaus", verdict: "not listed", source: "urlhaus" });
      checks.push({ name: "URLhaus", status: "completed", source: "urlhaus" });
    } catch {
      checks.push({ name: "URLhaus", status: "unavailable", source: "urlhaus" });
      verdicts.push({ name: "URLhaus", verdict: "unavailable", source: "urlhaus" });
    }
  }

  // PhishTank (optional)
  const pt = process.env["PHISHTANK_API_KEY"];
  if (pt) {
    try {
      const res = await fetchWithTimeout(
        "https://checkurl.phishtank.com/checkurl/",
        { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "user-agent": "phishtank/second-look" }, body: `url=${encodeURIComponent(url)}&format=json&app_key=${encodeURIComponent(pt)}` },
        5000,
      );
      if (!res.ok) throw new Error(String(res.status));
      const j = (await res.json()) as { results?: { in_database?: boolean; valid?: boolean } };
      if (j.results?.in_database && j.results.valid) {
        hit("phishtank", "PhishTank", "Listed as a verified phishing page.");
        verdicts.push({ name: "PhishTank", verdict: "listed", source: "phishtank" });
      } else verdicts.push({ name: "PhishTank", verdict: "not listed", source: "phishtank" });
      checks.push({ name: "PhishTank", status: "completed", source: "phishtank" });
    } catch {
      checks.push({ name: "PhishTank", status: "unavailable", source: "phishtank" });
    }
  }

  // VirusTotal (optional, domain reputation)
  const vt = process.env["VIRUSTOTAL_API_KEY"];
  if (vt) {
    try {
      const res = await fetchWithTimeout(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(registrableDomain(host))}`, { headers: { "x-apikey": vt } }, 5000);
      if (!res.ok) throw new Error(String(res.status));
      const j = (await res.json()) as { data?: { attributes?: { last_analysis_stats?: { malicious?: number } } } };
      const mal = j.data?.attributes?.last_analysis_stats?.malicious ?? 0;
      if (mal >= 2) {
        hit("virustotal", "VirusTotal", `${mal} security vendors flagged this domain.`);
        verdicts.push({ name: "VirusTotal", verdict: `${mal} vendors flagged`, source: "virustotal" });
      } else verdicts.push({ name: "VirusTotal", verdict: mal === 1 ? "1 vendor flagged" : "not flagged", source: "virustotal" });
      checks.push({ name: "VirusTotal", status: "completed", source: "virustotal" });
    } catch {
      checks.push({ name: "VirusTotal", status: "unavailable", source: "virustotal" });
    }
  }

  return { checks, signals, verdicts };
}
