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
  HOSTNAME_TRUST_WORDS,
  SUSPICIOUS_TLDS,
  URL_SHORTENERS,
} from "@/shared/suspicious";
import type { Check, RedirectHop, Signal, TechnicalDetails } from "@/shared/types";
import { defangUrl } from "@/shared/types";
import { fetchWithTimeout } from "./stages.server";
import { checkKnownThreats } from "./threat-lists.server";
const NONEXISTENT_NOTE = "This domain does not exist or has been taken down. Do not use it.";
import { checkCloudflareSecurity, checkQuad9, queryDns } from "./security-dns.server";

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
      const tokens = label.split(/[-_]/).filter((t) => t.length >= 4);
      if (bl.length >= 5 && tokens.some((t) => t === bl || levenshtein(t, bl) <= 1)) return true;
      if (bl.length >= 5 && label.includes(bl)) return true;
      return bl.length >= 5 && levenshtein(label, bl) <= (bl.length >= 8 ? 2 : 1);
    });
    if (lookalike) {
      out.push(
        makeSignal("brand_lookalike_domain", {
          found: `"${reg}" resembles ${lookalike.brand}, whose official domain is ${lookalike.domain}.`,
          confidence: 1,
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
    out.push(makeSignal("suspicious_tld", { found: `The domain ends in .${tld}.` }));
  }
  const hostNoTld = host.slice(0, Math.max(0, host.length - tld.length - 1));
  if (!exactOfficial) {
    const words = HOSTNAME_TRUST_WORDS.filter((w) => hostNoTld.includes(w));
    if (words.length > 0) {
      out.push(makeSignal("deceptive_hostname_keywords", { found: `The hostname ${host} contains: ${words.join(", ")}.` }));
    }
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

async function doh(name: string, type: string, signal?: AbortSignal): Promise<DnsResponse | null> {
  try { return await queryDns("https://cloudflare-dns.com/dns-query", name, type, signal); } catch { return null; }
}
type DnsResponse = import("./security-dns.server").DnsResponse;

/** Resolve and verify every A/AAAA is public. */
export async function resolveAndGuard(host: string, signal?: AbortSignal): Promise<{ ok: boolean; reason?: string; ips: string[]; dnsFailed?: boolean; nxdomain?: boolean }> {
  const c = classifyHost(host);
  if (c.kind === "blocked") return { ok: false, reason: c.reason, ips: [] };
  const v4 = expandIpV4Literal(host);
  if (v4) return isPrivateV4(v4) ? { ok: false, reason: "private_or_reserved_ip", ips: [v4] } : { ok: true, ips: [v4] };
  if (host.startsWith("[")) return { ok: true, ips: [host] }; // classifyHost already checked v6 literals
  const [a, aaaa] = await Promise.all([doh(host, "A", signal), doh(host, "AAAA", signal)]);
  if (a === null && aaaa === null) return { ok: false, reason: "dns_failed", ips: [], dnsFailed: true };
  const ips = [...(a?.Answer ?? []).filter((x) => x.type === 1), ...(aaaa?.Answer ?? []).filter((x) => x.type === 28)].map((x) => x.data);
  for (const ip of ips) {
    if (ip.includes(":")) {
      if (classifyHost(ip).kind === "blocked" || isPrivateV6Safe(ip)) return { ok: false, reason: "resolves_to_private_ip", ips };
    } else if (isPrivateV4(ip)) return { ok: false, reason: "resolves_to_private_ip", ips };
  }
  return { ok: true, ips, nxdomain: a?.Status === 3 || aaaa?.Status === 3 };
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

type StageFn = (id: string, status: "running" | "done" | "skipped" | "unavailable", note?: string) => Promise<void>;

const CORE_CHECKS = [
  ["Link parsing and normalization", "heuristic"], ["DNS records", "dns"],
  ["Cloudflare security DNS", "cloudflare_security"], ["Quad9 threat blocking", "quad9"],
  ["Google Safe Browsing", "safe_browsing"], ["Known phishing lists", "known_threats"],
  ["Link pattern heuristics", "heuristic"],
] as const;

export async function analyzeUrl(rawUrl: string, stage: StageFn = async () => {}, opts: { emailClaim?: boolean; signal?: AbortSignal; skipCache?: boolean; destination?: boolean } = {}): Promise<UrlAnalysis> {
  const u = new URL(rawUrl);
  u.username = ""; u.password = ""; u.hash = "";
  const normalizedUrl = u.toString();
  const host = u.hostname.toLowerCase();
  const signals = urlHeuristics(normalizedUrl);
  const checks: Check[] = [{ name: "Link parsing and normalization", status: "completed", source: "heuristic" }, { name: "Link pattern heuristics", status: "completed", source: "heuristic" }];
  const technical: TechnicalDetails = { redirectChain: [], threatIntel: [], rawSignals: [], dns: null, rdap: null, tls: null };
  let finalUrl = normalizedUrl;
  let blocked: string | undefined;
  const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(normalizedUrl)))).map((b) => b.toString(16).padStart(2, "0")).join("");
  if (!opts.skipCache) {
    try {
      const { getSupabaseAdmin } = await import("./supabase.server");
      const { data } = await getSupabaseAdmin().from("url_analysis_cache").select("payload").eq("url_hash", hash).gt("expires_at", new Date().toISOString()).maybeSingle();
      if (data && !opts.emailClaim) {
        for (const id of ["validate", "threatintel", "domain", "redirects", "patterns"]) await stage(id, "done", "Cached check from the last 10 minutes");
        return data.payload as unknown as UrlAnalysis;
      }
    } catch { /* Cache is optional, never block a check. */ }
  }
  const deadline = AbortSignal.any([AbortSignal.timeout(15000), ...(opts.signal ? [opts.signal] : [])]);
  const commit = (r: { checks: Check[]; signals: Signal[]; verdicts?: TechnicalDetails["threatIntel"] }) => {
    if (deadline.aborted) return;
    checks.push(...r.checks); signals.push(...r.signals);
    if (r.verdicts) technical.threatIntel.push(...r.verdicts);
  };
  await Promise.all(["validate", "threatintel", "domain", "redirects", "patterns"].map((id) => stage(id, "running")));
  const guardPromise = resolveAndGuard(host, deadline);
  const tasks = [
    threatIntel(normalizedUrl, host, deadline, commit),
    checkCloudflareSecurity(host, deadline).then(commit),
    checkQuad9(host, guardPromise, deadline).then(commit),
    checkKnownThreats(normalizedUrl, host).then(commit),
    guardPromise.then(async (guard) => {
      if (!guard.ok && guard.reason !== "dns_failed") { blocked = guard.reason; return; }
      const domainTasks = domainIntel(registrableDomain(host), host, guard, opts.emailClaim ?? false, deadline, (dom) => {
        commit(dom);
        if (!deadline.aborted) { technical.dns = dom.dns; technical.rdap = dom.rdap; technical.tls = dom.tls; }
      });
      const redirectTask = (async () => {
        if (guard.nxdomain) {
          commit({ signals: [], checks: [{ name: "Safe redirect following", source: "heuristic", status: "completed", note: NONEXISTENT_NOTE, excludeFromCoverage: true }] });
          return;
        }
        if (!guard.ok || (u.port && !["80", "443"].includes(u.port))) {
          commit({ signals: [], checks: [{ name: "Safe redirect following", source: "heuristic", status: "unavailable", note: "DNS lookup failed or non-standard port; destination was not requested", excludeFromCoverage: true }] });
          return;
        }
        const r = await followRedirects(normalizedUrl, deadline);
        if (deadline.aborted) return;
        finalUrl = r.finalUrl; technical.redirectChain = r.hops;
        commit({ checks: [{ name: "Safe redirect following", source: "heuristic", status: r.failed ? "unavailable" : "completed", note: r.blocked ? "Stopped before a private or unavailable destination; no request was made to it" : r.failed ? "Site did not respond within the analysis budget" : undefined, excludeFromCoverage: true }], signals: [] });
        if (r.hops.length > 3) signals.push(makeSignal("redirect_chain_long", { found: `The link passes through ${r.hops.length} redirects.` }));
        if (finalUrl !== normalizedUrl && !r.blocked && !opts.destination && !deadline.aborted) {
          const dest = await analyzeUrl(finalUrl, async () => {}, { signal: deadline, destination: true });
          if (!deadline.aborted) {
            commit({ signals: dest.signals.map((s) => ({ ...s, found: `Destination: ${s.found}` })), checks: dest.checks.map((c) => ({ ...c, name: `${c.name} · destination ${defangUrl(finalUrl)}` })), verdicts: dest.technical.threatIntel });
            signals.push(makeSignal("redirect_cross_domain", { found: `The link ends at ${defangUrl(finalUrl)}.` }));
          }
        }
      })();
      await Promise.all([domainTasks, redirectTask]);
    }),
  ];
  await Promise.race([Promise.allSettled(tasks), new Promise<void>((resolve) => { if (deadline.aborted) resolve(); else deadline.addEventListener("abort", () => resolve(), { once: true }); })]);
  for (const [name, source] of CORE_CHECKS) if (!checks.some((c) => c.name === name)) checks.push({ name, source, status: "unavailable", note: "The check did not finish within the 15-second analysis budget" });
  for (const [id, sources] of [["validate", ["heuristic"]], ["threatintel", ["cloudflare_security", "quad9", "safe_browsing", "known_threats"]], ["domain", ["dns", "rdap", "crtsh"]], ["redirects", ["redirects"]], ["patterns", ["heuristic"]]] as const) {
    const relevant = id === "redirects" ? checks.filter((c) => c.name === "Safe redirect following") : checks.filter((c) => (sources as readonly string[]).includes(c.source));
    const unavailable = relevant.length > 0 && relevant.every((c) => c.status === "unavailable");
    await stage(id, unavailable ? "unavailable" : "done", unavailable ? relevant[0]?.note : undefined);
  }
  const result = structuredClone({ normalizedUrl, defangedUrl: defangUrl(normalizedUrl), finalUrl, hops: technical.redirectChain, signals, checks, technical, blocked });
  if (!opts.skipCache && !blocked) {
    try {
      const { getSupabaseAdmin } = await import("./supabase.server");
      await getSupabaseAdmin().from("url_analysis_cache").upsert({ url_hash: hash, payload: result as unknown as import("@/integrations/supabase/types").Json, expires_at: new Date(Date.now() + 600000).toISOString() });
    } catch { /* No cache is preferable to no report. */ }
  }
  return result;
}

async function followRedirects(start: string, signal?: AbortSignal): Promise<{ hops: RedirectHop[]; finalUrl: string; blocked?: boolean; failed?: boolean }> {
  const hops: RedirectHop[] = [];
  let current = start;
  for (let i = 0; i < 5; i++) {
    let res: Response;
    let method = "HEAD";
    try {
      res = await fetchWithTimeout(current, { method: "HEAD", redirect: "manual", headers: { "user-agent": UA }, credentials: "omit", signal }, 8000);
      if (res.status === 405 || res.status === 403 || res.status === 501) {
        method = "GET";
        res = await fetchWithTimeout(current, { method: "GET", redirect: "manual", headers: { "user-agent": UA, range: "bytes=0-0" }, credentials: "omit", signal }, 8000);
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
      const g = await resolveAndGuard(next.hostname, signal);
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
  guard: { ok: boolean; ips: string[]; dnsFailed?: boolean; nxdomain?: boolean },
  emailClaim: boolean,
  signal?: AbortSignal,
  publish: (data: { checks: Check[]; signals: Signal[]; dns: TechnicalDetails["dns"]; rdap: TechnicalDetails["rdap"]; tls: TechnicalDetails["tls"] }) => void = () => {},
) {
  const checks: Check[] = [];
  const signals: Signal[] = [];
  let dns: TechnicalDetails["dns"] = null;
  let rdap: TechnicalDetails["rdap"] = null;
  let tls: TechnicalDetails["tls"] = null;

  if (expandIpV4Literal(host) || host.startsWith("[")) {
    checks.push({ name: "Domain registration (RDAP)", status: "skipped", source: "rdap", note: "IP address, no domain" });
    publish({ checks: checks.splice(0), signals: signals.splice(0), dns, rdap, tls });
    return { checks, signals, dns, rdap, tls };
  }

  // DNS
  const types = ["A", "AAAA", "MX", "NS", "TXT"] as const;
  const rdapPromise = lookupRdap(reg, signal);
  const tlsPromise = guard.nxdomain ? Promise.resolve(null) : withRetry(() => fetchWithTimeout(`https://crt.sh/?q=${encodeURIComponent(reg)}&output=json&exclude=expired`, { signal }, 8000)).catch(() => null);
  const results = await Promise.all(types.map((t) => doh(t === "MX" || t === "NS" || t === "TXT" ? reg : host, t, signal)));
  if (results.every((r) => r === null)) {
    checks.push({ name: "DNS records", status: "unavailable", source: "dns", note: "DNS-over-HTTPS lookup did not respond" });
  } else {
    const records = results.flatMap((r, i) => (r?.Answer ?? []).map((a) => ({ type: types[i], value: a.data.slice(0, 200) })));
    dns = { records: records.slice(0, 30), source: "Cloudflare DNS-over-HTTPS" };
    checks.push({ name: "DNS records", status: "completed", source: "dns", note: guard.nxdomain ? NONEXISTENT_NOTE : undefined });
    if (guard.nxdomain) signals.push(makeSignal("domain_unresolvable", { found: `${host}: ${NONEXISTENT_NOTE}` }));
    const mx = results[2]?.Answer ?? [];
    if (emailClaim && mx.length === 0) signals.push(makeSignal("dns_no_mx_for_email_claim", { found: `${reg} publishes no mail servers.` }));
  }

  publish({ checks: checks.splice(0), signals: signals.splice(0), dns, rdap, tls });
  // RDAP
  const r = await rdapPromise;
  if (r.kind === "unavailable") {
    rdap = { status: "unavailable" };
    checks.push({ name: "Domain registration (RDAP)", status: "unavailable", source: "rdap", note: r.reason });
  } else if (r.kind === "none") {
    rdap = { status: "no record" };
    checks.push({ name: "Domain registration (RDAP)", status: "completed", source: "rdap", note: "No registration record found" });
  } else {
    const j = r.data;
    const created = j.events?.find((e) => e.eventAction === "registration")?.eventDate;
    const registrarEnt = j.entities?.find((e) => e.roles?.includes("registrar"));
    const vcard = registrarEnt?.vcardArray?.[1] as unknown[] | undefined;
    const fn = (vcard?.find((x) => Array.isArray(x) && x[0] === "fn") as unknown[] | undefined)?.[3] as string | undefined;
    const ageDays = created ? Math.floor((Date.now() - new Date(created).getTime()) / 86400000) : null;
    rdap = { registrar: fn, created, ageDays, status: "ok" };
    checks.push({ name: "Domain registration (RDAP)", status: "completed", source: "rdap", note: created ? undefined : "No registration date published" });
    if (ageDays !== null && ageDays < 30) {
      signals.push(makeSignal("domain_very_new", { found: `${reg} was registered ${ageDays} days ago (${created?.slice(0, 10)}).`, status: "info" }));
    } else if (ageDays !== null && ageDays < 90) {
      signals.push(makeSignal("domain_new", { found: `${reg} was registered ${ageDays} days ago (${created?.slice(0, 10)}).`, status: "info" }));
    }
    const raw = JSON.stringify(j).toLowerCase();
    if (raw.includes("redacted for privacy") || (raw.includes("privacy") && raw.includes("proxy"))) {
      signals.push(makeSignal("registrar_privacy_hidden", { found: "Registrant details are redacted.", status: "info" }));
    }
  }

  publish({ checks: checks.splice(0), signals: signals.splice(0), dns, rdap, tls });
  // TLS: not applicable to a domain that does not resolve
  if (guard.nxdomain) {
    tls = { status: "not applicable" };
    checks.push({ name: "TLS certificate history", status: "completed", source: "crtsh", note: NONEXISTENT_NOTE, excludeFromCoverage: true });
    publish({ checks: checks.splice(0), signals: signals.splice(0), dns, rdap, tls });
    return { checks, signals, dns, rdap, tls };
  }

  // TLS via Certificate Transparency
  try {
    const res = await tlsPromise;
    if (!res || !res.ok) throw new Error("certificate_unavailable");
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
    checks.push({ name: "TLS certificate history", status: "completed", source: "crtsh", note: "HTTPS does not indicate that a site is trustworthy.", excludeFromCoverage: true });
  } catch {
    tls = { status: "unavailable" };
    checks.push({ name: "TLS certificate history", status: "unavailable", source: "crtsh", note: "Certificate log (crt.sh) did not respond in time; not counted in coverage", excludeFromCoverage: true });
  }

  publish({ checks: checks.splice(0), signals: signals.splice(0), dns, rdap, tls });
  return { checks, signals, dns, rdap, tls };
}

async function threatIntel(url: string, host: string, signal?: AbortSignal, publish: (data: { checks: Check[]; signals: Signal[]; verdicts: TechnicalDetails["threatIntel"] }) => void = () => {}) {
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

  const tasks: Promise<void>[] = [];
  tasks.push((async () => {
  // Google Safe Browsing
  const sb = process.env["SAFE_BROWSING_API_KEY"];
  if (!sb) {
    checks.push({ name: "Google Safe Browsing", status: "unavailable", source: "safe_browsing", note: "Not configured" });
    verdicts.push({ name: "Google Safe Browsing", verdict: "unavailable", source: "safe_browsing" });
  } else {
    try {
      const res = await withRetry(() => fetchWithTimeout(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(sb)}`,
        {
          method: "POST", signal,
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
        8000,
      ));
      if (!res.ok) throw new Error(String(res.status));
      const j = (await res.json()) as { matches?: { threatType: string }[] };
      if (j.matches?.length) {
        hit("safe_browsing", "Google Safe Browsing", `Listed as ${j.matches.map((m) => m.threatType.toLowerCase().replace(/_/g, " ")).join(", ")}.`);
        verdicts.push({ name: "Google Safe Browsing", verdict: "listed", source: "safe_browsing" });
      } else verdicts.push({ name: "Google Safe Browsing", verdict: "not listed", source: "safe_browsing" });
      checks.push({ name: "Google Safe Browsing", status: "completed", source: "safe_browsing" });
    } catch {
      checks.push({ name: "Google Safe Browsing", status: "unavailable", source: "safe_browsing", note: "The service did not respond" });
      verdicts.push({ name: "Google Safe Browsing", verdict: "unavailable", source: "safe_browsing" });
    }
  }

  publish({ checks: checks.splice(0), signals: signals.splice(0), verdicts: verdicts.splice(0) });
  })());
  tasks.push((async () => {
  // URLhaus
  const uh = process.env["URLHAUS_AUTH_KEY"];
  if (!uh) {
    checks.push({ name: "URLhaus", status: "unavailable", source: "urlhaus", note: "Not configured" });
    verdicts.push({ name: "URLhaus", verdict: "unavailable", source: "urlhaus" });
  } else {
    try {
      const res = await withRetry(async () => {
        const r = await fetchWithTimeout(
          "https://urlhaus-api.abuse.ch/v1/url/",
          { method: "POST", signal, headers: { "Auth-Key": uh, "content-type": "application/x-www-form-urlencoded" }, body: `url=${encodeURIComponent(url)}` },
          10000,
        );
        if (!r.ok) throw new Error(String(r.status));
        return r;
      });
      const j = (await res.json()) as { query_status: string; threat?: string };
      if (j.query_status === "ok") {
        hit("urlhaus", "URLhaus", `Listed as ${j.threat ?? "malicious"}.`);
        verdicts.push({ name: "URLhaus", verdict: "listed", source: "urlhaus" });
      } else verdicts.push({ name: "URLhaus", verdict: "not listed", source: "urlhaus" });
      checks.push({ name: "URLhaus", status: "completed", source: "urlhaus" });
    } catch {
      checks.push({ name: "URLhaus", status: "unavailable", source: "urlhaus", note: "The service did not respond" });
      verdicts.push({ name: "URLhaus", verdict: "unavailable", source: "urlhaus" });
    }
  }

  publish({ checks: checks.splice(0), signals: signals.splice(0), verdicts: verdicts.splice(0) });
  })());
  tasks.push((async () => {
  // PhishTank (optional)
  const pt = process.env["PHISHTANK_API_KEY"];
  if (pt) {
    try {
      const res = await fetchWithTimeout(
        "https://checkurl.phishtank.com/checkurl/",
        { method: "POST", signal, headers: { "content-type": "application/x-www-form-urlencoded", "user-agent": "phishtank/second-look" }, body: `url=${encodeURIComponent(url)}&format=json&app_key=${encodeURIComponent(pt)}` },
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
      checks.push({ name: "PhishTank", status: "unavailable", source: "phishtank", note: "The service did not respond" });
    }
  }

  publish({ checks: checks.splice(0), signals: signals.splice(0), verdicts: verdicts.splice(0) });
  })());
  tasks.push((async () => {
  // VirusTotal (optional, domain reputation)
  const vt = process.env["VIRUSTOTAL_API_KEY"];
  if (vt) {
    try {
      const res = await fetchWithTimeout(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(registrableDomain(host))}`, { signal, headers: { "x-apikey": vt } }, 8000);
      if (!res.ok) throw new Error(String(res.status));
      const j = (await res.json()) as { data?: { attributes?: { last_analysis_stats?: { malicious?: number } } } };
      const mal = j.data?.attributes?.last_analysis_stats?.malicious ?? 0;
      if (mal >= 2) {
        hit("virustotal", "VirusTotal", `${mal} security vendors flagged this domain.`);
        verdicts.push({ name: "VirusTotal", verdict: `${mal} vendors flagged`, source: "virustotal" });
      } else verdicts.push({ name: "VirusTotal", verdict: mal === 1 ? "1 vendor flagged" : "not flagged", source: "virustotal" });
      checks.push({ name: "VirusTotal", status: "completed", source: "virustotal" });
    } catch {
      checks.push({ name: "VirusTotal", status: "unavailable", source: "virustotal", note: "The service did not respond" });
    }
  }

  publish({ checks: checks.splice(0), signals: signals.splice(0), verdicts: verdicts.splice(0) });
  })());
  await Promise.allSettled(tasks);
  return { checks, signals, verdicts };
}

/** Run once, retry once on failure. */
async function withRetry<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch {
    return await fn();
  }
}

/** Hostname that cannot be a real public domain (OCR fragment, missing TLD). */
export function isMalformedHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (h.startsWith("[") || /^[\d.]+$/.test(h)) return false;
  if (!h.includes(".") || h.endsWith("-") || h.startsWith("-")) return true;
  const labels = h.split(".");
  if (labels.some((l) => !l || l.startsWith("-") || l.endsWith("-"))) return true;
  const tld = labels[labels.length - 1];
  return !(/^[a-z]{2,63}$/.test(tld) || /^xn--[a-z0-9-]+$/.test(tld));
}

type RdapJson = {
  events?: { eventAction: string; eventDate: string }[];
  entities?: { roles?: string[]; vcardArray?: unknown[] }[];
};

let ianaCache: { at: number; services: [string[], string[]][] } | null = null;

async function rdapBaseFor(tld: string, signal?: AbortSignal): Promise<string | null> {
  try {
    if (!ianaCache || Date.now() - ianaCache.at > 6 * 3600_000) {
      const res = await fetchWithTimeout("https://data.iana.org/rdap/dns.json", { signal }, 8000);
      if (!res.ok) return null;
      const j = (await res.json()) as { services: [string[], string[]][] };
      ianaCache = { at: Date.now(), services: j.services };
    }
    const svc = ianaCache.services.find(([tlds]) => tlds.includes(tld));
    const base = svc?.[1].find((u) => u.startsWith("https://")) ?? svc?.[1][0];
    return base ? (base.endsWith("/") ? base : `${base}/`) : null;
  } catch {
    return null;
  }
}

/** RDAP via the IANA bootstrap server for the TLD, falling back to rdap.org. */
export async function lookupRdap(
  reg: string,
  signal?: AbortSignal,
): Promise<{ kind: "ok"; data: RdapJson } | { kind: "none" } | { kind: "unavailable"; reason: string }> {
  const tld = reg.split(".").pop() ?? "";
  const headers = { accept: "application/rdap+json, application/json" };
  const base = await rdapBaseFor(tld, signal);
  if (base) {
    try {
      const res = await fetchWithTimeout(`${base}domain/${encodeURIComponent(reg)}`, { headers, redirect: "follow", signal }, 8000);
      if (res.status === 404) return { kind: "none" };
      if (res.ok) return { kind: "ok", data: (await res.json()) as RdapJson };
    } catch {
      /* fall back */
    }
  }
  try {
    const res = await fetchWithTimeout(`https://rdap.org/domain/${encodeURIComponent(reg)}`, { headers, redirect: "follow", signal }, 8000);
    if (res.status === 404) return { kind: "none" };
    if (!res.ok) return { kind: "unavailable", reason: `Registration lookup returned an error (${res.status})` };
    return { kind: "ok", data: (await res.json()) as RdapJson };
  } catch {
    return { kind: "unavailable", reason: "Registration lookup did not respond in time" };
  }
}
