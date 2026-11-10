import type { Check, Signal } from "@/shared/types";
import { SIGNALS } from "@/shared/signals.config";
import { fetchWithTimeout } from "./stages.server";

export type DnsResponse = { Status: number; Answer?: { type: number; data: string }[]; Comment?: string; EDE?: { info_code?: number; extra_text?: string }[] };

export async function queryDns(endpoint: string, host: string, type = "A"): Promise<DnsResponse> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const response = await fetchWithTimeout(`${endpoint}?name=${encodeURIComponent(host)}&type=${type}`, { headers: { accept: "application/dns-json" } }, 8000);
      if (!response.ok) throw new Error("dns_service_unavailable");
      const data = await response.json() as DnsResponse;
      if (typeof data.Status !== "number" || ![0, 3].includes(data.Status)) throw new Error("dns_lookup_failed");
      return data;
    } catch (error) {
      if (attempt === 1) throw error;
    }
  }
  throw new Error("dns_lookup_failed");
}

export function cloudflareBlocked(data: DnsResponse): boolean {
  return Boolean(data.Answer?.some((a) => a.data === "0.0.0.0" || a.data === "::") ||
    data.EDE?.some((e) => [15, 16, 17, 18].includes(e.info_code ?? -1) || /blocked|malware|phishing/i.test(e.extra_text ?? "")) ||
    /blocked|malware|phishing/i.test(data.Comment ?? ""));
}

export async function checkCloudflareSecurity(host: string): Promise<{ checks: Check[]; signals: Signal[]; verdicts: { name: string; verdict: string; source: string }[] }> {
  const name = "Cloudflare security DNS";
  const source = "cloudflare_security";
  try {
    const data = await queryDns("https://security.cloudflare-dns.com/dns-query", host);
    const blocked = cloudflareBlocked(data);
    return {
      checks: [{ name, source, status: "completed", note: data.Status === 3 ? "Domain unknown to this resolver" : undefined }],
      signals: blocked ? [{ id: "threat_feed_hit", ...SIGNALS.threat_feed_hit, status: "confirmed", source, confidence: 1, title: "Blocked by Cloudflare security DNS", found: `${host} is blocked by Cloudflare's security resolver.` }] : [],
      verdicts: [{ name, source, verdict: blocked ? "listed" : data.Status === 3 ? "unknown" : "not listed" }],
    };
  } catch {
    return { checks: [{ name, source, status: "unavailable", note: "Security DNS did not respond after a retry" }], signals: [], verdicts: [{ name, source, verdict: "unavailable" }] };
  }
}