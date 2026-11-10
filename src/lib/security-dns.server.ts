import type { Check, Signal } from "@/shared/types";
import { SIGNALS } from "@/shared/signals.config";
import { fetchWithTimeout } from "./stages.server";

export type DnsResponse = { Status: number; Answer?: { type: number; data: string }[]; Comment?: string; EDE?: { info_code?: number; extra_text?: string }[] };

export async function queryDns(endpoint: string, host: string, type = "A", signal?: AbortSignal): Promise<DnsResponse> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const response = await fetchWithTimeout(`${endpoint}?name=${encodeURIComponent(host)}&type=${type}`, { signal, headers: { accept: "application/dns-json" } }, 8000);
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

export async function checkCloudflareSecurity(host: string, signal?: AbortSignal): Promise<{ checks: Check[]; signals: Signal[]; verdicts: { name: string; verdict: string; source: string }[] }> {
  const name = "Cloudflare security DNS";
  const source = "cloudflare_security";
  try {
    const data = await queryDns("https://security.cloudflare-dns.com/dns-query", host, "A", signal);
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

export async function checkQuad9(host: string, baseline: Promise<{ ips: string[]; ok: boolean }>, signal?: AbortSignal) {
  const source = "quad9";
  const name = "Quad9 threat blocking";
  try {
    // Quad9's native endpoint uses RFC8484 wire format, not DNS JSON.
    const labels = host.replace(/\.$/, "").split(".");
    const bytes = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...labels.flatMap((l) => [l.length, ...new TextEncoder().encode(l)]), 0, 0, 1, 0, 1];
    let data: Uint8Array | undefined;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const response = await fetchWithTimeout("https://dns.quad9.net/dns-query", { method: "POST", headers: { accept: "application/dns-message", "content-type": "application/dns-message" }, body: new Uint8Array(bytes), signal }, 8000);
        if (!response.ok) throw new Error("quad9_failed");
        data = new Uint8Array(await response.arrayBuffer());
        if (data.length < 12 || ![0, 3].includes(data[3] & 15)) throw new Error("quad9_failed");
        break;
      } catch (error) { if (attempt === 1) throw error; }
    }
    if (!data) throw new Error("quad9_failed");
    const base = await baseline;
    const blocked = (data[3] & 15) === 3 && base.ok && base.ips.length > 0;
    return { checks: [{ name, source, status: "completed" as const }], signals: blocked ? [{ id: "threat_feed_hit", ...SIGNALS.threat_feed_hit, source, status: "confirmed" as const, confidence: 1, title: "Blocked by Quad9 threat blocking", found: `${host} resolves on Cloudflare DNS but is blocked by Quad9.` }] : [], verdicts: [{ name, source, verdict: blocked ? "listed" : (data[3] & 15) === 3 ? "unknown" : "not listed" }] };
  } catch {
    return { checks: [{ name, source, status: "unavailable" as const, note: "Quad9 did not respond after a retry" }], signals: [], verdicts: [{ name, source, verdict: "unavailable" }] };
  }
}