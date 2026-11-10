import { describe, expect, it, vi, afterEach } from "vitest";
import { buildReport, fallbackReport } from "@/lib/report-build";
import { checkCloudflareSecurity, cloudflareBlocked } from "@/lib/security-dns.server";
import { computeScore } from "@/shared/scoring";
import { SIGNALS } from "@/shared/signals.config";
import { urlHeuristics } from "@/lib/url-analysis.server";
import { coverageOf } from "@/lib/report-build";
import type { Signal } from "@/shared/types";

afterEach(() => vi.unstubAllGlobals());

describe("actionable verdicts", () => {
  it("returns caution when no threat database completed", () => {
    expect(buildReport({ kind: "url", inputDisplay: "test", signals: [], checks: [] }).classification).toBe("unverified");
  });
  it("returns low only with a clean feed and established resolving domain", () => {
    expect(buildReport({ kind: "url", inputDisplay: "test", signals: [], checks: [{ name: "Security DNS", source: "cloudflare_security", status: "completed" }], technical: { redirectChain: [], rawSignals: [], dns: { source: "dns", records: [{ type: "A", value: "93.184.216.34" }] }, rdap: { status: "ok", ageDays: 365 }, threatIntel: [{ name: "Security DNS", source: "cloudflare_security", verdict: "not listed" }] } }).classification).toBe("low");
  });
  it("error fallback has caution verdict and retry", () => {
    const report = fallbackReport("screenshot", "Text reading unavailable");
    expect(report.classification).toBe("unverified");
    expect(report.retryAvailable).toBe(true);
  });
});

describe("Cloudflare threat blocking", () => {
  it("detects zero address and extended blocking errors", () => {
    expect(cloudflareBlocked({ Status: 0, Answer: [{ type: 1, data: "0.0.0.0" }] })).toBe(true);
    expect(cloudflareBlocked({ Status: 3, EDE: [{ info_code: 15, extra_text: "Phishing" }] })).toBe(true);
    expect(cloudflareBlocked({ Status: 3 })).toBe(false);
  });
  it("confirmed security DNS hit forces score 85", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ Status: 0, Answer: [{ type: 1, data: "0.0.0.0" }] }))));
    const result = await checkCloudflareSecurity("phishing.test");
    expect(result.checks[0].status).toBe("completed");
    expect(computeScore(result.signals).score).toBe(85);
  });
});

const signal = (id: string): Signal => ({ id, ...SIGNALS[id], source: "rules", status: "suspicious", confidence: 1, found: "test" });
describe("unknown means caution", () => {
  it("NXDOMAIN adds exactly 15", () => expect(computeScore([signal("domain_unresolvable")]).score).toBe(15));
  it("new domain adds 15, and 30–90 days adds 8", () => {
    expect(computeScore([signal("domain_very_new")]).score).toBe(15);
    expect(computeScore([signal("domain_new")]).score).toBe(8);
  });
  it.each(["domain_unresolvable", "domain_very_new"])("%s plus urgency has minimum 50", (id) => expect(computeScore([signal(id), signal("urgency_pressure")]).score).toBe(50));
  it("nonexistent risky link is at least moderate", () => expect(computeScore([...urlHeuristics("https://secure-login-verify-account-xyz123.top"), signal("domain_unresolvable")]).score).toBeGreaterThanOrEqual(25));
  it("bonus checks never reduce core coverage", () => expect(coverageOf([{ name: "DNS", source: "dns", status: "completed" }, { name: "URLhaus", source: "urlhaus", status: "unavailable" }, { name: "Certificate", source: "crtsh", status: "unavailable" }]).ratio).toBe(1));
  it("required URL weights are retained", () => {
    expect(SIGNALS.deceptive_hostname_keywords.weight).toBe(10);
    expect(SIGNALS.suspicious_tld.weight).toBe(8);
    expect(SIGNALS.brand_lookalike_domain.weight).toBe(25);
    expect(SIGNALS.ip_literal_host.weight).toBe(20);
    expect(SIGNALS.url_shortener.weight).toBe(10);
    expect(SIGNALS.sender_name_mismatch.weight).toBe(10);
  });
});