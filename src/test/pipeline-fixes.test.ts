import { describe, expect, it, vi, afterEach } from "vitest";
import { buildReport, fallbackReport } from "@/lib/report-build";
import { checkCloudflareSecurity, cloudflareBlocked } from "@/lib/security-dns.server";
import { computeScore } from "@/shared/scoring";

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