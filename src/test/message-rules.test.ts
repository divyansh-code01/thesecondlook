import { describe, expect, it } from "vitest";
import { govLinkMismatch, runMessageRules } from "@/shared/message-rules";
import { extractRefs } from "@/shared/sanitize";
import { computeScore } from "@/shared/scoring";
import { urlHeuristics } from "@/lib/url-analysis.server";
import { buildReport } from "@/lib/report-build";

const DL_SCAM =
  "Driver License | Department of Public Safety. Office of the secretary of state. Starting 11/Aug/2021 all driver's license need to update. Follow the secure link and update your info: http://dl-secure-online.quest?=DriverLicenses32fN";

describe("rule-based message check (no AI)", () => {
  it("driver-license scam text scores HIGH RISK or above without AI", () => {
    const refs = extractRefs(DL_SCAM);
    expect(refs.urls.length).toBe(1);
    const signals = [
      ...runMessageRules(DL_SCAM),
      ...govLinkMismatch(DL_SCAM, refs.urls),
      ...urlHeuristics(refs.urls[0]),
    ];
    expect(signals.some((s) => s.source === "ai")).toBe(false);
    const ids = signals.map((s) => s.id);
    expect(ids).toEqual(expect.arrayContaining(["impersonation_org", "urgency_pressure", "credential_request", "link_text_mismatch", "suspicious_tld", "deceptive_hostname_keywords"]));
    const r = computeScore(signals);
    expect(r.score).toBeGreaterThanOrEqual(50);
    const report = buildReport({
      kind: "screenshot",
      inputDisplay: "test",
      signals,
      checks: [
        { name: "Message rule checks", status: "completed", source: "rules" },
        { name: "Message wording analysis", status: "unavailable", source: "ai" },
      ],
    });
    expect(["high", "critical"]).toContain(report.classification);
  });

  it("rule signals use source 'rules' and catalogue weights", () => {
    const s = runMessageRules("Final notice: your parcel is held, pay the delivery fee now. Contact us on Telegram.");
    for (const x of s) expect(x.source).toBe("rules");
    expect(s.map((x) => x.id)).toEqual(expect.arrayContaining(["urgency_pressure", "prize_or_lottery", "payment_request", "off_platform_move"]));
  });

  it("email sender emits sender_name_mismatch", () => {
    expect(runMessageRules("hello", "alerts@random-mail.co").map((s) => s.id)).toContain("sender_name_mismatch");
    expect(runMessageRules("hello", "+1 555 0100").map((s) => s.id)).not.toContain("sender_name_mismatch");
  });

  it("gov claim with a .gov link does not flag mismatch", () => {
    expect(govLinkMismatch("Department of Revenue notice", ["https://tax.ny.gov/pay"])).toHaveLength(0);
  });
});
