/**
 * Builds the final report payload from signals + checks. Isomorphic, pure, tested.
 */
import { computeScore, effectiveClassification, pointsFor } from "@/shared/scoring";
import type { Check, ReportPayload, Signal, TechnicalDetails } from "@/shared/types";

export function coverageOf(checks: Check[]) {
  const applicable = checks.filter((c) => c.status !== "skipped");
  const completed = applicable.filter((c) => c.status === "completed");
  return {
    completed: completed.length,
    applicable: applicable.length,
    ratio: applicable.length ? completed.length / applicable.length : 0,
  };
}

export function buildSummary(cls: string, signals: Signal[], kind: "url" | "screenshot"): string {
  const top = signals
    .filter((s) => pointsFor(s) > 0)
    .sort((a, b) => pointsFor(b) - pointsFor(a))
    .slice(0, 2)
    .map((s) => s.title.toLowerCase());
  const subject = kind === "url" ? "this link" : "this message";
  switch (cls) {
    case "critical":
    case "high":
      return `We found strong warning signs in ${subject}${top.length ? `, including: ${top.join("; ")}` : ""}. Treat it as a likely scam and do not act on it.`;
    case "moderate":
      return `${subject[0].toUpperCase() + subject.slice(1)} shows some warning signs${top.length ? ` (${top.join("; ")})` : ""}. Don't act on it until you've verified it through an official channel you find yourself.`;
    case "low":
      return `No major threats were detected in the available checks. That is not a guarantee — verify the sender independently and avoid sharing sensitive information.`;
    default:
      return `Too few checks could run to give a reliable assessment of ${subject}. See which checks were unavailable below, and try again or add more context.`;
  }
}

export function buildReport(input: {
  kind: "url" | "screenshot";
  inputDisplay: string;
  signals: Signal[];
  checks: Check[];
  technical?: TechnicalDetails;
  extra?: Partial<ReportPayload>;
}): ReportPayload {
  const scoreResult = computeScore(input.signals);
  const cov = coverageOf(input.checks);
  const cls = effectiveClassification(scoreResult, cov.ratio);
  const technical: TechnicalDetails = input.technical ?? { redirectChain: [], threatIntel: [], rawSignals: [] };
  technical.rawSignals = input.signals.map((s) => ({ id: s.id, weight: s.weight, confidence: s.confidence, points: pointsFor(s) }));
  return {
    kind: input.kind,
    inputDisplay: input.inputDisplay,
    score: scoreResult.score,
    classification: cls.key,
    coverage: cov.ratio,
    completedChecks: cov.completed,
    applicableChecks: cov.applicable,
    signals: input.signals,
    checks: input.checks,
    summary: buildSummary(cls.key, input.signals, input.kind),
    technical,
    ...input.extra,
  };
}
