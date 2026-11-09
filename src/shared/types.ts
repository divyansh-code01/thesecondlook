/**
 * Second Look® — shared types used by both the client UI and the server pipeline.
 * No secrets live here; this module is isomorphic.
 */

export type SignalCategory = "url" | "domain" | "message" | "screenshot";
export type SignalStatus = "confirmed" | "suspicious" | "info" | "unavailable";

export type Signal = {
  id: string;
  category: SignalCategory;
  status: SignalStatus;
  source: string;
  weight: number; // catalogue points; negative only for mitigations
  confidence: number; // 0..1
  title: string;
  found: string;
  why: string;
  evidence?: string;
};

export type CheckStatus = "completed" | "skipped" | "unavailable" | "failed";

export type Check = {
  name: string;
  status: CheckStatus;
  source: string;
  note?: string;
  excludeFromCoverage?: boolean;
};

export type StageStatus = "pending" | "running" | "done" | "skipped" | "unavailable";

export type Stage = {
  id: string;
  label: string;
  status: StageStatus;
  started_at?: string;
  ended_at?: string;
  note?: string;
};

export type RedirectHop = {
  from: string;
  to: string;
  status: number;
  method: string;
};

export type TechnicalDetails = {
  redirectChain: RedirectHop[];
  dns?: { records: { type: string; value: string }[]; source: string } | null;
  rdap?: { registrar?: string; created?: string; ageDays?: number | null; status: string } | null;
  tls?: { issuer?: string; firstSeen?: string; status: string } | null;
  threatIntel: { name: string; verdict: string; source: string }[];
  rawSignals: { id: string; weight: number; confidence: number; points: number }[];
};

export type ReportPayload = {
  kind: "url" | "screenshot";
  inputDisplay: string; // defanged, monospace-safe
  normalizedUrl?: string;
  defangedUrl?: string;
  finalUrl?: string;
  score: number;
  classification: string;
  coverage: number; // 0..1
  completedChecks: number;
  applicableChecks: number;
  signals: Signal[];
  checks: Check[];
  summary: string;
  extractedText?: string;
  technical?: TechnicalDetails;
  ocrConfidence?: number | null;
  appGuess?: string | null;
  senderLabel?: string | null;
  analysisNotes?: string[];
  demo?: boolean;
};

export const CLASSIFICATION_LABELS: Record<string, string> = {
  low: "LOW RISK",
  moderate: "MODERATE RISK",
  high: "HIGH RISK",
  critical: "CRITICAL RISK",
  insufficient: "INSUFFICIENT EVIDENCE",
};

export function classificationForScore(score: number): "low" | "moderate" | "high" | "critical" {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "moderate";
  return "low";
}

export function classificationColor(cls: string): string {
  switch (cls) {
    case "low":
      return "text-risk-low";
    case "moderate":
      return "text-risk-medium";
    case "high":
    case "critical":
      return "text-risk-high";
    default:
      return "text-grey-soft";
  }
}

export function defangUrl(url: string): string {
  return url.replace(/^http(s?):\/\//i, (_m, s: string) => `hxxp${s}://`).replace(/\./g, "[.]");
}
