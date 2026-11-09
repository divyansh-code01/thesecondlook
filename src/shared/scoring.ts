/**
 * Second Look® — deterministic scoring (spec §7).
 * The LLM never outputs a score. This module is the only place scores are computed.
 */

import {
  AI_SIGNAL_CAP,
  CATEGORY_CAPS,
  MITIGATION_FLOOR,
  SIGNALS,
  THREAT_FEED_FLOOR,
} from "./signals.config";
import { classificationForScore } from "./types";
import type { Signal, SignalCategory } from "./types";

export function pointsFor(signal: Signal): number {
  if (signal.weight === 0) return 0;
  return Math.round(signal.weight * signal.confidence);
}

export type CategoryBreakdown = {
  category: SignalCategory;
  label: string;
  raw: number;
  capped: number;
  cap: number;
};

export type ScoreResult = {
  score: number;
  classification: "low" | "moderate" | "high" | "critical";
  categories: CategoryBreakdown[];
  aiPointsRaw: number;
  aiPointsCounted: number;
  aiCapApplied: boolean;
  mitigationPoints: number;
  mitigationFloorApplied: boolean;
  threatFeedFloorApplied: boolean;
  hasConfirmedThreatFeedHit: boolean;
  positivePoints: number;
  steps: string[];
};

export const CATEGORY_LABELS: Record<SignalCategory, string> = {
  url: "Link",
  domain: "Domain",
  message: "Message",
  screenshot: "Screenshot",
};

export function computeScore(signals: Signal[]): ScoreResult {
  // Points per signal, with AI-sourced signals limited to a shared budget
  // (deterministic: in the order signals are listed).
  let aiBudget = AI_SIGNAL_CAP;
  let aiPointsRaw = 0;
  const scored = signals
    .filter((s) => s.status !== "unavailable" && s.weight !== 0)
    .map((s) => {
      let points = pointsFor(s);
      if (s.source === "ai" && points > 0) {
        aiPointsRaw += points;
        points = Math.min(points, aiBudget);
        aiBudget -= points;
      }
      return { signal: s, points };
    });
  const aiPointsCounted = AI_SIGNAL_CAP - aiBudget;
  const aiCapApplied = aiPointsRaw > aiPointsCounted;

  const positivePoints = scored.filter((x) => x.points > 0).reduce((sum, x) => sum + x.points, 0);

  // Per-category sums, each capped at its maximum.
  const categories: CategoryBreakdown[] = (["url", "domain", "message", "screenshot"] as const).map(
    (category) => {
      const raw = scored
        .filter((x) => x.signal.category === category && x.points > 0)
        .reduce((sum, x) => sum + x.points, 0);
      const cap = CATEGORY_CAPS[category];
      return { category, label: CATEGORY_LABELS[category], raw, capped: Math.min(raw, cap), cap };
    },
  );
  const afterAiCap = categories.reduce((sum, c) => sum + c.capped, 0);

  // 3. Mitigations (negative points) reduce the score, never below the floor.
  const mitigationPoints = scored
    .filter((x) => x.points < 0)
    .reduce((sum, x) => sum + x.points, 0);
  let afterMitigation = afterAiCap + mitigationPoints;
  let mitigationFloorApplied = false;
  if (mitigationPoints < 0 && afterMitigation < MITIGATION_FLOOR && positivePoints > 0) {
    afterMitigation = MITIGATION_FLOOR;
    mitigationFloorApplied = true;
  }

  // 4. Any confirmed threat-feed hit forces a minimum score.
  const hasConfirmedThreatFeedHit = signals.some(
    (s) => s.id === "threat_feed_hit" && s.status === "confirmed",
  );
  const afterFloor = hasConfirmedThreatFeedHit
    ? Math.max(afterMitigation, THREAT_FEED_FLOOR)
    : afterMitigation;

  const score = Math.max(0, Math.min(100, Math.round(afterFloor)));

  const steps: string[] = [];
  for (const c of categories) {
    if (c.raw > 0) {
      steps.push(
        `${c.label}: ${c.raw} pts${c.capped < c.raw ? ` capped at ${c.capped} (max ${c.cap})` : ""}`,
      );
    }
  }
  if (aiCapApplied) steps.push(`AI-sourced signals capped at ${aiPointsCounted} pts`);
  if (mitigationPoints < 0) steps.push(`Mitigation: ${mitigationPoints} pts${mitigationFloorApplied ? ` (floor ${MITIGATION_FLOOR} applied)` : ""}`);
  if (hasConfirmedThreatFeedHit) steps.push(`Confirmed threat-feed hit: minimum ${THREAT_FEED_FLOOR} applied`);
  steps.push(`Final score: ${score} / 100`);

  return {
    score,
    classification: classificationForScore(score),
    categories,
    aiPointsRaw,
    aiPointsCounted,
    aiCapApplied,
    mitigationPoints,
    mitigationFloorApplied,
    threatFeedFloorApplied: hasConfirmedThreatFeedHit && afterMitigation < THREAT_FEED_FLOOR,
    hasConfirmedThreatFeedHit,
    positivePoints,
    steps,
  };
}

/**
 * Displayed classification. Evidence coverage under 50% caps the displayed
 * classification at INSUFFICIENT EVIDENCE unless a confirmed-malicious signal exists.
 */
export function effectiveClassification(
  result: ScoreResult,
  coverage: number,
): { label: string; key: string } {
  if (coverage < 0.5 && !result.hasConfirmedThreatFeedHit) {
    return { label: "INSUFFICIENT EVIDENCE", key: "insufficient" };
  }
  return { label: { low: "LOW RISK", moderate: "MODERATE RISK", high: "HIGH RISK", critical: "CRITICAL RISK" }[result.classification], key: result.classification };
}

export function signalMetaOrFallback(signal: Signal) {
  return SIGNALS[signal.id];
}
