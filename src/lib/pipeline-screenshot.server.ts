import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/integrations/supabase/types";
import { SIGNALS } from "@/shared/signals.config";
import { extractPaymentIdentifiers, extractRefs, isPromptInjectionAttempt, stripControlChars, truncate } from "@/shared/sanitize";
import type { Check, Signal } from "@/shared/types";
import { defangUrl } from "@/shared/types";
import { AiUnavailableError, extractMessageSignals, runOcr, type OcrResult } from "./ai.server";
import { buildReport } from "./report-build";
import { govLinkMismatch, runMessageRules } from "@/shared/message-rules";
import { createStageTracker, failJob, finishJob } from "./stages.server";
import { analyzeUrl, isMalformedHost, makeSignal, urlHeuristics } from "./url-analysis.server";

const CONF = { low: 0.4, medium: 0.7, high: 1 } as const;

function sniff(b: Uint8Array): string | null {
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
  if (b[0] === 0x52 && b[1] === 0x49 && b[8] === 0x57 && b[9] === 0x45) return "image/webp";
  return null;
}

export async function runScreenshotPipeline(admin: SupabaseClient<Database>, jobId: string, uploadPath: string) {
  const tracker = await createStageTracker(admin, jobId);
  const checks: Check[] = [];
  const signals: Signal[] = [];
  let ocr: OcrResult | null = null;

  // Validate + OCR, always deleting the upload afterwards.
  try {
    await tracker.set("validate", "running");
    const { data: blob, error } = await admin.storage.from("uploads").download(uploadPath);
    if (error || !blob) {
      await failJob(admin, jobId, "missing_upload");
      return;
    }
    const bytes = new Uint8Array(await blob.arrayBuffer());
    const type = sniff(bytes);
    if (!type || bytes.length > 8 * 1024 * 1024) {
      await failJob(admin, jobId, "invalid_image");
      return;
    }
    await tracker.set("validate", "done");

    await tracker.set("ocr", "running");
    let bin = "";
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    try {
      ocr = await runOcr(`data:${type};base64,${btoa(bin)}`);
      checks.push({ name: "Text extraction (OCR)", status: "completed", source: "ai" });
    } catch (e) {
      const code = e instanceof AiUnavailableError ? e.code : "ocr_failed";
      await tracker.set("ocr", "unavailable", "Text reading service did not respond");
      await failJob(admin, jobId, code === "http_429" ? "rate_limited_ai" : code === "http_402" ? "ai_credits" : "ai_unavailable");
      return;
    }
  } finally {
    await admin.storage.from("uploads").remove([uploadPath]);
  }

  const text = stripControlChars(ocr.text ?? "").slice(0, 20000);
  if (text.trim().length < 3) {
    await tracker.set("ocr", "done");
    await failJob(admin, jobId, "no_text");
    return;
  }
  await tracker.set("ocr", "done");
  if ((ocr.ocr_confidence ?? 1) < 0.6) {
    signals.push(makeSignal("ocr_low_confidence", { found: "Parts of the screenshot were hard to read.", status: "info" }));
    checks.push({ name: "Readable text quality", status: "failed", source: "ai", note: "Low OCR confidence" });
  }

  // Regex extraction
  await tracker.set("extract", "running");
  const refs = extractRefs(text);
  const payments = extractPaymentIdentifiers(text);
  checks.push({ name: "Link, phone, email and payment extraction", status: "completed", source: "heuristic" });
  if (isPromptInjectionAttempt(text)) {
    signals.push(
      makeSignal("prompt_injection_attempt", {
        found: "The text contains instructions directed at an automated analyzer. We ignored them.",
        evidence: truncate(text.match(/[^\n]*(ignore|disregard|declare|system)[^\n]*/i)?.[0] ?? "", 160),
      }),
    );
  }
  if (payments.length) {
    signals.push(
      makeSignal("payment_request", {
        source: "heuristic",
        confidence: 0.5,
        found: `Payment identifiers found: ${payments.slice(0, 3).map((p) => p.kind).join(", ")}.`,
      }),
    );
  }
  // Deterministic message rules run first; AI can only add to them.
  const ruleSignals = runMessageRules(text, ocr.sender_label);
  signals.push(...ruleSignals, ...govLinkMismatch(text, refs.urls));
  checks.push({ name: "Message rule checks", status: "completed", source: "rules" });
  await tracker.set("extract", "done");

  // Links
  await tracker.set("links", "running");
  const notes: string[] = [];
  const candidates = refs.urls.slice(0, 5);
  const urls: string[] = [];
  for (const raw of candidates) {
    let host = "";
    try {
      host = new URL(raw).hostname;
    } catch {
      /* unparseable */
    }
    if (!host || isMalformedHost(host)) {
      notes.push(`${defangUrl(raw)}: Link looks incomplete or malformed and was not checked.`);
      try {
        for (const s of urlHeuristics(raw)) signals.push({ ...s, found: `${defangUrl(raw)}: ${s.found}` });
      } catch {
        /* not parseable at all */
      }
      continue;
    }
    urls.push(raw);
  }
  if (refs.urls.length > 5) notes.push(`${refs.urls.length - 5} more links were found but not checked.`);
  if (urls.length === 0) {
    await tracker.set("links", "skipped");
  } else {
    const results = await Promise.all(urls.map((u) => analyzeUrl(u).catch(() => null)));
    results.forEach((r, i) => {
      if (!r) {
        checks.push({ name: `Link check: ${defangUrl(urls[i])}`, status: "unavailable", source: "heuristic", note: "The link checks failed to run" });
        return;
      }
      if (r.blocked) {
        notes.push(
          r.blocked === "resolves_to_private_ip" || r.blocked === "private_or_reserved_ip"
            ? `${r.defangedUrl} points to a private network and was not checked.`
            : `${r.defangedUrl}: Link looks incomplete or malformed and was not checked.`,
        );
        return;
      }
      for (const s of r.signals) signals.push({ ...s, found: `${r.defangedUrl}: ${s.found}` });
      for (const c of r.checks) checks.push({ ...c, name: `${c.name} · ${r.defangedUrl}` });
    });
    await tracker.set("links", "done");
  }

  // AI message analysis (enum-only; quotes validated as substrings)
  await tracker.set("message", "running");
  try {
    const ai = await extractMessageSignals(text, ocr.sender_label);
    const seen = new Set<string>(signals.filter((x) => x.source === "rules").map((x) => x.id));
    for (const s of ai.signals) {
      const quote = s.quote.slice(0, 160);
      if (!quote || !text.includes(quote) || seen.has(s.id) || !SIGNALS[s.id]) continue;
      seen.add(s.id);
      const meta = SIGNALS[s.id];
      signals.push({
        id: s.id,
        category: meta.category,
        status: "suspicious",
        source: "ai",
        weight: meta.weight,
        confidence: CONF[s.confidence],
        title: meta.title,
        found: `“${quote}”`,
        why: meta.why,
        evidence: quote,
      });
    }
    checks.push({ name: "Message wording analysis", status: "completed", source: "ai" });
    await tracker.set("message", "done");
  } catch {
    checks.push({ name: "Message wording analysis", status: "unavailable", source: "ai", note: "The AI wording check did not respond; rule checks still ran" });
    await tracker.set("message", "unavailable", "AI wording check did not respond");
  }

  await tracker.set("risk", "running");
  const report = buildReport({
    kind: "screenshot",
    inputDisplay: `Screenshot${ocr.app_guess ? ` (${truncate(ocr.app_guess, 40)})` : ""}`,
    signals,
    checks,
    extra: {
      extractedText: text,
      ocrConfidence: ocr.ocr_confidence ?? null,
      appGuess: ocr.app_guess,
      senderLabel: ocr.sender_label,
      analysisNotes: notes,
    },
  });
  await tracker.set("risk", "done");
  await finishJob(admin, jobId, report);
}
