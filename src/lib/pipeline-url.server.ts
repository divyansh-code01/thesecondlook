import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/integrations/supabase/types";
import { analyzeUrl } from "./url-analysis.server";
import { buildReport } from "./report-build";
import { createStageTracker, failJob, finishJob } from "./stages.server";

export async function runUrlPipeline(admin: SupabaseClient<Database>, jobId: string, url: string) {
  const tracker = await createStageTracker(admin, jobId);
  const a = await analyzeUrl(url, tracker.set);
  if (a.blocked) {
    for (const s of tracker.stages) if (s.status === "pending") await tracker.set(s.id, "skipped");
    await failJob(admin, jobId, "blocked_private");
    return;
  }
  await tracker.set("risk", "running");
  const report = buildReport({
    kind: "url",
    inputDisplay: a.defangedUrl,
    signals: a.signals,
    checks: a.checks,
    technical: a.technical,
    extra: { normalizedUrl: a.normalizedUrl, defangedUrl: a.defangedUrl, finalUrl: a.finalUrl },
  });
  await tracker.set("risk", "done");
  await finishJob(admin, jobId, report);
}
