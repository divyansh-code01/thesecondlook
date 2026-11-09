import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database, Json } from "@/integrations/supabase/types";
import type { Stage, StageStatus } from "@/shared/types";

type Admin = SupabaseClient<Database>;

/** Tracks real stage progress on the jobs row so the UI reflects backend state. */
export async function createStageTracker(admin: Admin, jobId: string) {
  const { data } = await admin.from("jobs").select("stages").eq("id", jobId).single();
  const stages = ((data?.stages as unknown as Stage[]) ?? []).map((s) => ({ ...s }));

  async function persist() {
    await admin
      .from("jobs")
      .update({ stages: stages as unknown as Json, updated_at: new Date().toISOString() })
      .eq("id", jobId);
  }

  async function set(id: string, status: StageStatus, note?: string) {
    const s = stages.find((x) => x.id === id);
    if (!s) return;
    s.status = status;
    if (note) s.note = note;
    const now = new Date().toISOString();
    if (status === "running") s.started_at = now;
    else {
      s.started_at ??= now;
      s.ended_at = now;
    }
    await persist();
  }

  return { set, stages };
}

export async function finishJob(admin: Admin, jobId: string, result: unknown) {
  await admin
    .from("jobs")
    .update({ status: "done", result: result as Json, updated_at: new Date().toISOString() })
    .eq("id", jobId);
}

export async function failJob(admin: Admin, jobId: string, code: string) {
  await admin
    .from("jobs")
    .update({ status: "error", error_code: code, updated_at: new Date().toISOString() })
    .eq("id", jobId);
}

export async function fetchWithTimeout(url: string, init: RequestInit = {}, ms = 4000): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}
