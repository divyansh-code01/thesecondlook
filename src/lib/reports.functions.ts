import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

export const saveReport = createServerFn({ method: "POST" })
  .inputValidator((i) => z.object({ jobId: z.string().uuid() }).strict().parse(i))
  .handler(async ({ data }) => {
    const { getSupabaseAdmin } = await import("./supabase.server");
    const admin = getSupabaseAdmin();
    const { data: job } = await admin.from("jobs").select("status, result, type").eq("id", data.jobId).single();
    if (!job || job.status !== "done" || !job.result) return { error: "This report can't be saved." };
    const r = job.result as Record<string, unknown>;
    if (r.demo) return { error: "Demo reports are never saved." };
    // Saved reports never contain the extracted text or screenshot (spec §9).
    const { extractedText: _drop, ...stored } = r;
    void _drop;
    const tokenBytes = crypto.getRandomValues(new Uint8Array(24));
    const token = Array.from(tokenBytes, (b) => b.toString(16).padStart(2, "0")).join("");
    const hashBuf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
    const hash = Array.from(new Uint8Array(hashBuf), (b) => b.toString(16).padStart(2, "0")).join("");
    const { data: row, error } = await admin
      .from("reports")
      .insert({
        input_kind: job.type,
        input_display: String(r.inputDisplay ?? "").slice(0, 500),
        score: Number(r.score ?? 0),
        classification: String(r.classification ?? ""),
        coverage: Number(r.coverage ?? 0),
        signals: (r.signals ?? []) as never,
        checks: (r.checks ?? []) as never,
        summary: String(r.summary ?? ""),
        result: stored as never,
        delete_token_hash: hash,
        expires_at: new Date(Date.now() + 30 * 86400000).toISOString(),
      })
      .select("id")
      .single();
    if (error || !row) return { error: "The report couldn't be saved. Please try again." };
    return { id: row.id, deleteToken: token };
  });

export const getReport = createServerFn({ method: "POST" })
  .inputValidator((i) => z.object({ id: z.string().uuid() }).strict().parse(i))
  .handler(async ({ data }) => {
    const { getSupabasePublishable } = await import("./supabase.server");
    const { data: r, error } = await getSupabasePublishable().rpc("get_report", { report_id: data.id });
    if (error) return { error: "backend" as const };
    return { json: r ? JSON.stringify(r) : null };
  });

export const deleteReport = createServerFn({ method: "POST" })
  .inputValidator((i) => z.object({ id: z.string().uuid(), token: z.string().min(10).max(200) }).strict().parse(i))
  .handler(async ({ data }) => {
    const { getSupabasePublishable } = await import("./supabase.server");
    const { data: ok } = await getSupabasePublishable().rpc("delete_report", { report_id: data.id, token: data.token });
    return { ok: ok === true };
  });
