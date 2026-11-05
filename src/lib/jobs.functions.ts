import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

/**
 * Job lifecycle server functions. All privileged access (service role) is
 * loaded dynamically inside handlers; secrets never leave the server.
 */

const MAX_URL_LENGTH = 2048;

const createUploadTargetInput = z.object({}).strict();

export const createUploadTarget = createServerFn({ method: "POST" })
  .inputValidator((input) => createUploadTargetInput.parse(input ?? {}))
  .handler(async () => {
    const { getSupabaseAdmin } = await import("./supabase.server");
    const admin = getSupabaseAdmin();
    const path = `${crypto.randomUUID()}/${Date.now().toString(36)}.png`;
    const { data, error } = await admin.storage.from("uploads").createSignedUploadUrl(path, 600);
    if (error || !data) {
      return { error: "upload_target_failed" as const };
    }
    return { path: data.path, token: data.token, signedUrl: data.signed_url };
  });

const createJobInput = z
  .object({
    kind: z.enum(["url", "screenshot"]),
    url: z.string().max(MAX_URL_LENGTH).optional(),
    uploadPath: z.string().max(300).optional(),
    uploadToken: z.string().max(2000).optional(),
    fileName: z.string().max(200).optional(),
    fileSize: z.number().int().nonnegative().max(8 * 1024 * 1024).optional(),
    honeypot: z.string().max(200).optional(),
  })
  .strict();

export type CreateJobResult =
  | { jobId: string }
  | { error: string; message: string; retryAfterSeconds?: number }
  | { demoJobId: string };

export const createJob = createServerFn({ method: "POST" })
  .inputValidator((input) => createJobInput.parse(input))
  .handler(async ({ data }): Promise<CreateJobResult> => {
    const { getSupabaseAdmin } = await import("./supabase.server");
    const { hashClientIp, checkAndCountRateLimit, globalConcurrencyCount } = await import("./ratelimit.server");
    const admin = getSupabaseAdmin();

    // Honeypot: a filled field is a bot. Reject without creating anything.
    if (data.honeypot && data.honeypot.trim().length > 0) {
      return { error: "rate_limited", message: "Too many requests from this network. Please try again later.", retryAfterSeconds: 600 };
    }

    // URL validation happens again server-side, strictly.
    let normalizedUrl: string | undefined;
    if (data.kind === "url") {
      const { validateSubmittedUrl } = await import("./url-validate.server");
      const v = validateSubmittedUrl(data.url ?? "");
      if (!v.ok) return { error: "invalid_url", message: v.message };
      normalizedUrl = v.normalized;
    }

    if (data.kind === "screenshot") {
      if (!data.uploadPath || !data.uploadToken) {
        return { error: "missing_upload", message: "The screenshot did not reach us. Please try uploading it again." };
      }
      const { data: stat, error: statError } = await admin.storage.from("uploads").list(data.uploadPath.split("/")[0], {
        search: data.uploadPath.split("/")[1] ?? "",
        limit: 1,
      });
      if (statError || !stat || stat.length === 0) {
        return { error: "missing_upload", message: "The screenshot did not reach us. Please try uploading it again." };
      }
    }

    // Rate limiting: 10/hour, 30/day per salted IP hash; global concurrency cap.
    const ip = await hashClientIp();
    const limit = await checkAndCountRateLimit(admin, ip);
    if (limit.exceeded) {
      return { error: "rate_limited", message: limit.message, retryAfterSeconds: limit.retryAfterSeconds };
    }
    const running = await globalConcurrencyCount(admin);
    if (running >= 3) {
      return { error: "busy", message: "The analyzer is busy right now. Please try again in a moment.", retryAfterSeconds: 60 };
    }

    const stages =
      data.kind === "url"
        ? [
            { id: "validate", label: "Validating and normalizing link", status: "pending" },
            { id: "threatintel", label: "Checking threat intelligence", status: "pending" },
            { id: "domain", label: "Examining the domain", status: "pending" },
            { id: "redirects", label: "Following redirects safely", status: "pending" },
            { id: "patterns", label: "Analyzing link patterns", status: "pending" },
            { id: "risk", label: "Calculating risk", status: "pending" },
          ]
        : [
            { id: "validate", label: "Validating image", status: "pending" },
            { id: "ocr", label: "Extracting text (OCR)", status: "pending" },
            { id: "extract", label: "Finding links, phone numbers, emails and payment details", status: "pending" },
            { id: "links", label: "Analyzing each extracted link", status: "pending" },
            { id: "message", label: "Analyzing message wording", status: "pending" },
            { id: "risk", label: "Calculating risk", status: "pending" },
          ];

    const expiresAt = new Date(Date.now() + 6 * 60 * 60 * 1000).toISOString(); // server cleans up earlier
    const { data: job, error } = await admin
      .from("jobs")
      .insert({
        type: data.kind,
        status: "queued",
        stages,
        expires_at: expiresAt,
        ip_hash: ip,
        ...(data.kind === "url" ? {} : {}),
      })
      .select("id")
      .single();

    if (error || !job) {
      return { error: "backend_failed", message: "The analyzer could not start. Please try again in a moment." };
    }
    return { jobId: job.id };
  });

const getJobInput = z.object({ jobId: z.string().uuid() }).strict();

export const getJobStatus = createServerFn({ method: "POST" })
  .inputValidator((input) => getJobInput.parse(input))
  .handler(async ({ data }) => {
    const { getSupabasePublishable } = await import("./supabase.server");
    const supabase = getSupabasePublishable();
    const { data: job, error } = await supabase.rpc("get_job", { job_id: data.jobId });
    if (error) {
      return { error: "backend_failed" as const };
    }
    return { job: (job as unknown) as Record<string, unknown> | null };
  });

const runAnalysisInput = z.object({ jobId: z.string().uuid() }).strict();

export const runAnalysis = createServerFn({ method: "POST" })
  .inputValidator((input) => runAnalysisInput.parse(input))
  .handler(async ({ data }) => {
    const { getSupabaseAdmin } = await import("./supabase.server");
    const admin = getSupabaseAdmin();

    const { data: job, error: jobError } = await admin
      .from("jobs")
      .select("id, type, status, expires_at")
      .eq("id", data.jobId)
      .single();

    if (jobError || !job) {
      return { error: "not_found" as const, message: "This job could not be found or has expired." };
    }

    if (job.status === "done") {
      return { alreadyDone: true as const };
    }

    if (job.status === "error") {
      return { alreadyFailed: true as const };
    }

    // Claim the job (also re-claims stale runs after 3 minutes).
    const { data: claimed, error: claimError } = await admin
      .from("jobs")
      .update({ status: "running", updated_at: new Date().toISOString() })
      .eq("id", data.jobId)
      .in("status", ["queued"])
      .select("id")
      .single();

    if (claimError || !claimed) {
      const { data: fresh } = await admin
        .from("jobs")
        .select("id, status, updated_at")
        .eq("id", data.jobId)
        .single();
      const staleAt = fresh ? new Date(fresh.updated_at).getTime() : 0;
      if (fresh?.status === "running" && Date.now() - staleAt > 180_000) {
        await admin.from("jobs").update({ status: "error", error_code: "stale_run" }).eq("id", data.jobId);
        return { error: "stale_run" as const, message: "The analysis stalled. Use Try again to restart it." };
      }
      // Someone else is running it (or it just finished) — the UI will pick up state by polling.
      return { inFlight: true as const };
    }

    try {
      if (job.type === "url") {
        const { runUrlPipeline } = await import("./pipeline-url.server");
        await runUrlPipeline(admin, data.jobId);
      } else {
        const { runScreenshotPipeline } = await import("./pipeline-screenshot.server");
        await runScreenshotPipeline(admin, data.jobId);
      }
    } catch (e) {
      await admin
        .from("jobs")
        .update({ status: "error", error_code: "pipeline_failed", updated_at: new Date().toISOString() })
        .eq("id", data.jobId);
      // Log only job id and error code — never submitted text, URLs or images.
      console.error("pipeline_failed", { jobId: data.jobId, code: e instanceof Error ? e.name : "unknown" });
      return { error: "pipeline_failed" as const, message: "The analysis could not complete. Please try again." };
    }

    return { done: true as const };
  });
