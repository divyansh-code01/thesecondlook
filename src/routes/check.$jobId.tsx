import { useEffect, useRef, useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { toast } from "sonner";

import { getJobStatus, runAnalysis } from "@/lib/jobs.functions";
import { saveReport } from "@/lib/reports.functions";
import { ReportView } from "@/components/site/report-view";
import { DEMO_REPORT } from "@/shared/demo";
import type { ReportPayload, Stage } from "@/shared/types";

export const Route = createFileRoute("/check/$jobId")({
  head: () => ({
    meta: [
      { title: "Checking… — Second Look®" },
      { name: "description", content: "Your Second Look analysis is in progress." },
      { property: "og:title", content: "Second Look® analysis" },
      { property: "og:description", content: "Evidence-based scam check in progress." },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: CheckPage,
});

type Job = { status: string; stages: Stage[]; result: ReportPayload | null; error_code: string | null; type: string };

const ERRORS: Record<string, string> = {
  no_text: "We couldn't find readable text. Try a sharper, uncropped screenshot.",
  invalid_image: "That file isn't a readable PNG, JPG or WebP image.",
  missing_upload: "The screenshot didn't reach us. Please upload it again.",
  blocked_private: "That link points to a private or internal network, so it was blocked. No request was made to it.",
  rate_limited_ai: "The analyzer is rate limited right now. Please try again in a minute.",
  ai_credits: "The text-reading service is temporarily unavailable for this app.",
  ai_unavailable: "The text-reading service is unavailable right now, so the screenshot couldn't be analyzed.",
  stale_run: "The analysis stalled.",
  timeout: "The analysis took too long and was stopped.",
  pipeline_failed: "Something went wrong on our side while analyzing.",
};

const GLYPH: Record<string, string> = { pending: "○", running: "◐", done: "●", skipped: "–", unavailable: "×" };

function CheckPage() {
  const { jobId } = Route.useParams();
  const navigate = useNavigate();
  const getStatus = useServerFn(getJobStatus);
  const run = useServerFn(runAnalysis);
  const save = useServerFn(saveReport);
  const [job, setJob] = useState<Job | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [timedOut, setTimedOut] = useState(false);
  const [saveState, setSaveState] = useState<"idle" | "saving" | "saved">("idle");
  const [demo, setDemo] = useState(false);
  const stopped = useRef(false);

  useEffect(() => {
    stopped.current = false;
    const started = Date.now();
    void run({ data: { jobId } }).catch(() => {});
    let t: ReturnType<typeof setTimeout>;
    const poll = async () => {
      if (stopped.current) return;
      try {
        const r = await getStatus({ data: { jobId } });
        if ("job" in r) {
          if (!r.job) return setNotFound(true);
          const j = r.job as unknown as Job;
          setJob(j);
          if (j.status === "done" || j.status === "error") return;
        }
      } catch {
        /* keep polling */
      }
      if (Date.now() - started > 120_000) return setTimedOut(true);
      t = setTimeout(poll, 1500);
    };
    void poll();
    return () => {
      stopped.current = true;
      clearTimeout(t);
    };
  }, [jobId, getStatus, run]);

  async function onSave() {
    setSaveState("saving");
    const r = await save({ data: { jobId } });
    if ("id" in r && r.id) {
      localStorage.setItem(`sl-delete-${r.id}`, r.deleteToken);
      setSaveState("saved");
      toast.success("Report saved for 30 days");
      navigate({ to: "/report/$id", params: { id: r.id }, search: { token: r.deleteToken } });
    } else {
      setSaveState("idle");
      toast.error("error" in r ? r.error : "Couldn't save");
    }
  }

  if (demo) return <ReportView report={DEMO_REPORT} />;

  if (job?.status === "done" && job.result) {
    return <ReportView report={job.result} onSave={onSave} saveState={saveState} />;
  }

  const errorCode = notFound ? "not_found" : timedOut ? "timeout" : job?.status === "error" ? job.error_code ?? "pipeline_failed" : null;

  return (
    <main id="main" className="py-16">
      <p className="micro-label">ANALYSIS</p>
      <h1 className="heading-display mt-4 text-[clamp(28px,3.4vw,48px)]">
        {errorCode ? "WE COULDN'T FINISH" : "TAKING A"}
        <br />
        <span className="tone-grey">{errorCode ? "THIS CHECK." : "SECOND LOOK."}</span>
      </h1>

      {errorCode ? (
        <div role="alert" className="mt-10 max-w-xl">
          <p className="text-[16px]">{notFound ? "This check could not be found or has expired." : ERRORS[errorCode] ?? ERRORS.pipeline_failed}</p>
          <div className="mt-6 flex flex-wrap gap-4">
            <Link to="/" className="btn-pill">Start over</Link>
            {(errorCode === "ai_unavailable" || errorCode === "ai_credits") && (
              <button type="button" className="link-arrow" onClick={() => setDemo(true)}>View a labeled sample report →</button>
            )}
          </div>
        </div>
      ) : (
        <ol aria-live="polite" className="mt-10 max-w-xl">
          {(job?.stages ?? []).map((s) => {
            const secs = s.started_at && s.ended_at ? ((new Date(s.ended_at).getTime() - new Date(s.started_at).getTime()) / 1000).toFixed(1) : null;
            return (
              <li key={s.id} className="flex items-center gap-4 border-t border-line py-4 text-[15px]">
                <span aria-hidden className={`w-4 font-mono ${s.status === "running" ? "animate-pulse" : ""}`}>{GLYPH[s.status]}</span>
                <span className={s.status === "pending" ? "text-grey-soft" : ""}>{s.label}</span>
                <span className="ml-auto text-[12px] uppercase text-grey-soft">{s.status}{secs ? ` · ${secs}s` : ""}</span>
              </li>
            );
          })}
          {!job && <li className="text-grey-mid">Starting…</li>}
        </ol>
      )}
      {!errorCode && (
        <button type="button" className="link-arrow mt-8" onClick={() => { stopped.current = true; navigate({ to: "/" }); }}>
          Cancel
        </button>
      )}
    </main>
  );
}
