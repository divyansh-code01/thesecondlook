import { useEffect, useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { toast } from "sonner";
import { z } from "zod";

import { deleteReport, getReport } from "@/lib/reports.functions";
import { ReportView } from "@/components/site/report-view";
import type { ReportPayload } from "@/shared/types";

export const Route = createFileRoute("/report/$id")({
  validateSearch: (s) => z.object({ token: z.string().optional() }).parse(s),
  head: () => ({
    meta: [
      { title: "Saved report — Second Look®" },
      { name: "description", content: "A saved Second Look scam-check report. Expires after 30 days." },
      { property: "og:title", content: "Second Look® saved report" },
      { property: "og:description", content: "An evidence-based scam-check report." },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: ReportPage,
});

function ReportPage() {
  const { id } = Route.useParams();
  const { token: freshToken } = Route.useSearch();
  const navigate = useNavigate();
  const get = useServerFn(getReport);
  const del = useServerFn(deleteReport);
  const [report, setReport] = useState<ReportPayload | null | undefined>(undefined);
  const [token, setToken] = useState<string | null>(null);
  const [expires, setExpires] = useState<string | null>(null);

  useEffect(() => {
    if (freshToken) localStorage.setItem(`sl-delete-${id}`, freshToken);
    setToken(localStorage.getItem(`sl-delete-${id}`));
    void get({ data: { id } }).then((r) => {
      if ("report" in r && r.report) {
        setReport(r.report.result as ReportPayload);
        setExpires(String(r.report.expires_at ?? ""));
      } else setReport(null);
    });
  }, [id, freshToken, get]);

  async function onDelete() {
    if (!token) return;
    const r = await del({ data: { id, token } });
    if (r.ok) {
      localStorage.removeItem(`sl-delete-${id}`);
      toast.success("Report deleted");
      navigate({ to: "/" });
    } else toast.error("Couldn't delete this report.");
  }

  if (report === undefined) return <main id="main" className="py-16 text-grey-mid">Loading report…</main>;
  if (report === null)
    return (
      <main id="main" className="py-16">
        <h1 className="heading-display text-[clamp(28px,3.4vw,48px)]">REPORT NOT FOUND <span className="tone-grey">OR EXPIRED.</span></h1>
        <Link to="/" className="btn-pill mt-8">Start a new check</Link>
      </main>
    );

  return (
    <main id="main">
      <div className="print-hidden mt-8 flex flex-wrap items-center gap-4 border border-line p-4 text-[13px]">
        <span className="text-grey-mid">Saved report{expires ? ` · expires ${new Date(expires).toLocaleDateString()}` : ""}</span>
        {freshToken && (
          <span className="font-mono text-[12px]">Delete code (copy it now): {freshToken}</span>
        )}
        {token && (
          <button type="button" className="btn-pill ml-auto" onClick={() => void onDelete()}>Delete this report now</button>
        )}
      </div>
      <ReportView report={report} />
    </main>
  );
}
