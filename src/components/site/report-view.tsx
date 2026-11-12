import { useMemo, useState } from "react";
import { Link } from "@tanstack/react-router";
import { ChevronDown, Copy } from "lucide-react";
import { toast } from "sonner";

import { computeScore, pointsFor, CATEGORY_LABELS } from "@/shared/scoring";
import { CLASSIFICATION_LABELS, classificationColor } from "@/shared/types";
import type { ReportPayload, Signal } from "@/shared/types";
import { defangForDisplay } from "@/shared/sanitize";
import { buildReport } from "@/lib/report-build";
import { Button } from "@/components/ui/button";

const DISCLAIMER =
  "This is an automated assessment based on the checks listed above. It is not a guarantee. When in doubt, contact the organization using details you find independently.";

function actionsFor(cls: string): string[] {
  void cls;
  return [
      "Don't click the link or reply to the message.",
      "Look up the organization's official website or phone number yourself and contact them.",
      "Never share OTPs, passwords or card details.",
      "Report it to your national cybercrime service, and to your bank or the company being impersonated.",
      "If you already clicked or shared something: change your passwords and contact your bank straight away.",
    ];
}

function Tag({ s }: { s: Signal }) {
  const cls =
    s.status === "confirmed" ? "tag tag-confirmed" : s.status === "suspicious" ? "tag tag-suspicious" : s.status === "unavailable" ? "tag tag-unavailable" : "tag";
  return <span className={cls}>{s.status}</span>;
}

function Accordion({ title, children }: { title: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border-t border-line">
      <button type="button" aria-expanded={open} className="flex w-full items-center justify-between py-5 text-left" onClick={() => setOpen((v) => !v)}>
        <span className="heading-display text-[15px]">{title}</span>
        <ChevronDown className={`size-4 transition-transform ${open ? "rotate-180" : ""}`} strokeWidth={1} aria-hidden />
      </button>
      <div className={open ? "pb-6" : "hidden print-block"}>{children}</div>
    </div>
  );
}

export function ReportView({ report: originalReport, onSave, saveState, analyzeAnotherHref = "/" }: {
  report: ReportPayload;
  onSave?: () => void;
  saveState?: "idle" | "saving" | "saved";
  analyzeAnotherHref?: string;
}) {
  const report = useMemo(() => ({ ...originalReport, ...buildReport({ kind: originalReport.kind, inputDisplay: originalReport.inputDisplay, signals: originalReport.signals, checks: originalReport.checks, technical: originalReport.technical }), }), [originalReport]);
  const [showAll, setShowAll] = useState(false);
  const calc = useMemo(() => computeScore(report.signals), [report.signals]);
  const label = CLASSIFICATION_LABELS[report.classification] ?? report.classification;
  const color = classificationColor(report.classification);

  const findings = useMemo(
    () => [...report.signals].sort((a, b) => pointsFor(b) - pointsFor(a)),
    [report.signals],
  );
  const shown = showAll ? findings : findings.slice(0, 5);
  const grouped = (["url", "domain", "message", "screenshot"] as const)
    .map((c) => ({ c, items: shown.filter((s) => s.category === c) }))
    .filter((g) => g.items.length);

  function copySummary() {
    const lines = [
      `The SecondLook report — ${label} (${report.score}/100)`,
      `Input: ${report.inputDisplay}`,
      "",
      report.summary,
      "",
      "Top findings:",
      ...findings.slice(0, 5).map((s) => `- ${s.title}${pointsFor(s) ? ` (+${pointsFor(s)})` : ""}`),
      "",
      `Evidence coverage: ${report.completedChecks} of ${report.applicableChecks} checks completed.`,
      DISCLAIMER,
    ];
    void navigator.clipboard.writeText(lines.join("\n")).then(
      () => toast.success("Summary copied"),
      () => toast.error("Couldn't copy to the clipboard"),
    );
  }

  return (
    <article className="pt-10" data-testid="report">
      {report.demo && (
        <p role="status" className="mb-6 border border-risk-medium px-4 py-3 text-[13px] font-semibold uppercase tracking-wide text-risk-medium">
          DEMO MODE: sample data, not a real scan
        </p>
      )}
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <p className="micro-label">REPORT</p>
        <p className="micro-label">{new Date().toLocaleString()}</p>
      </div>
      <p className="mt-3 break-all font-mono text-[13px] text-grey-mid">{report.inputDisplay}</p>

      {/* Primary assessment */}
      <section className="mt-10 grid gap-10 border-t border-line pt-10 md:grid-cols-2" aria-live="polite">
        <div>
          <p className="heading-display text-[clamp(64px,10vw,128px)]">
            {report.score}
            <span className="tone-grey text-[0.3em]"> / 100</span>
          </p>
          <p className={`heading-display mt-3 text-[18px] ${color}`}>{label}</p>
          <p className="mt-4 text-[13px] text-grey-mid">No tool can catch every scam. If something feels wrong, contact the organization using details you find yourself.</p>
          <div className="relative mt-6 h-[2px] w-full bg-line" aria-hidden>
            {[25, 50, 75].map((t) => (
              <span key={t} className="absolute -top-1 h-2.5 w-px bg-line-strong" style={{ left: `${t}%` }} />
            ))}
            <span className="absolute -top-1.5 size-3.5 -translate-x-1/2 rounded-full bg-foreground" style={{ left: `${report.score}%` }} />
          </div>
          <div className="mt-2 flex justify-between text-[10.5px] text-grey-soft">
            <span>LOW</span><span>MODERATE</span><span>HIGH</span><span>CRITICAL</span>
          </div>
        </div>
        <div>
          <p className="text-[17px] leading-relaxed">{report.summary}</p>
          <details className="mt-6 text-[13px]">
            <summary className="cursor-pointer text-grey-mid">
              Evidence coverage: {report.completedChecks} of {report.applicableChecks} checks completed
            </summary>
            <ul className="mt-3 space-y-1.5">
              {report.checks.map((c, i) => (
                <li key={i} className="flex justify-between gap-4 border-b border-line pb-1.5">
                  <span>{c.name}</span>
                  <span className="text-right text-grey-soft">
                    <span className="uppercase">{c.status}</span>
                    {c.note && <span className="block text-[12px] normal-case">{c.status === "unavailable" && c.note === "Not configured" ? "Not configured (no API key)" : c.note}</span>}
                  </span>
                </li>
              ))}
            </ul>
          </details>
          {report.kind === "url" && (
            <p className="mt-4 text-[13px] text-grey-mid">We analyzed the link and its public records. We did not inspect the page's content.</p>
          )}
          {report.analysisNotes?.map((n, i) => (
            <p key={i} className="mt-2 text-[13px] text-grey-mid">{n}</p>
          ))}
        </div>
      </section>

      {/* Findings */}
      <section className="mt-16">
        <p className="micro-label">EVIDENCE</p>
        <h2 className="heading-display mt-3 text-[clamp(24px,2.6vw,36px)]">WHAT WE FOUND</h2>
        {findings.length === 0 && <p className="mt-6 text-grey-mid">No warning signs were found in the checks that ran.</p>}
        {grouped.map((g) => (
          <div key={g.c} className="mt-8">
            <p className="micro-label">{CATEGORY_LABELS[g.c]}</p>
            <ul className="mt-2">
              {g.items.map((s, i) => (
                <li key={s.id + i} className="border-t border-line py-5">
                  <div className="flex flex-wrap items-center gap-3">
                    <Tag s={s} />
                    {report.demo && <span className="tag">DEMO</span>}
                    <h3 className="font-medium">{s.title}</h3>
                    {pointsFor(s) !== 0 && <span className="ml-auto font-mono text-[13px]">{pointsFor(s) > 0 ? "+" : ""}{pointsFor(s)}</span>}
                  </div>
                  <div className="mt-3 grid gap-3 text-[14px] md:grid-cols-2">
                    <p><span className="micro-label block">What we found</span>{s.found}</p>
                    <p className="text-grey-mid"><span className="micro-label block">Why it matters</span>{s.why}</p>
                  </div>
                  <p className="mt-2 text-[11.5px] text-grey-soft">Source: {s.source === "ai" ? "AI contextual analysis" : s.source}</p>
                </li>
              ))}
            </ul>
          </div>
        ))}
        {findings.length > 5 && (
          <button type="button" className="link-arrow mt-6 print-hidden" onClick={() => setShowAll((v) => !v)}>
            {showAll ? "Show fewer findings" : `Show all findings (${findings.length})`} →
          </button>
        )}
      </section>

      {/* Actions */}
      <section className="mt-16 border-t border-line pt-10">
        <p className="micro-label">WHAT TO DO</p>
        <ol className="mt-4 list-decimal space-y-2 pl-5 text-[15px]">
          {actionsFor(report.classification).map((a) => <li key={a}>{a}</li>)}
        </ol>
        <p className="micro-label mt-8">Check this elsewhere</p>
        <div className="mt-4 flex flex-wrap gap-4 print-hidden">
          {[
            ["VirusTotal URL search", "https://www.virustotal.com/gui/search/"],
            ["Google Safe Browsing Transparency Report", "https://transparencyreport.google.com/safe-browsing/search"],
            ["urlscan.io search", "https://urlscan.io/search/"],
          ].map(([name, href]) => <Button key={name} asChild variant="link" className="link-arrow h-auto whitespace-normal p-0 text-left"><a href={href} target="_blank" rel="noopener noreferrer">{name} →</a></Button>)}
        </div>
        {report.retryAvailable && <Link to="/" hash="submit" className="btn-pill mt-6">Try again</Link>}
      </section>

      {/* Utility row */}
      <div className="print-hidden mt-12 flex flex-wrap items-center gap-x-6 gap-y-4 border-t border-line pt-8">
        <button type="button" className="link-arrow" onClick={copySummary}><Copy className="size-3.5" strokeWidth={1} />Copy summary</button>
        <button type="button" className="link-arrow" onClick={() => window.print()}>Export report →</button>
        {onSave && !report.demo && (
          <span className="flex flex-col">
            <button type="button" className="link-arrow" disabled={saveState !== "idle"} onClick={onSave}>
              {saveState === "saving" ? "Saving…" : saveState === "saved" ? "Saved" : "Save report →"}
            </button>
            <span className="text-[11.5px] text-grey-soft">Saving stores the findings (not your screenshot) for 30 days.</span>
          </span>
        )}
        <Link to={analyzeAnotherHref} className="btn-pill ml-auto">Analyze another</Link>
      </div>

      {/* Accordions */}
      <section className="mt-12 border-b border-line">
        {report.extractedText && (
          <Accordion title="Extracted text">
            <pre className="max-h-96 overflow-auto whitespace-pre-wrap bg-secondary p-4 font-mono text-[12.5px]">{defangForDisplay(report.extractedText)}</pre>
          </Accordion>
        )}
        <Accordion title="Technical details">
          <div className="space-y-6 text-[13px]">
            {report.technical?.redirectChain?.length ? (
              <div>
                <p className="micro-label">Redirect chain</p>
                {report.technical.redirectChain.map((h, i) => (
                  <p key={i} className="break-all font-mono">{h.status} {defangForDisplay(h.from)} → {defangForDisplay(h.to)}</p>
                ))}
              </div>
            ) : null}
            {report.technical?.dns && (
              <div>
                <p className="micro-label">DNS ({report.technical.dns.source})</p>
                {report.technical.dns.records.map((r, i) => <p key={i} className="break-all font-mono">{r.type} {r.value}</p>)}
              </div>
            )}
            {report.technical?.rdap && (
              <div>
                <p className="micro-label">RDAP</p>
                <p>Status: {report.technical.rdap.status}{report.technical.rdap.created ? ` · Registered ${report.technical.rdap.created.slice(0, 10)}` : ""}{report.technical.rdap.registrar ? ` · ${report.technical.rdap.registrar}` : ""}</p>
              </div>
            )}
            {report.technical?.tls && (
              <div>
                <p className="micro-label">TLS certificate</p>
                <p>Status: {report.technical.tls.status}{report.technical.tls.firstSeen ? ` · First seen ${report.technical.tls.firstSeen.slice(0, 10)}` : ""}</p>
                <p className="text-grey-mid">HTTPS does not indicate that a site is trustworthy.</p>
              </div>
            )}
            {report.technical?.threatIntel?.length ? (
              <div>
                <p className="micro-label">Threat intelligence</p>
                {report.technical.threatIntel.map((t) => <p key={t.name}>{t.name}: {t.verdict}</p>)}
              </div>
            ) : null}
            <div>
              <p className="micro-label">Raw signals</p>
              {report.technical?.rawSignals?.map((s, i) => (
                <p key={i} className="font-mono">{s.id} · weight {s.weight} × {s.confidence} = {s.points}</p>
              ))}
            </div>
          </div>
        </Accordion>
        <Accordion title="How this score was calculated">
          <ol className="list-decimal space-y-1.5 pl-5 text-[14px]">
            <li>Each finding's points = weight × confidence, rounded.</li>
            {calc.steps.map((s) => <li key={s}>{s}</li>)}
          </ol>
          <Link to="/methodology" className="link-arrow mt-4">Read the methodology →</Link>
        </Accordion>
      </section>

      <p className="mt-8 text-[12.5px] text-grey-mid">{DISCLAIMER}</p>
    </article>
  );
}
