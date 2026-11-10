import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { Clipboard, Code2, Download, Eye, Globe, Link2, MessageSquareText, ScanText, ScanSearch, Upload, FileText, ChevronDown } from "lucide-react";

import { SubmissionPanel } from "@/components/site/submission-panel";
import { DarkCta } from "@/components/site/dark-cta";
import { CATEGORY_CAPS } from "@/shared/signals.config";

export const Route = createFileRoute("/")({
  staticData: { sitemap: true },
  head: () => ({
    meta: [
      { title: "Second Look® — Before you trust it, check it." },
      { name: "description", content: "Upload a screenshot or paste a suspicious link. Second Look examines the evidence and explains what it finds, in plain language." },
      { property: "og:title", content: "Second Look® — Before you trust it, check it." },
      { property: "og:description", content: "Free, evidence-based scam checks for screenshots and links. No account needed." },
      { property: "og:type", content: "website" },
      { property: "og:url", content: "https://thesecondlook.lovable.app/" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
    links: [{ rel: "canonical", href: "https://thesecondlook.lovable.app/" }],
  }),
  component: Index,
});

const STEPS = [
  { n: "01", icon: Upload, title: "Submit", body: "Upload a screenshot of the message, or paste the link exactly as you got it." },
  { n: "02", icon: ScanSearch, title: "Analyze", body: "We read the text, check the link's public records and run every available check." },
  { n: "03", icon: FileText, title: "Understand", body: "You get a score, the evidence behind it, and clear next steps." },
];

const CHECKS = [
  { icon: Link2, title: "URL INTELLIGENCE", body: "Threat feeds, lookalike brands, shorteners and redirects — followed safely on our server, never in your browser." },
  { icon: Globe, title: "DOMAIN INTELLIGENCE", body: "Registration age, DNS records and certificate history from public sources." },
  { icon: MessageSquareText, title: "MESSAGE ANALYSIS", body: "Urgency, requests for codes or payment, impersonation and other classic scam patterns." },
  { icon: ScanText, title: "SCREENSHOT ANALYSIS", body: "Text extraction, then every link, number, email and payment detail it contains." },
];

const RESULT_TOOLS = [
  { n: "01", icon: Clipboard, title: "Copy summary", body: "A plain-text summary to share with family or your bank." },
  { n: "02", icon: Download, title: "Export report", body: "A clean, printable black-and-white PDF." },
  { n: "03", icon: Eye, title: "View extracted text", body: "See exactly what we read from your screenshot." },
  { n: "04", icon: Code2, title: "Technical details", body: "Redirects, DNS, registration data and every signal's weight." },
];

const PRINCIPLES = [
  { t: "We show our evidence", b: "Every point in the score traces back to a finding you can read." },
  { t: "We say when a check is unavailable", b: "If a source is down or not configured, the report says so — we never fill the gap." },
  { t: "We never promise safety", b: "“Low risk” means no major threats were found in the checks that ran. Not a guarantee." },
  { t: "We delete screenshots after analysis", b: "Your image is removed as soon as the text has been extracted." },
];

const FAQ = [
  ["What does Second Look check?", "Links (threat-intelligence feeds, lookalike domains, redirects, link patterns), domains (registration age, DNS, certificate history), and message wording (pressure, requests for codes or money, impersonation)."],
  ["How accurate is it?", "It's an evidence-based assessment, not a verdict. New scams appear every day, and some checks may be unavailable. Treat the result as a second opinion, not a guarantee."],
  ["What happens to my data?", "Screenshots are deleted as soon as the text is extracted. Nothing is stored unless you choose to save a report, which keeps only the findings — never the screenshot — for 30 days."],
  ["Do you open the links I submit?", "Never in your browser. Our server looks up public records and follows redirects using lightweight requests, without loading the page's content. Private and internal network addresses are blocked."],
  ["Why isn't “low risk” the same as “safe”?", "A low score means the checks we could run didn't find major warning signs. A brand-new scam might not be listed anywhere yet, so always verify independently."],
  ["Which files can I upload?", "PNG, JPG or WebP screenshots, up to 8 MB and 8000×8000 pixels. PDFs and other formats aren't supported."],
  ["I already clicked or shared something. What now?", "Change the passwords for any account involved, contact your bank if you shared payment details, and report the message to your national cybercrime service."],
  ["Who built this?", "Second Look is an independent tool built to give people a calm, honest second opinion before they act on a suspicious message."],
];

const BAR = (Object.entries(CATEGORY_CAPS) as [keyof typeof CATEGORY_CAPS, number][]).map(([k, v]) => ({
  k,
  v,
  label: { url: "Link", domain: "Domain", message: "Message", screenshot: "Screenshot" }[k],
}));
const BAR_TOTAL = BAR.reduce((s, b) => s + b.v, 0);

function Card({ n, icon: Icon, title, body }: { n: string; icon: typeof Upload; title: string; body: string }) {
  return (
    <div className="bordered-card flex flex-col items-center p-6 text-center">
      <p className="micro-label">// {n} //</p>
      <Icon className="my-7 size-12 text-foreground" strokeWidth={1} aria-hidden />
      <h3 className="text-[15px] font-medium">{title}</h3>
      <p className="mt-2 text-[13px] leading-snug text-grey-mid">{body}</p>
    </div>
  );
}

function Index() {
  const [openFaq, setOpenFaq] = useState<number | null>(null);
  return (
    <main id="main">
      {/* Hero */}
      <section className="grid gap-10 pt-14 pb-12 md:grid-cols-2 md:pt-20">
        <h1 className="heading-display text-[clamp(40px,6vw,88px)]">
          BEFORE YOU
          <br />
          TRUST IT,
          <br />
          <span className="tone-grey">CHECK IT.</span>
        </h1>
        <div className="flex flex-col gap-6">
          <p className="text-[17px] leading-relaxed">
            <span className="text-foreground">Upload a screenshot or paste a link.</span>{" "}
            <span className="tone-grey">Second Look is a free scam-detection tool for suspicious messages and links. We examine the evidence and explain what we find, in plain language.</span>
          </p>
          <SubmissionPanel />
        </div>
      </section>
      <p className="micro-label border-t border-line py-4">FREE · NO ACCOUNT · SCREENSHOTS DELETED AFTER ANALYSIS</p>

      {/* Process */}
      <section id="process" className="reveal scroll-mt-24 pt-20">
        <div className="grid gap-6 md:grid-cols-2">
          <div>
            <p className="micro-label">PROCESS</p>
            <h2 className="heading-display mt-4 text-[clamp(28px,3.4vw,48px)]">
              THREE STEPS.
              <br />
              <span className="tone-grey">NO GUESSWORK.</span>
            </h2>
          </div>
          <p className="text-[17px] leading-relaxed">
            <span>From your screenshot to a clear answer, every step is</span>{" "}
            <span className="tone-grey">grounded in evidence you can read, check and share.</span>
          </p>
        </div>
        <div className="mt-12 grid gap-4 sm:grid-cols-3">
          {STEPS.map((s) => <Card key={s.n} {...s} />)}
        </div>
      </section>

      {/* What we check */}
      <section className="reveal pt-24">
        <p className="micro-label text-center">OUR CHECKS</p>
        <ul className="mt-8">
          {CHECKS.map((c) => (
            <li key={c.title} className="group border-b border-line py-6 first:border-t">
              <div className="flex items-center justify-center gap-5">
                <span className="icon-tile hidden size-12 shrink-0 opacity-0 transition-opacity duration-150 group-hover:opacity-100 md:flex">
                  <c.icon className="size-6" strokeWidth={1} aria-hidden />
                </span>
                <h3 className="heading-display text-center text-[clamp(22px,3.6vw,44px)] font-normal text-grey-mid transition-colors duration-150 group-hover:text-foreground">
                  {c.title}
                </h3>
              </div>
              <p className="mx-auto mt-3 max-w-lg text-center text-[14px] text-grey-mid md:hidden md:group-hover:block md:group-focus-within:block">
                {c.body}
              </p>
            </li>
          ))}
        </ul>
      </section>

      {/* Score */}
      <section className="reveal grid gap-10 pt-24 md:grid-cols-2">
        <div>
          <p className="micro-label">SCORING</p>
          <h2 className="heading-display mt-4 text-[clamp(28px,3.4vw,48px)]">
            HOW THE SCORE
            <br />
            <span className="tone-grey">IS CALCULATED.</span>
          </h2>
        </div>
        <div>
          <p className="text-[16px] leading-relaxed">
            Each finding carries fixed points. Points are capped per category, AI-detected wording can never add more than 40,
            and a confirmed threat-feed hit sets a floor of 85.{" "}
            <span className="tone-grey">The same evidence always produces the same score.</span>
          </p>
          <div className="mt-8 flex h-8 w-full overflow-hidden rounded-sm border border-line" aria-label="Maximum points per category">
            {BAR.map((b, i) => (
              <div key={b.k} className="flex items-center justify-center text-[11px]" style={{ width: `${(b.v / BAR_TOTAL) * 100}%`, background: `color-mix(in oklab, var(--ink) ${85 - i * 22}%, white)`, color: i < 2 ? "white" : "var(--ink)" }}>
                {b.label} {b.v}
              </div>
            ))}
          </div>
          <Link to="/methodology" className="link-arrow mt-6">Read the full methodology →</Link>
        </div>
      </section>

      {/* Results tools */}
      <section className="reveal pt-24">
        <p className="micro-label">YOUR REPORT</p>
        <h2 className="heading-display mt-4 text-[clamp(28px,3.4vw,48px)]">
          WHAT YOU CAN DO <span className="tone-grey">WITH RESULTS.</span>
        </h2>
        <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {RESULT_TOOLS.map((r) => <Card key={r.n} {...r} />)}
        </div>
      </section>

      {/* Trust */}
      <section className="reveal pt-24">
        <p className="micro-label">PRINCIPLES</p>
        <h2 className="heading-display mt-4 text-[clamp(28px,3.4vw,48px)]">
          WHY YOU <span className="tone-grey">CAN TRUST IT.</span>
        </h2>
        <div className="mt-10 grid border-t border-l border-line sm:grid-cols-2">
          {PRINCIPLES.map((p) => (
            <div key={p.t} className="border-r border-b border-line p-7">
              <h3 className="text-[17px] font-medium">{p.t}</h3>
              <p className="mt-2 text-[14px] text-grey-mid">{p.b}</p>
            </div>
          ))}
        </div>
      </section>

      {/* FAQ */}
      <section className="reveal pt-24">
        <p className="micro-label">FAQ</p>
        <h2 className="heading-display mt-4 text-[clamp(28px,3.4vw,48px)]">QUESTIONS.</h2>
        <div className="mt-8 border-b border-line">
          {FAQ.map(([q, a], i) => (
            <div key={q} className="border-t border-line">
              <h3>
                <button
                  type="button"
                  id={`faq-q-${i}`}
                  aria-expanded={openFaq === i}
                  aria-controls={`faq-a-${i}`}
                  className="flex w-full items-center justify-between gap-4 py-5 text-left text-[16px]"
                  onClick={() => setOpenFaq(openFaq === i ? null : i)}
                >
                  {q}
                  <ChevronDown className={`size-4 shrink-0 transition-transform duration-150 ${openFaq === i ? "rotate-180" : ""}`} strokeWidth={1} aria-hidden />
                </button>
              </h3>
              <div id={`faq-a-${i}`} role="region" aria-labelledby={`faq-q-${i}`} hidden={openFaq !== i} className="pb-5 text-[14.5px] text-grey-mid">
                {a}
              </div>
            </div>
          ))}
        </div>
      </section>

      <DarkCta />
    </main>
  );
}
