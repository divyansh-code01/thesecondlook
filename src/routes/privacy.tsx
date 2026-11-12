import { createFileRoute } from "@tanstack/react-router";
import { ProsePage } from "@/components/site/prose-page";

export const Route = createFileRoute("/privacy")({
  staticData: { sitemap: true },
  head: () => ({
    meta: [
      { title: "Privacy — The SecondLook" },
      { name: "description", content: "Exactly what The SecondLook processes, what it keeps, and for how long." },
      { property: "og:title", content: "Privacy — The SecondLook" },
      { property: "og:description", content: "Screenshots deleted after text extraction. Nothing stored unless you save a report." },
      { property: "og:type", content: "article" },
      { property: "og:url", content: "https://thesecondlook.lovable.app/privacy" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
    links: [{ rel: "canonical", href: "https://thesecondlook.lovable.app/privacy" }],
  }),
  component: () => (
    <ProsePage label="PRIVACY" title="WHAT WE KEEP." grey="(ALMOST NOTHING.)">
      <h2>Screenshots</h2>
      <p>Your screenshot is re-encoded in your browser (which strips photo metadata), uploaded to a short-lived private storage area, read once to extract its text, and deleted immediately afterwards — whatever the outcome. A background job removes anything older than 15 minutes as a backstop. Screenshots are never used to train models.</p>
      <h2>Links and extracted text</h2>
      <p>Links are never opened in your browser. Our server looks up public records and follows redirects without loading page content. The link and any extracted text are held only for the analysis and are not stored unless you choose to save a report.</p>
      <h2>Saved reports</h2>
      <p>If you click “Save report”, we store the score, findings and a defanged display of the input — never the screenshot or its full text. Saved reports expire after 30 days, are reachable only by their unguessable link, and can be deleted at any time with the delete code shown when you save.</p>
      <h2>Rate limiting</h2>
      <p>To prevent abuse we keep a salted, one-way hash of your network address for up to two days. The raw address is never stored.</p>
      <h2>Third parties that may receive data</h2>
      <ul>
        <li>Lovable AI (text extraction and wording analysis) — receives the screenshot or its text.</li>
        <li>Google Safe Browsing, URLhaus, PhishTank and VirusTotal, when enabled — receive only the link or domain, never screenshots.</li>
        <li>Cloudflare DNS, rdap.org and crt.sh — receive only the domain name.</li>
      </ul>
      <h2>Logs</h2>
      <p>We log only job IDs, stage timings and error codes — never submitted text, links or images.</p>
    </ProsePage>
  ),
});
