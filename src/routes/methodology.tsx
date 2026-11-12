import { createFileRoute } from "@tanstack/react-router";
import { ProsePage } from "@/components/site/prose-page";
import { AI_SIGNAL_CAP, CATEGORY_CAPS, SIGNALS, THREAT_FEED_FLOOR } from "@/shared/signals.config";

export const Route = createFileRoute("/methodology")({
  staticData: { sitemap: true },
  head: () => ({
    meta: [
      { title: "Methodology — The SecondLook" },
      { name: "description", content: "How The SecondLook detects scams: detection layers, the full weight table, scoring rules and limits." },
      { property: "og:title", content: "Methodology — The SecondLook" },
      { property: "og:description", content: "Detection layers, weights and the honest limits of an automated scam check." },
      { property: "og:type", content: "article" },
      { property: "og:url", content: "https://thesecondlook.lovable.app/methodology" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
    links: [{ rel: "canonical", href: "https://thesecondlook.lovable.app/methodology" }],
  }),
  component: Methodology,
});

function Methodology() {
  const rows = Object.entries(SIGNALS);
  return (
    <ProsePage label="METHODOLOGY" title="HOW WE" grey="LOOK TWICE.">
      <p>The SecondLook turns a screenshot or link into a list of typed findings. A fixed, deterministic formula turns those findings into a score. AI is used only to read text and to tag message wording from a fixed list — it never sets the score.</p>
      <h2>Detection layers</h2>
      <ul>
        <li>Link: threat-intelligence feeds (when configured), lookalike brands, shorteners, safe server-side redirect following, address patterns.</li>
        <li>Domain: registration age (RDAP), DNS records, certificate history (Certificate Transparency).</li>
        <li>Message: wording patterns such as urgency, requests for codes, payment or credentials, impersonation.</li>
        <li>Screenshot: text extraction, then regex extraction of links, phone numbers, emails and payment identifiers.</li>
      </ul>
      <h2>Scoring rules</h2>
      <ul>
        <li>Points per finding = weight × confidence, rounded.</li>
        <li>Category caps: Link {CATEGORY_CAPS.url}, Domain {CATEGORY_CAPS.domain}, Message {CATEGORY_CAPS.message}, Screenshot {CATEGORY_CAPS.screenshot}.</li>
        <li>AI-sourced findings add at most {AI_SIGNAL_CAP} points in total.</li>
        <li>A confirmed threat-feed hit sets a minimum score of {THREAT_FEED_FLOOR}.</li>
        <li>Mitigations can reduce the score by up to 15, never below 5.</li>
        <li>0–24 Low · 25–49 Moderate · 50–74 High · 75–100 Critical. Low scores remain unverified unless a threat check completed cleanly, the domain resolves and is at least a year old, and no warning signals were found. Coverage is informational only.</li>
      </ul>
      <h2>Weight table</h2>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-[13px]">
          <thead><tr className="border-b border-line"><th className="py-2">Signal</th><th>Layer</th><th className="text-right">Weight</th></tr></thead>
          <tbody>
            {rows.map(([id, m]) => (
              <tr key={id} className="border-b border-line">
                <td className="py-2 pr-4">{m.title}<span className="block font-mono text-[11px] text-grey-soft">{id}</span></td>
                <td className="pr-4 capitalize text-grey-mid">{m.category}</td>
                <td className="text-right font-mono">{m.weight > 0 ? `+${m.weight}` : m.weight}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <h2>Limits and what we don't check</h2>
      <ul>
        <li>We don't load or inspect page content, files or JavaScript, and we don't scan for malware.</li>
        <li>“Not listed” in a database never means safe. New scams appear faster than any list.</li>
        <li>A valid HTTPS certificate doesn't make a site trustworthy, and a new domain isn't automatically malicious.</li>
        <li>Text extraction can miss details in blurry or cropped screenshots.</li>
      </ul>
    </ProsePage>
  );
}
