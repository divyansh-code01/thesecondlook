import { createFileRoute } from "@tanstack/react-router";
import { ProsePage } from "@/components/site/prose-page";

export const Route = createFileRoute("/terms")({
  staticData: { sitemap: true },
  head: () => ({
    meta: [
      { title: "Terms — The SecondLook" },
      { name: "description", content: "The plain-language terms for using The SecondLook." },
      { property: "og:title", content: "Terms — The SecondLook" },
      { property: "og:description", content: "An automated second opinion, not a guarantee." },
      { property: "og:type", content: "article" },
      { property: "og:url", content: "https://thesecondlook.lovable.app/terms" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
    links: [{ rel: "canonical", href: "https://thesecondlook.lovable.app/terms" }],
  }),
  component: () => (
    <ProsePage label="TERMS" title="THE SHORT" grey="VERSION.">
      <h2>What this is</h2>
      <p>The SecondLook is a free, automated tool that gives a second opinion on suspicious messages and links. Its results are an assessment based on the checks listed in each report — not a guarantee, and not legal, financial or security advice.</p>
      <h2>Your responsibility</h2>
      <p>You decide what to do with a message. When in doubt, contact the organisation using details you find independently. Only submit content you're entitled to share.</p>
      <h2>Fair use</h2>
      <p>Don't use the service to probe networks, overload it, or test content you created to evade detection. We limit checks per network to keep the service available for everyone.</p>
      <h2>No warranty</h2>
      <p>The service is provided as is. We can't promise every check is available or every scam is caught, and we aren't liable for decisions made using a report.</p>
      <h2>Contact</h2>
      <p>Questions: hello@secondlook.app</p>
    </ProsePage>
  ),
});
