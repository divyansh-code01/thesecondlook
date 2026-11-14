import { createFileRoute } from "@tanstack/react-router";
import { ScamGuide, guideHead } from "@/components/site/scam-guide";

export const Route = createFileRoute("/phishing-vs-smishing")({
  staticData: { sitemap: true },
  head: () => guideHead("/phishing-vs-smishing"),
  component: () => <ScamGuide path="/phishing-vs-smishing" />,
});