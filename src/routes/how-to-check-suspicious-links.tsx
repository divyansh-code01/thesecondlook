import { createFileRoute } from "@tanstack/react-router";
import { ScamGuide, guideHead } from "@/components/site/scam-guide";

export const Route = createFileRoute("/how-to-check-suspicious-links")({
  staticData: { sitemap: true },
  head: () => guideHead("/how-to-check-suspicious-links"),
  component: () => <ScamGuide path="/how-to-check-suspicious-links" />,
});