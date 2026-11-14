import { createFileRoute } from "@tanstack/react-router";
import { ScamGuide, guideHead } from "@/components/site/scam-guide";

export const Route = createFileRoute("/how-to-identify-online-scams")({
  staticData: { sitemap: true },
  head: () => guideHead("/how-to-identify-online-scams"),
  component: () => <ScamGuide path="/how-to-identify-online-scams" />,
});