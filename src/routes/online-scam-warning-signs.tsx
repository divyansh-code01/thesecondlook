import { createFileRoute } from "@tanstack/react-router";
import { ScamGuide, guideHead } from "@/components/site/scam-guide";

export const Route = createFileRoute("/online-scam-warning-signs")({
  staticData: { sitemap: true },
  head: () => guideHead("/online-scam-warning-signs"),
  component: () => <ScamGuide path="/online-scam-warning-signs" />,
});