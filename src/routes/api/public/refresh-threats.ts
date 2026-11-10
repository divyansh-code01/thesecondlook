import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/public/refresh-threats")({
  staticData: { sitemap: false },
  server: { handlers: { POST: async ({ request }) => {
    const { authenticateCronRequest } = await import("@/integrations/supabase/cron-auth");
    const failure = await authenticateCronRequest(request);
    if (failure) return failure;
    const { refreshThreatLists } = await import("@/lib/threat-lists.server");
    try { return Response.json({ refreshed: await refreshThreatLists() }); }
    catch { return Response.json({ error: "threat_refresh_failed" }, { status: 503 }); }
  } } },
});