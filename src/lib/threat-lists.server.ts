import { getSupabaseAdmin } from "./supabase.server";
import { SIGNALS } from "@/shared/signals.config";
import type { Check, Signal } from "@/shared/types";
import { fetchWithTimeout } from "./stages.server";

const FEEDS = [
  { source: "OpenPhish", url: "https://openphish.com/feed.txt", urls: true },
  { source: "Phishing.Database", url: "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt", urls: false },
];

export async function checkKnownThreats(url: string, host: string) {
  const name = "Known phishing lists", source = "known_threats";
  const checks: Check[] = [];
  const signals: Signal[] = [];
  try {
    const admin = getSupabaseAdmin();
    const [state, matches] = await Promise.all([
      admin.from("threat_feed_refresh").select("source,fetched_at,entry_count"),
      admin.from("known_threats").select("host,source,url,fetched_at").eq("host", host),
    ]);
    if (state.error || matches.error) throw new Error("list_unavailable");
    const cutoff = Date.now() - 86400000;
    const fresh = new Set((state.data ?? []).filter((r) => r.entry_count > 0 && Date.parse(r.fetched_at) >= cutoff).map((r) => r.source));
    const hits = (matches.data ?? []).filter((r) => fresh.has(r.source) && Date.parse(r.fetched_at) >= cutoff);
    for (const hit of hits) signals.push({ id: "threat_feed_hit", ...SIGNALS.threat_feed_hit, source: hit.source, status: "confirmed", confidence: 1, title: `Listed by ${hit.source}`, found: `${host} matches the active phishing list.` });
    const complete = FEEDS.every((f) => fresh.has(f.source));
    checks.push({ name, source, status: complete ? "completed" : "unavailable", note: complete ? undefined : "One or more phishing lists are empty or older than 24 hours" });
    return { checks, signals, verdicts: [{ name, source, verdict: hits.length ? "listed" : complete ? "not listed" : "unavailable" }] };
  } catch {
    return { checks: [{ name, source, status: "unavailable" as const, note: "Phishing lists could not be read" }], signals, verdicts: [{ name, source, verdict: "unavailable" }] };
  }
}

export async function refreshThreatLists() {
  const admin = getSupabaseAdmin();
  return Promise.all(FEEDS.map(async (feed) => {
    const response = await fetchWithTimeout(feed.url, {}, 8000);
    if (!response.ok) throw new Error("feed_download_failed");
    const fetched_at = new Date().toISOString();
    const rows = new Map<string, { host: string; source: string; url: string; fetched_at: string }>();
    for (const line of (await response.text()).split(/\r?\n/)) {
      const value = line.trim();
      if (!value || value.startsWith("#")) continue;
      try {
        const parsed = new URL(feed.urls ? value : `https://${value}`);
        if (!["http:", "https:"].includes(parsed.protocol)) continue;
        parsed.hash = "";
        const url = feed.urls ? parsed.toString() : "";
        const host = parsed.hostname.toLowerCase();
        rows.set(`${host}|${url}`, { host, source: feed.source, url, fetched_at });
      } catch { /* Invalid feed entry is not evidence. */ }
    }
    if (!rows.size) throw new Error("empty_feed");
    const entries = [...rows.values()];
    for (let i = 0; i < entries.length; i += 20000) {
      await Promise.all([0, 5000, 10000, 15000].map(async (offset) => {
        const chunk = entries.slice(i + offset, i + offset + 5000);
        if (!chunk.length) return;
        const { error } = await admin.from("known_threats").upsert(chunk);
        if (error) throw new Error("feed_store_failed");
      }));
    }
    const { error } = await admin.from("threat_feed_refresh").upsert({ source: feed.source, fetched_at, entry_count: entries.length });
    if (error) throw new Error("feed_store_failed");
    await admin.from("known_threats").delete().eq("source", feed.source).lt("fetched_at", fetched_at);
    return { source: feed.source, count: entries.length };
  }));
}