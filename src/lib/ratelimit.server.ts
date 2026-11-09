import { getRequestHeader } from "@tanstack/react-start/server";

/**
 * Second Look® — rate limiting (spec §8).
 * Per salted IP hash: 10 submissions/hour, 30/day, plus a global concurrency cap.
 * The raw IP is never stored — only a salted SHA-256 hex digest.
 */

import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/integrations/supabase/types";

export async function hashClientIp(): Promise<string> {
  const forwarded = getRequestHeader("cf-connecting-ip") ?? getRequestHeader("x-forwarded-for") ?? "unknown";
  const ip = forwarded.split(",")[0]?.trim() || "unknown";
  const salt = process.env["RATE_LIMIT_SALT"] ?? process.env["SUPABASE_PROJECT_ID"] ?? "second-look-static-salt";
  const data = new TextEncoder().encode(`${salt}:${ip}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export type RateLimitResult =
  | { exceeded: false }
  | { exceeded: true; message: string; retryAfterSeconds: number };

const HOURLY_LIMIT = 10;
const DAILY_LIMIT = 30;

function bucketStart(ms: number): number {
  return Math.floor(Date.now() / ms);
}

async function checkAndCount(
  admin: SupabaseClient<Database>,
  key: string,
  limit: number,
  windowMs: number,
): Promise<RateLimitResult> {
  const start = new Date(bucketStart(windowMs) * windowMs).toISOString();
  const { data: row } = await admin
    .from("rate_limits")
    .select("count, window_start")
    .eq("key", key)
    .maybeSingle();

  if (row && row.count >= limit && row.window_start === start) {
    const windowEnd = (bucketStart(windowMs) + 1) * windowMs;
    const retryAfterSeconds = Math.max(60, Math.ceil((windowEnd - Date.now()) / 1000));
    return {
      exceeded: true,
      message:
        windowMs === 3600_000
          ? `You've reached the limit of ${limit} checks per hour. You can run more again in about ${Math.ceil(retryAfterSeconds / 60)} minutes.`
          : `You've reached the limit of ${limit} checks per day. Please try again tomorrow.`,
      retryAfterSeconds,
    };
  }

  if (row && row.window_start === start) {
    await admin.from("rate_limits").update({ count: row.count + 1 }).eq("key", key);
  } else {
    await admin.from("rate_limits").upsert({ key, window_start: start, count: 1 }, { onConflict: "key" });
  }

  return { exceeded: false };
}

export async function checkAndCountRateLimit(
  admin: SupabaseClient<Database>,
  ipHash: string,
): Promise<RateLimitResult> {
  const hourly = await checkAndCount(admin, `${ipHash}:h:${bucketStart(3600_000)}`, HOURLY_LIMIT, 3600_000);
  if (hourly.exceeded) return hourly;
  const daily = await checkAndCount(admin, `${ipHash}:d:${bucketStart(86400_000)}`, DAILY_LIMIT, 86400_000);
  if (daily.exceeded) {
    return daily;
  }
  return { exceeded: false };
}

export async function globalConcurrencyCount(admin: SupabaseClient<Database>): Promise<number> {
  const cutoff = new Date(Date.now() - 5 * 60_000).toISOString();
  const { count } = await admin
    .from("jobs")
    .select("id", { count: "exact", head: true })
    .eq("status", "running")
    .gt("updated_at", cutoff);
  return count ?? 0;
}
