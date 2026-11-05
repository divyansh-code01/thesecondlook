/**
 * Second Look® — URL submission validation (server side, strict).
 * Client-side validation mirrors these rules for fast feedback.
 */

import { classifyHost, isDisguisedPrivateLiteral } from "@/shared/ip-guard";

export type UrlValidation =
  | { ok: true; normalized: string }
  | { ok: false; message: string };

const FORBIDDEN_SCHEMES = ["javascript", "data", "file", "vbscript", "blob", "ftp", "mailto", "tel", "chrome", "about", "ws", "wss"];

export function validateSubmittedUrl(raw: string): UrlValidation {
  const input = (raw ?? "").trim();
  if (!input) {
    return { ok: false, message: "Paste the link exactly as you received it." };
  }
  if (input.length > 2048) {
    return { ok: false, message: "That link is too long to check (maximum 2048 characters)." };
  }

  const schemeMatch = input.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (scheme === "http" || scheme === "https") {
      // fine
    } else if (FORBIDDEN_SCHEMES.includes(scheme)) {
      return {
        ok: false,
        message: `That's a ${scheme}: link, not a web address. Only http:// or https:// links can be checked.`,
      };
    } else {
      return {
        ok: false,
        message: "Only http:// or https:// web links can be checked.",
      };
    }
  } else if (input.includes("/") && !input.startsWith("//")) {
    // "example.com/path" without a scheme
    return {
      ok: false,
      message: "Add http:// or https:// at the start of the link.",
    };
  } else if (!input.includes("://") && !input.includes(".")) {
    return { ok: false, message: "Add http:// or https:// at the start of the link." };
  }

  let url: URL;
  try {
    url = new URL(schemeMatch ? input : `https://${input.replace(/^\/+/, "")}`);
  } catch {
    return { ok: false, message: "That doesn't look like a working web address. Check for typos." };
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, message: "Only http:// or https:// web links can be checked." };
  }

  const host = url.hostname;
  const classified = classifyHost(host);
  if (classified.kind === "blocked") {
    return {
      ok: false,
      message:
        classified.reason === "private_or_reserved_ip"
          ? "That address points at a private or internal network. It can't be checked here."
          : "That address points at a local or internal network. It can't be checked here.",
    };
  }
  if (isDisguisedPrivateLiteral(host)) {
    return { ok: false, message: "That address points at a private or internal network. It can't be checked here." };
  }

  return { ok: true, normalized: url.toString() };
}
