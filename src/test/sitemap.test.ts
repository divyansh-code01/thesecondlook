import { QueryClient } from "@tanstack/react-query";
import { createRouter } from "@tanstack/react-router";
import { describe, expect, it } from "vitest";
import { routeTree } from "@/routeTree.gen";
import { sitemapStaticPaths, sitemapXML } from "@/lib/sitemap";

describe("public sitemap", () => {
  it("includes exactly the four public pages and excludes submissions and API endpoints", () => {
    const router = createRouter({ routeTree, context: { queryClient: new QueryClient() } });
    expect(sitemapStaticPaths(router)).toEqual(["/", "/methodology", "/privacy", "/terms"]);
  });
  it("uses canonical HTTPS URLs with no duplicate entries or invented modification dates", () => {
    const xml = sitemapXML("https://thesecondlook.lovable.app", [{ path: "/" }, { path: "/" }, { path: "/methodology" }]);
    const document = new DOMParser().parseFromString(xml, "application/xml");
    expect([...document.querySelectorAll("loc")].map((node) => node.textContent)).toEqual(["https://thesecondlook.lovable.app/", "https://thesecondlook.lovable.app/methodology"]);
    expect(document.querySelector("parsererror")).toBeNull();
    expect(document.querySelector("lastmod")).toBeNull();
  });
});