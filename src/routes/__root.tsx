import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  Outlet,
  Link,
  createRootRouteWithContext,
  useRouter,
  HeadContent,
  Scripts,
  useLocation,
  type ErrorComponentProps,
} from "@tanstack/react-router";
import { useEffect, type ReactNode } from "react";

import appCss from "../styles.css?url";
import { reportLovableError } from "../lib/lovable-error-reporting";
import { SiteNav } from "@/components/site/nav";
import { SiteFooter } from "@/components/site/footer";
import { Toaster } from "@/components/ui/sonner";

function NotFoundComponent() {
  return (
    <main id="main" className="flex min-h-[60vh] flex-col items-center justify-center px-4 py-24 text-center">
      <p className="micro-label">ERROR 404</p>
      <h1 className="heading-display mt-6 text-[clamp(28px,3.4vw,48px)]">
        THIS PAGE DOESN'T <span className="tone-grey">EXIST.</span>
      </h1>
      <p className="mt-4 max-w-md text-[15px] tone-mid">
        The page you're looking for has moved, or never was.
      </p>
      <Link to="/" className="btn-pill mt-8">
        Back to the check
      </Link>
    </main>
  );
}

function ErrorComponent({ error, reset }: ErrorComponentProps) {
  console.error(error);
  const router = useRouter();
  useEffect(() => {
    reportLovableError(error, { boundary: "tanstack_root_error_component" });
  }, [error]);

  return (
    <main id="main" className="flex min-h-[60vh] flex-col items-center justify-center px-4 py-24 text-center">
      <p className="micro-label">SOMETHING WENT WRONG</p>
      <h1 className="heading-display mt-6 text-[clamp(28px,3.4vw,48px)]">
        THIS PAGE DIDN'T <span className="tone-grey">LOAD.</span>
      </h1>
      <p className="mt-4 max-w-md text-[15px] tone-mid">
        You can try again, or head back and start a new check.
      </p>
      <div className="mt-8 flex flex-wrap justify-center gap-3">
        <button
          onClick={() => {
            router.invalidate();
            reset();
          }}
          className="btn-pill"
        >
          Try again
        </button>
        <Link to="/" className="btn-pill">
          Go home
        </Link>
      </div>
    </main>
  );
}

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  staticData: { sitemap: false },
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      // Google Search Console site ownership; must stay verbatim in <head>.
      {
        name: "google-site-verification",
        content: "4WcTOcM8DjaPK0oEwoypVd9sI4z_IJTDXt_ZF1RzX8o",
      },
      { title: "The SecondLook" },
      { name: "description", content: "Before you trust it, check it. Upload a screenshot or paste a link." },
      { property: "og:title", content: "The SecondLook" },
      { property: "og:description", content: "Before you trust it, check it." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
    links: [
      { rel: "preconnect", href: "https://fonts.googleapis.com" },
      { rel: "preconnect", href: "https://fonts.gstatic.com", crossOrigin: "anonymous" },
      {
        rel: "stylesheet",
        href: "https://fonts.googleapis.com/css2?family=Inter+Tight:wght@400;500;600;700&display=swap",
      },
      {
        rel: "stylesheet",
        href: appCss,
      },
      { rel: "icon", href: "/favicon.ico", type: "image/x-icon" },
    ],
  }),
  shellComponent: RootShell,
  component: RootComponent,
  notFoundComponent: NotFoundComponent,
  errorComponent: ErrorComponent,
});

function RootShell({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <head>
        <HeadContent />
      </head>
      <body>
        {children}
        <Scripts />
      </body>
    </html>
  );
}

function RootComponent() {
  const { queryClient } = Route.useRouteContext();
  const location = useLocation();

  // Scroll-reveal: observe .reveal elements after each navigation.
  useEffect(() => {
    const els = Array.from(document.querySelectorAll<HTMLElement>(".reveal:not(.is-visible)"));
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches || !("IntersectionObserver" in window)) {
      els.forEach((el) => el.classList.add("is-visible"));
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            io.unobserve(entry.target);
          }
        }
      },
      { threshold: 0.12 },
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, [location.pathname]);

  return (
    <QueryClientProvider client={queryClient}>
      <div className="site-container min-h-screen flex flex-col">
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:bg-white focus:px-4 focus:py-2 focus:text-sm"
        >
          Skip to content
        </a>
        <SiteNav />
        <div className="flex-1">
          <Outlet />
        </div>
        <SiteFooter />
      </div>
      <Toaster position="bottom-right" />
    </QueryClientProvider>
  );
}
