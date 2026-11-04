import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "@tanstack/react-router";
import { Menu, X } from "lucide-react";

export function Wordmark({ className = "" }: { className?: string }) {
  return (
    <Link
      to="/"
      aria-label="Second Look — home"
      className={`text-[15px] font-semibold uppercase tracking-[-0.01em] text-foreground ${className}`}
    >
      Second Look<span aria-hidden className="align-super text-[9px]">®</span>
    </Link>
  );
}

const PRIMARY_LINKS = [
  { label: "Home", to: "/" },
  { label: "How it works", to: "/#process" },
  { label: "Methodology", to: "/methodology" },
];

const LEGAL_LINKS = [
  { label: "Privacy", to: "/privacy" },
  { label: "Terms", to: "/terms" },
];

export function SiteNav() {
  const [open, setOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => setOpen(false), [location.pathname]);

  function go(e: React.MouseEvent, to: string) {
    e.preventDefault();
    const [path, hash] = to.split("#");
    if (hash) {
      if (path && path !== location.pathname) {
        navigate({ to: path, hash });
      } else {
        document.getElementById(hash)?.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    } else {
      navigate({ to: path || "/" });
    }
  }

  const linkClass = "text-[13px] text-grey-mid hover:text-foreground transition-colors duration-150";

  return (
    <header className="print-hidden" data-testid="site-nav">
      <nav aria-label="Main" className="flex items-center justify-between py-6">
        <Wordmark />

        {/* Desktop links */}
        <div className="hidden md:flex items-start gap-14">
          <div className="flex flex-col items-start gap-1.5">
            {PRIMARY_LINKS.map((l) => (
              <a key={l.label} href={l.to} className={linkClass} onClick={(e) => go(e, l.to)}>
                {l.label}
              </a>
            ))}
          </div>
          <div className="flex flex-col items-start gap-1.5">
            {LEGAL_LINKS.map((l) => (
              <a key={l.label} href={l.to} className={linkClass} onClick={(e) => go(e, l.to)}>
                {l.label}
              </a>
            ))}
          </div>
          <a
            href="/#submit"
            className="btn-pill"
            onClick={(e) => {
              go(e, "/#submit");
            }}
          >
            Check now
          </a>
        </div>

        {/* Mobile */}
        <button
          type="button"
          className="md:hidden p-2 -mr-2 text-foreground"
          aria-expanded={open}
          aria-label={open ? "Close menu" : "Open menu"}
          onClick={() => setOpen((v) => !v)}
        >
          {open ? <X className="size-5" strokeWidth={1} /> : <Menu className="size-5" strokeWidth={1} />}
        </button>
      </nav>

      {open && (
        <div className="fixed inset-0 z-40 bg-white md:hidden" role="dialog" aria-modal="true" aria-label="Menu">
          <div className="flex items-center justify-between px-5 py-6">
            <Wordmark />
            <button
              type="button"
              className="p-2 -mr-2"
              aria-label="Close menu"
              onClick={() => setOpen(false)}
            >
              <X className="size-5" strokeWidth={1} />
            </button>
          </div>
          <nav aria-label="Mobile" className="flex flex-col px-5 pt-8">
            {[...PRIMARY_LINKS, ...LEGAL_LINKS].map((l) => (
              <a
                key={l.label}
                href={l.to}
                className="heading-display border-b border-line py-5 text-[22px] text-foreground"
                onClick={(e) => {
                  setOpen(false);
                  go(e, l.to);
                }}
              >
                {l.label}
              </a>
            ))}
            <a
              href="/#submit"
              className="btn-pill mt-8 self-start"
              onClick={(e) => {
                setOpen(false);
                go(e, "/#submit");
              }}
            >
              Check now
            </a>
          </nav>
        </div>
      )}
      <div className="hairline-t" />
    </header>
  );
}
