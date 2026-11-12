import { Link } from "@tanstack/react-router";

const COLUMNS = [
  {
    title: "Links",
    items: [
      { label: "Home", to: "/" },
      { label: "How it works", to: "/#process" },
      { label: "Methodology", to: "/methodology" },
    ],
  },
  {
    title: "Legal",
    items: [
      { label: "Privacy", to: "/privacy" },
      { label: "Terms", to: "/terms" },
    ],
  },
  {
    title: "Report scams",
    items: [
      { label: "US — IC3", href: "https://www.ic3.gov" },
      { label: "UK — Action Fraud", href: "https://www.actionfraud.police.uk" },
      { label: "India — Cybercrime portal", href: "https://cybercrime.gov.in" },
      { label: "Or your national cybercrime unit", href: "https://www.internetsociety.org/actionagenda/basics/where-report-scams/" },
    ],
  },
];

export function SiteFooter() {
  return (
    <footer className="print-hidden mt-24">
      <div className="hairline-t pt-14">
        <p className="micro-label">— Contact</p>
        <a
          href="mailto:hello@secondlook.app"
          className="mt-3 block text-[clamp(22px,3.2vw,40px)] font-semibold uppercase tracking-[-0.02em] text-foreground hover:text-ink-hover transition-colors"
        >
          hello@secondlook.app
        </a>
      </div>

      <div className="mt-14 grid grid-cols-2 gap-8 sm:grid-cols-3">
        {COLUMNS.map((col) => (
          <nav key={col.title} aria-label={col.title} className="flex flex-col items-start gap-2.5">
            <p className="micro-label">{col.title}</p>
            {col.items.map((item) =>
              "to" in item ? (
                <Link key={item.label} to={item.to} className="text-[13px] text-grey-mid hover:text-foreground transition-colors">
                  {item.label}
                </Link>
              ) : (
                <a
                  key={item.label}
                  href={item.href}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="text-[13px] text-grey-mid hover:text-foreground transition-colors"
                >
                  {item.label}
                </a>
              ),
            )}
          </nav>
        ))}
      </div>

      <div className="mt-16 pb-8">
        <p
          aria-hidden
          className="select-none whitespace-nowrap font-semibold uppercase leading-[0.95] tracking-[-0.03em] text-foreground"
          style={{ fontSize: "clamp(38px, 8.2vw, 113px)" }}
        >
          The SecondLook
        </p>
        <div className="mt-2 flex items-center justify-between">
          <p className="micro-label">© {new Date().getFullYear()} The SecondLook</p>
          <p className="micro-label">Not a guarantee — a second look.</p>
        </div>
        <p className="mt-4 text-[13px] text-grey-mid">
          The SecondLook is an early version. Treat results as guidance, not a guarantee.
        </p>
      </div>
    </footer>
  );
}
