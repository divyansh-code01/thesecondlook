import type { ReactNode } from "react";

export function ProsePage({ label, title, grey, children }: { label: string; title: string; grey: string; children: ReactNode }) {
  return (
    <main id="main" className="py-16">
      <p className="micro-label">{label}</p>
      <h1 className="heading-display mt-4 text-[clamp(32px,4.4vw,64px)]">
        {title} <span className="tone-grey">{grey}</span>
      </h1>
      <div className="mt-12 max-w-3xl space-y-6 text-[16px] leading-relaxed [&_h2]:heading-display [&_h2]:mt-12 [&_h2]:border-t [&_h2]:border-line [&_h2]:pt-8 [&_h2]:text-[20px] [&_li]:ml-5 [&_li]:list-disc [&_p]:text-grey-mid [&_li]:text-grey-mid">
        {children}
      </div>
    </main>
  );
}
