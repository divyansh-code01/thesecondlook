import { Link } from "@tanstack/react-router";

export function DarkCta() {
  return (
    <section className="grain-dark print-hidden mt-20 px-6 py-20 text-center sm:px-12 sm:py-28" data-testid="dark-cta">
      <p className="micro-label !text-[#8a8a8a]">WHAT ARE YOU WAITING FOR?</p>
      <h2 className="heading-display mt-6 text-[clamp(30px,4.6vw,64px)] text-white">
        LET'S MAKE SURE
        <br />
        IT'S REAL.
      </h2>
      <Link to="/" hash="submit" className="btn-pill-light mt-10">
        Check something now
      </Link>
      <p className="mx-auto mt-8 max-w-md text-[13px] leading-relaxed text-[#9a9a9a]">
        A screenshot or a link is all it takes. Free, no account, and your screenshot is deleted as soon as the text is extracted.
      </p>
    </section>
  );
}
