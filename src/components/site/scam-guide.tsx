import { Link } from "@tanstack/react-router";
import { ProsePage } from "@/components/site/prose-page";

export const GUIDE_LINKS = [
  { to: "/how-to-identify-online-scams", label: "How to identify online scams" },
  { to: "/how-to-check-suspicious-links", label: "How to check suspicious links" },
  { to: "/phishing-vs-smishing", label: "Phishing vs. smishing" },
  { to: "/online-scam-warning-signs", label: "Online scam warning signs" },
] as const;

type GuidePath = typeof GUIDE_LINKS[number]["to"];
type Section = { heading: string; paragraphs: string[]; steps?: string[]; example?: string };
type Guide = { path: GuidePath; title: string; titleStart: string; titleEnd: string; description: string; intro: string; sections: Section[]; source: { label: string; url: string } };

const warningSource = { label: "Consumer Financial Protection Bureau: warning signs of fraud and scams", url: "https://www.consumerfinance.gov/ask-cfpb/what-are-some-classic-warning-signs-of-possible-fraud-and-scams-en-2094/" };
const textSource = { label: "Federal Trade Commission: common text-message scams", url: "https://search.ftc.gov/system/files/ftc_gov/pdf/spotlight-top-text-scams.pdf" };

export const SCAM_GUIDES: Record<GuidePath, Guide> = {
  "/how-to-identify-online-scams": {
    path: "/how-to-identify-online-scams", title: "How to Identify Online Scams — The SecondLook", titleStart: "HOW TO IDENTIFY", titleEnd: "ONLINE SCAMS.",
    description: "Learn how to assess an unexpected message, verify the sender independently and respond to common online scams without following suspicious links.",
    intro: "An online scam is a deceptive attempt to obtain your money, personal information or account access. It can arrive as an email, text, social message, advert or conversation. Start with what the sender wants you to do, not how professional the message looks.",
    sections: [
      { heading: "Separate the story from the request", paragraphs: ["A delivery delay, unpaid bill or account alert can be a believable story. The important question is whether the requested action makes sense: an unexpected fee, a password entered through a message link, or money moved to a supposedly protected account deserves independent checking.", "Your name, a familiar logo or a detail about a recent purchase is not proof of identity. Scammers may reuse public information or material from earlier data breaches. Correct spelling is not proof either; convincing wording is easy to produce."], example: "Fictional example: ‘Your parcel is held. Pay a small redelivery charge today.’ The warning is not just the fee: it is an unexpected payment request tied to a deadline and a link you did not seek out." },
      { heading: "Verify through a separate channel", paragraphs: ["Do not use a number, reply address or website supplied by the suspicious message to verify that same message. Open the organisation’s app yourself or use a number from your bank card or an existing statement. If a friend asks for money from a new account, call them on a number you already know."], steps: ["Pause before replying, paying or opening an attachment.", "Check whether you expected the contact and whether the request appears in your existing account.", "Ask the organisation about the specific claim through independently sourced contact details.", "If you cannot confirm the request, leave it unanswered rather than letting the deadline decide for you."] },
      { heading: "Recognise the transaction, not just the message", paragraphs: ["Requests for gift-card codes, cryptocurrency or an upfront payment to release a prize are strong warning signs. A fake job may show earnings on a website, then demand a deposit before you can withdraw them. A convincing balance on a screen does not establish that money exists.", "Unexpected technical support is another common route: someone claims your device has a problem and asks for remote access. Do not install software or give control of your device because an unsolicited caller or pop-up instructs you to."] },
      { heading: "Use a scam check as supporting evidence", paragraphs: ["The SecondLook is a free scam-detection tool for suspicious messages and links. A screenshot check can identify pressure, impersonation and requests for sensitive information. A link check can examine domain records, redirects and available threat sources.", "Read the findings and unavailable checks, not only the score. A threat database may not yet list a new scam. The tool does not inspect a website’s page content or scan downloads for malware; it cannot establish the identity of someone contacting you."] },
      { heading: "If you have already acted", paragraphs: ["If you paid, contact your bank or payment provider promptly through its official channel and ask what recovery options exist. If you entered a password, change it on the real service and on any other account where you reused it; review active sessions and enable multi-factor authentication.", "Keep the original message and transaction records for a report, but do not continue the conversation to collect more evidence. Be wary of anyone who later promises to recover the money for an upfront fee. Use your country’s official fraud-reporting service."] },
    ], source: warningSource,
  },
  "/how-to-check-suspicious-links": {
    path: "/how-to-check-suspicious-links", title: "How to Check Suspicious Links — The SecondLook", titleStart: "HOW TO CHECK", titleEnd: "SUSPICIOUS LINKS.",
    description: "Check a suspicious link without opening it: understand hostnames, misleading subdomains, short links, HTTPS and the limits of phishing-link checks.",
    intro: "You do not need to open a suspicious link to investigate its address. First ask why it was sent, then examine the destination without visiting it. When a message claims an account problem, opening the real app independently is usually a better next step than following its link.",
    sections: [
      { heading: "Inspect the destination without navigating", paragraphs: ["On a desktop, hovering over a link often shows its destination. On a phone, a long press may display the address, but behaviour varies and some apps load previews. If you are unsure, do not press it; use a screenshot of the message instead.", "Visible link text and the destination can differ. Copying a link address is different from copying its label. Do not paste the address into a browser’s address bar and press Enter just to investigate it. Avoid sharing links that contain password-reset tokens, private document access or other account-specific secrets."], steps: ["Read the surrounding request: payment, sign-in, a code or a download?", "Compare the actual hostname with an address you already know for the organisation.", "If needed, paste a non-sensitive link into The SecondLook’s link check, not into your browser’s navigation bar.", "Use the organisation’s official app or independently found contact details to confirm the claim."] },
      { heading: "Read the hostname, not the brand word", paragraphs: ["In a simple web address, the hostname comes after https:// and before the next slash. A familiar word in the path does not identify the owner. Subdomains can also be misleading: the leftmost word may be a brand while the actual domain belongs to someone else.", "Domain endings vary, so do not assume the final two labels always identify the registered domain; addresses under endings such as co.uk need different interpretation. Compare the complete expected address rather than relying on a shortcut."], example: "Fictional, non-clickable example: https[:]//bank.example.com/sign-in has example.com as its domain. https[:]//example.com.bank-login.test/sign-in belongs under bank-login.test, not example.com. The .test ending here is reserved for examples." },
      { heading: "Understand HTTPS, shorteners and redirects", paragraphs: ["HTTPS encrypts the connection to a site; it does not prove the site is honest. A scam site can have a valid certificate. Likewise, words such as ‘secure’, ‘official’ or ‘verify’ in an address are claims, not credentials.", "A shortened link hides its final destination, and a normal-looking link can redirect elsewhere. The SecondLook follows supported redirects on its server with network safeguards, rather than opening the submitted link in your browser. If a destination check is unavailable, treat that as missing information, not a clean result."] },
      { heading: "Interpret a phishing-link checker carefully", paragraphs: ["A confirmed threat-source match is important evidence. A ‘not listed’ response is much narrower: that source has not identified the submitted address at the time of the check. New or targeted phishing links can be absent from public lists.", "Domain age, suspicious address patterns and DNS results are context. A new domain is not automatically a scam, and an old domain can be compromised. The SecondLook combines available signals into a reproducible score and shows the evidence, but does not inspect page content, attachments or downloaded files."] },
      { heading: "Choose the next step based on what happened", paragraphs: ["If you only received the link, avoid clicking or replying and report the message using the app’s reporting option. If you clicked but supplied nothing, close the page and do not accept downloads, notification permissions or installation prompts.", "If you entered login details, visit the real service independently, change the password and review sessions. If you shared card information or sent money, contact the bank or payment provider promptly. A screenshot or link score cannot undo a transaction or replace those recovery steps."] },
    ], source: warningSource,
  },
  "/phishing-vs-smishing": {
    path: "/phishing-vs-smishing", title: "Phishing vs. Smishing: Email and Text Scams — The SecondLook", titleStart: "PHISHING VS.", titleEnd: "SMISHING.",
    description: "Understand phishing and smishing, compare email and SMS scam examples, and learn how to verify unexpected account, delivery and payment messages.",
    intro: "Phishing is deception intended to make you disclose sensitive information or take a harmful action, often through an impersonated message. Smishing is phishing delivered by SMS or text message. The delivery channel differs; the need to verify the request independently is the same.",
    sections: [
      { heading: "Email phishing: more space for a convincing story", paragraphs: ["An email can include a logo, a long explanation, attachments and a button whose label hides its destination. A display name such as ‘Account Support’ is easy to imitate. Inspecting the sender address helps, but even an expected address is not conclusive because an account may have been compromised.", "A fake invoice may ask you to call a number to cancel a purchase you never made. The harmful step may be the phone call rather than a link: the person answering could ask for remote access or payment. Verify purchases in your actual account instead of calling the number in the alert."], example: "Fictional example: ‘Your subscription renewed for a large amount. Call the billing team below for a refund.’ The unexpected charge creates panic, while the supplied number routes you back to the sender." },
      { heading: "Smishing: a short message with pressure", paragraphs: ["A text has little room for context, so a scam may rely on a familiar event: a missed delivery, unpaid toll or blocked card. Small fees can make the request feel routine. The destination may instead collect card details, account credentials or identity information.", "A message appearing in a familiar conversation or showing a plausible sender name should not settle the question. Sender labels are not strong proof of who is contacting you. Do not treat a requested YES/NO reply or a supplied callback number as an independent check."], example: "Fictional example: ‘Delivery failed. Confirm your address and pay a redelivery fee before 6 pm.’ Open the courier’s app or check tracking details from your original order, not the message link." },
      { heading: "The practical difference when checking them", paragraphs: ["For email, review the sender, reply address, actual link destination and any attachment request. For texts, examine the phone number or label, the claimed organisation and the link. Neither a local number nor polished writing establishes trust.", "Take a screenshot that includes the sender and full request when using a suspicious-message checker. Crop out unrelated personal information first. Text extraction may miss blurry or cut-off details, so review the extracted text in your report before relying on the findings."], steps: ["Do not reply, follow the link or open the attachment to resolve an unexpected alert.", "Open the existing account or app independently and check for the claimed event.", "Contact the organisation using a number you already have or find separately.", "Report the message in your email or messaging app, then block the sender if appropriate."] },
      { heading: "Where AI-assisted checks help—and where they do not", paragraphs: ["The SecondLook uses AI for screenshot text extraction and constrained message signals, alongside deterministic rules and link checks. AI does not set the score. The report can highlight urgency, impersonation or a request for codes, but it cannot confirm that a sender really works for a bank or courier.", "A low score is not permission to share a password or one-time code. Threat lists can lag behind new campaigns. If the message and your independently opened account disagree, resolve that disagreement with the organisation rather than the sender."] },
      { heading: "After sharing information", paragraphs: ["If a phishing email or smishing text led you to enter a password, change it on the real site, review sessions and secure other accounts that reused it. If you gave away a one-time code, contact the affected service immediately; changing the password alone may not reverse an action already authorised.", "For payments or card details, contact your bank through an official number. Preserve the message and receipts, and report the incident to the appropriate national service. Avoid anyone asking for another fee to recover your money."] },
    ], source: textSource,
  },
  "/online-scam-warning-signs": {
    path: "/online-scam-warning-signs", title: "Online Scam Warning Signs to Check — The SecondLook", titleStart: "ONLINE SCAM", titleEnd: "WARNING SIGNS.",
    description: "Recognise pressure, impersonation, unusual payment demands and requests for codes; learn which warning signs matter and how to check them independently.",
    intro: "A warning sign is a reason to pause and verify, not a complete diagnosis. Look for the combination of the sender’s claim, the requested action and the pressure applied. A message with no spelling mistakes can still be a scam; an unfamiliar website can also be genuine.",
    sections: [
      { heading: "Pressure that stops you checking", paragraphs: ["An immediate deadline, threatened account closure or claim that you must act secretly can cut off the time you need to verify. Scammers may tell you not to discuss the request with your bank or family. That isolation is especially concerning when money or access codes are involved.", "Real deadlines do exist. The answer is not to ignore every urgent message, but to check the event through an independent account or contact channel before following instructions."], example: "Fictional example: ‘Your account closes in 30 minutes. Do not call the branch; this team handles security.’ The deadline and instruction not to contact the branch work together to prevent verification." },
      { heading: "Impersonation plus a sensitive request", paragraphs: ["A claimed bank, government office or support team may use a copied logo and convincing title. Ask whether the requested action fits the relationship. An unexpected request to send a password, one-time code, card details or remote-access permission is more important than the branding.", "Some services ask you to enter a code in their own sign-in process. That is different from telling a caller or message sender the code. Read what the code authorises and do not relay it in response to unsolicited contact."] },
      { heading: "Payment methods and invented fees", paragraphs: ["Requests for gift-card numbers, cryptocurrency or an upfront fee to claim a prize are strong warning signs. Transfers and payment-app transactions can be difficult to reverse. Ask why that method is required and whether the recipient matches the person or organisation you intended to pay.", "A fake investment or job platform may let you see apparent profits, then demand ‘tax’, ‘verification’ or a deposit to unlock them. Do not send more money just because the screen shows a balance. Confirm the company and transaction independently before making any payment."], example: "Fictional example: ‘You earned a commission. Deposit more to finish the task and withdraw.’ A demand to pay before receiving supposed earnings should stop the transaction, not accelerate it." },
      { heading: "A mismatch between the claim and the address", paragraphs: ["Compare the link’s actual hostname and the sender’s address with the organisation’s known details. Brand words in a subdomain or path can mislead. A shortened address hides the destination, and a valid HTTPS certificate only protects the connection—it does not establish honesty.", "These are contextual clues rather than stand-alone verdicts. A small organisation may use an unfamiliar domain, while a compromised established site may host a scam. Verify the specific request, not just the domain’s appearance or age."] },
      { heading: "Turn the warning signs into a decision", paragraphs: ["The SecondLook can assess a screenshot or link and show which warning signals contributed to its score. Read each finding and the check coverage. Missing evidence or a link not appearing in threat databases does not establish that the request is trustworthy."], steps: ["Stop the requested action while you check.", "Confirm the claim in an app or account you open independently.", "Contact the organisation using independently sourced details, never the suspicious message’s own callback number.", "Do not share passwords, one-time codes or card details in response to unexpected contact.", "Report the message; if you already paid or shared credentials, contact the bank or service promptly."] },
      { heading: "Do not use a checklist as a guarantee", paragraphs: ["Some scams have only one obvious warning sign. Others look routine because the sender has copied a genuine conversation or account. A checklist and an automated score are useful prompts, but neither can guarantee that an offer or person is genuine.", "When the evidence is unclear, leave the message unanswered and use a separate channel. You do not need to prove that something is a scam before declining to share information or send money."] },
    ], source: warningSource,
  },
};

export function guideHead(path: GuidePath) {
  const guide = SCAM_GUIDES[path];
  const url = `https://thesecondlook.lovable.app${path}`;
  return {
    meta: [
      { title: guide.title },
      { name: "description", content: guide.description },
      { property: "og:title", content: guide.title },
      { property: "og:description", content: guide.description },
      { property: "og:type", content: "article" },
      { property: "og:url", content: url },
      { name: "twitter:card", content: "summary_large_image" },
    ],
    links: [{ rel: "canonical", href: url }],
  };
}

export function GuideLinks() {
  return <nav aria-label="Scam prevention guides" className="flex flex-col items-start gap-3">
    {GUIDE_LINKS.map((guide) => <Link key={guide.to} to={guide.to} className="link-arrow">{guide.label} →</Link>)}
  </nav>;
}

export function ScamGuide({ path }: { path: GuidePath }) {
  const guide = SCAM_GUIDES[path];
  return <ProsePage label="SCAM PREVENTION" title={guide.titleStart} grey={guide.titleEnd}>
    <p>{guide.intro}</p>
    {guide.sections.map((section) => <section key={section.heading}>
      <h2>{section.heading}</h2>
      {section.paragraphs.map((paragraph) => <p key={paragraph} className="mt-4">{paragraph}</p>)}
      {section.example && <blockquote className="mt-5 border-l border-line-strong pl-5 text-grey-mid">{section.example}</blockquote>}
      {section.steps && <ol className="mt-4 space-y-2 [&_li]:list-decimal">{section.steps.map((step) => <li key={step}>{step}</li>)}</ol>}
    </section>)}
    <h2>Check the evidence with The SecondLook</h2>
    <p>Upload a screenshot or paste a link for a free check. Before you trust it, check it. No tool can catch every scam; contact the organisation using details you find yourself if something feels wrong.</p>
    <div className="flex flex-wrap gap-6">
      <Link to="/" hash="submit" className="link-arrow">Check a message or link →</Link>
      <Link to="/methodology" className="link-arrow">Read our methodology →</Link>
    </div>
    <h2>Related guides</h2>
    <nav aria-label="Related scam prevention guides" className="flex flex-col items-start gap-3">
      {GUIDE_LINKS.filter((item) => item.to !== path).map((item) => <Link key={item.to} to={item.to} className="link-arrow">{item.label} →</Link>)}
    </nav>
    <h2>Further reading</h2>
    <a href={guide.source.url} className="link-arrow underline underline-offset-4">{guide.source.label}</a>
  </ProsePage>;
}