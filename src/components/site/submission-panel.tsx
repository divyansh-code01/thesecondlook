import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { ArrowUpRight, FileWarning, ImageIcon, Link2, Replace, Trash2 } from "lucide-react";

import { createJob, createUploadTarget } from "@/lib/jobs.functions";
import type { CreateJobResult } from "@/lib/jobs.functions";

const ACCEPTED_TYPES = new Set(["image/png", "image/jpeg", "image/jpg", "image/webp"]);
const MAX_BYTES = 8 * 1024 * 1024;
const MAX_DIMENSION = 8000;
const OCR_MAX_EDGE = 2048;

type Tab = "screenshot" | "link";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

async function readMagicBytes(file: File): Promise<Uint8Array> {
  const header = new Uint8Array(await file.slice(0, 16).arrayBuffer());
  return header;
}

function sniffType(bytes: Uint8Array): string | null {
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return "image/png";
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "image/jpeg";
  if (
    bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
    bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50
  ) {
    return "image/webp";
  }
  if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) return "application/pdf";
  return null;
}

async function validateImage(file: File): Promise<{ ok: true; type: string } | { ok: false; message: string }> {
  if (file.size > MAX_BYTES) {
    return { ok: false, message: `That file is ${formatBytes(file.size)}. The maximum is 8 MB.` };
  }
  const bytes = await readMagicBytes(file);
  const sniffed = sniffType(bytes);
  if (sniffed === "application/pdf") {
    return { ok: false, message: "That file is a PDF. Please upload a PNG, JPG or WebP screenshot." };
  }
  const declared = (file.type || "").toLowerCase();
  const extension = file.name.split(".").pop()?.toLowerCase() ?? "";
  const extensionType =
    extension === "png" ? "image/png" : extension === "jpg" || extension === "jpeg" ? "image/jpeg" : extension === "webp" ? "image/webp" : null;
  if (!sniffed || !ACCEPTED_TYPES.has(sniffed)) {
    if (extensionType) {
      return { ok: false, message: "That file's contents don't match its extension. Please upload a real PNG, JPG or WebP screenshot." };
    }
    return { ok: false, message: "That file isn't a PNG, JPG or WebP screenshot. Please upload one of those." };
  }
  if (declared && !ACCEPTED_TYPES.has(declared) && declared !== "image/jpg") {
    return { ok: false, message: "That file type isn't supported. Please upload a PNG, JPG or WebP screenshot." };
  }
  return { ok: true, type: sniffed };
}

async function getDimensions(file: File): Promise<{ w: number; h: number } | null> {
  try {
    const bitmap = await createImageBitmap(file);
    const dims = { w: bitmap.width, h: bitmap.height };
    bitmap.close();
    return dims;
  } catch {
    return null;
  }
}

/** Re-encode via canvas: strips EXIF metadata and downscales oversized images. */
async function reEncode(file: File, type: string): Promise<Blob | null> {
  try {
    const bitmap = await createImageBitmap(file);
    const longest = Math.max(bitmap.width, bitmap.height);
    const scale = longest > OCR_MAX_EDGE ? OCR_MAX_EDGE / longest : 1;
    const canvas = document.createElement("canvas");
    canvas.width = Math.round(bitmap.width * scale);
    canvas.height = Math.round(bitmap.height * scale);
    const ctx = canvas.getContext("2d");
    if (!ctx) {
      bitmap.close();
      return null;
    }
    ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    bitmap.close();
    const outType = type === "image/png" ? "image/png" : type === "image/webp" ? "image/webp" : "image/jpeg";
    const blob = await new Promise<Blob | null>((resolve) =>
      canvas.toBlob(resolve, outType, outType === "image/png" ? undefined : 0.92),
    );
    return blob;
  } catch {
    return null;
  }
}

function validateLink(raw: string): { ok: true } | { ok: false; message: string } {
  const input = raw.trim();
  if (!input) return { ok: false, message: "Paste the link exactly as you received it." };
  if (input.length > 2048) return { ok: false, message: "That link is too long to check (maximum 2048 characters)." };
  const schemeMatch = input.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  if (schemeMatch) {
    const s = schemeMatch[1].toLowerCase();
    if (s !== "http" && s !== "https") {
      return {
        ok: false,
        message: ["javascript", "data", "file", "vbscript", "blob", "ftp", "mailto", "tel", "chrome", "about", "ws", "wss"].includes(s)
          ? `That's a ${s}: link, not a web address. Only http:// or https:// links can be checked.`
          : "Only http:// or https:// web links can be checked.",
      };
    }
  } else if (input.includes("/") && !input.startsWith("//")) {
    return { ok: false, message: "Add http:// or https:// at the start of the link." };
  } else if (!input.includes(".")) {
    return { ok: false, message: "Add http:// or https:// at the start of the link." };
  }
  try {
    const u = new URL(schemeMatch ? input : `https://${input.replace(/^\/+/, "")}`);
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      return { ok: false, message: "Only http:// or https:// web links can be checked." };
    }
    const host = u.hostname.toLowerCase();
    if (
      host === "localhost" ||
      host.endsWith(".localhost") ||
      host.endsWith(".local") ||
      host.endsWith(".internal") ||
      host.endsWith(".arpa") ||
      /^\d+$/.test(host) ||
      /^\[?(:?[0-9a-f]+:.*:[0-9a-f]+)\]?$/i.test(host) === false && /:/.test(host)
    ) {
      // localhost-style names and bare numeric hosts are rejected server-side too
    }
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) {
      return { ok: false, message: "That address points at a local or internal network. It can't be checked here." };
    }
    if (/^\[.*\]$/.test(host) || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      return { ok: false, message: "That address points at a network or numeric host that can't be checked here." };
    }
    return { ok: true };
  } catch {
    return { ok: false, message: "That doesn't look like a working web address. Check for typos." };
  }
}

export function SubmissionPanel() {
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>("screenshot");

  // Screenshot state
  const [file, setFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Link state
  const [linkValue, setLinkValue] = useState("");
  const [linkError, setLinkError] = useState<string | null>(null);

  const [honeypot, setHoneypot] = useState("");

  const createUploadTargetFn = useServerFn(createUploadTarget);
  const createJobFn = useServerFn(createJob);

  useEffect(() => {
    if (!file) return;
    const url = URL.createObjectURL(file);
    setPreviewUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [file]);

  const acceptFile = useCallback(async (candidate: File) => {
    setFileError(null);
    const v = await validateImage(candidate);
    if (!v.ok) {
      setFileError(v.message);
      setFile(null);
      return;
    }
    const dims = await getDimensions(candidate);
    if (!dims) {
      setFileError("That image couldn't be read. It may be corrupt — try a fresh screenshot.");
      setFile(null);
      return;
    }
    if (dims.w > MAX_DIMENSION || dims.h > MAX_DIMENSION) {
      setFileError(`That image is ${dims.w}×${dims.h} pixels. The maximum is 8000×8000.`);
      setFile(null);
      return;
    }
    setFile(candidate);
  }, []);

  const uploadWithProgress = useCallback(
    (signedUrl: string, blob: Blob): Promise<void> =>
      new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open("PUT", signedUrl, true);
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) setUploadProgress(Math.round((e.loaded / e.total) * 100));
        };
        xhr.onload = () => (xhr.status >= 200 && xhr.status < 300 ? resolve() : reject(new Error(`upload_${xhr.status}`)));
        xhr.onerror = () => reject(new Error("upload_failed"));
        xhr.send(blob);
      }),
    [],
  );

  const startScreenshotCheck = useCallback(async () => {
    if (!file || submitting) return;
    setSubmitting(true);
    setSubmitError(null);
    setStatusMessage("Preparing your screenshot…");
    try {
      const magic = await readMagicBytes(file);
      const sniffed = sniffType(magic);
      const type = sniffed ?? file.type;
      const blob = (await reEncode(file, type)) ?? file;
      setStatusMessage("Uploading…");
      setUploadProgress(0);
      const target = await createUploadTargetFn({ data: {} });
      if ("error" in target) throw new Error("upload_target_failed");
      setStatusMessage(`Uploading… ${0}%`);
      await uploadWithProgress(
        `${import.meta.env.VITE_SUPABASE_URL}/storage/v1/object/upload/sign/uploads/${target.path}?token=${encodeURIComponent(target.token)}`,
        blob,
      );
      setStatusMessage("Starting the analysis…");
      const result = (await createJobFn({
        data: {
          kind: "screenshot",
          uploadPath: target.path,
          uploadToken: target.token,
          fileName: file.name.slice(0, 200),
          fileSize: file.size,
          honeypot,
        },
      })) as CreateJobResult;
      if ("jobId" in result) {
        navigate({ to: "/check/$jobId", params: { jobId: result.jobId } });
        return;
      }
      setSubmitError(result.message);
      setUploadProgress(null);
    } catch {
      setSubmitError("The screenshot couldn't be uploaded. Check your connection and try again.");
      setUploadProgress(null);
    } finally {
      setSubmitting(false);
      setStatusMessage(null);
    }
  }, [file, submitting, honeypot, createUploadTargetFn, createJobFn, uploadWithProgress, navigate]);

  const startLinkCheck = useCallback(async () => {
    if (submitting) return;
    const v = validateLink(linkValue);
    if (!v.ok) {
      setLinkError(v.message);
      return;
    }
    setLinkError(null);
    setSubmitting(true);
    setSubmitError(null);
    setStatusMessage("Starting the analysis…");
    try {
      const input = linkValue.trim();
      const hasScheme = /^https?:\/\//i.test(input);
      const result = (await createJobFn({
        data: { kind: "url", url: hasScheme ? input : `https://${input.replace(/^\/+/, "")}`, honeypot },
      })) as CreateJobResult;
      if ("jobId" in result) {
        navigate({ to: "/check/$jobId", params: { jobId: result.jobId } });
        return;
      }
      setSubmitError(result.message);
    } catch {
      setSubmitError("The check couldn't start. Check your connection and try again.");
    } finally {
      setSubmitting(false);
      setStatusMessage(null);
    }
  }, [linkValue, submitting, honeypot, createJobFn, navigate]);

  // Paste-from-clipboard support for images (Ctrl/Cmd+V).
  useEffect(() => {
    if (tab !== "screenshot") return;
    const onPaste = (e: ClipboardEvent) => {
      const items = e.clipboardData?.items;
      if (!items) return;
      for (const item of items) {
        if (item.type.startsWith("image/")) {
          const pasted = item.getAsFile();
          if (pasted) {
            e.preventDefault();
            void acceptFile(new File([pasted], pasted.name || "pasted-screenshot.png", { type: pasted.type }));
          }
          return;
        }
      }
    };
    window.addEventListener("paste", onPaste);
    return () => window.removeEventListener("paste", onPaste);
  }, [tab, acceptFile]);

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const dropped = e.dataTransfer.files?.[0];
    if (dropped) void acceptFile(dropped);
  };

  function selectTab(next: Tab) {
    setTab(next);
    setSubmitError(null);
  }

  function onTabKeyDown(e: React.KeyboardEvent, current: Tab) {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    e.preventDefault();
    const next: Tab = current === "screenshot" ? "link" : "screenshot";
    selectTab(next);
    document.getElementById(`tab-${next}`)?.focus();
  }

  const hasScheme = /^https?:\/\//i.test(linkValue.trim());
  const needsScheme = linkValue.trim().length > 0 && !hasScheme;

  return (
    <div id="submit" data-testid="submission-panel" className="bordered-card p-5 sm:p-7 scroll-mt-24">
      {/* Tabs */}
      <div role="tablist" aria-label="What would you like to check?" className="flex gap-8 border-b border-line">
        <button
          id="tab-screenshot"
          role="tab"
          aria-selected={tab === "screenshot"}
          aria-controls="panel-screenshot"
          tabIndex={tab === "screenshot" ? 0 : -1}
          className="tab-underline flex items-center gap-2"
          onClick={() => selectTab("screenshot")}
          onKeyDown={(e) => onTabKeyDown(e, "screenshot")}
        >
          <ImageIcon className="size-4" strokeWidth={1} aria-hidden />
          Upload Screenshot
        </button>
        <button
          id="tab-link"
          role="tab"
          aria-selected={tab === "link"}
          aria-controls="panel-link"
          tabIndex={tab === "link" ? 0 : -1}
          className="tab-underline flex items-center gap-2"
          onClick={() => selectTab("link")}
          onKeyDown={(e) => onTabKeyDown(e, "link")}
        >
          <Link2 className="size-4" strokeWidth={1} aria-hidden />
          Paste Link
        </button>
      </div>

      {/* Hidden honeypot — bots fill this; humans never see it */}
      <div aria-hidden className="absolute h-0 w-0 overflow-hidden opacity-0">
        <label htmlFor="hp-company">Company</label>
        <input
          id="hp-company"
          name="company"
          type="text"
          tabIndex={-1}
          autoComplete="off"
          value={honeypot}
          onChange={(e) => setHoneypot(e.target.value)}
        />
      </div>

      {tab === "screenshot" && (
        <div id="panel-screenshot" role="tabpanel" aria-labelledby="tab-screenshot" className="pt-5">
          {!file ? (
            <div
              className={`dropzone flex flex-col items-center justify-center gap-3 px-6 py-12 md:py-16 lg:py-20 text-center ${dragOver ? "is-dragover" : ""}`}
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={onDrop}
            >
              <input
                ref={inputRef}
                id="screenshot-input"
                type="file"
                accept=".png,.jpg,.jpeg,.webp,image/png,image/jpeg,image/webp"
                className="sr-only"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) void acceptFile(f);
                  e.target.value = "";
                }}
              />
              <FileWarning className="size-8 text-grey-soft" strokeWidth={1} aria-hidden />
              <p className="text-[15px] text-foreground">
                Drop a screenshot here, or{" "}
                <button
                  type="button"
                  className="underline underline-offset-2 hover:text-ink-hover"
                  onClick={() => inputRef.current?.click()}
                >
                  browse
                </button>
              </p>
              <p className="text-[12.5px] text-grey-soft">PNG, JPG or WebP · up to 8 MB · you can also paste with Ctrl/Cmd + V</p>
            </div>
          ) : (
            <div className="flex flex-col gap-4">
              <div className="flex items-start gap-4">
                {previewUrl && (
                  <img
                    src={previewUrl}
                    alt={`Screenshot you uploaded: ${file.name}`}
                    className="max-h-48 w-auto max-w-[55%] rounded-sm border border-line object-contain"
                  />
                )}
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[14px] font-medium text-foreground">{file.name}</p>
                  <p className="text-[12.5px] text-grey-mid">{formatBytes(file.size)}</p>
                  <div className="mt-3 flex gap-4">
                    <button
                      type="button"
                      className="link-arrow text-[13px]"
                      onClick={() => {
                        setFile(null);
                        setFileError(null);
                      }}
                    >
                      <Trash2 className="size-3.5" strokeWidth={1} aria-hidden />
                      Remove
                    </button>
                    <button type="button" className="link-arrow text-[13px]" onClick={() => inputRef.current?.click()}>
                      <Replace className="size-3.5" strokeWidth={1} aria-hidden />
                      Replace
                    </button>
                    <input
                      ref={inputRef}
                      id="screenshot-input-replace"
                      type="file"
                      accept=".png,.jpg,.jpeg,.webp,image/png,image/jpeg,image/webp"
                      className="sr-only"
                      onChange={(e) => {
                        const f = e.target.files?.[0];
                        if (f) void acceptFile(f);
                        e.target.value = "";
                      }}
                    />
                  </div>
                </div>
              </div>
            </div>
          )}

          {fileError && (
            <p role="alert" className="mt-3 text-[13px] text-risk-high">
              {fileError}
            </p>
          )}

          <div className="mt-5 flex flex-col gap-3">
            <button type="button" className="btn-pill w-full sm:w-auto sm:self-start" disabled={!file || submitting} onClick={() => void startScreenshotCheck()}>
              {uploadProgress !== null && uploadProgress < 100 ? `Uploading… ${uploadProgress}%` : submitting ? "Starting…" : "Check this screenshot"}
            </button>
            {statusMessage && submitting && (
              <p aria-live="polite" className="text-[12.5px] text-grey-mid">
                {statusMessage}
              </p>
            )}
            {uploadProgress !== null && uploadProgress > 0 && (
              <div className="h-1 w-full overflow-hidden rounded-full bg-secondary" role="presentation">
                <div className="h-full bg-foreground transition-all duration-200" style={{ width: `${uploadProgress}%` }} />
              </div>
            )}
          </div>
        </div>
      )}

      {tab === "link" && (
        <div id="panel-link" role="tabpanel" aria-labelledby="tab-link" className="pt-5">
          <label htmlFor="link-input" className="sr-only">
            Link to check
          </label>
          <input
            id="link-input"
            type="text"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            className="w-full rounded-sm border border-input bg-surface px-4 py-3.5 font-mono text-[14px] text-foreground placeholder:text-grey-soft focus:border-foreground focus:outline-none"
            placeholder="https://example.com/verify-account"
            value={linkValue}
            onChange={(e) => {
              setLinkValue(e.target.value);
              setLinkError(null);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") void startLinkCheck();
            }}
          />
          {needsScheme && (
            <p className="mt-2 flex flex-wrap items-center gap-2 text-[13px] text-risk-medium">
              Add http:// or https:// at the start
              <button
                type="button"
                className="rounded-full border border-line-strong px-3 py-0.5 text-[12px] font-medium text-foreground hover:bg-secondary"
                onClick={() => setLinkValue(`https://${linkValue.trim().replace(/^\/+/, "")}`)}
              >
                Fix it
              </button>
            </p>
          )}
          {linkError && (
            <p role="alert" className="mt-2 text-[13px] text-risk-high">
              {linkError}
            </p>
          )}
          <p className="mt-3 text-[13px] text-grey-mid">Paste the link exactly as you received it. We will not open it in your browser.</p>
          <button
            type="button"
            className="mt-2 inline-flex items-center gap-1 text-[13px] text-grey-mid underline-offset-2 hover:text-foreground hover:underline"
            onClick={() => {
              setLinkValue("https://example.com");
              setLinkError(null);
            }}
          >
            <ArrowUpRight className="size-3.5" strokeWidth={1} aria-hidden />
            Try an example
          </button>

          <div className="mt-5">
            <button type="button" className="btn-pill w-full sm:w-auto sm:self-start" disabled={submitting} onClick={() => void startLinkCheck()}>
              {submitting ? "Starting…" : "Check this link"}
            </button>
          </div>
        </div>
      )}

      {submitError && (
        <p role="alert" aria-live="polite" className="mt-4 rounded-sm border border-line bg-secondary px-4 py-3 text-[13px] text-foreground">
          {submitError}
        </p>
      )}

      <p className="mt-5 border-t border-line pt-4 text-[12.5px] text-grey-soft">
        Links are never opened in your browser. Screenshots are deleted as soon as the text is extracted.
      </p>
    </div>
  );
}
