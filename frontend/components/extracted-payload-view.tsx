"use client";

import Link from "next/link";
import {
  Lock,
  Copy,
  Check,
  DownloadCloud,
  ExternalLink,
  AlertTriangle,
  FileCode,
  ArrowRight,
} from "lucide-react";
import { Candidate, CandidatePayload } from "@/types";

export interface ExtractedPayloadViewProps {
  payload: CandidatePayload | null;
  activeCandidate: Candidate | null;
  analysisId: string;
  onCopyText?: () => void;
  copiedText?: boolean;
}

export function formatTechniqueDetails(t: string, params?: Record<string, unknown>) {
  const ch =
    (params?.channel as string) ||
    (t.includes("RGB")
      ? "RGB"
      : t.includes("_B_")
      ? "B"
      : t.includes("_R_")
      ? "R"
      : t.includes("_G_")
      ? "G"
      : "RGB");
  const plane =
    params?.bit_plane !== undefined
      ? (params.bit_plane as number)
      : t.includes("P0")
      ? 0
      : t.includes("P1")
      ? 1
      : 0;
  const rawOrder = (params?.order as string) || "";
  const order = rawOrder
    ? rawOrder.charAt(0).toUpperCase() + rawOrder.slice(1)
    : t.includes("SEQ")
    ? "Sequential"
    : t.includes("COL")
    ? "Column"
    : "Sequential";
  return {
    techniqueName: `${ch} LSB`,
    bitPlane: plane,
    channels: ch,
    traversal: order,
  };
}

export function formatPayloadType(type?: string): string {
  if (!type) return "Unknown";
  if (type === "text/plain") return "Plain Text";
  if (type === "application/zip") return "Zip Archive";
  if (type === "application/pdf") return "PDF Document";
  if (type.startsWith("image/")) return `Image (${type.split("/")[1].toUpperCase()})`;
  if (type.includes("high-entropy")) return "High-Entropy Data";
  if (type === "application/octet-stream") return "Binary Stream";
  return type;
}

export function ExtractedPayloadView({
  payload,
  activeCandidate,
  analysisId,
  onCopyText,
  copiedText = false,
}: ExtractedPayloadViewProps) {
  const activeParams = activeCandidate
    ? formatTechniqueDetails(activeCandidate.technique, activeCandidate.parameters)
    : null;

  const downloadUrl = payload?.evidence?.download_url || (activeCandidate?.evidence_object_id ? `/api/v1/evidence/${activeCandidate.evidence_object_id}/download` : undefined);

  return (
    <div
      data-testid="extracted-payload-section"
      className="bg-cyber-card border-2 border-cyber-cyan/70 rounded-xl p-6 space-y-6 shadow-2xl relative overflow-hidden"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-cyber-border pb-4">
        <div className="flex items-center gap-2">
          <Lock className="w-5 h-5 text-cyber-cyan" />
          <h2 className="text-lg font-bold text-white font-mono tracking-wider">EXTRACTED PAYLOAD</h2>
        </div>
        <div className="flex items-center gap-2">
          <span
            data-testid="decode-status-badge"
            className={`px-3 py-1 rounded text-xs font-mono font-bold ${
              payload?.decode_status === "SUCCESS"
                ? "bg-cyber-green/20 text-cyber-green border border-cyber-green/40"
                : payload?.decode_status === "IDENTIFIED"
                ? "bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40"
                : payload?.decode_status === "ENCRYPTED_OR_UNKNOWN"
                ? "bg-cyber-amber/20 text-cyber-amber border border-cyber-amber/40"
                : "bg-slate-800 text-slate-400 border border-cyber-border"
            }`}
          >
            DECODE: {payload?.decode_status || activeCandidate?.decode_status || "NONE"}
          </span>
        </div>
      </div>

      {/* Payload Metadata Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-3 font-mono text-xs">
        <div className="p-3 rounded bg-slate-900/80 border border-cyber-border">
          <span className="text-slate-500 block text-[10px] uppercase">Technique</span>
          <span className="text-white font-bold block truncate">
            {activeParams?.techniqueName || activeCandidate?.technique || "—"}
          </span>
        </div>

        <div className="p-3 rounded bg-slate-900/80 border border-cyber-border">
          <span className="text-slate-500 block text-[10px] uppercase">Bit Plane</span>
          <span className="text-cyber-cyan font-bold block">
            {activeParams?.bitPlane !== undefined ? activeParams.bitPlane : "—"}
          </span>
        </div>

        <div className="p-3 rounded bg-slate-900/80 border border-cyber-border">
          <span className="text-slate-500 block text-[10px] uppercase">Channels</span>
          <span className="text-white font-bold block">
            {activeParams?.channels || "—"}
          </span>
        </div>

        <div className="p-3 rounded bg-slate-900/80 border border-cyber-border">
          <span className="text-slate-500 block text-[10px] uppercase">Traversal</span>
          <span className="text-white font-bold block">
            {activeParams?.traversal || "—"}
          </span>
        </div>

        <div className="p-3 rounded bg-slate-900/80 border border-cyber-border">
          <span className="text-slate-500 block text-[10px] uppercase">Confidence</span>
          <span className="text-cyber-green font-bold block">
            {activeCandidate ? `${Math.round(activeCandidate.final_score * 100)}%` : "—"}
          </span>
        </div>

        <div className="p-3 rounded bg-slate-900/80 border border-cyber-border">
          <span className="text-slate-500 block text-[10px] uppercase">Payload Type</span>
          <span className="text-cyber-cyan font-bold block truncate">
            {formatPayloadType(payload?.type || activeCandidate?.extracted_type)}
          </span>
        </div>

        <div className="p-3 rounded bg-slate-900/80 border border-cyber-border">
          <span className="text-slate-500 block text-[10px] uppercase">Encoding</span>
          <span className="text-white font-bold block truncate">
            {payload?.encoding || activeCandidate?.encoding || (payload?.decode_status === "IDENTIFIED" ? "Binary" : "N/A")}
          </span>
        </div>
      </div>

      {/* Recovered Content Presentation (Safe Rendering, Never Executed) */}
      {payload?.decode_status === "SUCCESS" && payload.decoded_text ? (
        <div className="space-y-3" data-testid="recovered-text-section">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-slate-300 flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyber-green" />
              RECOVERED CONTENT
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={onCopyText}
                data-testid="copy-payload-button"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono font-bold text-slate-950 bg-cyber-green hover:bg-green-400 transition-colors"
              >
                {copiedText ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedText ? "COPIED" : "COPY TEXT"}</span>
              </button>
              <Link
                href={`/evidence/${analysisId}`}
                data-testid="view-evidence-button"
                className="flex items-center gap-1 px-3 py-1.5 rounded text-xs font-mono text-cyber-cyan hover:bg-slate-800 border border-cyber-border transition-colors"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>VIEW EVIDENCE</span>
              </Link>
              {downloadUrl && (
                <a
                  href={downloadUrl}
                  data-testid="download-evidence-button"
                  className="flex items-center gap-1 px-3 py-1.5 rounded text-xs font-mono text-slate-200 bg-slate-800 hover:bg-slate-700 border border-cyber-border transition-colors"
                >
                  <DownloadCloud className="w-3.5 h-3.5 text-cyber-cyan" />
                  <span>DOWNLOAD EVIDENCE</span>
                </a>
              )}
            </div>
          </div>

          {/* Rendered purely as escaped text node */}
          <div className="relative">
            <pre
              id="recovered-payload-content"
              data-testid="recovered-payload-content"
              className="bg-black/60 border border-cyber-green/40 rounded-lg p-5 text-cyber-green text-sm font-mono overflow-x-auto whitespace-pre-wrap break-all shadow-inner leading-relaxed select-text"
            >
              {payload.decoded_text}
            </pre>
          </div>
        </div>
      ) : payload?.decode_status === "IDENTIFIED" ? (
        /* Binary Payload UI (Requirement 17) */
        <div data-testid="binary-payload-section" className="p-5 rounded-lg bg-slate-900/90 border border-cyber-blue/40 space-y-4 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-cyber-border pb-3">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-cyber-blue" />
              <span className="font-bold text-white uppercase">PAYLOAD EXTRACTED (BINARY CONTAINER)</span>
            </div>
            <span className="text-cyber-blue text-[11px] font-bold">Static Analysis Only</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[11px]">
            <div>
              <span className="text-slate-500 block text-[10px]">Detected Format</span>
              <span className="text-cyber-cyan font-bold">{formatPayloadType(payload.type)}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Payload Size</span>
              <span className="text-white font-bold">{payload.payload_size || payload.evidence?.size || "—"} bytes</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Extraction Method</span>
              <span className="text-white font-bold">{payload.technique}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Decode Status</span>
              <span className="text-cyber-blue font-bold">IDENTIFIED (Binary)</span>
            </div>
            {payload.evidence && (
              <div className="sm:col-span-4">
                <span className="text-slate-500 block text-[10px]">Payload SHA-256 Digest:</span>
                <span className="text-cyber-cyan break-all bg-black/40 px-2 py-1 rounded border border-cyber-border block mt-0.5">
                  {payload.evidence.sha256}
                </span>
              </div>
            )}
          </div>

          <p className="text-slate-400 text-xs italic">
            Notice: Arbitrary binary payloads are never executed in StegoSentinel. Quarantined for safe static inspection.
          </p>

          <div className="flex items-center gap-3 pt-2">
            <Link
              href={`/evidence/${analysisId}`}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold text-slate-950 bg-cyber-cyan hover:bg-cyan-400 transition-colors"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>VIEW EVIDENCE</span>
            </Link>
            {downloadUrl && (
              <a
                href={downloadUrl}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold text-slate-200 bg-slate-800 hover:bg-slate-700 border border-cyber-border transition-colors"
              >
                <DownloadCloud className="w-3.5 h-3.5 text-cyber-cyan" />
                <span>DOWNLOAD EVIDENCE</span>
              </a>
            )}
          </div>
        </div>
      ) : payload?.decode_status === "ENCRYPTED_OR_UNKNOWN" ? (
        /* Encrypted or High-Entropy Payload UI */
        <div data-testid="encrypted-payload-section" className="p-4 rounded-lg bg-amber-500/10 border border-amber-500/30 font-mono text-xs space-y-2">
          <div className="flex items-center gap-2 text-cyber-amber font-bold">
            <AlertTriangle className="w-4 h-4" />
            <span>Payload extracted; encrypted or unknown content.</span>
          </div>
          <p className="text-slate-300">
            The candidate bitstream exhibits uniform high entropy consistent with encryption (AES/ChaCha20) or unknown compressed data. Zero brute-force attempted.
          </p>
          <div className="pt-2 flex items-center gap-3">
            <Link href={`/evidence/${analysisId}`} className="text-cyber-cyan underline hover:text-cyan-300">
              VIEW EVIDENCE OBJECT
            </Link>
            {downloadUrl && (
              <a href={downloadUrl} className="text-cyber-cyan underline hover:text-cyan-300">
                DOWNLOAD EVIDENCE
              </a>
            )}
          </div>
        </div>
      ) : activeCandidate && activeCandidate.status === "PARTIAL" ? (
        /* Partial extraction */
        <div data-testid="partial-payload-section" className="p-4 rounded-lg bg-slate-900 border border-cyber-border font-mono text-xs space-y-2">
          <div className="flex items-center gap-2 text-cyber-amber font-bold">
            <AlertTriangle className="w-4 h-4" />
            <span>Payload extracted but could not be decoded.</span>
          </div>
          <p className="text-slate-400">
            Bitstream contains interspersed printable fragments without sufficient linguistic or structural coherence.
          </p>
        </div>
      ) : (
        /* Extraction unsuccessful */
        <div data-testid="unsuccessful-payload-section" className="p-4 rounded-lg bg-slate-900/60 border border-cyber-border font-mono text-xs text-slate-400">
          Extraction unsuccessful. No candidate bitstream produced a valid payload.
        </div>
      )}

      {/* Evidence Link Footer */}
      {payload?.evidence && (
        <div className="pt-2 border-t border-cyber-border flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
          <div>
            <span>Linked Evidence: </span>
            <span className="text-white font-bold">{payload.evidence.name}</span>
            <span className="text-slate-500 ml-2">({payload.evidence.size} bytes)</span>
          </div>
          <div className="flex items-center gap-3">
            <Link
              href={`/evidence/${analysisId}`}
              className="text-cyber-cyan hover:underline flex items-center gap-1 font-bold"
            >
              <span>Inspect in Evidence DAG</span>
              <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
