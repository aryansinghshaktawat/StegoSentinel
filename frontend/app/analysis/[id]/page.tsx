"use client";

import { useEffect, useState, useCallback, use } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  FileText,
  Layers,
  ArrowRight,
  RefreshCw,
  Copy,
  Check,
  Hash,
  Activity,
  GitBranch,
  Lock,
  Eye,
  ShieldCheck,
} from "lucide-react";
import { api } from "@/lib/api";
import { AnalysisDetail, Candidate, CandidatePayload } from "@/types";
import {
  ExtractedPayloadView,
  formatTechniqueDetails as formatTechnique,
  formatPayloadType,
} from "@/components/extracted-payload-view";

export default function AnalysisDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const resolvedParams = use(params);
  const analysisId = resolvedParams.id;

  const [analysis, setAnalysis] = useState<AnalysisDetail | null>(null);
  const [selectedCandidate, setSelectedCandidate] = useState<Candidate | null>(null);
  const [payload, setPayload] = useState<CandidatePayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [copiedHash, setCopiedHash] = useState(false);
  const [copiedPayload, setCopiedPayload] = useState(false);
  const [activeTab, setActiveTab] = useState<"findings" | "candidates" | "evidence">("candidates");

  const loadPayloadForCandidate = useCallback(
    async (cand: Candidate, caseAnalysis: AnalysisDetail) => {
      setSelectedCandidate(cand);
      if (cand.evidence_object_id) {
        try {
          const p = await api.getCandidatePayload(caseAnalysis.id, cand.id);
          setPayload(p);
          return;
        } catch (e) {
          console.error("Error loading candidate payload from API:", e);
        }
      }

      // Direct fallback from candidate attributes
      const eo = cand.evidence_object_id
        ? caseAnalysis.evidence_objects.find((e) => e.id === cand.evidence_object_id)
        : undefined;

      setPayload({
        candidate_id: cand.id,
        analysis_id: caseAnalysis.id,
        technique: cand.technique,
        status: cand.status,
        type: cand.extracted_type,
        payload_size: cand.payload_size || (eo ? eo.size : undefined),
        encoding: cand.encoding,
        decode_status: cand.decode_status,
        decoded_text: cand.decoded_text,
        evidence_object_id: cand.evidence_object_id,
        evidence: eo
          ? {
              id: eo.id,
              name: eo.name,
              sha256: eo.sha256,
              size: eo.size,
              detected_type: eo.detected_type,
              download_url: api.getDownloadUrl(eo.id),
            }
          : undefined,
      });
    },
    []
  );

  const loadAnalysis = useCallback(async () => {
    try {
      const data = await api.getAnalysis(analysisId);
      setAnalysis(data);

      if (data.candidates && data.candidates.length > 0) {
        // Prefer top VALID candidate, else rank #1
        const topValid = data.candidates.find((c) => c.status === "VALID") || data.candidates[0];
        await loadPayloadForCandidate(topValid, data);
      }
    } catch (e) {
      console.error("Error loading analysis:", e);
    } finally {
      setLoading(false);
    }
  }, [analysisId, loadPayloadForCandidate]);

  useEffect(() => {
    loadAnalysis();
    const interval = setInterval(() => {
      if (analysis?.status === "PENDING" || analysis?.status === "RUNNING") {
        loadAnalysis();
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [analysis?.status, loadAnalysis]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const copyPayloadText = () => {
    if (payload?.decoded_text) {
      navigator.clipboard.writeText(payload.decoded_text);
      setCopiedPayload(true);
      setTimeout(() => setCopiedPayload(false), 2000);
    }
  };

  if (loading) {
    return (
      <div className="py-24 text-center font-mono space-y-4">
        <RefreshCw className="w-8 h-8 animate-spin mx-auto text-cyber-cyan" />
        <p className="text-sm text-slate-400">Loading forensic case telemetry #{analysisId}...</p>
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="py-20 text-center font-mono space-y-4">
        <ShieldAlert className="w-12 h-12 text-cyber-red mx-auto" />
        <h2 className="text-xl font-bold text-white">Case Not Found</h2>
        <p className="text-xs text-slate-400">Analysis #{analysisId} does not exist or access was denied.</p>
        <Link href="/dashboard" className="text-cyber-cyan hover:underline text-sm inline-block">
          Return to Dashboard
        </Link>
      </div>
    );
  }

  const likelihood =
    analysis.stego_likelihood !== null && analysis.stego_likelihood !== undefined
      ? Math.round(analysis.stego_likelihood * 100)
      : null;

  const topCandidate =
    analysis.candidates.length > 0
      ? analysis.candidates.find((c) => c.status === "VALID") || analysis.candidates[0]
      : null;

  const activeCandidate = selectedCandidate || topCandidate;
  const activeParams = activeCandidate ? formatTechnique(activeCandidate.technique, activeCandidate.parameters) : null;

  return (
    <div className="space-y-8">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-cyber-border pb-6">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold font-mono text-white truncate max-w-xl">
              {analysis.original_filename}
            </h1>
            <span
              className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold ${
                analysis.status === "COMPLETED"
                  ? "bg-cyber-green/15 text-cyber-green border border-cyber-green/30"
                  : analysis.status === "RUNNING"
                  ? "bg-cyber-blue/15 text-cyber-blue border border-cyber-blue/30 animate-pulse"
                  : analysis.status === "FAILED"
                  ? "bg-cyber-red/15 text-cyber-red border border-cyber-red/30"
                  : "bg-slate-800 text-slate-300"
              }`}
            >
              {analysis.status}
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-1">
            CASE ID: {analysis.id} • Registered: {new Date(analysis.created_at).toLocaleString()}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href={`/evidence/${analysis.id}`}
            className="flex items-center gap-2 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded-lg border border-cyber-border transition-colors"
          >
            <GitBranch className="w-4 h-4 text-cyber-cyan" />
            <span>EVIDENCE TREE ({analysis.evidence_objects.length})</span>
          </Link>
          <Link
            href={`/reports/${analysis.id}`}
            className="flex items-center gap-2 px-4 py-2 bg-cyber-cyan hover:bg-cyan-400 text-slate-950 text-xs font-bold font-mono rounded-lg transition-all glow-cyan"
          >
            <FileText className="w-4 h-4" />
            <span>VIEW REPORT</span>
          </Link>
        </div>
      </div>

      {/* Forensic Telemetry & Distinct Scores (Requirement 19) */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Score 1: Steganography Likelihood */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 relative overflow-hidden flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              <span>Stego Likelihood</span>
              <Activity className="w-4 h-4 text-cyber-cyan" />
            </div>
            <div className="mt-3 flex items-baseline gap-2">
              <span
                className={`text-4xl font-extrabold font-mono ${
                  likelihood !== null
                    ? likelihood >= 70
                      ? "text-cyber-red"
                      : likelihood >= 40
                      ? "text-cyber-amber"
                      : "text-cyber-green"
                    : "text-slate-500"
                }`}
              >
                {likelihood !== null ? `${likelihood}%` : "—"}
              </span>
              <span className="text-[10px] font-mono text-slate-500">anomaly probability</span>
            </div>
          </div>
          <div className="mt-3">
            <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden border border-cyber-border">
              <div
                className={`h-full transition-all duration-500 ${
                  likelihood !== null && likelihood >= 70
                    ? "bg-cyber-red"
                    : likelihood !== null && likelihood >= 40
                    ? "bg-cyber-amber"
                    : "bg-cyber-green"
                }`}
                style={{ width: `${likelihood || 0}%` }}
              ></div>
            </div>
            <span className="text-[10px] text-slate-500 font-mono mt-1.5 block">
              Statistical likelihood of covert channel presence
            </span>
          </div>
        </div>

        {/* Score 2: Extraction Confidence */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              <span>Extraction Confidence</span>
              <Layers className="w-4 h-4 text-cyber-cyan" />
            </div>
            <div className="mt-3 flex items-baseline gap-2">
              <span className="text-4xl font-extrabold font-mono text-white">
                {activeCandidate ? `${Math.round(activeCandidate.final_score * 100)}%` : "—"}
              </span>
              <span className="text-[10px] font-mono text-slate-500">ensemble score</span>
            </div>
          </div>
          <div className="mt-3 text-[11px] font-mono text-slate-400">
            <span className="text-slate-500 block text-[10px]">Top Candidate Method:</span>
            <span className="text-cyber-cyan font-bold truncate block">
              {activeParams ? `${activeParams.techniqueName} / Plane ${activeParams.bitPlane}` : "None"}
            </span>
          </div>
        </div>

        {/* Score 3: Payload Validation */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              <span>Payload Validation</span>
              <ShieldCheck className="w-4 h-4 text-cyber-cyan" />
            </div>
            <div className="mt-3 flex items-baseline gap-2">
              <span
                className={`text-4xl font-extrabold font-mono ${
                  activeCandidate && activeCandidate.status === "VALID"
                    ? "text-cyber-green"
                    : activeCandidate && activeCandidate.status === "PARTIAL"
                    ? "text-cyber-amber"
                    : "text-slate-400"
                }`}
              >
                {activeCandidate ? `${Math.round(activeCandidate.validation_score * 100)}%` : "—"}
              </span>
              <span className="text-[10px] font-mono text-slate-500">format validity</span>
            </div>
          </div>
          <div className="mt-3 text-[11px] font-mono text-slate-400">
            <span className="text-slate-500 block text-[10px]">Format Detected:</span>
            <span className="text-white font-bold truncate block">
              {activeCandidate ? formatPayloadType(activeCandidate.extracted_type) : "—"}
            </span>
          </div>
        </div>

        {/* Score 4: Decode Verdict */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              <span>Decode Status</span>
              <Lock className="w-4 h-4 text-cyber-cyan" />
            </div>
            <div className="mt-3">
              <span
                className={`inline-block px-3 py-1 rounded text-sm font-mono font-extrabold tracking-wide ${
                  payload?.decode_status === "SUCCESS"
                    ? "bg-cyber-green/20 text-cyber-green border border-cyber-green/40 glow-green"
                    : payload?.decode_status === "IDENTIFIED"
                    ? "bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40"
                    : payload?.decode_status === "ENCRYPTED_OR_UNKNOWN"
                    ? "bg-cyber-amber/20 text-cyber-amber border border-cyber-amber/40"
                    : "bg-slate-800 text-slate-400 border border-slate-700"
                }`}
              >
                {payload?.decode_status || activeCandidate?.decode_status || "NOT_ATTEMPTED"}
              </span>
            </div>
          </div>
          <div className="mt-3 text-[11px] font-mono text-slate-400">
            <span className="text-slate-500 block text-[10px]">Encoding / Nature:</span>
            <span className="text-white font-bold block">
              {payload?.encoding || activeCandidate?.encoding || (payload?.decode_status === "IDENTIFIED" ? "Structured Binary" : "N/A")}
            </span>
          </div>
        </div>
      </div>

      {/* Cryptographic Chain of Custody Card */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 font-mono text-xs space-y-3">
        <div className="flex items-center justify-between border-b border-cyber-border pb-3">
          <span className="text-sm font-bold text-white flex items-center gap-2">
            <Hash className="w-4 h-4 text-cyber-cyan" />
            Artifact Cryptographic Chain of Custody
          </span>
          <span className="text-[10px] text-slate-400 uppercase">Isolated Quarantine</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 pt-1">
          <div className="md:col-span-2">
            <span className="text-slate-400 block text-[11px]">Artifact SHA-256 Digest:</span>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-cyber-cyan break-all bg-slate-900/80 px-2 py-1 rounded border border-cyber-border flex-1 font-mono text-xs">
                {analysis.sha256}
              </span>
              <button
                onClick={() => copyToClipboard(analysis.sha256)}
                className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                title="Copy SHA-256"
              >
                {copiedHash ? <Check className="w-4 h-4 text-cyber-green" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <div className="p-2.5 rounded bg-slate-900/60 border border-cyber-border">
            <span className="text-slate-400 block text-[10px]">MIME & Size</span>
            <span className="text-white font-bold block">{analysis.detected_type}</span>
            <span className="text-slate-400 text-[10px]">{(analysis.size / 1024).toFixed(1)} KB</span>
          </div>

          <div className="p-2.5 rounded bg-slate-900/60 border border-cyber-border">
            <span className="text-slate-400 block text-[10px]">Shannon Entropy</span>
            <span className="text-cyber-cyan font-bold block">
              {analysis.entropy ? `${analysis.entropy.toFixed(3)} / 8.0` : "—"}
            </span>
            <span className="text-slate-400 text-[10px]">{analysis.evidence_objects.length} evidence object(s)</span>
          </div>
        </div>
      </div>

      {/* EXTRACTED PAYLOAD PANEL (Requirements 16, 17, 29) */}
      <ExtractedPayloadView
        payload={payload}
        activeCandidate={activeCandidate}
        analysisId={analysis.id}
        onCopyText={copyPayloadText}
        copiedText={copiedPayload}
      />


      {/* Tabs */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl overflow-hidden">
        <div className="flex border-b border-cyber-border bg-slate-900/60 font-mono text-xs">
          <button
            onClick={() => setActiveTab("candidates")}
            className={`px-5 py-3 font-bold transition-colors border-b-2 flex items-center gap-2 ${
              activeTab === "candidates"
                ? "border-cyber-cyan text-cyber-cyan bg-cyber-card"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>EXTRACTION CANDIDATES ({analysis.candidates.length})</span>
          </button>

          <button
            onClick={() => setActiveTab("findings")}
            className={`px-5 py-3 font-bold transition-colors border-b-2 flex items-center gap-2 ${
              activeTab === "findings"
                ? "border-cyber-cyan text-cyber-cyan bg-cyber-card"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>FINDINGS ({analysis.findings.length})</span>
          </button>

          <button
            onClick={() => setActiveTab("evidence")}
            className={`px-5 py-3 font-bold transition-colors border-b-2 flex items-center gap-2 ${
              activeTab === "evidence"
                ? "border-cyber-cyan text-cyber-cyan bg-cyber-card"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <GitBranch className="w-4 h-4" />
            <span>CHILD EVIDENCE ({analysis.evidence_objects.length})</span>
          </button>
        </div>

        <div className="p-6">
          {/* Candidates Tab (Requirement 18: Rank, Technique, Parameters, Validation, Payload Type, Decode Status, Confidence, Action) */}
          {activeTab === "candidates" && (
            <div className="overflow-x-auto">
              {analysis.candidates.length === 0 ? (
                <p className="text-sm font-mono text-slate-500 text-center py-8">
                  No extraction hypotheses generated.
                </p>
              ) : (
                <table className="w-full text-left font-mono text-xs text-slate-300">
                  <thead className="bg-slate-900/80 text-slate-400 uppercase border-b border-cyber-border">
                    <tr>
                      <th className="py-2.5 px-3">Rank</th>
                      <th className="py-2.5 px-3">Technique</th>
                      <th className="py-2.5 px-3">Parameters</th>
                      <th className="py-2.5 px-3">Validation</th>
                      <th className="py-2.5 px-3">Payload Type</th>
                      <th className="py-2.5 px-3">Decode Status</th>
                      <th className="py-2.5 px-3">Confidence</th>
                      <th className="py-2.5 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-cyber-border">
                    {analysis.candidates.map((c, idx) => {
                      const p = formatTechnique(c.technique, c.parameters);
                      const isSelected = selectedCandidate?.id === c.id;
                      return (
                        <tr
                          key={c.id}
                          className={`hover:bg-slate-800/40 transition-colors ${
                            isSelected ? "bg-cyber-cyan/10 border-l-2 border-cyber-cyan" : ""
                          }`}
                        >
                          <td className="py-3 px-3 font-bold text-slate-400">#{idx + 1}</td>
                          <td className="py-3 px-3 font-bold text-white">{c.technique}</td>
                          <td className="py-3 px-3 text-slate-300">
                            {p.channels} / P{p.bitPlane} / {p.traversal}
                          </td>
                          <td className="py-3 px-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                c.status === "VALID"
                                  ? "bg-cyber-green/20 text-cyber-green border border-cyber-green/40"
                                  : c.status === "PARTIAL"
                                  ? "bg-cyber-amber/20 text-cyber-amber border border-cyber-amber/40"
                                  : "bg-slate-800 text-slate-400"
                              }`}
                            >
                              {c.status}
                            </span>
                          </td>
                          <td className="py-3 px-3 text-cyber-cyan">
                            {formatPayloadType(c.extracted_type)}
                          </td>
                          <td className="py-3 px-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                c.decode_status === "SUCCESS"
                                  ? "bg-cyber-green/20 text-cyber-green"
                                  : c.decode_status === "IDENTIFIED"
                                  ? "bg-cyber-blue/20 text-cyber-blue"
                                  : c.decode_status === "ENCRYPTED_OR_UNKNOWN"
                                  ? "bg-cyber-amber/20 text-cyber-amber"
                                  : "bg-slate-800 text-slate-400"
                              }`}
                            >
                              {c.decode_status || "—"}
                            </span>
                          </td>
                          <td className="py-3 px-3 font-bold text-white">
                            {Math.round(c.final_score * 100)}%
                          </td>
                          <td className="py-3 px-3 text-right">
                            <button
                              onClick={() => {
                                loadPayloadForCandidate(c, analysis);
                                window.scrollTo({ top: 400, behavior: "smooth" });
                              }}
                              className={`inline-flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-bold border transition-colors ${
                                isSelected
                                  ? "bg-cyber-cyan text-slate-950 border-cyber-cyan"
                                  : "bg-slate-800 hover:bg-slate-700 text-cyber-cyan border-cyber-border"
                              }`}
                            >
                              <Eye className="w-3 h-3" />
                              <span>VIEW</span>
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* Findings Tab */}
          {activeTab === "findings" && (
            <div className="space-y-4">
              {analysis.findings.length === 0 ? (
                <p className="text-sm font-mono text-slate-500 text-center py-8">
                  No forensic findings recorded.
                </p>
              ) : (
                analysis.findings.map((f) => (
                  <div
                    key={f.id}
                    className="p-4 rounded-lg bg-slate-900/60 border border-cyber-border space-y-2 font-mono text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            f.severity === "CRITICAL"
                              ? "bg-red-500/20 text-red-400 border border-red-500/40"
                              : f.severity === "HIGH"
                              ? "bg-cyber-red/20 text-cyber-red border border-cyber-red/40"
                              : f.severity === "MEDIUM"
                              ? "bg-cyber-amber/20 text-cyber-amber border border-cyber-amber/40"
                              : "bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40"
                          }`}
                        >
                          {f.severity}
                        </span>
                        <span className="font-bold text-white">{f.type}</span>
                      </div>
                      <span className="text-slate-500 text-[11px]">
                        Analyzer: {f.analyzer} (v{f.analyzer_version})
                      </span>
                    </div>

                    <p className="text-slate-300 text-xs font-sans leading-relaxed">
                      {f.description}
                    </p>

                    {f.evidence && Object.keys(f.evidence).length > 0 && (
                      <div className="mt-2 p-2.5 rounded bg-black/40 border border-slate-800 text-[11px] text-slate-400 overflow-x-auto">
                        <pre>{JSON.stringify(f.evidence, null, 2)}</pre>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          )}

          {/* Evidence Tab */}
          {activeTab === "evidence" && (
            <div className="space-y-4 font-mono text-xs">
              <div className="flex items-center justify-between pb-3 border-b border-cyber-border">
                <span className="text-slate-400">
                  Showing {analysis.evidence_objects.length} evidence artifact(s).
                </span>
                <Link
                  href={`/evidence/${analysis.id}`}
                  className="text-cyber-cyan hover:underline flex items-center gap-1 font-bold"
                >
                  <span>View Interactive Evidence Tree</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>

              <div className="space-y-3">
                {analysis.evidence_objects.map((eo) => (
                  <div
                    key={eo.id}
                    className="p-3.5 rounded-lg bg-slate-900/60 border border-cyber-border flex items-center justify-between"
                  >
                    <div>
                      <span className="font-bold text-white text-sm block">{eo.name}</span>
                      <span className="text-slate-400 text-[11px] block mt-0.5">
                        Depth: {eo.recursion_depth} • Method: {eo.extraction_method} • Format: {eo.detected_type} • Size: {eo.size} B
                      </span>
                      <span className="text-slate-500 text-[10px] block font-mono">
                        SHA-256: {eo.sha256}
                      </span>
                    </div>
                    <a
                      href={api.getDownloadUrl(eo.id)}
                      className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyber-cyan text-xs font-bold border border-cyber-border"
                    >
                      Export Payload
                    </a>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

