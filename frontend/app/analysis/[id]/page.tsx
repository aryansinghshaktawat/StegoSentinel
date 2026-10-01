"use client";

import { useEffect, useState, use } from "react";
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
} from "lucide-react";
import { api } from "@/lib/api";
import { AnalysisDetail } from "@/types";

export default function AnalysisDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const resolvedParams = use(params);
  const analysisId = resolvedParams.id;

  const [analysis, setAnalysis] = useState<AnalysisDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [copiedHash, setCopiedHash] = useState(false);
  const [activeTab, setActiveTab] = useState<"findings" | "candidates" | "evidence">("findings");

  const loadAnalysis = async () => {
    try {
      const data = await api.getAnalysis(analysisId);
      setAnalysis(data);
    } catch (e) {
      console.error("Error loading analysis:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAnalysis();
    // Poll while running or pending
    const interval = setInterval(() => {
      if (analysis?.status === "PENDING" || analysis?.status === "RUNNING") {
        loadAnalysis();
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [analysis?.status, analysisId]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
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

  const likelihood = analysis.stego_likelihood !== null && analysis.stego_likelihood !== undefined
    ? Math.round(analysis.stego_likelihood * 100)
    : null;

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

      {/* Primary Telemetry: Stego Likelihood Meter & File Identity */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Steganography Likelihood Score */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 relative overflow-hidden flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-xs font-mono text-slate-400 uppercase">
              <span>Steganography Likelihood</span>
              <Activity className="w-4 h-4 text-cyber-cyan" />
            </div>
            <div className="mt-4 flex items-baseline gap-2">
              <span
                className={`text-5xl font-extrabold font-mono ${
                  likelihood !== null
                    ? likelihood >= 70
                      ? "text-cyber-red"
                      : likelihood >= 40
                      ? "text-cyber-amber"
                      : "text-cyber-green"
                    : "text-slate-500"
                }`}
              >
                {likelihood !== null ? `${likelihood}%` : "CALC"}
              </span>
              <span className="text-xs font-mono text-slate-400">probability score</span>
            </div>
          </div>

          <div className="mt-4">
            <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-cyber-border">
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
            <p className="text-[11px] text-slate-400 mt-2 font-mono leading-tight">
              {likelihood !== null && likelihood >= 70
                ? "Elevated statistical anomalies and structured candidate signals detected."
                : likelihood !== null && likelihood >= 40
                ? "Moderate entropy or bit-plane variance observed."
                : "No supported steganographic indicators found within tested parameters."}
            </p>
          </div>
        </div>

        {/* Cryptographic Identification */}
        <div className="md:col-span-2 bg-cyber-card border border-cyber-border rounded-xl p-6 font-mono text-xs space-y-3">
          <div className="flex items-center justify-between border-b border-cyber-border pb-3">
            <span className="text-sm font-bold text-white flex items-center gap-2">
              <Hash className="w-4 h-4 text-cyber-cyan" />
              Cryptographic Chain of Custody
            </span>
            <span className="text-[10px] text-slate-400 uppercase">Immutable Storage</span>
          </div>

          <div className="space-y-2">
            <div>
              <span className="text-slate-400 block text-[11px]">SHA-256 Digest:</span>
              <div className="flex items-center gap-2 mt-0.5">
                <span className="text-cyber-cyan break-all bg-slate-900/80 px-2 py-1 rounded border border-cyber-border flex-1">
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

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
              <div className="p-2 rounded bg-slate-900/60 border border-cyber-border">
                <span className="text-slate-400 block text-[10px]">Detected Format</span>
                <span className="text-white font-bold">{analysis.detected_type}</span>
              </div>
              <div className="p-2 rounded bg-slate-900/60 border border-cyber-border">
                <span className="text-slate-400 block text-[10px]">File Size</span>
                <span className="text-white font-bold">{(analysis.size / 1024).toFixed(1)} KB</span>
              </div>
              <div className="p-2 rounded bg-slate-900/60 border border-cyber-border">
                <span className="text-slate-400 block text-[10px]">Shannon Entropy</span>
                <span className="text-cyber-cyan font-bold">{analysis.entropy ? `${analysis.entropy.toFixed(3)}/8` : "—"}</span>
              </div>
              <div className="p-2 rounded bg-slate-900/60 border border-cyber-border">
                <span className="text-slate-400 block text-[10px]">Discovered Objects</span>
                <span className="text-white font-bold">{analysis.evidence_objects.length}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Telemetry Tabs: Findings, Candidates, Evidence */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl overflow-hidden">
        <div className="flex border-b border-cyber-border bg-slate-900/60 font-mono text-xs">
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
          {/* TAB 1: FINDINGS */}
          {activeTab === "findings" && (
            <div className="space-y-4">
              {analysis.findings.length === 0 ? (
                <p className="text-sm font-mono text-slate-500 text-center py-8">
                  No forensic findings recorded for this artifact.
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

          {/* TAB 2: CANDIDATES */}
          {activeTab === "candidates" && (
            <div className="overflow-x-auto">
              {analysis.candidates.length === 0 ? (
                <p className="text-sm font-mono text-slate-500 text-center py-8">
                  No steganographic extraction hypotheses generated.
                </p>
              ) : (
                <table className="w-full text-left font-mono text-xs text-slate-300">
                  <thead className="bg-slate-900/80 text-slate-400 uppercase border-b border-cyber-border">
                    <tr>
                      <th className="py-2.5 px-3">Technique</th>
                      <th className="py-2.5 px-3">Parameters</th>
                      <th className="py-2.5 px-3">Extracted Type</th>
                      <th className="py-2.5 px-3">ML Score</th>
                      <th className="py-2.5 px-3">Validation</th>
                      <th className="py-2.5 px-3">Final Score</th>
                      <th className="py-2.5 px-3">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-cyber-border">
                    {analysis.candidates.map((c) => (
                      <tr key={c.id} className="hover:bg-slate-800/40">
                        <td className="py-3 px-3 font-bold text-white">{c.technique}</td>
                        <td className="py-3 px-3 text-slate-400">
                          Ch:{c.parameters.channel}, P:{c.parameters.bit_plane}, {c.parameters.order}
                        </td>
                        <td className="py-3 px-3 text-cyber-cyan">{c.extracted_type || "raw"}</td>
                        <td className="py-3 px-3">{c.ml_score.toFixed(2)}</td>
                        <td className="py-3 px-3">{c.validation_score.toFixed(2)}</td>
                        <td className="py-3 px-3 font-bold text-white">{c.final_score.toFixed(2)}</td>
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
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* TAB 3: EVIDENCE */}
          {activeTab === "evidence" && (
            <div className="space-y-4 font-mono text-xs">
              <div className="flex items-center justify-between pb-3 border-b border-cyber-border">
                <span className="text-slate-400">
                  Showing {analysis.evidence_objects.length} quarantined evidence artifact(s).
                </span>
                <Link
                  href={`/evidence/${analysis.id}`}
                  className="text-cyber-cyan hover:underline flex items-center gap-1 font-bold"
                >
                  <span>Explore Interactive Evidence Tree</span>
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
