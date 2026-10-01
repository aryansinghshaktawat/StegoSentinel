"use client";

import { useEffect, useState, use } from "react";
import Link from "next/link";
import {
  FileText,
  Download,
  Copy,
  Check,
  ArrowLeft,
  Printer,
  Shield,
  RefreshCw,
  AlertCircle,
} from "lucide-react";
import { api } from "@/lib/api";
import { Report } from "@/types";

export default function ReportViewerPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const resolvedParams = use(params);
  const analysisId = resolvedParams.id;

  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [viewMode, setViewMode] = useState<"formatted" | "markdown" | "json">("formatted");

  useEffect(() => {
    const loadReport = async () => {
      try {
        const data = (await api.getReport(analysisId, "json")) as Report;
        setReport(data);
      } catch (e) {
        console.error("Error loading report:", e);
      } finally {
        setLoading(false);
      }
    };
    loadReport();
  }, [analysisId]);

  const copyMarkdown = () => {
    if (report?.markdown_content) {
      navigator.clipboard.writeText(report.markdown_content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const downloadMarkdown = () => {
    if (!report?.markdown_content) return;
    const blob = new Blob([report.markdown_content], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `StegoSentinel_Report_${analysisId.substring(0, 8)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Top Navigation */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyber-border pb-6">
        <div>
          <Link
            href={`/analysis/${analysisId}`}
            className="inline-flex items-center gap-1 text-xs font-mono text-cyber-cyan hover:underline mb-2"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Return to Case Analysis
          </Link>
          <h1 className="text-3xl font-extrabold font-mono text-white tracking-tight flex items-center gap-3">
            <FileText className="w-7 h-7 text-cyber-cyan" />
            FORENSIC REPORT <span className="text-cyber-cyan">VIEWER</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Defensible executive briefing, technical findings correlation, and chain of custody documentation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={copyMarkdown}
            className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono rounded-lg border border-cyber-border transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-cyber-green" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? "COPIED" : "COPY MD"}</span>
          </button>
          <button
            onClick={downloadMarkdown}
            className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono rounded-lg border border-cyber-border transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>EXPORT MD</span>
          </button>
          <button
            onClick={() => window.print()}
            className="flex items-center gap-1.5 px-3 py-2 bg-cyber-cyan hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono rounded-lg transition-all glow-cyan"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>PRINT</span>
          </button>
        </div>
      </div>

      {/* Mode Selector */}
      <div className="flex border-b border-cyber-border font-mono text-xs">
        <button
          onClick={() => setViewMode("formatted")}
          className={`px-4 py-2 border-b-2 font-bold transition-colors ${
            viewMode === "formatted"
              ? "border-cyber-cyan text-cyber-cyan"
              : "border-transparent text-slate-400 hover:text-white"
          }`}
        >
          FORMATTED BRIEFING
        </button>
        <button
          onClick={() => setViewMode("markdown")}
          className={`px-4 py-2 border-b-2 font-bold transition-colors ${
            viewMode === "markdown"
              ? "border-cyber-cyan text-cyber-cyan"
              : "border-transparent text-slate-400 hover:text-white"
          }`}
        >
          RAW MARKDOWN
        </button>
        <button
          onClick={() => setViewMode("json")}
          className={`px-4 py-2 border-b-2 font-bold transition-colors ${
            viewMode === "json"
              ? "border-cyber-cyan text-cyber-cyan"
              : "border-transparent text-slate-400 hover:text-white"
          }`}
        >
          STRUCTURED JSON
        </button>
      </div>

      {loading ? (
        <div className="py-24 text-center font-mono space-y-4">
          <RefreshCw className="w-8 h-8 animate-spin mx-auto text-cyber-cyan" />
          <p className="text-sm text-slate-400">Compiling report from telemetry store...</p>
        </div>
      ) : !report ? (
        <div className="py-20 text-center font-mono space-y-3 bg-cyber-card border border-cyber-border rounded-xl p-8">
          <AlertCircle className="w-10 h-10 text-cyber-amber mx-auto" />
          <p className="text-slate-300 text-sm font-bold">Report Not Yet Compiled</p>
          <p className="text-xs text-slate-400">The analysis may still be in progress or experienced an error.</p>
        </div>
      ) : viewMode === "formatted" ? (
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-8 space-y-8 font-sans">
          {/* Executive Summary */}
          <div className="space-y-3 border-b border-cyber-border pb-6">
            <h2 className="text-lg font-bold font-mono text-white flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyber-cyan" />
              1. Executive Forensic Summary
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed bg-slate-900/60 p-4 rounded-lg border border-cyber-border">
              {report.result.executive_summary}
            </p>
          </div>

          {/* Recommendations */}
          {report.result.analyst_recommendations && (
            <div className="space-y-3 border-b border-cyber-border pb-6">
              <h2 className="text-lg font-bold font-mono text-white">
                2. DFIR Analyst Recommendations
              </h2>
              <ul className="space-y-2 text-sm text-slate-300">
                {report.result.analyst_recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-cyber-cyan font-bold font-mono">[{i + 1}]</span>
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Forensic Limitations & Disclaimers */}
          <div className="space-y-3 bg-slate-900/40 p-5 rounded-lg border border-cyber-border">
            <h2 className="text-sm font-bold font-mono text-slate-300 uppercase tracking-wider">
              3. Forensic Defense & Limitations Statement
            </h2>
            <ul className="space-y-1.5 text-xs text-slate-400 font-mono">
              {report.result.forensic_limitations.map((lim, i) => (
                <li key={i}>• {lim}</li>
              ))}
            </ul>
          </div>
        </div>
      ) : viewMode === "markdown" ? (
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
          <pre className="font-mono text-xs text-slate-300 whitespace-pre-wrap overflow-x-auto leading-relaxed">
            {report.markdown_content}
          </pre>
        </div>
      ) : (
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
          <pre className="font-mono text-xs text-cyber-cyan whitespace-pre-wrap overflow-x-auto leading-relaxed">
            {JSON.stringify(report, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
